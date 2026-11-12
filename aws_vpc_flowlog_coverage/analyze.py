"""The coverage engine.

Pure functions over the shapes EC2 returns: DescribeVpcs['Vpcs'],
DescribeSubnets['Subnets'] and DescribeFlowLogs['FlowLogs']. No boto3 client
touches this module, which is why the whole decision table is unit-testable
without an AWS account.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import BROKEN, FORMAT, MISSING, PARTIAL, TRAFFIC_TYPE, Finding

ACTIVE = "ACTIVE"

# What AWS writes when CreateFlowLogs is called without LogFormat (the version 2
# record). DescribeFlowLogs returns the format string even for such logs; this is
# only the fallback for a response that leaves the key out.
DEFAULT_LOG_FORMAT = (
    "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} "
    "${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} "
    "${log-status}"
)

# CreateFlowLogs default for MaxAggregationInterval, in seconds.
DEFAULT_MAX_AGGREGATION_INTERVAL = 600

# Field presets for --format-profile. `ir` is what an incident responder asks
# of a record and the default format cannot answer: which VPC and subnet, the
# real peers behind a NAT gateway or load balancer, the TCP handshake, and
# which way the flow went.
FORMAT_PROFILES: Dict[str, List[str]] = {
    "none": [],
    "ir": [
        "vpc-id",
        "subnet-id",
        "pkt-srcaddr",
        "pkt-dstaddr",
        "tcp-flags",
        "flow-direction",
    ],
}

_FIELD_TOKEN = re.compile(r"\$\{([^}\s]+)\}")


def _tag_name(tags: Optional[Iterable[Dict[str, str]]]) -> str:
    for tag in tags or []:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


def resource_scope(resource_id: str) -> str:
    """vpc / subnet / eni / unknown, from the flow log's ResourceId prefix."""
    if resource_id.startswith("vpc-"):
        return "vpc"
    if resource_id.startswith("subnet-"):
        return "subnet"
    if resource_id.startswith("eni-"):
        return "eni"
    return "unknown"


def is_broken(flow_log: Dict[str, Any]) -> bool:
    """A flow log that is not delivering.

    Two independent signals, because they fail independently: FlowLogStatus
    goes to FAILED when the whole log is dead, but DeliverLogsStatus and
    DeliverLogsErrorMessage can report a broken delivery role while
    FlowLogStatus still reads ACTIVE. The console leads with the first one,
    which is how a log stays "present" for three weeks and records nothing.
    """
    if (flow_log.get("FlowLogStatus") or "").upper() != ACTIVE:
        return True
    if (flow_log.get("DeliverLogsErrorMessage") or "").strip():
        return True
    deliver = (flow_log.get("DeliverLogsStatus") or "").upper()
    return bool(deliver) and deliver != "SUCCESS"


def broken_reason(flow_log: Dict[str, Any]) -> str:
    err = (flow_log.get("DeliverLogsErrorMessage") or "").strip()
    status = flow_log.get("FlowLogStatus") or "UNKNOWN"
    deliver = (flow_log.get("DeliverLogsStatus") or "").strip()
    bits = ["status={0}".format(status)]
    if deliver and deliver.upper() != "SUCCESS":
        bits.append("delivery={0}".format(deliver))
    reason = " ".join(bits)
    if err:
        reason = "{0}: {1}".format(reason, err)
    return reason


def log_fields(flow_log: Dict[str, Any]) -> List[str]:
    """Field ids in the log's LogFormat, in record order.

    The format is a space-separated list of `${field-id}` tokens. A response
    without LogFormat is read as the default version 2 format.
    """
    fmt = flow_log.get("LogFormat")
    if fmt is None:
        fmt = DEFAULT_LOG_FORMAT
    return _FIELD_TOKEN.findall(fmt)


def missing_fields(flow_log: Dict[str, Any], required: Sequence[str]) -> List[str]:
    """The required fields this log's records do not carry, in `required` order."""
    present = set(log_fields(flow_log))
    out: List[str] = []
    for name in required:
        if name not in present and name not in out:
            out.append(name)
    return out


def aggregation_interval(flow_log: Dict[str, Any]) -> int:
    value = flow_log.get("MaxAggregationInterval")
    if value is None:
        return DEFAULT_MAX_AGGREGATION_INTERVAL
    return int(value)


def unattributed_eni_logs(
    flow_logs: Sequence[Dict[str, Any]],
) -> List[str]:
    """ENI-level flow log ids that cannot be placed in a VPC.

    DescribeFlowLogs returns no VpcId, so an ENI-scoped log can only be mapped
    to a VPC by calling DescribeNetworkInterfaces, which is outside this tool's
    read-only call budget. Such logs never count as coverage anyway (one log,
    one interface), but they are reported so nobody wonders where they went.
    """
    out = []
    for log in flow_logs:
        rid = log.get("ResourceId", "")
        if resource_scope(rid) == "eni" and not log.get("VpcId"):
            out.append(log.get("FlowLogId", rid))
    return sorted(out)


def _index_subnets(subnets: Sequence[Dict[str, Any]]) -> Dict[str, List[str]]:
    by_vpc: Dict[str, List[str]] = {}
    for subnet in subnets:
        vpc_id = subnet.get("VpcId", "")
        by_vpc.setdefault(vpc_id, []).append(subnet.get("SubnetId", ""))
    for ids in by_vpc.values():
        ids.sort()
    return by_vpc


def _index_flow_logs(
    flow_logs: Sequence[Dict[str, Any]],
    subnets: Sequence[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Group flow logs by the VPC they belong to.

    A subnet-level log carries no VpcId of its own, so it is mapped through the
    subnet table. ENI-level logs are attributed only when the response happens
    to carry a VpcId; see unattributed_eni_logs().
    """
    subnet_to_vpc = {s.get("SubnetId", ""): s.get("VpcId", "") for s in subnets}
    by_vpc: Dict[str, List[Dict[str, Any]]] = {}
    for log in flow_logs:
        rid = log.get("ResourceId", "")
        scope = resource_scope(rid)
        if scope == "vpc":
            vpc_id = rid
        elif scope == "subnet":
            vpc_id = subnet_to_vpc.get(rid, "") or log.get("VpcId", "")
        else:
            vpc_id = log.get("VpcId", "")
        if not vpc_id:
            continue
        by_vpc.setdefault(vpc_id, []).append(log)
    return by_vpc


def _traffic_findings(
    region: str,
    vpc_meta: Tuple[str, str, str],
    active: Sequence[Dict[str, Any]],
    required_traffic_type: str,
) -> List[Finding]:
    vpc_id, cidr, name = vpc_meta
    required = required_traffic_type.upper()
    if required == "ANY":
        return []
    out: List[Finding] = []
    for log in sorted(active, key=lambda l: l.get("FlowLogId", "")):
        tt = (log.get("TrafficType") or "").upper()
        if not tt or tt == required:
            continue
        out.append(
            Finding(
                region=region,
                vpc_id=vpc_id,
                vpc_cidr=cidr,
                vpc_name=name,
                kind=TRAFFIC_TYPE,
                flow_log_id=log.get("FlowLogId"),
                flow_log_status=log.get("FlowLogStatus"),
                traffic_type=tt,
                detail=(
                    "captures {0} traffic only; {1} is required to reconstruct "
                    "a conversation".format(tt, required)
                ),
            )
        )
    return out


def _format_findings(
    region: str,
    vpc_meta: Tuple[str, str, str],
    active: Sequence[Dict[str, Any]],
    required_fields: Sequence[str],
    max_interval: Optional[int],
) -> List[Finding]:
    """One `format` finding per active log that lacks a field or aggregates too long.

    Both checks read values DescribeFlowLogs already returned, so they cost no
    extra API call. A log can pass coverage and still be unable to answer the
    question asked of it mid-incident.
    """
    vpc_id, cidr, name = vpc_meta
    if not required_fields and max_interval is None:
        return []
    out: List[Finding] = []
    for log in sorted(active, key=lambda l: l.get("FlowLogId", "")):
        lacking = missing_fields(log, required_fields)
        interval = aggregation_interval(log)
        too_long = max_interval is not None and interval > max_interval
        if not lacking and not too_long:
            continue
        bits = []
        if lacking:
            bits.append("log format lacks " + ", ".join(lacking))
        if too_long:
            bits.append(
                "MaxAggregationInterval={0}s, at most {1}s required".format(
                    interval, max_interval
                )
            )
        out.append(
            Finding(
                region=region,
                vpc_id=vpc_id,
                vpc_cidr=cidr,
                vpc_name=name,
                kind=FORMAT,
                flow_log_id=log.get("FlowLogId"),
                flow_log_status=log.get("FlowLogStatus"),
                missing_fields=lacking,
                max_aggregation_interval=interval if too_long else None,
                detail="; ".join(bits),
            )
        )
    return out


def analyze_region(
    region: str,
    vpcs: Sequence[Dict[str, Any]],
    subnets: Sequence[Dict[str, Any]],
    flow_logs: Sequence[Dict[str, Any]],
    required_traffic_type: str = "ALL",
    required_fields: Sequence[str] = (),
    max_interval: Optional[int] = None,
) -> List[Finding]:
    """Join VPCs, subnets and flow logs into findings for one region.

    required_fields and max_interval switch on the `format` check; with the
    defaults it is off.
    """
    subnets_by_vpc = _index_subnets(subnets)
    logs_by_vpc = _index_flow_logs(flow_logs, subnets)
    findings: List[Finding] = []

    for vpc in sorted(vpcs, key=lambda v: v.get("VpcId", "")):
        vpc_id = vpc.get("VpcId", "")
        cidr = vpc.get("CidrBlock", "")
        name = _tag_name(vpc.get("Tags"))
        meta = (vpc_id, cidr, name)
        logs = logs_by_vpc.get(vpc_id, [])

        if not logs:
            findings.append(
                Finding(
                    region=region,
                    vpc_id=vpc_id,
                    vpc_cidr=cidr,
                    vpc_name=name,
                    kind=MISSING,
                    detail="no flow log of any kind is attached to this VPC",
                )
            )
            continue

        broken = [log for log in logs if is_broken(log)]
        active = [log for log in logs if not is_broken(log)]

        for log in sorted(broken, key=lambda l: l.get("FlowLogId", "")):
            findings.append(
                Finding(
                    region=region,
                    vpc_id=vpc_id,
                    vpc_cidr=cidr,
                    vpc_name=name,
                    kind=BROKEN,
                    flow_log_id=log.get("FlowLogId"),
                    flow_log_status=log.get("FlowLogStatus"),
                    error_message=(log.get("DeliverLogsErrorMessage") or "") or None,
                    traffic_type=log.get("TrafficType"),
                    detail=broken_reason(log),
                )
            )

        if not active:
            # Every log on this VPC is dead. The `broken` findings above already
            # say coverage is zero; adding a `partial` on top would report the
            # same outage twice, the second time at a lower severity.
            continue

        vpc_wide = [
            log for log in active if resource_scope(log.get("ResourceId", "")) == "vpc"
        ]
        if not vpc_wide:
            all_subnets = subnets_by_vpc.get(vpc_id, [])
            covered = sorted(
                {
                    log.get("ResourceId", "")
                    for log in active
                    if resource_scope(log.get("ResourceId", "")) == "subnet"
                }
                & set(all_subnets)
            )
            uncovered = [s for s in all_subnets if s not in set(covered)]
            if uncovered or not covered:
                scopes = "/".join(
                    sorted(
                        {resource_scope(log.get("ResourceId", "")) for log in active}
                    )
                )
                findings.append(
                    Finding(
                        region=region,
                        vpc_id=vpc_id,
                        vpc_cidr=cidr,
                        vpc_name=name,
                        kind=PARTIAL,
                        uncovered_subnets=uncovered,
                        covered_subnets=covered,
                        detail=(
                            "{0}-level flow logs only: {1} of {2} subnets "
                            "recorded, {3} dark".format(
                                scopes, len(covered), len(all_subnets), len(uncovered)
                            )
                        ),
                    )
                )

        findings.extend(_traffic_findings(region, meta, active, required_traffic_type))
        findings.extend(
            _format_findings(region, meta, active, required_fields, max_interval)
        )

    return findings
