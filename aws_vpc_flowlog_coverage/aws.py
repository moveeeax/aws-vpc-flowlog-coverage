"""boto3 adapter: the only module that talks to AWS.

Every call here is read-only: ec2:DescribeRegions, ec2:DescribeVpcs,
ec2:DescribeSubnets, ec2:DescribeFlowLogs.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Sequence, Tuple

from botocore.exceptions import BotoCoreError, ClientError

from .analyze import analyze_region, unattributed_eni_logs
from .models import RegionError, ScanResult, sort_findings

RegionData = Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]


def _paginate(client, operation: str, key: str) -> List[Dict[str, Any]]:
    """Collect every page of a Describe* call.

    Falls back to a single call for operations botocore has no paginator for,
    so a stubbed or older client still works.
    """
    if client.can_paginate(operation):
        out: List[Dict[str, Any]] = []
        for page in client.get_paginator(operation).paginate():
            out.extend(page.get(key, []))
        return out
    return getattr(client, operation)().get(key, [])


def enabled_regions(session) -> List[str]:
    """Regions this account can actually call, opt-ins included."""
    client = session.client("ec2")
    resp = client.describe_regions(
        AllRegions=False,
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}],
    )
    return sorted(r["RegionName"] for r in resp.get("Regions", []))


def fetch_region(client) -> RegionData:
    """The three describes a region needs, in one place."""
    vpcs = _paginate(client, "describe_vpcs", "Vpcs")
    subnets = _paginate(client, "describe_subnets", "Subnets")
    flow_logs = _paginate(client, "describe_flow_logs", "FlowLogs")
    return vpcs, subnets, flow_logs


def scan(
    session,
    regions: Sequence[str],
    required_traffic_type: str = "ALL",
    concurrency: int = 8,
    client_factory=None,
) -> ScanResult:
    """Audit every region concurrently and merge the findings.

    A region that errors out (SCP deny, expired creds, a region that went
    unreachable) is recorded in result.errors rather than killing the run — a
    partial audit you can see the holes in beats no audit.
    """
    factory = client_factory or (lambda region: session.client("ec2", region_name=region))
    result = ScanResult(regions=list(regions))
    workers = max(1, min(int(concurrency), len(regions) or 1))

    def one(region: str):
        client = factory(region)
        return region, fetch_region(client)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for region, outcome in zip(regions, pool.map(_safe(one), regions)):
            err, payload = outcome
            if err is not None:
                result.errors.append(RegionError(region=region, error=err))
                continue
            _region, (vpcs, subnets, flow_logs) = payload
            result.vpc_count += len(vpcs)
            result.findings.extend(
                analyze_region(
                    region,
                    vpcs,
                    subnets,
                    flow_logs,
                    required_traffic_type=required_traffic_type,
                )
            )
            result.unattributed_eni_logs.extend(
                "{0}/{1}".format(region, fid) for fid in unattributed_eni_logs(flow_logs)
            )

    result.findings = sort_findings(result.findings)
    return result


def _safe(fn):
    """Turn an exception into (message, None) so one bad region stays local."""

    def wrapped(arg):
        try:
            return None, fn(arg)
        except (ClientError, BotoCoreError) as exc:
            return str(exc), None
        except Exception as exc:  # pragma: no cover - defensive
            return "{0}: {1}".format(type(exc).__name__, exc), None

    return wrapped
