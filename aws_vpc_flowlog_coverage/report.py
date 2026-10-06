"""Rendering: a text report for humans, JSON for jq and CI."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from .models import BROKEN, MISSING, PARTIAL, TRAFFIC_TYPE, ScanResult, sort_findings

KIND_ORDER = [MISSING, BROKEN, PARTIAL, TRAFFIC_TYPE]


def to_dict(result: ScanResult, generated_at: str = "") -> Dict[str, Any]:
    stamp = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    counts = result.by_kind()
    return {
        "generatedAt": stamp,
        "regions": list(result.regions),
        "summary": {
            "vpcs": result.vpc_count,
            "findings": len(result.findings),
            "byKind": {k: counts[k] for k in KIND_ORDER if k in counts},
            "worst": result.worst(),
        },
        "findings": [f.to_dict() for f in sort_findings(result.findings)],
        "unattributedEniLogs": list(result.unattributed_eni_logs),
        "errors": [e.to_dict() for e in result.errors],
    }


def render_json(result: ScanResult, generated_at: str = "") -> str:
    return json.dumps(to_dict(result, generated_at), indent=2, sort_keys=False)


def render_text(result: ScanResult) -> str:
    lines: List[str] = []
    plural = "region" if len(result.regions) == 1 else "regions"
    lines.append(
        "aws-vpc-flowlog-coverage  {0} {1}  {2} VPCs  {3} findings".format(
            len(result.regions), plural, result.vpc_count, len(result.findings)
        )
    )

    if not result.findings:
        lines.append("")
        lines.append("Every VPC has an active, VPC-wide flow log. Nothing to fix.")
    else:
        current = None
        for f in sort_findings(result.findings):
            if f.region != current:
                current = f.region
                lines.append("")
                lines.append(f.region)
            label = f.kind.upper().ljust(13)
            head = "  {0}{1}".format(label, f.vpc_id)
            if f.vpc_cidr:
                head += "  " + f.vpc_cidr
            if f.vpc_name:
                head += "  " + f.vpc_name
            lines.append(head)
            lines.append("               " + f.detail)
            if f.kind == PARTIAL and f.uncovered_subnets:
                lines.append(
                    "               dark subnets: " + ", ".join(f.uncovered_subnets)
                )
            if f.kind == BROKEN and f.flow_log_id:
                lines.append("               flow log: " + f.flow_log_id)

        counts = result.by_kind()
        lines.append("")
        lines.append(
            "Summary: "
            + "  ".join(
                "{0} {1}".format(counts[k], k) for k in KIND_ORDER if k in counts
            )
        )

    if result.unattributed_eni_logs:
        lines.append(
            "Note: {0} ENI-level flow log(s) could not be mapped to a VPC "
            "(DescribeFlowLogs returns no VpcId): {1}".format(
                len(result.unattributed_eni_logs),
                ", ".join(result.unattributed_eni_logs),
            )
        )

    for err in result.errors:
        lines.append("ERROR  {0}: {1}".format(err.region, err.error))

    return "\n".join(lines) + "\n"
