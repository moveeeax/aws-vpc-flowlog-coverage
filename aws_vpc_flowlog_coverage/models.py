"""Finding model and the severity ordering the exit code is built on."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Finding kinds, from most to least severe.
MISSING = "missing"
BROKEN = "broken"
PARTIAL = "partial"
TRAFFIC_TYPE = "traffic-type"

# `broken` sits at the same rank as `missing` on purpose: a flow log stuck in
# FAILED delivers exactly as many packets to your bucket as no flow log at all.
# The kinds stay distinct in the report because the fix is different (repair the
# delivery role vs. create the log), but gating treats them as the same outage.
SEVERITY = {
    MISSING: 3,
    BROKEN: 3,
    PARTIAL: 2,
    TRAFFIC_TYPE: 1,
}

# Tie-break for worst(): `missing` and `broken` share a severity rank, so the
# reported headline kind needs a stable order of its own.
KIND_PRIORITY = [MISSING, BROKEN, PARTIAL, TRAFFIC_TYPE]

# --fail-on thresholds -> minimum severity rank that trips a non-zero exit.
FAIL_ON = {
    "none": None,
    "missing": 3,
    "partial": 2,
    "any": 1,
}


@dataclass
class Finding:
    region: str
    vpc_id: str
    kind: str
    detail: str
    vpc_cidr: str = ""
    vpc_name: str = ""
    flow_log_id: Optional[str] = None
    flow_log_status: Optional[str] = None
    error_message: Optional[str] = None
    traffic_type: Optional[str] = None
    uncovered_subnets: List[str] = field(default_factory=list)
    covered_subnets: List[str] = field(default_factory=list)

    @property
    def severity(self) -> int:
        return SEVERITY[self.kind]

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "region": self.region,
            "vpcId": self.vpc_id,
            "vpcCidr": self.vpc_cidr,
            "vpcName": self.vpc_name,
            "kind": self.kind,
            "detail": self.detail,
        }
        if self.flow_log_id is not None:
            out["flowLogId"] = self.flow_log_id
        if self.flow_log_status is not None:
            out["flowLogStatus"] = self.flow_log_status
        if self.error_message is not None:
            out["errorMessage"] = self.error_message
        if self.traffic_type is not None:
            out["trafficType"] = self.traffic_type
        if self.kind == PARTIAL:
            out["uncoveredSubnets"] = list(self.uncovered_subnets)
            out["coveredSubnets"] = list(self.covered_subnets)
        return out


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Report order: region, then severity, then a stable id.

    Worst-first inside a region is what makes the text report skimmable — the
    thing to fix today is on the first line.
    """
    return sorted(
        findings,
        key=lambda f: (
            f.region,
            KIND_PRIORITY.index(f.kind),
            f.vpc_id,
            f.flow_log_id or "",
        ),
    )


@dataclass
class RegionError:
    region: str
    error: str

    def to_dict(self) -> Dict[str, str]:
        return {"region": self.region, "error": self.error}


@dataclass
class ScanResult:
    regions: List[str] = field(default_factory=list)
    vpc_count: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[RegionError] = field(default_factory=list)
    unattributed_eni_logs: List[str] = field(default_factory=list)

    def worst(self) -> Optional[str]:
        """Kind of the most severe finding, or None when everything is covered."""
        present = {f.kind for f in self.findings}
        for kind in KIND_PRIORITY:
            if kind in present:
                return kind
        return None

    def worst_severity(self) -> int:
        return max((f.severity for f in self.findings), default=0)

    def by_kind(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.kind] = counts.get(f.kind, 0) + 1
        return counts
