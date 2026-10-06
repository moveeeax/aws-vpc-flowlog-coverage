"""Acceptance criteria for the coverage engine."""

from __future__ import annotations

import pytest

from aws_vpc_flowlog_coverage.analyze import (
    analyze_region,
    broken_reason,
    is_broken,
    resource_scope,
    unattributed_eni_logs,
)
from aws_vpc_flowlog_coverage.models import BROKEN, MISSING, PARTIAL, TRAFFIC_TYPE

REGION = "eu-west-1"


def vpc(vpc_id, cidr="10.0.0.0/16", name=None):
    out = {"VpcId": vpc_id, "CidrBlock": cidr}
    if name:
        out["Tags"] = [{"Key": "Name", "Value": name}]
    return out


def subnet(subnet_id, vpc_id):
    return {"SubnetId": subnet_id, "VpcId": vpc_id}


def flow_log(flow_log_id, resource_id, status="ACTIVE", traffic="ALL", **extra):
    out = {
        "FlowLogId": flow_log_id,
        "ResourceId": resource_id,
        "FlowLogStatus": status,
        "TrafficType": traffic,
    }
    out.update(extra)
    return out


def kinds(findings):
    return [f.kind for f in findings]


def only(findings, kind):
    matched = [f for f in findings if f.kind == kind]
    assert len(matched) == 1, "expected exactly one {0}, got {1}".format(
        kind, kinds(findings)
    )
    return matched[0]


class TestMissing:
    def test_vpc_with_no_flow_log_is_missing(self):
        findings = analyze_region(REGION, [vpc("vpc-1", name="staging")], [], [])
        f = only(findings, MISSING)
        assert f.vpc_id == "vpc-1"
        assert f.vpc_name == "staging"
        assert f.region == REGION

    def test_vpc_with_active_vpc_level_log_is_clean(self):
        findings = analyze_region(
            REGION,
            [vpc("vpc-1")],
            [subnet("subnet-a", "vpc-1")],
            [flow_log("fl-1", "vpc-1")],
        )
        assert findings == []

    def test_a_log_on_another_vpc_does_not_cover_this_one(self):
        findings = analyze_region(
            REGION, [vpc("vpc-1"), vpc("vpc-2")], [], [flow_log("fl-1", "vpc-1")]
        )
        f = only(findings, MISSING)
        assert f.vpc_id == "vpc-2"


class TestBroken:
    def test_failed_status_is_broken_with_error_text(self):
        err = "Access error: role flowlogs-delivery cannot be assumed"
        findings = analyze_region(
            REGION,
            [vpc("vpc-1")],
            [],
            [flow_log("fl-1", "vpc-1", status="FAILED", DeliverLogsErrorMessage=err)],
        )
        f = only(findings, BROKEN)
        assert f.flow_log_id == "fl-1"
        assert f.flow_log_status == "FAILED"
        assert f.error_message == err
        assert err in f.detail

    def test_broken_is_not_reported_as_missing(self):
        findings = analyze_region(
            REGION, [vpc("vpc-1")], [], [flow_log("fl-1", "vpc-1", status="FAILED")]
        )
        assert kinds(findings) == [BROKEN]

    def test_active_status_but_failed_delivery_is_broken(self):
        """The console shows ACTIVE while nothing lands in the bucket."""
        findings = analyze_region(
            REGION,
            [vpc("vpc-1")],
            [],
            [
                flow_log(
                    "fl-1",
                    "vpc-1",
                    status="ACTIVE",
                    DeliverLogsStatus="FAILED",
                    DeliverLogsErrorMessage="log group was deleted",
                )
            ],
        )
        f = only(findings, BROKEN)
        assert "log group was deleted" in f.detail

    def test_a_dead_log_does_not_also_raise_partial(self):
        findings = analyze_region(
            REGION,
            [vpc("vpc-1")],
            [subnet("subnet-a", "vpc-1"), subnet("subnet-b", "vpc-1")],
            [flow_log("fl-1", "subnet-a", status="FAILED")],
        )
        assert kinds(findings) == [BROKEN]

    @pytest.mark.parametrize(
        "log,expected",
        [
            (flow_log("fl", "vpc-1"), False),
            (flow_log("fl", "vpc-1", status="FAILED"), True),
            (flow_log("fl", "vpc-1", status="active"), False),
            (flow_log("fl", "vpc-1", DeliverLogsStatus="SUCCESS"), False),
            (flow_log("fl", "vpc-1", DeliverLogsStatus="FAILED"), True),
            (flow_log("fl", "vpc-1", DeliverLogsErrorMessage="  "), False),
            (flow_log("fl", "vpc-1", DeliverLogsErrorMessage="boom"), True),
        ],
    )
    def test_is_broken_table(self, log, expected):
        assert is_broken(log) is expected

    def test_broken_reason_without_error_message(self):
        assert broken_reason(flow_log("fl", "vpc-1", status="FAILED")) == "status=FAILED"


class TestPartial:
    def test_one_of_three_subnets_names_the_two_dark_ones(self):
        findings = analyze_region(
            REGION,
            [vpc("vpc-1", name="sandbox")],
            [
                subnet("subnet-a", "vpc-1"),
                subnet("subnet-b", "vpc-1"),
                subnet("subnet-c", "vpc-1"),
            ],
            [flow_log("fl-1", "subnet-a")],
        )
        f = only(findings, PARTIAL)
        assert f.covered_subnets == ["subnet-a"]
        assert f.uncovered_subnets == ["subnet-b", "subnet-c"]
        assert "2 dark" in f.detail

    def test_subnet_logs_covering_every_subnet_are_not_partial(self):
        findings = analyze_region(
            REGION,
            [vpc("vpc-1")],
            [subnet("subnet-a", "vpc-1"), subnet("subnet-b", "vpc-1")],
            [flow_log("fl-1", "subnet-a"), flow_log("fl-2", "subnet-b")],
        )
        assert findings == []

    def test_eni_only_coverage_is_partial_not_covered(self):
        """One ENI log is not a VPC. It covers a single interface."""
        findings = analyze_region(
            REGION,
            [vpc("vpc-1")],
            [subnet("subnet-a", "vpc-1")],
            [flow_log("fl-1", "eni-1", VpcId="vpc-1")],
        )
        f = only(findings, PARTIAL)
        assert f.uncovered_subnets == ["subnet-a"]

    def test_vpc_level_log_wins_over_subnet_gaps(self):
        findings = analyze_region(
            REGION,
            [vpc("vpc-1")],
            [subnet("subnet-a", "vpc-1"), subnet("subnet-b", "vpc-1")],
            [flow_log("fl-1", "vpc-1"), flow_log("fl-2", "subnet-a")],
        )
        assert findings == []

    def test_subnet_log_counts_only_for_its_own_vpc(self):
        findings = analyze_region(
            REGION,
            [vpc("vpc-1"), vpc("vpc-2")],
            [
                subnet("subnet-a", "vpc-1"),
                subnet("subnet-b", "vpc-1"),
                subnet("subnet-c", "vpc-2"),
            ],
            [flow_log("fl-1", "subnet-a")],
        )
        assert only(findings, MISSING).vpc_id == "vpc-2"
        assert only(findings, PARTIAL).vpc_id == "vpc-1"


class TestTrafficType:
    def test_reject_only_log_is_flagged(self):
        findings = analyze_region(
            REGION, [vpc("vpc-1")], [], [flow_log("fl-1", "vpc-1", traffic="REJECT")]
        )
        f = only(findings, TRAFFIC_TYPE)
        assert f.traffic_type == "REJECT"
        assert f.flow_log_id == "fl-1"

    def test_all_traffic_is_clean(self):
        findings = analyze_region(
            REGION, [vpc("vpc-1")], [], [flow_log("fl-1", "vpc-1", traffic="ALL")]
        )
        assert findings == []

    def test_any_disables_the_check(self):
        findings = analyze_region(
            REGION,
            [vpc("vpc-1")],
            [],
            [flow_log("fl-1", "vpc-1", traffic="ACCEPT")],
            required_traffic_type="ANY",
        )
        assert findings == []

    def test_required_accept_accepts_accept(self):
        findings = analyze_region(
            REGION,
            [vpc("vpc-1")],
            [],
            [flow_log("fl-1", "vpc-1", traffic="ACCEPT")],
            required_traffic_type="ACCEPT",
        )
        assert findings == []

    def test_broken_log_traffic_type_is_not_double_reported(self):
        findings = analyze_region(
            REGION,
            [vpc("vpc-1")],
            [],
            [flow_log("fl-1", "vpc-1", status="FAILED", traffic="REJECT")],
        )
        assert kinds(findings) == [BROKEN]


class TestHelpers:
    @pytest.mark.parametrize(
        "rid,scope",
        [
            ("vpc-123", "vpc"),
            ("subnet-123", "subnet"),
            ("eni-123", "eni"),
            ("tgw-123", "unknown"),
            ("", "unknown"),
        ],
    )
    def test_resource_scope(self, rid, scope):
        assert resource_scope(rid) == scope

    def test_unattributed_eni_logs_lists_unmappable_ids(self):
        logs = [
            flow_log("fl-1", "eni-1"),
            flow_log("fl-2", "eni-2", VpcId="vpc-1"),
            flow_log("fl-3", "vpc-1"),
        ]
        assert unattributed_eni_logs(logs) == ["fl-1"]

    def test_findings_are_deterministic_across_vpc_order(self):
        vpcs = [vpc("vpc-2"), vpc("vpc-1")]
        a = analyze_region(REGION, vpcs, [], [])
        b = analyze_region(REGION, list(reversed(vpcs)), [], [])
        assert [f.vpc_id for f in a] == [f.vpc_id for f in b] == ["vpc-1", "vpc-2"]
