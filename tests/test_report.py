"""Text and JSON rendering, driven by the committed fixtures."""

from __future__ import annotations

import json
import pathlib

from aws_vpc_flowlog_coverage.analyze import analyze_region, unattributed_eni_logs
from aws_vpc_flowlog_coverage.models import (
    BROKEN,
    MISSING,
    PARTIAL,
    TRAFFIC_TYPE,
    ScanResult,
)
from aws_vpc_flowlog_coverage.report import render_json, render_text, to_dict

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "examples" / "fixtures"
REGION = "eu-west-1"


def fixture_result():
    vpcs = json.loads((FIXTURES / "vpcs.json").read_text())
    subnets = json.loads((FIXTURES / "subnets.json").read_text())
    logs = json.loads((FIXTURES / "flow_logs.json").read_text())
    r = ScanResult(regions=[REGION], vpc_count=len(vpcs))
    r.findings = analyze_region(REGION, vpcs, subnets, logs)
    r.unattributed_eni_logs = [
        "{0}/{1}".format(REGION, f) for f in unattributed_eni_logs(logs)
    ]
    return r


class TestFixtures:
    def test_every_kind_is_represented(self):
        r = fixture_result()
        assert r.by_kind() == {MISSING: 1, BROKEN: 1, PARTIAL: 1, TRAFFIC_TYPE: 1}

    def test_worst_is_missing(self):
        assert fixture_result().worst() == MISSING

    def test_clean_vpc_produces_no_finding(self):
        ids = {f.vpc_id for f in fixture_result().findings}
        assert "vpc-0aa1111111111111a" not in ids

    def test_unattributed_eni_log_is_surfaced(self):
        assert fixture_result().unattributed_eni_logs == [
            "eu-west-1/fl-0fff000000000005"
        ]


class TestJson:
    def test_shape(self):
        payload = json.loads(render_json(fixture_result(), "2026-01-01T00:00:00Z"))
        assert payload["generatedAt"] == "2026-01-01T00:00:00Z"
        assert payload["regions"] == [REGION]
        assert payload["summary"]["vpcs"] == 5
        assert payload["summary"]["findings"] == 4
        assert payload["summary"]["worst"] == MISSING
        assert payload["errors"] == []

    def test_findings_are_filterable_by_kind(self):
        payload = json.loads(render_json(fixture_result()))
        missing = [f for f in payload["findings"] if f["kind"] == MISSING]
        assert [f["vpcId"] for f in missing] == ["vpc-0cc3333333333333c"]

    def test_partial_finding_carries_subnet_lists(self):
        payload = json.loads(render_json(fixture_result()))
        partial = [f for f in payload["findings"] if f["kind"] == PARTIAL][0]
        assert partial["coveredSubnets"] == ["subnet-0d01"]
        assert partial["uncoveredSubnets"] == ["subnet-0d02", "subnet-0d03"]

    def test_broken_finding_carries_the_delivery_error(self):
        payload = json.loads(render_json(fixture_result()))
        broken = [f for f in payload["findings"] if f["kind"] == BROKEN][0]
        assert "flowlogs-delivery" in broken["errorMessage"]

    def test_optional_keys_are_omitted_when_empty(self):
        payload = json.loads(render_json(fixture_result()))
        missing = [f for f in payload["findings"] if f["kind"] == MISSING][0]
        assert "flowLogId" not in missing
        assert "errorMessage" not in missing

    def test_to_dict_stamps_a_time_when_not_given(self):
        assert to_dict(fixture_result())["generatedAt"].endswith("Z")


class TestText:
    def test_mentions_each_kind_and_the_dark_subnets(self):
        out = render_text(fixture_result())
        for kind in (MISSING, BROKEN, PARTIAL, TRAFFIC_TYPE):
            assert kind.upper() in out
        assert "subnet-0d02, subnet-0d03" in out
        assert "5 VPCs  4 findings" in out

    def test_clean_scan_says_so(self):
        out = render_text(ScanResult(regions=[REGION], vpc_count=3))
        assert "Nothing to fix." in out
        assert "MISSING" not in out

    def test_singular_region_wording(self):
        assert "1 region " in render_text(ScanResult(regions=[REGION]))

    def test_region_errors_are_printed(self):
        from aws_vpc_flowlog_coverage.models import RegionError

        r = ScanResult(regions=[REGION])
        r.errors.append(RegionError(region="ap-east-1", error="AccessDenied"))
        assert "ERROR  ap-east-1: AccessDenied" in render_text(r)

    def test_output_ends_with_one_newline(self):
        out = render_text(fixture_result())
        assert out.endswith("\n") and not out.endswith("\n\n")
