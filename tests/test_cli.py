"""Exit-code gate and argument parsing."""

from __future__ import annotations

import pytest

from aws_vpc_flowlog_coverage.cli import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    build_parser,
    exit_code,
    parse_regions,
)
from aws_vpc_flowlog_coverage.models import (
    BROKEN,
    MISSING,
    PARTIAL,
    TRAFFIC_TYPE,
    Finding,
    RegionError,
    ScanResult,
)


def result_with(*kinds):
    r = ScanResult(regions=["eu-west-1"], vpc_count=len(kinds))
    r.findings = [
        Finding(region="eu-west-1", vpc_id="vpc-{0}".format(i), kind=k, detail="")
        for i, k in enumerate(kinds)
    ]
    return r


class TestExitCode:
    def test_fail_on_missing_exits_zero_when_worst_is_partial(self):
        assert exit_code(result_with(PARTIAL), "missing") == EXIT_OK

    def test_fail_on_missing_exits_one_on_missing(self):
        assert exit_code(result_with(PARTIAL, MISSING), "missing") == EXIT_FINDINGS

    def test_fail_on_missing_also_trips_on_broken(self):
        assert exit_code(result_with(BROKEN), "missing") == EXIT_FINDINGS

    def test_fail_on_partial_trips_on_partial(self):
        assert exit_code(result_with(PARTIAL), "partial") == EXIT_FINDINGS

    def test_fail_on_partial_ignores_traffic_type(self):
        assert exit_code(result_with(TRAFFIC_TYPE), "partial") == EXIT_OK

    def test_fail_on_any_trips_on_traffic_type(self):
        assert exit_code(result_with(TRAFFIC_TYPE), "any") == EXIT_FINDINGS

    def test_fail_on_none_never_trips(self):
        assert exit_code(result_with(MISSING, BROKEN), "none") == EXIT_OK

    def test_clean_scan_exits_zero(self):
        assert exit_code(result_with(), "any") == EXIT_OK

    def test_region_error_exits_two_even_when_clean(self):
        r = result_with()
        r.errors.append(RegionError(region="ap-east-1", error="AccessDenied"))
        assert exit_code(r, "missing") == EXIT_ERROR

    def test_findings_outrank_region_errors(self):
        r = result_with(MISSING)
        r.errors.append(RegionError(region="ap-east-1", error="AccessDenied"))
        assert exit_code(r, "missing") == EXIT_FINDINGS


class TestParser:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("", []),
            ("eu-west-1", ["eu-west-1"]),
            ("eu-west-1,us-east-1", ["eu-west-1", "us-east-1"]),
            (" eu-west-1 , us-east-1 ,", ["eu-west-1", "us-east-1"]),
        ],
    )
    def test_parse_regions(self, raw, expected):
        assert parse_regions(raw) == expected

    def test_defaults(self):
        args = build_parser().parse_args([])
        assert args.format == "text"
        assert args.fail_on == "none"
        assert args.traffic_type == "ALL"
        assert args.concurrency == 8

    def test_rejects_unknown_fail_on(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--fail-on", "catastrophic"])


class TestScanResult:
    def test_worst_picks_the_most_severe_kind(self):
        assert result_with(TRAFFIC_TYPE, PARTIAL, MISSING).worst() == MISSING

    def test_worst_is_none_when_clean(self):
        assert result_with().worst() is None

    def test_by_kind_counts(self):
        assert result_with(MISSING, MISSING, PARTIAL).by_kind() == {
            MISSING: 2,
            PARTIAL: 1,
        }
