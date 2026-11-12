"""Exit-code gate and argument parsing."""

from __future__ import annotations

import argparse

import pytest

from aws_vpc_flowlog_coverage.cli import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    build_parser,
    exit_code,
    parse_fields,
    parse_regions,
    required_fields,
)
from aws_vpc_flowlog_coverage.models import (
    BROKEN,
    FORMAT,
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

    def test_fail_on_partial_ignores_format(self):
        assert exit_code(result_with(FORMAT), "partial") == EXIT_OK

    def test_fail_on_any_trips_on_format(self):
        assert exit_code(result_with(FORMAT), "any") == EXIT_FINDINGS

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
        assert args.require_fields == []
        assert args.format_profile == "none"
        assert args.max_interval is None

    def test_format_flags(self):
        args = build_parser().parse_args(
            [
                "--require-fields",
                "pkt-srcaddr,tcp-flags",
                "--format-profile",
                "ir",
                "--max-interval",
                "60",
            ]
        )
        assert args.require_fields == ["pkt-srcaddr", "tcp-flags"]
        assert args.format_profile == "ir"
        assert args.max_interval == 60

    def test_rejects_an_interval_aws_does_not_offer(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--max-interval", "300"])

    def test_rejects_unknown_format_profile(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--format-profile", "forensics"])

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("", []),
            ("tcp-flags", ["tcp-flags"]),
            ("pkt-srcaddr, pkt-dstaddr,", ["pkt-srcaddr", "pkt-dstaddr"]),
            ("${pkt-srcaddr} ${tcp-flags}", ["pkt-srcaddr", "tcp-flags"]),
            ("tcp-flags,tcp-flags", ["tcp-flags"]),
        ],
    )
    def test_parse_fields(self, raw, expected):
        assert parse_fields(raw) == expected

    @pytest.mark.parametrize("raw", ["tcp_flags", "TcpFlags", "${tcp-flags", "-x"])
    def test_parse_fields_rejects_malformed_ids(self, raw):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_fields(raw)

    def test_required_fields_merges_profile_and_extra(self):
        assert required_fields("ir", ["tcp-flags", "instance-id"]) == [
            "vpc-id",
            "subnet-id",
            "pkt-srcaddr",
            "pkt-dstaddr",
            "tcp-flags",
            "flow-direction",
            "instance-id",
        ]

    def test_required_fields_none_profile(self):
        assert required_fields("none", ["tcp-flags"]) == ["tcp-flags"]

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
