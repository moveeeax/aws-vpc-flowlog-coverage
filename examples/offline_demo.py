#!/usr/bin/env python3
"""Run the coverage engine over the fixtures in this directory.

No AWS account, no credentials — the fixtures are real DescribeVpcs /
DescribeSubnets / DescribeFlowLogs shapes, so this is exactly what the CLI
prints against an account in that state.

    python3 examples/offline_demo.py
    python3 examples/offline_demo.py --format json
"""

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from aws_vpc_flowlog_coverage.analyze import analyze_region, unattributed_eni_logs
from aws_vpc_flowlog_coverage.models import ScanResult
from aws_vpc_flowlog_coverage.report import render_json, render_text

HERE = pathlib.Path(__file__).resolve().parent / "fixtures"
REGION = "eu-west-1"


def load(name):
    return json.loads((HERE / name).read_text())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--format", choices=("text", "json"), default="text")
    args = ap.parse_args()

    vpcs = load("vpcs.json")
    subnets = load("subnets.json")
    flow_logs = load("flow_logs.json")

    result = ScanResult(regions=[REGION], vpc_count=len(vpcs))
    result.findings = analyze_region(REGION, vpcs, subnets, flow_logs)
    result.unattributed_eni_logs = [
        "{0}/{1}".format(REGION, fid) for fid in unattributed_eni_logs(flow_logs)
    ]

    if args.format == "json":
        print(render_json(result, generated_at="2026-01-01T00:00:00Z"))
    else:
        print(render_text(result), end="")


if __name__ == "__main__":
    main()
