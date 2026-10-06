"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Sequence

from . import __version__
from .models import FAIL_ON, ScanResult

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-vpc-flowlog-coverage",
        description=(
            "Audit VPC Flow Log coverage: VPCs with no flow log, logs that "
            "stopped delivering, and subnet-only configs that leave the rest "
            "of the VPC dark."
        ),
    )
    parser.add_argument(
        "--regions",
        default="",
        help="comma-separated regions to audit (default: all enabled regions)",
    )
    parser.add_argument("--profile", default=None, help="AWS profile name")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(FAIL_ON),
        default="none",
        help=(
            "exit 1 when the worst finding reaches this level. "
            "missing = missing or broken; partial = those plus partial; "
            "any = any finding at all (default: none)"
        ),
    )
    parser.add_argument(
        "--traffic-type",
        choices=("ALL", "ACCEPT", "REJECT", "ANY"),
        default="ALL",
        help=(
            "traffic type a log must capture to count as complete; "
            "ANY disables the check (default: ALL)"
        ),
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=8,
        help="parallel region workers (default: 8)",
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def parse_regions(raw: str) -> List[str]:
    return [r.strip() for r in raw.split(",") if r.strip()]


def exit_code(result: ScanResult, fail_on: str) -> int:
    """Findings gate first, then region errors.

    A region that could not be scanned is an audit you cannot trust, so it
    exits 2 even when the regions that did answer were clean.
    """
    threshold = FAIL_ON[fail_on]
    if threshold is not None and result.worst_severity() >= threshold:
        return EXIT_FINDINGS
    if result.errors:
        return EXIT_ERROR
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    # Imported here so --help and --version work without credentials or boto3
    # import cost.
    import boto3

    from .aws import enabled_regions, scan
    from .report import render_json, render_text

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()

    regions = parse_regions(args.regions)
    if not regions:
        try:
            regions = enabled_regions(session)
        except Exception as exc:
            sys.stderr.write(
                "cannot list regions ({0}); pass --regions explicitly\n".format(exc)
            )
            return EXIT_ERROR
    if not regions:
        sys.stderr.write("no regions to audit\n")
        return EXIT_ERROR

    result = scan(
        session,
        regions,
        required_traffic_type=args.traffic_type,
        concurrency=args.concurrency,
    )

    out = render_json(result) if args.format == "json" else render_text(result)
    sys.stdout.write(out if out.endswith("\n") else out + "\n")
    return exit_code(result, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
