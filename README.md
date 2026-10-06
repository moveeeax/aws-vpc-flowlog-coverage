# aws-vpc-flowlog-coverage

[![ci](https://github.com/moveeeax/aws-vpc-flowlog-coverage/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-vpc-flowlog-coverage/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Find the VPCs whose traffic nobody is recording — including the ones that have a flow log that quietly stopped delivering.

Flow logs answer "what talked to that host" after an incident, and they are enabled exactly once, by hand, at account creation. Then a new VPC gets terraformed without one, or the delivery IAM role is replaced and the log flips to `FAILED` while the console still lists it as present. A Config rule tells you a flow log exists. It does not tell you the log is still delivering, or that it covers one subnet out of nine.

## What it finds

| kind | meaning |
| --- | --- |
| `missing` | the VPC has no flow log of any kind |
| `broken` | a log exists but is not delivering (`FlowLogStatus != ACTIVE`, or a delivery error) |
| `partial` | only subnet- or ENI-level logs; the uncovered subnet ids are listed |
| `traffic-type` | the log captures `ACCEPT` or `REJECT` only, so half of every conversation is gone |

`broken` and `missing` share a severity on purpose: a log stuck in `FAILED` puts exactly as many packets in your bucket as no log at all. They stay separate findings because the fix differs — repair the delivery role, or create the log.

## Install

```console
pip install git+https://github.com/moveeeax/aws-vpc-flowlog-coverage
```

Needs read-only EC2 permissions: `ec2:DescribeRegions`, `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeFlowLogs`.

## Usage

```console
$ aws-vpc-flowlog-coverage --regions eu-west-1
aws-vpc-flowlog-coverage  1 region  5 VPCs  4 findings

eu-west-1
  MISSING      vpc-0cc3333333333333c  10.2.0.0/16  staging
               no flow log of any kind is attached to this VPC
  BROKEN       vpc-0bb2222222222222b  10.1.0.0/16  prod-data
               status=FAILED delivery=FAILED: Access error: the IAM role flowlogs-delivery does not exist or cannot be assumed
               flow log: fl-0bbb000000000002
  PARTIAL      vpc-0dd4444444444444d  10.3.0.0/16  sandbox
               subnet-level flow logs only: 1 of 3 subnets recorded, 2 dark
               dark subnets: subnet-0d02, subnet-0d03
  TRAFFIC-TYPE vpc-0ee5555555555555e  10.4.0.0/16  edge
               captures REJECT traffic only; ALL is required to reconstruct a conversation

Summary: 1 missing  1 broken  1 partial  1 traffic-type
```

JSON for pipelines:

```console
$ aws-vpc-flowlog-coverage --format json | jq -r '.findings[] | select(.kind=="missing") | .vpcId'
vpc-0cc3333333333333c
```

Gate a pipeline on it:

```console
$ aws-vpc-flowlog-coverage --fail-on missing
```

With no `--regions`, every enabled region is audited concurrently.

### Flags

| flag | default | what it does |
| --- | --- | --- |
| `--regions` | all enabled regions | comma-separated region list |
| `--profile` | default chain | AWS profile |
| `--format` | `text` | `text` or `json` |
| `--fail-on` | `none` | `none`, `missing` (missing/broken), `partial` (those plus partial), `any` |
| `--traffic-type` | `ALL` | traffic type a log must capture to count as complete; `ANY` disables the check |
| `--concurrency` | `8` | parallel region workers |

### Exit codes

| code | meaning |
| --- | --- |
| `0` | nothing reached the `--fail-on` threshold |
| `1` | findings at or above the threshold |
| `2` | a region could not be scanned, or no regions resolved |

A region that errors out (an SCP deny, expired credentials) is reported in `errors` and exits `2` rather than killing the run: a partial audit you can see the holes in beats no audit. Findings outrank region errors, so a real `missing` still exits `1`.

## How it works

Three read-only describes per region, then a join. A flow log's `ResourceId` prefix says what it covers — `vpc-`, `subnet-` or `eni-` — and that prefix is the whole coverage model:

- An active `vpc-` log covers everything. Done.
- Otherwise subnet-level logs are intersected with the VPC's subnet list; whatever is left over is dark and gets named.
- An `eni-` log never counts as subnet coverage. It covers one interface.

Only active logs contribute coverage; a broken log contributes nothing. When *every* log on a VPC is broken, the report emits the `broken` findings and stops — adding a `partial` on top would report the same outage twice, the second time at a lower severity.

The engine in `aws_vpc_flowlog_coverage/analyze.py` is pure: it takes the lists `DescribeVpcs`, `DescribeSubnets` and `DescribeFlowLogs` return and gives back findings. boto3 lives in `aws.py` and nowhere else, which is why the whole decision table is tested with no AWS account.

## Try it without an AWS account

`examples/fixtures/` holds real response shapes covering all four finding kinds:

```console
$ python3 examples/offline_demo.py
$ python3 examples/offline_demo.py --format json
```

## One limitation worth knowing

`DescribeFlowLogs` does not return a `VpcId`. A subnet-level log can be mapped to its VPC through the subnet table, but an ENI-level log cannot without `DescribeNetworkInterfaces`, which is outside this tool's call budget. Those logs are listed separately in the output (`unattributedEniLogs`) instead of being silently dropped — a coverage auditor that hides data it could not place is worse than useless.

## Development

```console
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
flake8 aws_vpc_flowlog_coverage tests examples
```

## License

MIT — see [LICENSE](LICENSE).
