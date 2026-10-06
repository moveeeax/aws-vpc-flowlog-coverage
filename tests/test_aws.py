"""The boto3 adapter, driven entirely by botocore's Stubber.

No credentials, no network: Stubber asserts the request shape and replays a
canned response, so these tests check the paginator wiring and the
one-bad-region isolation that unit tests on pure functions cannot.
"""

from __future__ import annotations

import json
import pathlib

import boto3
import pytest
from botocore.stub import Stubber

from aws_vpc_flowlog_coverage.aws import enabled_regions, fetch_region, scan
from aws_vpc_flowlog_coverage.models import MISSING

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "examples" / "fixtures"
REGION = "eu-west-1"


@pytest.fixture
def session():
    return boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
        region_name=REGION,
    )


def ec2(session):
    return session.client("ec2", region_name=REGION)


def load(name):
    return json.loads((FIXTURES / name).read_text())


def stub_region(stubber, vpcs=None, subnets=None, flow_logs=None):
    stubber.add_response("describe_vpcs", {"Vpcs": vpcs or []}, {})
    stubber.add_response("describe_subnets", {"Subnets": subnets or []}, {})
    stubber.add_response("describe_flow_logs", {"FlowLogs": flow_logs or []}, {})


class TestEnabledRegions:
    def test_filters_to_usable_regions_and_sorts(self, session):
        client = ec2(session)
        with Stubber(client) as stubber:
            stubber.add_response(
                "describe_regions",
                {
                    "Regions": [
                        {"RegionName": "us-east-1"},
                        {"RegionName": "eu-central-1"},
                    ]
                },
                {
                    "AllRegions": False,
                    "Filters": [
                        {
                            "Name": "opt-in-status",
                            "Values": ["opt-in-not-required", "opted-in"],
                        }
                    ],
                },
            )
            session.client = lambda *a, **k: client
            assert enabled_regions(session) == ["eu-central-1", "us-east-1"]


class TestFetchRegion:
    def test_collects_all_three_describes(self, session):
        client = ec2(session)
        with Stubber(client) as stubber:
            stub_region(
                stubber,
                vpcs=[{"VpcId": "vpc-1"}],
                subnets=[{"SubnetId": "subnet-1", "VpcId": "vpc-1"}],
                flow_logs=[{"FlowLogId": "fl-1", "ResourceId": "vpc-1"}],
            )
            vpcs, subnets, flow_logs = fetch_region(client)
        assert [v["VpcId"] for v in vpcs] == ["vpc-1"]
        assert [s["SubnetId"] for s in subnets] == ["subnet-1"]
        assert [f["FlowLogId"] for f in flow_logs] == ["fl-1"]

    def test_follows_pagination(self, session):
        client = ec2(session)
        with Stubber(client) as stubber:
            stubber.add_response(
                "describe_vpcs", {"Vpcs": [{"VpcId": "vpc-1"}], "NextToken": "t"}, {}
            )
            stubber.add_response(
                "describe_vpcs", {"Vpcs": [{"VpcId": "vpc-2"}]}, {"NextToken": "t"}
            )
            stubber.add_response("describe_subnets", {"Subnets": []}, {})
            stubber.add_response("describe_flow_logs", {"FlowLogs": []}, {})
            vpcs, _, _ = fetch_region(client)
        assert [v["VpcId"] for v in vpcs] == ["vpc-1", "vpc-2"]


class TestScan:
    def test_end_to_end_over_the_fixtures(self, session):
        client = ec2(session)
        with Stubber(client) as stubber:
            stub_region(
                stubber,
                vpcs=load("vpcs.json"),
                subnets=load("subnets.json"),
                flow_logs=load("flow_logs.json"),
            )
            result = scan(session, [REGION], client_factory=lambda r: client)
        assert result.vpc_count == 5
        assert len(result.findings) == 4
        assert result.worst() == MISSING
        assert result.errors == []
        assert result.unattributed_eni_logs == ["eu-west-1/fl-0fff000000000005"]

    def test_multiple_regions_are_merged_and_tagged(self, session):
        clients = {}
        for region in ("eu-west-1", "us-east-1"):
            c = session.client("ec2", region_name=region)
            s = Stubber(c)
            s.add_response("describe_vpcs", {"Vpcs": [{"VpcId": "vpc-" + region}]}, {})
            s.add_response("describe_subnets", {"Subnets": []}, {})
            s.add_response("describe_flow_logs", {"FlowLogs": []}, {})
            s.activate()
            clients[region] = c

        result = scan(
            session,
            ["eu-west-1", "us-east-1"],
            concurrency=2,
            client_factory=lambda r: clients[r],
        )
        assert result.vpc_count == 2
        assert sorted(f.region for f in result.findings) == ["eu-west-1", "us-east-1"]

    def test_one_failing_region_does_not_kill_the_scan(self, session):
        good = session.client("ec2", region_name="eu-west-1")
        good_stub = Stubber(good)
        good_stub.add_response("describe_vpcs", {"Vpcs": [{"VpcId": "vpc-1"}]}, {})
        good_stub.add_response("describe_subnets", {"Subnets": []}, {})
        good_stub.add_response("describe_flow_logs", {"FlowLogs": []}, {})
        good_stub.activate()

        bad = session.client("ec2", region_name="ap-east-1")
        bad_stub = Stubber(bad)
        bad_stub.add_client_error(
            "describe_vpcs", service_error_code="UnauthorizedOperation"
        )
        bad_stub.activate()

        clients = {"eu-west-1": good, "ap-east-1": bad}
        result = scan(
            session,
            ["eu-west-1", "ap-east-1"],
            concurrency=2,
            client_factory=lambda r: clients[r],
        )
        assert [f.vpc_id for f in result.findings] == ["vpc-1"]
        assert [e.region for e in result.errors] == ["ap-east-1"]
        assert "UnauthorizedOperation" in result.errors[0].error

    def test_findings_sorted_by_region_then_severity(self, session):
        client = ec2(session)
        with Stubber(client) as stubber:
            stub_region(
                stubber,
                vpcs=[{"VpcId": "vpc-a"}, {"VpcId": "vpc-b"}],
                subnets=[{"SubnetId": "subnet-b1", "VpcId": "vpc-b"}],
                flow_logs=[
                    {
                        "FlowLogId": "fl-b",
                        "ResourceId": "vpc-b",
                        "FlowLogStatus": "ACTIVE",
                        "TrafficType": "REJECT",
                    }
                ],
            )
            result = scan(session, [REGION], client_factory=lambda r: client)
        assert [f.kind for f in result.findings] == ["missing", "traffic-type"]
