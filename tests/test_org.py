"""AWS Organizations: SCP layers along the tree, RCPs on the resource's account, org context keys."""

from __future__ import annotations

from pathlib import Path

import pytest

from reach.cli import main
from reach.engine import Principal, Query, ResourcePolicy, Verdict, decide
from reach.org import Organization
from reach.policy import parse_policy

ORG = Path(__file__).resolve().parent.parent / "examples" / "org" / "org.json"
APP = "123456789012"  # member account under the Prod OU
USER = f"arn:aws:iam::{APP}:user/alice"
OUTSIDER = "arn:aws:iam::999999999999:user/mallory"
BUCKET = "arn:aws:s3:::app-data/report.csv"


@pytest.fixture(scope="module")
def org() -> Organization:
    return Organization.load(str(ORG))


def pol(*statements):
    return parse_policy({"Version": "2012-10-17", "Statement": list(statements)}, "p")


ADMIN = pol({"Effect": "Allow", "Action": "*", "Resource": "*"})
TLS = {"aws:SecureTransport": "true", "aws:RequestedRegion": "eu-west-1"}


def test_scp_layers_follow_the_tree(org):
    assert [name for name, _ in org.scp_layers(APP)] == ["Root", "Prod", "app-prod"]
    assert org.org_path(APP) == "o-a1b2c3d4e5/r-ab12/ou-ab12-prod/"
    env = org.environment(APP)
    assert env.org_context["aws:PrincipalOrgID"] == "o-a1b2c3d4e5"
    assert env.org_context["aws:PrincipalOrgPaths"] == ["o-a1b2c3d4e5/r-ab12/ou-ab12-prod/"]


def test_scps_restrict_member_accounts_but_not_the_management_account(org):
    q = Query("organizations:LeaveOrganization", "*")
    assert decide(Principal(USER, [ADMIN]), q, org.environment(APP)).verdict is Verdict.DENIED
    mgmt = Principal("arn:aws:iam::111111111111:user/root-admin", [ADMIN])
    assert decide(mgmt, q, org.environment("111111111111")).verdict is Verdict.ALLOWED


def test_region_guard_from_an_ou(org):
    q = Query("s3:GetObject", BUCKET, {**TLS, "aws:RequestedRegion": "ap-south-1"})
    assert decide(Principal(USER, [ADMIN]), q, org.environment(APP)).verdict is Verdict.DENIED
    sandbox = Principal("arn:aws:iam::222222222222:user/dev", [ADMIN])
    assert decide(sandbox, q, org.environment("222222222222")).verdict is Verdict.ALLOWED


def test_rcp_data_perimeter_blocks_an_outsider_a_bucket_policy_lets_in(org):
    # The bucket policy grants an external account; the RCP on the bucket's account says only the org may enter.
    bucket_policy = ResourcePolicy(pol({"Effect": "Allow", "Principal": {"AWS": OUTSIDER}, "Action": "s3:GetObject",
                                        "Resource": "arn:aws:s3:::app-data/*"}), APP)  # fmt: skip
    outsider = Principal(OUTSIDER, [ADMIN])
    q = Query("s3:GetObject", BUCKET, TLS, bucket_policy)
    assert decide(outsider, q, org.environment("999999999999", APP)).verdict is Verdict.DENIED
    # Without the organization in the picture, the same request is allowed: the RCP is what stops it.
    assert decide(outsider, q).verdict is Verdict.ALLOWED


def test_rcp_lets_org_principals_through_and_enforces_tls(org):
    alice = Principal(USER, [ADMIN])
    assert decide(alice, Query("s3:GetObject", BUCKET, TLS), org.environment(APP)).verdict is Verdict.ALLOWED
    plain = {**TLS, "aws:SecureTransport": "false"}
    assert decide(alice, Query("s3:GetObject", BUCKET, plain), org.environment(APP)).verdict is Verdict.DENIED


def test_rcps_do_not_restrict_service_linked_roles_or_other_services(org):
    slr = Principal(f"arn:aws:iam::{APP}:role/aws-service-role/s3.amazonaws.com/AWSServiceRoleForS3", [ADMIN])
    plain = {**TLS, "aws:SecureTransport": "false"}
    assert decide(slr, Query("s3:GetObject", BUCKET, plain), org.environment(APP)).verdict is Verdict.ALLOWED
    # ec2 does not support RCPs: the TLS Deny never applies to it.
    alice = Principal(USER, [ADMIN])
    q = Query("ec2:DescribeInstances", "*", plain)
    assert decide(alice, q, org.environment(APP)).verdict is Verdict.ALLOWED


def test_rcp_on_kms_is_undecided_because_aws_managed_keys_are_exempt(org):
    outsider = Principal(OUTSIDER, [ADMIN])
    key_policy = ResourcePolicy(pol({"Effect": "Allow", "Principal": {"AWS": OUTSIDER}, "Action": "kms:Decrypt",
                                     "Resource": "*"}), APP, required=True)  # fmt: skip
    key = f"arn:aws:kms:eu-west-1:{APP}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    r = decide(outsider, Query("kms:Decrypt", key, TLS, key_policy), org.environment("999999999999", APP))
    assert r.verdict is Verdict.UNKNOWN
    assert any("AWS managed keys" in a for a in r.assumptions)


def test_resources_in_the_management_account_have_no_rcps(org):
    assert org.rcps("111111111111") == []
    assert org.rcps(APP) and all(p for p in org.rcps(APP))


def test_cli_org_flag(capsys, tmp_path):
    policy = tmp_path / "admin.json"
    policy.write_text('{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}')
    args = ["can", "--policy", str(policy), "--principal", USER, "organizations:LeaveOrganization", "*", "--json"]
    assert main(args) == 0
    assert '"verdict": "allowed"' in capsys.readouterr().out
    assert main([*args, "--org", str(ORG)]) == 0
    assert '"verdict": "denied"' in capsys.readouterr().out


class FakeOrganizations:
    """Just enough of the Organizations API, with pagination, for the exporter."""

    FULL = '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
    RCP_FULL = '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}'
    POLICIES = {"p-full": ("FullAWSAccess", FULL), "p-rcp": ("RCPFullAWSAccess", RCP_FULL)}

    def describe_organization(self):
        return {"Organization": {"Id": "o-test", "MasterAccountId": "111111111111"}}

    def list_roots(self, **_):
        types = [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"},
                 {"Type": "RESOURCE_CONTROL_POLICY", "Status": "ENABLED"}]  # fmt: skip
        return {"Roots": [{"Id": "r-1", "Name": "Root", "PolicyTypes": types}]}

    def list_policies_for_target(self, TargetId, Filter, NextToken=None):  # noqa: N803 - AWS parameter names
        pid = "p-full" if Filter == "SERVICE_CONTROL_POLICY" else "p-rcp"
        return {"Policies": [{"Id": pid, "Name": self.POLICIES[pid][0]}]}

    def describe_policy(self, PolicyId):  # noqa: N803
        return {"Policy": {"Content": self.POLICIES[PolicyId][1]}}

    def list_accounts_for_parent(self, ParentId, NextToken=None):  # noqa: N803
        if ParentId == "r-1":
            return {"Accounts": [{"Id": "111111111111", "Name": "mgmt"}]}
        if ParentId == "ou-1" and NextToken is None:
            return {"Accounts": [{"Id": "123456789012", "Name": "app"}], "NextToken": "page2"}
        if ParentId == "ou-1":
            return {"Accounts": [{"Id": "222222222222", "Name": "app2"}]}
        return {"Accounts": []}

    def list_organizational_units_for_parent(self, ParentId, NextToken=None):  # noqa: N803
        return {"OrganizationalUnits": [{"Id": "ou-1", "Name": "Prod"}] if ParentId == "r-1" else []}


def test_export_walks_the_tree_with_pagination():
    import sys  # noqa: PLC0415

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    from export_org import export  # noqa: PLC0415

    data = export(FakeOrganizations())
    assert {a["id"] for a in data["accounts"]} == {"111111111111", "123456789012", "222222222222"}
    org = Organization.from_json(data)
    assert [name for name, _ in org.scp_layers("222222222222")] == ["Root", "Prod", "app2"]
    assert org.org_path("222222222222") == "o-test/r-1/ou-1/"
    assert len(org.rcps("123456789012")) == 3 and org.rcps("111111111111") == []


def test_rcps_split_action_classes():
    # Fuzz seed 13, case 133: actions an RCP treats differently must not share a representative, or a Deny on
    # one of them "proves" the other denied.
    from reach.engine import Environment  # noqa: PLC0415

    rcp = parse_policy({"Version": "2012-10-17", "Statement": [
        {"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"},
        {"Effect": "Deny", "Principal": "*", "Action": "kms:*", "Resource": "*"},
    ]}, "rcp")  # fmt: skip
    env = Environment(rcps=[rcp])
    objects = Principal(USER, [pol({"Effect": "Allow", "Action": "s3:*Object", "Resource": "*"})])
    r = decide(objects, Query("s3:*", BUCKET), env)
    assert r.verdict is Verdict.ALLOWED and r.witness.action.lower() != "s3:getobject"
    # kms:RetireGrant is exempt from RCPs; kms:Decrypt is not (and is UNKNOWN: AWS managed keys are exempt).
    kms = Principal(USER, [pol({"Effect": "Allow", "Action": ["kms:Decrypt", "kms:RetireGrant"], "Resource": "*"})])
    key = f"arn:aws:kms:eu-west-1:{APP}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    r = decide(kms, Query("kms:*", key), env)
    assert r.verdict is Verdict.ALLOWED and r.witness.action.lower() == "kms:retiregrant"
