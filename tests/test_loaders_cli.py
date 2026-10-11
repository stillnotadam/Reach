from __future__ import annotations

import json
from pathlib import Path

import pytest

from reach.cli import main
from reach.engine import Query, Verdict, decide
from reach.loaders import AuthorizationDetails, trust_policy

FIXTURE = str(Path(__file__).parent / "fixtures" / "authz.json")


@pytest.fixture(scope="module")
def details() -> AuthorizationDetails:
    return AuthorizationDetails.load(FIXTURE)


def test_user_collects_group_managed_inline_and_boundary(details):
    alice = details.principal("alice")
    names = {p.name for p in alice.identity_policies}
    assert names == {"PowerUserAccess", "alice/inline/deny-iam"}
    assert alice.boundary and alice.boundary.name == "dev-boundary"
    assert alice.tags == {"team": "data"}
    assert not alice.unresolved


def test_only_the_default_policy_version_is_used(details):
    alice = details.principal("alice")
    # v1 of the boundary allowed everything; v2 (the default) does not allow ec2:RunInstances.
    assert decide(alice, Query("ec2:RunInstances", "*")).verdict is Verdict.DENIED
    assert decide(alice, Query("s3:GetObject", "*")).verdict is Verdict.ALLOWED


def test_url_encoded_inline_policy_and_principal_tags(details):
    role = details.principal("arn:aws:iam::123456789012:role/data-pipeline")
    assert decide(role, Query("s3:GetObject", "arn:aws:s3:::customer-pii/*")).verdict is Verdict.ALLOWED


def test_missing_managed_policy_is_unresolved(details):
    ghost = details.principal("ghost")
    assert ghost.unresolved == ["arn:aws:iam::123456789012:policy/gone"]
    assert decide(ghost, Query("s3:GetObject", "*")).verdict is Verdict.UNKNOWN


def test_trust_policy_is_loaded_as_required(details):
    trust = trust_policy(details, "arn:aws:iam::123456789012:role/data-pipeline")
    assert trust is not None and trust.required and trust.account == "123456789012"
    assert trust_policy(details, "arn:aws:iam::123456789012:role/missing") is None


def test_cli_assume_role_uses_trust_policy_from_snapshot(capsys):
    role = "arn:aws:iam::123456789012:role/data-pipeline"
    # alice is trusted directly, but her boundary allows only s3 and ec2:Describe*. A direct
    # user grant is not limited by her boundary, so she can still assume the role.
    assert main(["can", "--authz", FIXTURE, "--principal", "alice", "--json", "sts:AssumeRole", role]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "allowed"
    # ghost is not trusted, which alone would prove DENIED, but ghost has an attached policy
    # missing from the snapshot, and an unresolved policy downgrades every verdict to UNKNOWN.
    assert main(["can", "--authz", FIXTURE, "--principal", "ghost", "--json", "sts:AssumeRole", role]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "unknown"


def test_unknown_principal(details):
    with pytest.raises(KeyError):
        details.principal("nobody")


def test_cli_json_output(capsys):
    code = main(["can", "--authz", FIXTURE, "--principal", "alice", "--json", "iam:CreateUser", "*"])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "denied"


def test_cli_text_output_with_policy_files(tmp_path, capsys):
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}))
    scp = tmp_path / "scp.json"
    scp.write_text(json.dumps({"Statement": {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}}))
    assert main(["can", "--policy", str(policy), "--scp", f"root={scp}", "s3:DeleteBucket", "*"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("DENIED")
    assert "UNSAT" in out


def test_cli_reports_bad_input(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert main(["can", "--policy", str(bad), "s3:*", "*"]) == 2
    assert "no Statement" in capsys.readouterr().err
