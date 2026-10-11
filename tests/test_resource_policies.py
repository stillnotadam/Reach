from __future__ import annotations

from typing import Any

import pytest

from reach.catalog import Catalog
from reach.engine import Environment, Principal, Query, ResourcePolicy, Verdict, decide
from reach.policy import PolicyError, parse_policy
from reach.principals import Match, classify

ACCT = "123456789012"
OTHER = "999999999999"
USER = f"arn:aws:iam::{ACCT}:user/alice"
ROLE = f"arn:aws:iam::{ACCT}:role/app/data-pipeline"
BUCKET = "arn:aws:s3:::customer-pii"


def pol(*statements: dict[str, Any], name: str = "p"):
    return parse_policy({"Statement": list(statements)}, name)


def grant(principal: Any, action: str = "s3:GetObject", resource: str = f"{BUCKET}/*", **extra: Any):
    return {"Effect": "Allow", "Principal": principal, "Action": action, "Resource": resource, **extra}


def rp(*statements, account: str = ACCT, required: bool = False) -> ResourcePolicy:
    return ResourcePolicy(pol(*statements, name="bucket-policy"), account, required)


def can(principal: Principal, resource_policy: ResourcePolicy | None, action="s3:GetObject", resource=f"{BUCKET}/a",
        env=None) -> Verdict:  # fmt: skip
    return decide(principal, Query(action, resource, resource_policy=resource_policy), env, catalog=None).verdict


ALLOW_S3 = pol({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})
ONLY_EC2 = pol({"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}, name="boundary")


# --- principal classification -------------------------------------------------


@pytest.mark.parametrize(
    ("principal", "arn", "expected"),
    [
        ("*", USER, {Match.WILDCARD}),
        ({"AWS": "*"}, ROLE, {Match.WILDCARD}),
        ({"AWS": USER}, USER, {Match.USER}),
        ({"AWS": ROLE}, ROLE, {Match.ROLE}),
        ({"AWS": ACCT}, USER, {Match.ACCOUNT}),
        ({"AWS": f"arn:aws:iam::{ACCT}:root"}, ROLE, {Match.ACCOUNT}),
        ({"AWS": f"arn:aws:sts::{ACCT}:assumed-role/data-pipeline/session-1"}, ROLE, {Match.SESSION}),
        ({"AWS": f"arn:aws:sts::{ACCT}:assumed-role/other-role/s"}, ROLE, set()),
        ({"AWS": f"arn:aws:iam::{OTHER}:root"}, USER, set()),
        ({"Service": "lambda.amazonaws.com"}, ROLE, set()),
        ({"AWS": [USER, ACCT]}, USER, {Match.USER, Match.ACCOUNT}),
    ],
)
def test_classify(principal, arn, expected):
    assert classify(pol(grant(principal)).statements[0], arn) == expected


def test_not_principal():
    stmt = pol({"Effect": "Deny", "NotPrincipal": {"AWS": USER}, "Action": "*", "Resource": "*"}).statements[0]
    assert classify(stmt, USER) == set()
    assert classify(stmt, ROLE) == {Match.WILDCARD}


def test_principal_and_not_principal_together_is_rejected():
    with pytest.raises(PolicyError):
        pol({"Effect": "Allow", "Principal": "*", "NotPrincipal": "*", "Action": "*", "Resource": "*"})


# --- same account -----------------------------------------------------------------


def test_identity_path_alone_suffices_in_one_account():
    alice = Principal(USER, [ALLOW_S3])
    assert can(alice, rp(grant({"AWS": ROLE}))) is Verdict.ALLOWED


def test_direct_user_grant_needs_no_identity_policy_and_ignores_boundary():
    alice = Principal(USER, [], boundary=ONLY_EC2)
    assert can(alice, rp(grant({"AWS": USER}))) is Verdict.ALLOWED


def test_role_arn_grant_is_capped_by_boundary():
    role = Principal(ROLE, [], boundary=ONLY_EC2)
    assert can(role, rp(grant({"AWS": ROLE}))) is Verdict.DENIED
    assert can(Principal(ROLE, []), rp(grant({"AWS": ROLE}))) is Verdict.ALLOWED


def test_role_arn_grant_is_capped_by_session_policy():
    env = Environment(session_policies=[ONLY_EC2])
    assert can(Principal(ROLE, []), rp(grant({"AWS": ROLE})), env=env) is Verdict.DENIED


def test_session_arn_grant_is_not_capped():
    role = Principal(ROLE, [], boundary=ONLY_EC2)
    session = f"arn:aws:sts::{ACCT}:assumed-role/data-pipeline/any"
    assert can(role, rp(grant({"AWS": session}))) is Verdict.ALLOWED


def test_same_account_account_grant_is_unsettled():
    # AWS's simulator allows this without identity permissions; delegation is documented for
    # KMS and cross-account. Until a live test settles it, Reach reports UNKNOWN, never a proof.
    r = decide(Principal(USER, []), Query("s3:GetObject", f"{BUCKET}/a", resource_policy=rp(grant({"AWS": ACCT}))),
               catalog=None)  # fmt: skip
    assert r.verdict is Verdict.UNKNOWN
    assert any("simulator" in a for a in r.assumptions)
    # With identity permissions it is allowed either way.
    assert can(Principal(USER, [ALLOW_S3]), rp(grant({"AWS": ACCT}))) is Verdict.ALLOWED


def test_wildcard_grant_with_boundary_is_unknown_until_verified():
    role = Principal(ROLE, [], boundary=ONLY_EC2)
    r = decide(role, Query("s3:GetObject", f"{BUCKET}/a", resource_policy=rp(grant("*"))), catalog=None)
    assert r.verdict is Verdict.UNKNOWN
    assert any("not yet verified against AWS" in a for a in r.assumptions)
    # Without caps there is nothing to verify: a public grant is a public grant.
    assert can(Principal(ROLE, []), rp(grant("*"))) is Verdict.ALLOWED


def test_resource_policy_deny_applies_to_named_principals_only():
    deny_alice = {"Effect": "Deny", "Principal": {"AWS": USER}, "Action": "s3:*", "Resource": "*"}
    assert can(Principal(USER, [ALLOW_S3]), rp(deny_alice)) is Verdict.DENIED
    assert can(Principal(ROLE, [ALLOW_S3]), rp(deny_alice)) is Verdict.ALLOWED


def test_deny_everyone_except_with_not_principal():
    lock = {"Effect": "Deny", "NotPrincipal": {"AWS": ROLE}, "Action": "s3:*", "Resource": "*"}
    assert can(Principal(USER, [ALLOW_S3]), rp(lock)) is Verdict.DENIED
    assert can(Principal(ROLE, [ALLOW_S3]), rp(lock)) is Verdict.ALLOWED


def test_resource_policy_grant_still_needs_scps():
    env = Environment(scp_layers=[("root", [ONLY_EC2])])
    r = decide(Principal(USER, []), Query("s3:GetObject", f"{BUCKET}/a", resource_policy=rp(grant({"AWS": USER}))),
               env, catalog=None)  # fmt: skip
    assert r.verdict is Verdict.DENIED
    assert "SCPs at root" in r.reasons[0]


def test_resource_policy_grant_survives_catalogue_pruning():
    catalog = Catalog(("s3:GetObject", "s3:PutObject", "ec2:RunInstances"))
    q = Query("s3:*", f"{BUCKET}/a", resource_policy=rp(grant({"AWS": USER})))
    r = decide(Principal(USER, [pol({"Effect": "Allow", "Action": "ec2:*", "Resource": "*"})]), q, catalog=catalog)
    assert r.verdict is Verdict.ALLOWED
    assert r.witness.action == "s3:GetObject"


# --- required resource policies (role trust, KMS keys) -------------------------------


def trust(principal: Any) -> ResourcePolicy:
    stmt = {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
    return ResourcePolicy(pol(stmt, name="trust-policy"), ACCT, required=True)


TARGET = f"arn:aws:iam::{ACCT}:role/admin"
ASSUME_ANY = pol({"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"})


def test_required_policy_without_grant_denies_even_with_identity_permission():
    r = decide(Principal(USER, [ASSUME_ANY]), Query("sts:AssumeRole", TARGET, resource_policy=trust({"AWS": ROLE})),
               catalog=None)  # fmt: skip
    assert r.verdict is Verdict.DENIED
    assert any("must grant the principal directly" in reason for reason in r.reasons)


def test_trust_naming_the_user_suffices_alone():
    assert can(Principal(USER, []), trust({"AWS": USER}), "sts:AssumeRole", TARGET) is Verdict.ALLOWED


def test_trust_naming_the_account_needs_identity_permission():
    assert can(Principal(USER, []), trust({"AWS": ACCT}), "sts:AssumeRole", TARGET) is Verdict.DENIED
    assert can(Principal(USER, [ASSUME_ANY]), trust({"AWS": ACCT}), "sts:AssumeRole", TARGET) is Verdict.ALLOWED


# --- cross account ---------------------------------------------------------------------


def test_cross_account_needs_both_sides():
    other_bucket = rp(grant({"AWS": f"arn:aws:iam::{ACCT}:root"}), account=OTHER)
    assert can(Principal(USER, [ALLOW_S3]), other_bucket) is Verdict.ALLOWED
    assert can(Principal(USER, []), other_bucket) is Verdict.DENIED
    assert can(Principal(USER, [ALLOW_S3]), rp(grant({"AWS": OTHER}), account=OTHER)) is Verdict.DENIED


def test_cross_account_boundary_still_applies():
    other_bucket = rp(grant({"AWS": USER}), account=OTHER)
    r = decide(Principal(USER, [ALLOW_S3], boundary=ONLY_EC2), Query("s3:GetObject", f"{BUCKET}/a",
               resource_policy=other_bucket), catalog=None)  # fmt: skip
    assert r.verdict is Verdict.DENIED
    assert any("permissions boundary" in reason for reason in r.reasons)
