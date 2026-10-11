from __future__ import annotations

from typing import Any

import pytest

from reach.engine import Environment, Principal, Query, Verdict, decide
from reach.policy import PolicyError, parse_policy

ARN = "arn:aws:iam::123456789012:role/dev"
BUCKET = "arn:aws:s3:::customer-pii"


def pol(*statements: dict[str, Any], name: str = "p"):
    return parse_policy({"Version": "2012-10-17", "Statement": list(statements)}, name)


def allow(action: Any, resource: Any = "*", **extra: Any) -> dict[str, Any]:
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def deny(action: Any, resource: Any = "*", **extra: Any) -> dict[str, Any]:
    return {"Effect": "Deny", "Action": action, "Resource": resource, **extra}


def can(policies, action, resource, boundary=None, env=None, context=None, tags=None):
    principal = Principal(ARN, policies, boundary, tags or {})
    # Free action strings: these tests pin IAM semantics, independent of any catalogue snapshot.
    return decide(principal, Query(action, resource, context or {}), env, catalog=None)


# --- basic grants -------------------------------------------------------------


def test_exact_allow():
    r = can([pol(allow("s3:GetObject", f"{BUCKET}/*"))], "s3:GetObject", f"{BUCKET}/report.csv")
    assert r.verdict is Verdict.ALLOWED
    assert r.witness and r.witness.resource == f"{BUCKET}/report.csv"


def test_no_policies_is_proven_denied():
    r = can([], "s3:GetObject", "*")
    assert r.verdict is Verdict.DENIED
    assert "no identity-based policies" in r.reasons[0]


def test_actions_are_case_insensitive():
    assert can([pol(allow("S3:getobject"))], "s3:GetObject", "*").verdict is Verdict.ALLOWED


def test_resources_are_case_sensitive():
    r = can([pol(allow("s3:GetObject", f"{BUCKET}/Reports/*"))], "s3:GetObject", f"{BUCKET}/reports/a")
    assert r.verdict is Verdict.DENIED


def test_action_wildcards():
    p = [pol(allow("iam:Get*"))]
    assert can(p, "iam:GetRole", "*").verdict is Verdict.ALLOWED
    assert can(p, "iam:PassRole", "*").verdict is Verdict.DENIED


def test_question_mark_matches_exactly_one_char():
    p = [pol(allow("s3:GetObject", f"{BUCKET}/v?"))]
    assert can(p, "s3:GetObject", f"{BUCKET}/v1").verdict is Verdict.ALLOWED
    assert can(p, "s3:GetObject", f"{BUCKET}/v10").verdict is Verdict.DENIED


def test_wildcard_query_is_existential_and_returns_a_witness():
    r = can([pol(allow("iam:PassRole", "arn:aws:iam::123456789012:role/app-*"))], "iam:*", "*")
    assert r.verdict is Verdict.ALLOWED
    assert r.witness.action == "iam:passrole"
    assert r.witness.resource.startswith("arn:aws:iam::123456789012:role/app-")


# --- ARN segment semantics ----------------------------------------------------


def test_arn_wildcard_does_not_cross_segments():
    # The `*` sits in the region segment, so it cannot absorb the account's colon.
    p = [pol(allow("lambda:InvokeFunction", "arn:aws:lambda:*:function:x"))]
    assert can(p, "lambda:InvokeFunction", "arn:aws:lambda:eu-west-1:123456789012:function:x").verdict is Verdict.DENIED


def test_arn_resource_segment_wildcard_spans_colons():
    p = [pol(allow("logs:PutLogEvents", "arn:aws:logs:eu-west-1:123456789012:log-group:*"))]
    target = "arn:aws:logs:eu-west-1:123456789012:log-group:app:log-stream:s1"
    assert can(p, "logs:PutLogEvents", target).verdict is Verdict.ALLOWED


# --- NotAction / NotResource and explicit deny ---------------------------------


def test_not_action():
    p = [pol({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})]
    assert can(p, "s3:PutObject", "*").verdict is Verdict.ALLOWED
    assert can(p, "iam:CreateUser", "*").verdict is Verdict.DENIED


def test_not_resource():
    p = [pol({"Effect": "Allow", "Action": "s3:*", "NotResource": f"{BUCKET}/*"})]
    assert can(p, "s3:GetObject", f"{BUCKET}/a").verdict is Verdict.DENIED
    assert can(p, "s3:GetObject", "arn:aws:s3:::other/a").verdict is Verdict.ALLOWED


def test_explicit_deny_wins_and_is_named():
    p = [pol(allow("s3:*"), {**deny("s3:GetObject", f"{BUCKET}/*"), "Sid": "NoPII"}, name="dev-policy")]
    r = can(p, "s3:GetObject", f"{BUCKET}/a")
    assert r.verdict is Verdict.DENIED
    assert any("dev-policy#NoPII" in reason for reason in r.reasons)


def test_partial_deny_leaves_the_rest_reachable():
    p = [pol(allow("s3:GetObject", f"{BUCKET}/*"), deny("s3:GetObject", f"{BUCKET}/secret/*"))]
    r = can(p, "s3:GetObject", f"{BUCKET}/*")
    assert r.verdict is Verdict.ALLOWED
    assert not r.witness.resource.startswith(f"{BUCKET}/secret/")


# --- boundaries, SCPs, session policies ---------------------------------------


def test_permissions_boundary_caps_identity_policy():
    boundary = pol(allow("s3:*"), name="boundary")
    r = can([pol(allow("*"))], "iam:CreateAccessKey", "*", boundary=boundary)
    assert r.verdict is Verdict.DENIED
    assert any("permissions boundary" in reason for reason in r.reasons)


def test_scp_layers_must_all_allow():
    full = pol(allow("*"), name="FullAWSAccess")
    s3_only = pol(allow("s3:*"), name="s3-only")
    env = Environment(scp_layers=[("root", [full]), ("ou-prod", [s3_only])])
    assert can([pol(allow("*"))], "s3:GetObject", "*", env=env).verdict is Verdict.ALLOWED
    r = can([pol(allow("*"))], "ec2:RunInstances", "*", env=env)
    assert r.verdict is Verdict.DENIED
    assert any("ou-prod" in reason for reason in r.reasons)


def test_management_account_ignores_scps():
    env = Environment(scp_layers=[("root", [pol(deny("*"), allow("*"))])], management_account=True)
    assert can([pol(allow("*"))], "s3:GetObject", "*", env=env).verdict is Verdict.ALLOWED


def test_service_linked_roles_ignore_scps():
    env = Environment(scp_layers=[("root", [pol(deny("*"))])])
    slr = "arn:aws:iam::123456789012:role/aws-service-role/x.amazonaws.com/AWSServiceRole"
    principal = Principal(slr, [pol(allow("*"))])
    assert decide(principal, Query("s3:GetObject", "*"), env, catalog=None).verdict is Verdict.ALLOWED


def test_session_policy_intersects():
    env = Environment(session_policies=[pol(allow("s3:GetObject"), name="session")])
    assert can([pol(allow("*"))], "s3:GetObject", "*", env=env).verdict is Verdict.ALLOWED
    assert can([pol(allow("*"))], "s3:PutObject", "*", env=env).verdict is Verdict.DENIED


def test_layers_jointly_unsatisfiable_without_any_single_blocker():
    identity = pol(allow("s3:GetObject", f"{BUCKET}/a/*"), allow("s3:GetObject", "arn:aws:s3:::other/*"))
    boundary = pol(allow("s3:GetObject", f"{BUCKET}/b/*"), allow("s3:PutObject", "*"))
    r = can([identity], "s3:GetObject", "*", boundary=boundary)
    assert r.verdict is Verdict.DENIED


# --- conditions ---------------------------------------------------------------


def mfa_allow():
    return allow("iam:*", Condition={"Bool": {"aws:MultiFactorAuthPresent": True}})


def test_condition_shows_up_in_witness():
    r = can([pol(mfa_allow())], "iam:CreateUser", "*")
    assert r.verdict is Verdict.ALLOWED
    assert r.witness.context["aws:MultiFactorAuthPresent"] == "true"


def test_pinned_context_can_refute_a_condition():
    r = can([pol(mfa_allow())], "iam:CreateUser", "*", context={"aws:MultiFactorAuthPresent": "false"})
    assert r.verdict is Verdict.DENIED


def test_absent_key_fails_positive_operator_but_passes_negated_one():
    p = [pol(allow("s3:*", Condition={"StringEquals": {"aws:SourceVpc": "vpc-1"}}))]
    assert can(p, "s3:GetObject", "*", context={"aws:SourceVpc": None}).verdict is Verdict.DENIED
    p = [pol(allow("s3:*", Condition={"StringNotEquals": {"aws:SourceVpc": "vpc-1"}}))]
    assert can(p, "s3:GetObject", "*", context={"aws:SourceVpc": None}).verdict is Verdict.ALLOWED


def test_if_exists_passes_when_key_absent():
    p = [pol(allow("s3:*", Condition={"StringEqualsIfExists": {"aws:SourceVpc": "vpc-1"}}))]
    assert can(p, "s3:GetObject", "*", context={"aws:SourceVpc": None}).verdict is Verdict.ALLOWED


def test_null_operator():
    p = [pol(allow("s3:*"), deny("s3:*", Condition={"Null": {"aws:SourceVpc": "true"}}))]
    assert can(p, "s3:GetObject", "*", context={"aws:SourceVpc": None}).verdict is Verdict.DENIED
    assert can(p, "s3:GetObject", "*", context={"aws:SourceVpc": "vpc-9"}).verdict is Verdict.ALLOWED


def test_deny_unless_mfa_pattern():
    p = [
        pol(
            allow("*"),
            deny("*", Condition={"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}),
        )
    ]
    no_mfa = {"aws:MultiFactorAuthPresent": "false"}
    assert can(p, "ec2:TerminateInstances", "*", context=no_mfa).verdict is Verdict.DENIED
    r = can(p, "ec2:TerminateInstances", "*")
    assert r.verdict is Verdict.ALLOWED
    assert r.witness.context["aws:MultiFactorAuthPresent"] == "true"


def test_principal_arn_and_tags_are_fixed_from_the_principal():
    p = [pol(allow("s3:*", Condition={"StringEquals": {"aws:PrincipalTag/team": "data"}}))]
    assert can(p, "s3:GetObject", "*", tags={"team": "data"}).verdict is Verdict.ALLOWED
    assert can(p, "s3:GetObject", "*", tags={"team": "web"}).verdict is Verdict.DENIED
    # A tag the principal does not carry is absent, not free for the attacker to choose.
    assert can(p, "s3:GetObject", "*").verdict is Verdict.DENIED
    p = [pol(allow("s3:*", Condition={"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/prod-*"}}))]
    assert can(p, "s3:GetObject", "*").verdict is Verdict.DENIED


# --- three-valued soundness -----------------------------------------------------


def numeric_allow():
    # Decimal bounds are not modelled (only non-negative integers are).
    return allow("s3:*", Condition={"NumericLessThan": {"s3:max-keys": "10.5"}})


def test_unmodelled_allow_condition_gives_unknown_not_allowed():
    r = can([pol(numeric_allow())], "s3:ListBucket", "*")
    assert r.verdict is Verdict.UNKNOWN
    assert any("NumericLessThan" in a for a in r.assumptions)


def test_unmodelled_deny_condition_gives_unknown():
    ip6_deny = deny("s3:*", Condition={"IpAddress": {"aws:SourceIp": "2001:db8::/32"}})
    r = can([pol(allow("s3:*"), ip6_deny)], "s3:GetObject", "*")
    # The key only appears in an unmodelled condition, so it must not leak into the witness.
    assert "aws:SourceIp" not in r.witness.context
    assert r.verdict is Verdict.UNKNOWN


def test_unmodelled_condition_on_irrelevant_statement_still_proves():
    p = [pol(numeric_allow(), allow("ec2:DescribeInstances"))]
    assert can(p, "ec2:DescribeInstances", "*").verdict is Verdict.ALLOWED
    assert can(p, "iam:CreateUser", "*").verdict is Verdict.DENIED


def test_unmodelled_condition_beside_unconditional_grant_still_proves():
    assert can([pol(numeric_allow(), allow("s3:ListBucket"))], "s3:ListBucket", "*").verdict is Verdict.ALLOWED


def test_policy_variables_are_opaque():
    p = [pol(allow("s3:*", f"{BUCKET}/*", Condition={"StringLike": {"s3:prefix": "${aws:username}/*"}}))]
    assert can(p, "s3:ListBucket", f"{BUCKET}/x").verdict is Verdict.UNKNOWN


def test_unresolved_policies_downgrade_any_verdict():
    principal = Principal(ARN, [pol(allow("*"))], unresolved=["arn:aws:iam::aws:policy/Missing"])
    r = decide(principal, Query("s3:GetObject", "*"), catalog=None)
    assert r.verdict is Verdict.UNKNOWN
    assert "could not be loaded" in r.reasons[-1]


# --- parsing --------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        {"Effect": "Maybe", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Allow", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:*", "NotAction": "iam:*", "Resource": "*"},
        {"Effect": "Allow", "Action": [], "Resource": "*"},
    ],
)
def test_malformed_statements_are_rejected(statement):
    with pytest.raises(PolicyError):
        pol(statement)


def test_url_encoded_documents_are_accepted():
    doc = (
        "%7B%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C"
        "%22Action%22%3A%22s3%3A%2A%22%2C%22Resource%22%3A%22%2A%22%7D%7D"
    )
    assert parse_policy(doc, "encoded").statements[0].actions == ("s3:*",)


# --- numeric, IP and date conditions --------------------------------------------


def test_numeric_conditions():
    p = [pol(allow("s3:ListBucket", Condition={"NumericLessThanEquals": {"s3:max-keys": "100"}}))]
    r = can(p, "s3:ListBucket", "*")
    assert r.verdict is Verdict.ALLOWED
    assert int(r.witness.context["s3:max-keys"]) <= 100
    assert can(p, "s3:ListBucket", "*", context={"s3:max-keys": "101"}).verdict is Verdict.DENIED
    assert can(p, "s3:ListBucket", "*", context={"s3:max-keys": "0100"}).verdict is Verdict.ALLOWED


def test_non_integer_request_value_is_unknown_not_guessed():
    p = [pol(allow("s3:ListBucket", Condition={"NumericLessThan": {"s3:max-keys": "10"}}))]
    assert can(p, "s3:ListBucket", "*", context={"s3:max-keys": "1.5"}).verdict is Verdict.UNKNOWN


def test_numeric_not_equals_keeps_opaque_positive():
    # An Allow with NumericNotEquals: a non-digit value must give UNKNOWN, never ALLOWED.
    p = [pol(allow("s3:ListBucket", Condition={"NumericNotEquals": {"s3:max-keys": "5"}}))]
    assert can(p, "s3:ListBucket", "*", context={"s3:max-keys": "x"}).verdict is Verdict.UNKNOWN
    assert can(p, "s3:ListBucket", "*", context={"s3:max-keys": "5"}).verdict is Verdict.DENIED
    assert can(p, "s3:ListBucket", "*", context={"s3:max-keys": None}).verdict is Verdict.ALLOWED


def test_ip_conditions():
    corp_only = deny("*", Condition={"NotIpAddress": {"aws:SourceIp": ["10.0.0.0/8", "192.168.1.7"]}})
    p = [pol(allow("*"), corp_only)]
    r = can(p, "s3:GetObject", "*")
    assert r.verdict is Verdict.ALLOWED
    source = r.witness.context["aws:SourceIp"]
    assert source.startswith("10.") or source == "192.168.1.7"
    assert can(p, "s3:GetObject", "*", context={"aws:SourceIp": "8.8.8.8"}).verdict is Verdict.DENIED
    assert can(p, "s3:GetObject", "*", context={"aws:SourceIp": "192.168.1.8"}).verdict is Verdict.DENIED
    assert can(p, "s3:GetObject", "*", context={"aws:SourceIp": "2001:db8::1"}).verdict is Verdict.DENIED


def test_date_conditions_share_one_clock():
    before = allow("s3:*", Condition={"DateLessThan": {"aws:CurrentTime": "2027-01-01T00:00:00Z"}})
    after = deny("s3:*", Condition={"DateGreaterThan": {"aws:EpochTime": "1767225600"}})  # 2026-01-01
    r = can([pol(before, after)], "s3:GetObject", "*")
    assert r.verdict is Verdict.ALLOWED
    assert r.witness.context["aws:CurrentTime"] <= "2026-01-01T00:00:00Z"
    late = {"aws:CurrentTime": "2026-06-01T00:00:00Z"}
    assert can([pol(before, after)], "s3:GetObject", "*", context=late).verdict is Verdict.DENIED


def test_current_time_is_always_present():
    p = [pol(allow("s3:*"), deny("s3:*", Condition={"Null": {"aws:CurrentTime": "false"}}))]
    assert can(p, "s3:GetObject", "*").verdict is Verdict.DENIED


def test_string_operator_on_ip_key_is_unmodelled():
    p = [pol(allow("s3:*", Condition={"StringLike": {"aws:SourceIp": "10.*"}}))]
    assert can(p, "s3:GetObject", "*").verdict is Verdict.UNKNOWN


# --- keys AWS always sets (found by the AWS simulator harness) -----------------------


def test_requested_region_is_never_absent():
    only_without_region = allow("s3:*", Condition={"Null": {"aws:RequestedRegion": "true"}})
    assert can([pol(only_without_region)], "s3:GetObject", "*").verdict is Verdict.DENIED


def test_if_exists_deny_on_region_cannot_use_a_regionless_request():
    # Simulator case 195: an IfExists Deny matches an absent key, but the region is never absent.
    p = [pol(allow("s3:*"), deny("s3:*", Condition={"StringLikeIfExists": {"aws:RequestedRegion": "vpc-?"}}))]
    r = can(p, "s3:GetObject", "*")
    assert r.verdict is Verdict.ALLOWED
    assert r.witness.context["aws:RequestedRegion"] is not None


def test_principal_type_is_pinned():
    p = [pol(allow("s3:*", Condition={"StringEquals": {"aws:PrincipalType": "AssumedRole"}}))]
    assert can(p, "s3:GetObject", "*").verdict is Verdict.ALLOWED  # ARN is a role
    user = Principal("arn:aws:iam::123456789012:user/alice", p)
    assert decide(user, Query("s3:GetObject", "*"), catalog=None).verdict is Verdict.DENIED
