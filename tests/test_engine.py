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


def test_witness_arns_read_like_real_ones():
    # Unconstrained names come out of Z3 as " " or nothing; the witness shows a region, the account, a name.
    admin = Principal(ARN, [pol(allow("*", "*"))])

    def witness(principal, action):
        return decide(principal, Query(action, "*")).witness.resource  # with the catalogue: real resource types

    assert witness(admin, "secretsmanager:GetSecretValue") == (
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:example"
    )
    assert witness(admin, "s3:GetObject") == "arn:aws:s3:::example/example"
    prefix = Principal(ARN, [pol(allow("ssm:GetParameter", "arn:aws:ssm:eu-west-1:123456789012:parameter/app/*"))])
    assert witness(prefix, "ssm:GetParameter") == ("arn:aws:ssm:eu-west-1:123456789012:parameter/app/example")


def test_tidying_never_changes_what_the_witness_proves():
    # Only names ending in a space are allowed: "example" would not match, so the solver's name stays.
    odd = [pol(allow("s3:GetObject", f"{BUCKET}/* "))]
    w = can(odd, "s3:GetObject", "*").witness
    assert w.resource.startswith(f"{BUCKET}/") and w.resource.endswith(" ")
    # Without a catalogue the service is a free string too; the action's own service is filled in.
    assert can([pol(allow("*", "*"))], "kms:Decrypt", "*").witness.resource.startswith("arn:aws:kms:")


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


def unmodelled_allow():
    # A huge exponent is valid for AWS but outside Reach's model.
    return allow("s3:*", Condition={"NumericLessThan": {"s3:max-keys": "1e5000"}})


def test_unmodelled_allow_condition_gives_unknown_not_allowed():
    r = can([pol(unmodelled_allow())], "s3:ListBucket", "*")
    assert r.verdict is Verdict.UNKNOWN
    assert any("NumericLessThan" in a for a in r.assumptions)


def test_unmodelled_deny_condition_gives_unknown():
    huge_deny = deny("s3:*", Condition={"NumericGreaterThan": {"s3:max-keys": "1e5000"}})
    r = can([pol(allow("s3:*"), huge_deny)], "s3:GetObject", "*")
    # The key only appears in an unmodelled condition, so it must not leak into the witness.
    assert "s3:max-keys" not in r.witness.context
    assert r.verdict is Verdict.UNKNOWN


def test_unmodelled_condition_on_irrelevant_statement_still_proves():
    p = [pol(unmodelled_allow(), allow("ec2:DescribeInstances"))]
    assert can(p, "ec2:DescribeInstances", "*").verdict is Verdict.ALLOWED
    assert can(p, "iam:CreateUser", "*").verdict is Verdict.DENIED


def test_unmodelled_condition_beside_unconditional_grant_still_proves():
    assert can([pol(unmodelled_allow(), allow("s3:ListBucket"))], "s3:ListBucket", "*").verdict is Verdict.ALLOWED


# --- policy variables (IAM User Guide, "Policy variables") ---------------------------

USER = "arn:aws:iam::123456789012:user/alice"
HOME = allow("s3:GetObject", "arn:aws:s3:::corp/home/${aws:username}/*")


def as_user(policies, action, resource, context=None, tags=None):
    return decide(Principal(USER, policies, None, tags or {}), Query(action, resource, context or {}), catalog=None)


def test_username_variable_scopes_a_user_to_their_own_prefix():
    assert as_user([pol(HOME)], "s3:GetObject", "arn:aws:s3:::corp/home/alice/x").verdict is Verdict.ALLOWED
    assert as_user([pol(HOME)], "s3:GetObject", "arn:aws:s3:::corp/home/bob/x").verdict is Verdict.DENIED
    r = as_user([pol(HOME)], "s3:GetObject", "arn:aws:s3:::corp/home/*")
    assert r.verdict is Verdict.ALLOWED and r.witness.resource.startswith("arn:aws:s3:::corp/home/alice/")


def test_role_sessions_have_no_username_so_the_entry_matches_nothing():
    # A regression: ${aws:username} used to be literal text, giving a witness containing "${aws:username}".
    assert can([pol(HOME)], "s3:GetObject", "arn:aws:s3:::corp/home/*").verdict is Verdict.DENIED
    cond = allow("s3:ListBucket", BUCKET, Condition={"StringLike": {"s3:prefix": "${aws:username}/*"}})
    assert can([pol(cond)], "s3:ListBucket", BUCKET).verdict is Verdict.DENIED


def test_principal_tag_variable_and_default_value():
    team = allow("s3:*", "arn:aws:s3:::team-${aws:PrincipalTag/team, 'company-wide'}/*")
    tagged = as_user([pol(team)], "s3:GetObject", "arn:aws:s3:::team-data/x", tags={"team": "data"})
    assert tagged.verdict is Verdict.ALLOWED
    assert as_user([pol(team)], "s3:GetObject", "arn:aws:s3:::team-web/x", tags={"team": "data"}).verdict is (
        Verdict.DENIED
    )
    untagged = as_user([pol(team)], "s3:GetObject", "arn:aws:s3:::team-company-wide/x")
    assert untagged.verdict is Verdict.ALLOWED


def test_negated_operator_matches_a_null_variable():
    # The documented example: deny unless the object's Team tag equals the caller's. An untagged caller is denied.
    same_team = {"StringNotEquals": {"s3:ExistingObjectTag/Team": "${aws:PrincipalTag/Team}"}}
    deny_other_teams = deny("s3:GetObject", f"{BUCKET}/*", Condition=same_team)
    policies = [pol(allow("s3:*", f"{BUCKET}/*"), deny_other_teams)]
    assert as_user(policies, "s3:GetObject", f"{BUCKET}/x").verdict is Verdict.DENIED
    ok = as_user(policies, "s3:GetObject", f"{BUCKET}/x", {"s3:ExistingObjectTag/Team": "a"}, {"Team": "a"})
    assert ok.verdict is Verdict.ALLOWED


def test_variable_the_request_decides_is_solved_symbolically():
    vpc = allow("s3:GetObject", "arn:aws:s3:::logs-${aws:SourceVpc}/*")
    r = as_user([pol(vpc)], "s3:GetObject", "arn:aws:s3:::logs-vpc-1/x")
    assert r.verdict is Verdict.ALLOWED and r.witness.context["aws:SourceVpc"] == "vpc-1"
    other = as_user([pol(vpc)], "s3:GetObject", "arn:aws:s3:::logs-vpc-1/x", {"aws:SourceVpc": "vpc-2"})
    assert other.verdict is Verdict.DENIED


def test_variable_in_a_condition_value_is_solved_symbolically():
    # s3:prefix must start with the requested region: ties two request keys together.
    cond = allow("s3:ListBucket", BUCKET, Condition={"StringLike": {"s3:prefix": "${aws:RequestedRegion}/*"}})
    r = as_user([pol(cond)], "s3:ListBucket", BUCKET)
    assert r.verdict is Verdict.ALLOWED
    assert r.witness.context["s3:prefix"].startswith(r.witness.context["aws:RequestedRegion"] + "/")
    pinned = {"aws:RequestedRegion": "eu-west-1", "s3:prefix": "us-east-1/x"}
    assert as_user([pol(cond)], "s3:ListBucket", BUCKET, pinned).verdict is Verdict.DENIED


def test_variables_aws_does_not_substitute_stay_undecided():
    for resource in ("arn:aws:s3:::ip-${aws:SourceIp}/*", "arn:aws:${aws:username}:::b/*"):
        r = as_user([pol(allow("s3:GetObject", resource))], "s3:GetObject", "*")
        assert r.verdict is Verdict.UNKNOWN, resource


def test_escaped_wildcards_are_literal():
    star = pol(allow("s3:GetObject", "arn:aws:s3:::b/${*}"))
    assert as_user([star], "s3:GetObject", "arn:aws:s3:::b/*").verdict is Verdict.ALLOWED
    assert as_user([star], "s3:GetObject", "arn:aws:s3:::b/x").verdict is Verdict.DENIED


def test_variables_are_literal_without_the_2012_version():
    old = parse_policy({"Statement": [HOME]}, "versionless")
    assert as_user([old], "s3:GetObject", "arn:aws:s3:::corp/home/alice/x").verdict is Verdict.DENIED
    r = as_user([old], "s3:GetObject", "arn:aws:s3:::corp/home/${aws:username}/x")
    assert r.verdict is Verdict.ALLOWED


def test_null_entry_in_not_resource_excludes_nothing():
    stmt = {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::corp/home/${aws:username}/*"}
    # For a role there is no username, so the NotResource entry matches nothing and every resource is allowed.
    assert can([pol(stmt)], "s3:GetObject", "arn:aws:s3:::corp/home/dev/x").verdict is Verdict.ALLOWED
    assert as_user([pol(stmt)], "s3:GetObject", "arn:aws:s3:::corp/home/alice/x").verdict is Verdict.DENIED


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
    assert float(r.witness.context["s3:max-keys"]) <= 100  # any plain decimal, negative ones included
    assert can(p, "s3:ListBucket", "*", context={"s3:max-keys": "101"}).verdict is Verdict.DENIED
    assert can(p, "s3:ListBucket", "*", context={"s3:max-keys": "0100"}).verdict is Verdict.ALLOWED


def test_numbers_are_exact_decimals():
    # Measured on AWS (validation/num_probe.py): BigDecimal syntax, compared exactly.
    def keys(op, bound, value):
        p = [pol(allow("s3:ListBucket", Condition={op: {"s3:max-keys": bound}}))]
        return can(p, "s3:ListBucket", "*", context={"s3:max-keys": value}).verdict

    assert keys("NumericLessThan", "10", "9.999") is Verdict.ALLOWED
    assert keys("NumericLessThan", "10.5", "10.5000001") is Verdict.DENIED
    assert keys("NumericEquals", "007", "7.00") is Verdict.ALLOWED
    assert keys("NumericEquals", "1e1", "10") is Verdict.ALLOWED  # an exponent in the policy
    assert keys("NumericEquals", "9007199254740993", "9007199254740992") is Verdict.DENIED  # not a double
    assert keys("NumericGreaterThan", "-1.5", "-1.49") is Verdict.ALLOWED
    assert keys("NumericLessThan", "0", "-0.001") is Verdict.ALLOWED
    # A plain decimal is decided; other valid spellings are left UNKNOWN.
    assert keys("NumericLessThan", "10", "+5") is Verdict.UNKNOWN
    assert keys("NumericLessThan", "10", "١") is Verdict.UNKNOWN  # an Arabic-Indic digit


def test_free_decimal_and_negative_witnesses():
    between = [pol(allow("s3:ListBucket", Condition={"NumericGreaterThan": {"s3:max-keys": "-2.5"},
                                                     "NumericLessThan": {"s3:max-keys": "-2.4"}}))]  # fmt: skip
    value = can(between, "s3:ListBucket", "*").witness.context["s3:max-keys"]
    assert -2.5 < float(value) < -2.4


def test_invalid_numbers_make_every_numeric_operator_false():
    # AWS: an unparsable request value fails NumericNotEquals and the IfExists forms too.
    p = [pol(allow("s3:ListBucket", Condition={"NumericNotEquals": {"s3:max-keys": "5"}}))]
    assert can(p, "s3:ListBucket", "*", context={"s3:max-keys": "x"}).verdict is Verdict.DENIED
    assert can(p, "s3:ListBucket", "*", context={"s3:max-keys": " 5"}).verdict is Verdict.DENIED
    assert can(p, "s3:ListBucket", "*", context={"s3:max-keys": "5"}).verdict is Verdict.DENIED
    assert can(p, "s3:ListBucket", "*", context={"s3:max-keys": None}).verdict is Verdict.ALLOWED
    if_exists = [pol(allow("s3:ListBucket", Condition={"NumericLessThanIfExists": {"s3:max-keys": "10"}}))]
    assert can(if_exists, "s3:ListBucket", "*", context={"s3:max-keys": "abc"}).verdict is Verdict.DENIED
    # An invalid policy value never matches; the valid ones around it still do.
    mixed = [pol(allow("s3:ListBucket", Condition={"NumericEquals": {"s3:max-keys": ["abc", "10"]}}))]
    assert can(mixed, "s3:ListBucket", "*", context={"s3:max-keys": "10"}).verdict is Verdict.ALLOWED
    never = [pol(allow("s3:ListBucket", Condition={"NumericNotEquals": {"s3:max-keys": "abc"}}))]
    assert can(never, "s3:ListBucket", "*", context={"s3:max-keys": "7"}).verdict is Verdict.ALLOWED


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


def test_ipv6_conditions():
    office = allow("s3:*", Condition={"IpAddress": {"aws:SourceIp": ["2001:db8:1234::/48", "203.0.113.0/24"]}})
    r = can([pol(office)], "s3:GetObject", "*")
    assert r.verdict is Verdict.ALLOWED
    source = r.witness.context["aws:SourceIp"]
    assert source.startswith("2001:db8:1234:") or source.startswith("203.0.113.")
    assert (
        can([pol(office)], "s3:GetObject", "*", context={"aws:SourceIp": "2001:db8:1234:5::9"}).verdict
        is Verdict.ALLOWED
    )
    assert (
        can([pol(office)], "s3:GetObject", "*", context={"aws:SourceIp": "2001:db8:1235::1"}).verdict is Verdict.DENIED
    )
    # Spelling does not matter: upper case and zero padding are the same address.
    padded = {"aws:SourceIp": "2001:0DB8:1234:0000::0001"}
    assert can([pol(office)], "s3:GetObject", "*", context=padded).verdict is Verdict.ALLOWED


def test_ip_families_never_mix():
    # Measured on AWS (validation/ip_probe.py): 0.0.0.0/0 matches no IPv6 source and ::/0 no IPv4 source.
    v4_only = [pol(allow("s3:*", Condition={"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}}))]
    assert can(v4_only, "s3:GetObject", "*", context={"aws:SourceIp": "2001:db8::1"}).verdict is Verdict.DENIED
    assert can(v4_only, "s3:GetObject", "*").witness.context["aws:SourceIp"].count(".") == 3
    v6_only = [pol(allow("s3:*", Condition={"IpAddress": {"aws:SourceIp": "::/0"}}))]
    assert can(v6_only, "s3:GetObject", "*", context={"aws:SourceIp": "10.1.2.3"}).verdict is Verdict.DENIED
    # The IPv4 address 10.0.0.1 is not the IPv6 address ::a00:1, though both are the number 167772161.
    ten = [pol(allow("s3:*", Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}))]
    assert can(ten, "s3:GetObject", "*", context={"aws:SourceIp": "::a00:1"}).verdict is Verdict.DENIED
    # An IPv4-mapped source is the IPv4 address it carries.
    assert can(ten, "s3:GetObject", "*", context={"aws:SourceIp": "::ffff:10.1.2.3"}).verdict is Verdict.ALLOWED
    # And a free IPv6 witness is never an IPv4-mapped one.
    corp_v6 = [pol(allow("s3:*"), deny("*", Condition={"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}}))]
    source = can(corp_v6, "s3:GetObject", "*").witness.context["aws:SourceIp"]
    assert source is None or not source.startswith("::ffff:")


def test_malformed_networks_decide_an_absent_key_exactly():
    # AWS checks presence before it reads the networks (validation/ip_probe.py).
    bad = [pol(allow("s3:*"), deny("*", Condition={"IpAddress": {"aws:SourceIp": "bogus"}}))]
    r = can(bad, "s3:GetObject", "*")
    assert r.verdict is Verdict.ALLOWED and r.witness.context["aws:SourceIp"] is None
    present = can(bad, "s3:GetObject", "*", context={"aws:SourceIp": "10.1.2.3"})
    assert present.verdict is Verdict.UNKNOWN
    not_bad = [pol(allow("s3:*", Condition={"NotIpAddress": {"aws:SourceIp": ["::ffff:10.0.0.0/104"]}}))]
    assert can(not_bad, "s3:GetObject", "*").verdict is Verdict.ALLOWED  # absent: NotIpAddress holds


def test_string_equals_ignore_case_compares_lowercase_forms():
    # Measured on AWS (validation/case_probe.py): equal full Unicode lowercase forms, nothing more.
    home = [pol(allow("s3:ListBucket", Condition={"StringEqualsIgnoreCase": {"s3:prefix": "Home/K"}}))]

    def prefix(value):
        return can(home, "s3:ListBucket", "*", context={"s3:prefix": value}).verdict

    assert prefix("home/k") is Verdict.ALLOWED and prefix("HOME/K") is Verdict.ALLOWED
    assert prefix("home/K") is Verdict.ALLOWED  # the Kelvin sign lowercases to k
    assert prefix("home/kk") is Verdict.DENIED and prefix("home/") is Verdict.DENIED
    witness = can(home, "s3:ListBucket", "*").witness.context["s3:prefix"]
    assert witness.lower() == "home/k"
    sharp = [pol(allow("s3:ListBucket", Condition={"StringEqualsIgnoreCase": {"s3:prefix": "straße"}}))]
    assert can(sharp, "s3:ListBucket", "*", context={"s3:prefix": "STRAẞE"}).verdict is Verdict.ALLOWED
    assert can(sharp, "s3:ListBucket", "*", context={"s3:prefix": "STRASSE"}).verdict is Verdict.DENIED
    # Java's equalsIgnoreCase would match these; AWS does not.
    for policy_value, request_value in (("s", "ſ"), ("i", "ı"), ("i", "İ"), ("µ", "μ")):
        p = [pol(allow("s3:ListBucket", Condition={"StringEqualsIgnoreCase": {"s3:prefix": policy_value}}))]
        assert can(p, "s3:ListBucket", "*", context={"s3:prefix": request_value}).verdict is Verdict.DENIED


def test_ignore_case_denies_are_proofs_over_every_spelling():
    # A Deny on one spelling covers them all, so no spelling slips past it.
    p = [
        pol(
            allow("s3:ListBucket", Condition={"StringEquals": {"s3:prefix": ["admin", "ADMIN", "Admin", "aDMIN"]}}),
            deny("s3:*", Condition={"StringEqualsIgnoreCase": {"s3:prefix": "admin"}}),
        )
    ]
    assert can(p, "s3:ListBucket", "*").verdict is Verdict.DENIED
    negated = [pol(allow("s3:ListBucket"), deny("s3:*", Condition={"StringNotEqualsIgnoreCase": {"s3:prefix": "Tmp"}}))]
    r = can(negated, "s3:ListBucket", "*")
    assert r.verdict is Verdict.ALLOWED and r.witness.context["s3:prefix"].lower() == "tmp"


def test_ignore_case_set_operator_and_text_iam_rejects():
    tags = [pol(allow("s3:*", Condition={"ForAllValues:StringEqualsIgnoreCase": {"aws:TagKeys": ["Env", "Team"]}}))]
    assert can(tags, "s3:GetObject", "*", context={"aws:TagKeys": ["ENV", "team"]}).verdict is Verdict.ALLOWED
    assert can(tags, "s3:GetObject", "*", context={"aws:TagKeys": ["env", "cost"]}).verdict is Verdict.DENIED
    # IAM only accepts Latin-1 in a policy; anything else is not modelled rather than guessed.
    greek = [pol(allow("s3:ListBucket", Condition={"StringEqualsIgnoreCase": {"s3:prefix": "σ"}}))]
    assert can(greek, "s3:ListBucket", "*").verdict is Verdict.UNKNOWN


def test_binary_equals_compares_base64_text():
    # Measured on AWS (validation/binary_probe.py): no decoding, so "YWI=" and "YWJ=" (both "ab") differ.
    p = [pol(allow("s3:ListBucket", Condition={"BinaryEquals": {"s3:prefix": ["YWI=", "eHl6"]}}))]

    def prefix(value):
        return can(p, "s3:ListBucket", "*", context={"s3:prefix": value}).verdict

    assert prefix("YWI=") is Verdict.ALLOWED and prefix("eHl6") is Verdict.ALLOWED
    assert prefix("YWJ=") is Verdict.DENIED and prefix("YWI") is Verdict.DENIED and prefix("ab") is Verdict.DENIED
    assert can(p, "s3:ListBucket", "*").witness.context["s3:prefix"] in ("YWI=", "eHl6")
    negated = [pol(allow("s3:ListBucket"), deny("s3:*", Condition={"BinaryNotEquals": {"s3:prefix": "YWJj"}}))]
    r = can(negated, "s3:ListBucket", "*")
    assert r.verdict is Verdict.ALLOWED and r.witness.context["s3:prefix"] == "YWJj"
    # IAM rejects a value that is not base64; such a policy is not modelled.
    bad = [pol(allow("s3:ListBucket", Condition={"BinaryEquals": {"s3:prefix": "not base64!"}}))]
    assert can(bad, "s3:ListBucket", "*").verdict is Verdict.UNKNOWN


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


# --- Bool reads both sides as booleans (FINDINGS.md, finding 6) ---------------------


def test_bool_reads_any_case_true_and_treats_everything_else_as_false():
    mfa_off = [pol(allow("s3:GetObject", Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}}))]
    for value, verdict in (("other", Verdict.ALLOWED), ("", Verdict.ALLOWED), ("TRUE", Verdict.DENIED)):
        r = can(mfa_off, "s3:GetObject", f"{BUCKET}/x", context={"aws:MultiFactorAuthPresent": value})
        assert r.verdict is verdict, value
    odd_policy_value = [pol(allow("s3:GetObject", Condition={"Bool": {"aws:SecureTransport": "yes"}}))]
    r = can(odd_policy_value, "s3:GetObject", f"{BUCKET}/x", context={"aws:SecureTransport": "false"})
    assert r.verdict is Verdict.ALLOWED  # "yes" is not "true", so it reads as false


def test_bool_on_a_non_boolean_key_does_not_shrink_its_values():
    # Used to restrict s3:prefix to "true"/"false" everywhere, so this was a false DENIED proof.
    stmt = allow("s3:ListBucket", BUCKET,
                 Condition={"Bool": {"s3:prefix": "false"}, "StringLike": {"s3:prefix": "home/*"}})  # fmt: skip
    r = can([pol(stmt)], "s3:ListBucket", BUCKET)
    assert r.verdict is Verdict.ALLOWED and r.witness.context["s3:prefix"].startswith("home/")
