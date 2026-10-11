"""ForAnyValue / ForAllValues over multi-valued keys, following the IAM User Guide's own examples."""

from __future__ import annotations

from typing import Any

from reach.cli import _parse_context
from reach.conditions import key_kind
from reach.engine import Environment, Principal, Query, Verdict, decide, set_bounds
from reach.policy import parse_policy

ARN = "arn:aws:iam::123456789012:user/alice"
INSTANCE = "arn:aws:ec2:us-east-1:123456789012:instance/i-1"


def pol(*statements: dict[str, Any]):
    return parse_policy({"Version": "2012-10-17", "Statement": list(statements)}, "p")


def delete_tags(condition: dict[str, Any], effect: str = "Allow") -> dict[str, Any]:
    return {"Effect": effect, "Action": "ec2:DeleteTags", "Resource": INSTANCE, "Condition": condition}


def can(policies, context=None, resource=INSTANCE):
    return decide(Principal(ARN, policies), Query("ec2:DeleteTags", resource, context or {}), catalog=None)


FOR_ALL = {"ForAllValues:StringEquals": {"aws:TagKeys": ["environment", "cost-center"]}}
FOR_ANY = {"ForAnyValue:StringEquals": {"aws:TagKeys": ["environment", "cost-center"]}}


def test_for_all_values_matches_the_documented_table():
    guarded = [pol(delete_tags({**FOR_ALL, "Null": {"aws:TagKeys": "false"}}))]
    assert can(guarded, {"aws:TagKeys": ["environment"]}).verdict is Verdict.ALLOWED
    assert can(guarded, {"aws:TagKeys": ["environment", "cost-center"]}).verdict is Verdict.ALLOWED
    assert can(guarded, {"aws:TagKeys": ["environment", "dept"]}).verdict is Verdict.DENIED
    assert can(guarded, {"aws:TagKeys": None}).verdict is Verdict.DENIED


def test_for_all_values_without_null_check_allows_a_request_with_no_tags():
    # The documented pitfall: ForAllValues is true when the key is absent.
    r = can([pol(delete_tags(FOR_ALL))], {"aws:TagKeys": None})
    assert r.verdict is Verdict.ALLOWED


def test_for_any_value_matches_the_documented_table():
    p = [pol(delete_tags(FOR_ANY))]
    assert can(p, {"aws:TagKeys": ["environment", "dept"]}).verdict is Verdict.ALLOWED
    assert can(p, {"aws:TagKeys": ["dept"]}).verdict is Verdict.DENIED
    assert can(p, {"aws:TagKeys": None}).verdict is Verdict.DENIED
    free = can(p)
    assert free.verdict is Verdict.ALLOWED
    assert {"environment", "cost-center"} & set(free.witness.context["aws:TagKeys"])


def test_deny_on_any_reserved_tag_with_a_free_tag_set():
    p = [pol(delete_tags({}), delete_tags({"ForAnyValue:StringLike": {"aws:TagKeys": "aws:*"}}, "Deny"))]
    r = can(p)
    assert r.verdict is Verdict.ALLOWED
    assert not any(t.startswith("aws:") for t in r.witness.context.get("aws:TagKeys") or [])
    assert can(p, {"aws:TagKeys": ["team", "aws:cloudformation:stack-name"]}).verdict is Verdict.DENIED


def test_witness_with_several_elements():
    # Allowed only if the request carries both tags, and nothing outside the approved list.
    need_both = {
        "ForAnyValue:StringEquals": {"aws:TagKeys": "environment"},
        "ForAllValues:StringEquals": {"aws:TagKeys": ["environment", "cost-center", "team"]},
    }
    also_cost = {"Effect": "Deny", "Action": "ec2:DeleteTags", "Resource": INSTANCE,
                 "Condition": {"ForAllValues:StringNotEquals": {"aws:TagKeys": "cost-center"}}}  # fmt: skip
    r = can([pol(delete_tags(need_both), also_cost)])
    assert r.verdict is Verdict.ALLOWED
    assert {"environment", "cost-center"} <= set(r.witness.context["aws:TagKeys"])
    assert set(r.witness.context["aws:TagKeys"]) <= {"environment", "cost-center", "team"}


def test_impossible_set_constraints_are_proved_denied():
    contradictory = {
        "ForAnyValue:StringEquals": {"aws:TagKeys": "environment"},
        "ForAllValues:StringEquals": {"aws:TagKeys": "team"},
    }
    r = can([pol(delete_tags(contradictory))])
    assert r.verdict is Verdict.DENIED


def test_set_bound_counts_set_conditions():
    p = [pol(delete_tags({**FOR_ALL, **FOR_ANY}))]
    assert set_bounds(Principal(ARN, p), Query("ec2:DeleteTags", INSTANCE), Environment()) == {"aws:tagkeys": 3}


def test_set_operator_on_a_single_valued_key_is_a_set_of_at_most_one():
    # The over-permissive anti-pattern: ForAllValues on a single-valued key passes when it is absent.
    stmt = {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::b",
            "Condition": {"ForAllValues:StringLike": {"s3:prefix": "home/*"}}}  # fmt: skip
    query = Query("s3:ListBucket", "arn:aws:s3:::b", {"s3:prefix": None})
    assert decide(Principal(ARN, [pol(stmt)]), query, catalog=None).verdict is Verdict.ALLOWED
    query = Query("s3:ListBucket", "arn:aws:s3:::b", {"s3:prefix": "tmp/"})
    assert decide(Principal(ARN, [pol(stmt)]), query, catalog=None).verdict is Verdict.DENIED


def test_multi_valued_key_without_a_set_operator_is_unknown():
    r = can([pol(delete_tags({"StringEquals": {"aws:TagKeys": "environment"}}))])
    assert r.verdict is Verdict.UNKNOWN


def test_service_keys_typed_array_in_the_reference_data_are_sets():
    assert key_kind("ec2:IKEVersions") == "set"
    assert key_kind("aws:TagKeys") == "set"
    assert key_kind("s3:prefix") == "string"


def test_cli_parses_a_json_list_for_a_multi_valued_key():
    assert _parse_context(['aws:TagKeys=["a","b"]', "s3:prefix=x"], []) == {"aws:TagKeys": ["a", "b"], "s3:prefix": "x"}
