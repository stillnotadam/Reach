"""Per-action resource types and condition keys, from the bundled Service Authorization Reference."""

from __future__ import annotations

import time

import pytest

from reach.catalog import bundled, format_glob, key_pattern
from reach.engine import Principal, Query, Verdict, decide
from reach.policy import parse_policy

CATALOG = bundled()
pytestmark = pytest.mark.skipif(CATALOG is None, reason="no bundled catalogue; run scripts/build_catalog.py")

ROLE = "arn:aws:iam::123456789012:role/admin"
ALICE = Principal("arn:aws:iam::123456789012:user/alice", [])


def principal(*statements):
    return Principal(ALICE.arn, [parse_policy({"Statement": list(statements)}, "p")])


ALLOW_ALL = {"Effect": "Allow", "Action": "*", "Resource": "*"}


def test_format_and_key_globs():
    assert format_glob("arn:${Partition}:s3:::${BucketName}/${ObjectName}") == "arn:?*:s3:::?*/?*"
    assert key_pattern("aws:RequestTag/${TagKey}") == "aws:RequestTag/*"
    assert key_pattern("s3:prefix") == "s3:prefix"


def test_action_on_wrong_resource_type_cannot_happen():
    # Simulator finding 2: s3:PutObject on an IAM role ARN never occurs.
    r = decide(principal(ALLOW_ALL), Query("s3:PutObject", ROLE))
    assert r.verdict is Verdict.DENIED
    assert decide(principal(ALLOW_ALL), Query("iam:CreateUser", ROLE)).verdict is Verdict.DENIED
    assert decide(principal(ALLOW_ALL), Query("sts:AssumeRole", ROLE)).verdict is Verdict.ALLOWED


def test_wildcard_witness_pairs_action_with_a_real_resource_type():
    r = decide(principal(ALLOW_ALL), Query("s3:PutObject", "*"))
    assert r.verdict is Verdict.ALLOWED
    assert r.witness.resource.split(":")[2] == "s3" and "/" in r.witness.resource


def test_service_key_only_on_supporting_actions():
    # Simulator finding 3: s3:max-keys exists for s3:ListBucket, not for s3:GetObject.
    stmt = {"Effect": "Allow", "Action": "s3:*", "Resource": "*", "Condition": {"StringEquals": {"s3:max-keys": "5"}}}
    assert decide(principal(stmt), Query("s3:GetObject", "arn:aws:s3:::b/k")).verdict is Verdict.DENIED
    r = decide(principal(stmt), Query("s3:ListBucket", "arn:aws:s3:::b"))
    assert r.verdict is Verdict.ALLOWED and r.witness.context["s3:max-keys"] == "5"


def test_global_keys_are_unconstrained():
    stmt = {"Effect": "Allow", "Action": "s3:*", "Resource": "*", "Condition": {"StringEquals": {"aws:SourceVpc": "v"}}}
    assert decide(principal(stmt), Query("s3:GetObject", "arn:aws:s3:::b/k")).verdict is Verdict.ALLOWED


def test_star_query_over_every_action_stays_fast():
    start = time.perf_counter()
    r = decide(principal(ALLOW_ALL), Query("*", "*"))
    assert r.verdict is Verdict.ALLOWED
    assert time.perf_counter() - start < 30


def test_ignore_case_classes_cover_every_unicode_character():
    # Every character whose full lowercase is one Latin-1 character must be in that character's class:
    # a missing one would be a spelling AWS matches and Reach does not.
    from reach.values import ignore_case_classes  # noqa: PLC0415

    expected: dict[str, set[str]] = {}
    for cp in range(0x110000):
        c = chr(cp)
        lower = c.lower()
        if len(lower) == 1 and ord(lower) <= 0xFF:
            expected.setdefault(lower, set()).add(c)
    for target, members in expected.items():
        classes = ignore_case_classes(target)
        assert classes is not None and set(classes[0]) == members, target
