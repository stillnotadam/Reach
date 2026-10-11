from __future__ import annotations

import gzip
import json

from reach.catalog import Catalog
from reach.engine import Principal, Query, Verdict, decide
from reach.policy import parse_policy

CATALOG = Catalog(
    (
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "iam:PassRole",
        "iam:CreateUser",
        "iam:GetRole",
        "ec2:RunInstances",
    ),
    generated="test",
)
ARN = "arn:aws:iam::123456789012:role/dev"


def decide_with(statements, action, resource="*", catalog=CATALOG):
    policy = parse_policy({"Statement": statements}, "p")
    return decide(Principal(ARN, [policy]), Query(action, resource), catalog=catalog)


def test_witness_names_a_real_action_in_canonical_case():
    r = decide_with([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}], "s3:*")
    assert r.verdict is Verdict.ALLOWED
    assert r.witness.action in CATALOG.actions


def test_glob_matching_respects_iam_rules():
    assert CATALOG.matching("s3:*Object") == ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    assert CATALOG.matching("IAM:get????") == ["iam:GetRole"]
    # `[` is literal in IAM globs, not a character class.
    assert CATALOG.matching("s3:[G]etObject") == []


def test_fake_action_cannot_satisfy_a_wildcard_query():
    # Without a catalogue, "s3:Gx" would be a valid witness for s3:G* minus GetObject.
    statements = [
        {"Effect": "Allow", "Action": "s3:G*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"},
    ]
    assert decide_with(statements, "s3:G*", catalog=None).verdict is Verdict.ALLOWED
    assert decide_with(statements, "s3:G*").verdict is Verdict.DENIED


def test_not_action_grants_are_pruned_correctly():
    r = decide_with([{"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}], "*")
    assert r.verdict is Verdict.ALLOWED
    assert not r.witness.action.startswith("s3:")


def test_pattern_matching_nothing_is_denied_with_a_note():
    r = decide_with([{"Effect": "Allow", "Action": "*", "Resource": "*"}], "lambda:*")
    assert r.verdict is Verdict.DENIED
    assert any("matches no action" in n for n in r.notes)


def test_unknown_literal_action_is_evaluated_as_written():
    r = decide_with([{"Effect": "Allow", "Action": "bedrock:*", "Resource": "*"}], "bedrock:InvokeModel")
    assert r.verdict is Verdict.ALLOWED
    assert any("not in the action catalogue" in n for n in r.notes)


def test_round_trip_through_gzip(tmp_path):
    path = tmp_path / "actions.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump({"generated": "2026-10-11", "source": "test", "actions": list(CATALOG.actions)}, fh)
    loaded = Catalog.load(path)
    assert loaded.actions == CATALOG.actions
    assert "S3:GETOBJECT" in loaded
    assert loaded.canonical("iam:passrole") == "iam:PassRole"
