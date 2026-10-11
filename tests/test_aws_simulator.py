"""The AWS simulator harness, exercised against a fake client (no AWS account needed)."""

from __future__ import annotations

import json

import validation.aws_simulator as sim
from reach.engine import Environment, Principal, ResourcePolicy
from reach.policy import parse_policy
from reach.reference import evaluate
from validation.aws_simulator import build_request, context_entries, interpret, policy_json, run, simulatable
from validation.fuzz import Case

USER = "arn:aws:iam::123456789012:user/alice"
ROLE = "arn:aws:iam::123456789012:role/app-1"


def pol(*statements, name="p"):
    return parse_policy({"Statement": list(statements)}, name)


def test_policy_json_round_trips():
    original = pol(
        {
            "Effect": "Deny",
            "NotAction": ["iam:*"],
            "Resource": "*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        },
        {"Effect": "Allow", "Principal": {"AWS": [USER, "123456789012"]}, "Action": "s3:GetObject", "Resource": "*"},
        {"Effect": "Allow", "Principal": "*", "Action": "s3:ListBucket", "NotResource": "arn:aws:s3:::x"},
    )
    assert parse_policy(json.loads(policy_json(original)), "p") == original


def test_context_entry_types():
    entries = {e["ContextKeyName"]: e for e in context_entries({
        "aws:SourceIp": "10.1.2.3",
        "aws:CurrentTime": "2026-01-01T00:00:00Z",
        "aws:EpochTime": "1767225600",
        "aws:MultiFactorAuthPresent": "true",
        "s3:max-keys": "10",
        "s3:prefix": "home/",
        "aws:SourceVpc": None,
    })}  # fmt: skip
    assert {k: e["ContextKeyType"] for k, e in entries.items()} == {
        "aws:SourceIp": "ip",
        "aws:CurrentTime": "date",
        "aws:EpochTime": "numeric",
        "aws:MultiFactorAuthPresent": "boolean",
        "s3:max-keys": "numeric",
        "s3:prefix": "string",
    }


def test_simulatable_filters_what_the_simulator_cannot_express():
    bucket = "arn:aws:s3:::b/*"
    rp = ResourcePolicy(pol({"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": bucket}), "123456789012")
    assert simulatable(Case(Principal(ROLE, []), Environment(), rp))[0] is None
    required = ResourcePolicy(rp.policy, "123456789012", required=True)
    assert simulatable(Case(Principal(USER, []), Environment(), required))[1] == "required resource policy"
    scp_env = Environment(scp_layers=[("root", [pol({"Effect": "Deny", "Action": "*", "Resource": "*"})])])
    kept, _ = simulatable(Case(Principal(USER, []), scp_env, rp))
    assert kept is not None and kept.env.scp_layers == []
    wildcard = ResourcePolicy(
        pol({"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}), "123456789012"
    )
    assert (
        simulatable(Case(Principal(USER, []), Environment(), wildcard))[1] == "resource policy with a non-ARN Resource"
    )


def test_build_request_includes_boundary_and_resource_policy():
    boundary = pol({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})
    rp = ResourcePolicy(
        pol({"Effect": "Allow", "Principal": {"AWS": USER}, "Action": "*", "Resource": "*"}), "123456789012"
    )
    case = Case(Principal(USER, [], boundary, {"team": "data"}), Environment(), rp)
    req = build_request(case, "s3:GetObject", "arn:aws:s3:::b/k", {"aws:SourceIp": "10.0.0.1"})
    assert req["CallerArn"] == USER
    assert req["ResourceOwner"] == "arn:aws:iam::123456789012:root"
    assert len(req["PermissionsBoundaryPolicyInputList"]) == 1
    names = {e["ContextKeyName"] for e in req["ContextEntries"]}
    assert {"aws:PrincipalArn", "aws:PrincipalTag/team", "aws:SourceIp"} <= names


def test_interpret():
    assert interpret({"EvaluationResults": [{"EvalDecision": "allowed"}]})[0] == "allowed"
    assert interpret({"EvaluationResults": [{"EvalDecision": "implicitDeny"}]})[0] == "denied"
    assert (
        interpret({"EvaluationResults": [{"EvalDecision": "allowed", "MissingContextValues": ["k"]}]})[0] == "allowed"
    )


def test_run_reports_no_disagreements_against_a_consistent_fake(monkeypatch):
    """A fake simulator that answers like the reference evaluator: a correct harness finds zero disagreements."""
    current = {}
    original = sim.simulatable

    def remember(case):
        kept, reason = original(case)
        current["case"] = kept
        return kept, reason

    class Fake:
        def simulate_custom_policy(self, **request):
            case = current["case"]
            ctx = {e["ContextKeyName"]: e["ContextKeyValues"][0] for e in request["ContextEntries"]}
            allowed = evaluate(
                case.principal,
                request["ActionNames"][0],
                request["ResourceArns"][0],
                ctx,
                case.env,
                case.resource_policy,
            )
            return {"EvaluationResults": [{"EvalDecision": "allowed" if allowed else "implicitDeny"}]}

    monkeypatch.setattr(sim, "simulatable", remember)
    disagreements, stats = run(Fake(), cases=60, seed=3)
    assert stats["compared"] > 0
    assert stats["disagreements"] == 0, disagreements[:3]


def test_run_flags_a_disagreement():
    class AlwaysAllow:
        def simulate_custom_policy(self, **request):
            return {"EvaluationResults": [{"EvalDecision": "allowed"}]}

    _, stats = run(AlwaysAllow(), cases=60, seed=3)
    assert stats["disagreements"] > 0
