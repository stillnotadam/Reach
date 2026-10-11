"""Differential fuzzing: the Z3 engine against the solver-free reference evaluator.

    python -m validation.fuzz --cases 20000 --seed 1

Random principals (identity policies, boundaries, SCP layers, session
policies) are built from a small vocabulary chosen to collide often:
overlapping wildcards, NotAction/NotResource, positive, negated and
IfExists conditions, and conditions Reach deliberately does not model.

Two properties are checked:

1. Concrete agreement. With action, resource and every context key
   pinned, the engine's three-valued verdict must equal the reference
   evaluator's exactly.
2. Proof soundness. When a wildcard query with a free context is DENIED,
   no sampled concrete request matching it may be allowed, or even
   possibly allowed, by the reference evaluator.

(ALLOWED and UNKNOWN witnesses are already replayed through the reference
evaluator inside engine.decide on every call.)
"""

from __future__ import annotations

import argparse
import random
import sys
from dataclasses import dataclass

from reach.catalog import Catalog
from reach.conditions import ContextValue
from reach.engine import Environment, Principal, Query, ResourcePolicy, Verdict, decide
from reach.policy import Policy, parse_policy
from reach.reference import Tri, _arn, _glob, evaluate
from reach.values import render_time

ACCOUNT = "123456789012"
PRINCIPALS = [f"arn:aws:iam::{ACCOUNT}:role/app-1", f"arn:aws:iam::{ACCOUNT}:user/alice"]

ACTIONS = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "iam:PassRole", "iam:CreateUser", "ec2:RunInstances"]
ACTION_PATTERNS = [*ACTIONS, "*", "s3:*", "s3:Get*", "s3:*Object", "iam:*", "iam:Pass?ole", "ec2:Run*", "S3:GETOBJECT"]

RESOURCES = [
    "arn:aws:s3:::pii/a.csv",
    "arn:aws:s3:::pii/alice/notes",
    "arn:aws:s3:::team-data/x",
    "arn:aws:s3:::team-shared/x",
    "arn:aws:s3:::pii/sub/b",
    "arn:aws:s3:::logs/x",
    f"arn:aws:iam::{ACCOUNT}:role/app-1",
    f"arn:aws:iam::{ACCOUNT}:role/admin",
    f"arn:aws:ec2:eu-west-1:{ACCOUNT}:instance/i-1",
    f"arn:aws:logs:eu-west-1:{ACCOUNT}:log-group:a:log-stream:b",
]
RESOURCE_PATTERNS = [
    *RESOURCES,
    "*",
    "arn:aws:s3:::pii/*",
    "arn:aws:s3:::*",
    "arn:aws:iam::*:role/app-*",
    f"arn:aws:iam::{ACCOUNT}:role/*",
    f"arn:aws:*:*:{ACCOUNT}:*",
    "arn:aws:ec2:*:*:instance/i-?",
    "arn:aws:logs:*:*:log-group:*",
    "arn:aws:s3:::pii/?.csv",
    "arn:aws:s3*",
]
# Patterns with policy variables: only in Resource elements, never in the query's own resource.
VARIABLE_RESOURCES = [
    "arn:aws:s3:::pii/${aws:username}/*",
    "arn:aws:s3:::team-${aws:PrincipalTag/team}/*",
    "arn:aws:s3:::team-${aws:PrincipalTag/team, 'shared'}/*",
    "arn:aws:s3:::pii/${*}",
    "arn:aws:s3:::pii/${aws:SourceVpc}/*",
    "arn:aws:s3:::${s3:prefix}*",
]
VARIABLE_VALUES = ["${aws:username}", "${aws:PrincipalTag/team}", "${aws:PrincipalTag/team, 'web'}", "vpc-${*}",
                   "home/${aws:username}*", "${aws:RequestedRegion}", "${aws:SourceVpc}"]  # fmt: skip

# Context keys a request may carry, with values policies and requests draw from.
KEYS = {
    "aws:SourceVpc": ["vpc-1", "vpc-2", "vpc-10"],
    "aws:MultiFactorAuthPresent": ["true", "false"],
    "aws:RequestedRegion": ["eu-west-1", "us-east-1"],
    "s3:prefix": ["home/", "home/a", "tmp/"],
    "s3:max-keys": ["5", "10", "0100", "500", "abc", "1.5"],
}
SOURCE_IPS = ["10.1.2.3", "192.168.1.7", "192.168.2.1", "8.8.8.8", "2001:db8::5"]
EPOCHS = [1_700_000_000, 1_767_225_599, 1_767_225_600, 1_767_225_601, 1_800_000_000]
NETWORKS = ["10.0.0.0/8", "192.168.1.0/24", "192.168.1.7", "2001:db8::/32"]
MOMENTS = ["2026-01-01T00:00:00Z", "1767225600", "2027-06-01"]
COMPARISONS = ["Equals", "NotEquals", "LessThan", "LessThanEquals", "GreaterThan", "GreaterThanEquals"]
LIKE_VALUES = ["home/*", "vpc-?", "*", "eu-*", "tmp/"]
TAGS = [{}, {"team": "data"}, {"team": "web"}]

POSITIVE = ["StringEquals", "StringLike", "StringEqualsIfExists", "StringLikeIfExists", "Bool", "BoolIfExists"]
NEGATED = ["StringNotEquals", "StringNotLike", "StringNotEqualsIfExists"]
UNMODELLED = [
    ("StringEqualsIgnoreCase", "aws:SourceVpc", "VPC-1"),
    ("BinaryEquals", "s3:prefix", "QUJD"),
    ("ForAnyValue:StringEquals", "aws:TagKeys", "env"),
    ("StringEquals", "s3:prefix", "${aws:username}/"),
    ("StringLike", "aws:SourceIp", "10.*"),  # string operator on an IP key
    ("NumericLessThan", "aws:CurrentTime", "5"),  # numeric operator on a time key
]


RESOURCE_PRINCIPALS = [
    "*",
    {"AWS": "*"},
    {"AWS": PRINCIPALS[0]},
    {"AWS": PRINCIPALS[1]},
    {"AWS": ACCOUNT},
    {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
    {"AWS": "999999999999"},
    {"AWS": f"arn:aws:sts::{ACCOUNT}:assumed-role/app-1/s1"},
    {"Service": "lambda.amazonaws.com"},
    {"AWS": [PRINCIPALS[1], ACCOUNT]},
]


@dataclass
class Case:
    principal: Principal
    env: Environment
    resource_policy: ResourcePolicy | None = None


TAG_KEYS = ["env", "team", "cost", "aws:stack"]
SET_OPS = ["StringEquals", "StringLike", "StringNotEquals", "StringNotLike"]


def _set_condition(rng: random.Random) -> tuple[str, str, list[str]]:
    """ForAnyValue/ForAllValues, mostly on the multi-valued aws:TagKeys, sometimes on a single-valued key."""
    qualifier = rng.choice(["ForAnyValue", "ForAllValues"])
    op = f"{qualifier}:{rng.choice(SET_OPS)}"
    if rng.random() < 0.25:
        return op, "s3:prefix", rng.sample(KEYS["s3:prefix"] + ["home/*"], k=rng.randint(1, 2))
    return op, "aws:TagKeys", rng.sample([*TAG_KEYS, "aws:*", "*"], k=rng.randint(1, 3))


def _condition(rng: random.Random) -> tuple[str, str, list[str]]:
    if rng.random() < 0.15:
        return _set_condition(rng)
    roll = rng.random()
    if_exists = "IfExists" if rng.random() < 0.25 else ""
    if roll < 0.10:
        op, key, value = rng.choice(UNMODELLED)
        return op, key, [value]
    if roll < 0.17:
        keys = [*KEYS, "aws:SourceIp", "aws:CurrentTime", "aws:TokenIssueTime", "aws:TagKeys"]
        return "Null", rng.choice(keys), [rng.choice(["true", "false"])]
    if roll < 0.27:
        op = f"Numeric{rng.choice(COMPARISONS)}{if_exists}"
        return op, "s3:max-keys", rng.sample(["10", "100", "10.5", "0"], k=rng.randint(1, 2))
    if roll < 0.37:
        op = rng.choice(["IpAddress", "NotIpAddress"]) + if_exists
        return op, "aws:SourceIp", rng.sample(NETWORKS, k=rng.randint(1, 2))
    if roll < 0.45:
        op = f"Date{rng.choice(COMPARISONS)}{if_exists}"
        return op, rng.choice(["aws:CurrentTime", "aws:EpochTime"]), rng.sample(MOMENTS, k=rng.randint(1, 2))
    if roll < 0.52:
        op = rng.choice(["ArnLike", "ArnNotLike", "ArnEquals"])
        return op, "aws:PrincipalArn", [rng.choice([*PRINCIPALS, "arn:aws:iam::*:role/app-*", "arn:aws:iam::*:user/*"])]
    if roll < 0.58:
        return rng.choice(["StringEquals", "StringNotEquals"]), "aws:PrincipalTag/team", [rng.choice(["data", "web"])]
    key = rng.choice(list(KEYS))
    op = rng.choice(POSITIVE + NEGATED)
    if op.startswith("Bool"):
        key, values = "aws:MultiFactorAuthPresent", [rng.choice(["true", "false"])]
    elif "Like" in op:
        values = rng.sample(LIKE_VALUES + KEYS[key], k=rng.randint(1, 2))
    else:
        values = rng.sample(KEYS[key], k=rng.randint(1, 2))
    if rng.random() < 0.2:
        values = [*values[:1], rng.choice(VARIABLE_VALUES)] if rng.random() < 0.5 else [rng.choice(VARIABLE_VALUES)]
    return op, key, values


def _statement(rng: random.Random, deny_bias: float) -> dict:
    stmt: dict = {"Effect": "Deny" if rng.random() < deny_bias else "Allow"}
    actions = rng.sample(ACTION_PATTERNS, k=rng.randint(1, 2))
    stmt["NotAction" if rng.random() < 0.15 else "Action"] = actions if len(actions) > 1 else actions[0]
    resources = rng.sample(RESOURCE_PATTERNS, k=rng.randint(1, 2))
    if rng.random() < 0.25:
        resources[0] = rng.choice(VARIABLE_RESOURCES)
    stmt["NotResource" if rng.random() < 0.1 else "Resource"] = resources
    conditions: dict = {}
    for _ in range(rng.choice([0, 0, 1, 1, 2])):
        op, key, values = _condition(rng)
        conditions.setdefault(op, {})[key] = values
    if conditions:
        stmt["Condition"] = conditions
    return stmt


def _policy(rng: random.Random, name: str, deny_bias: float = 0.25) -> Policy:
    statements = [_statement(rng, deny_bias) for _ in range(rng.randint(1, 3))]
    # Variables are substituted only under Version 2012-10-17; without it they are literal text.
    doc = {"Version": "2012-10-17", "Statement": statements} if rng.random() < 0.85 else {"Statement": statements}
    return parse_policy(doc, name)


def _resource_policy(rng: random.Random) -> ResourcePolicy:
    statements = []
    for _ in range(rng.randint(1, 3)):
        stmt = _statement(rng, deny_bias=0.25)
        stmt["NotPrincipal" if stmt["Effect"] == "Deny" and rng.random() < 0.2 else "Principal"] = rng.choice(
            RESOURCE_PRINCIPALS
        )
        statements.append(stmt)
    policy = parse_policy({"Statement": statements}, "resource-policy")
    return ResourcePolicy(policy, ACCOUNT if rng.random() < 0.7 else "999999999999", required=rng.random() < 0.25)


def _rcp(rng: random.Random) -> Policy:
    """A resource control policy: Deny statements with Principal "*" (Allow exists only as RCPFullAWSAccess).

    AWS accepts only RCPs that name a service in Action and do not use NotAction, so neither is generated.
    """
    statements = []
    for _ in range(rng.randint(1, 2)):
        stmt = {**_statement(rng, deny_bias=1.0), "Principal": "*"}
        actions = stmt.pop("NotAction", None) or stmt.pop("Action")
        actions = [actions] if isinstance(actions, str) else actions
        stmt["Action"] = [a if a != "*" else "s3:*" for a in actions]
        statements.append(stmt)
    return parse_policy({"Version": "2012-10-17", "Statement": statements}, "rcp")


def random_case(rng: random.Random) -> Case:
    principal = Principal(
        arn=rng.choice(PRINCIPALS),
        identity_policies=[_policy(rng, f"identity-{i}") for i in range(rng.randint(1, 2))],
        boundary=_policy(rng, "boundary", 0.15) if rng.random() < 0.3 else None,
        tags=rng.choice(TAGS),
    )
    env = Environment(
        scp_layers=[(f"layer-{i}", [_policy(rng, f"scp-{i}", 0.2)]) for i in range(rng.choice([0, 0, 1, 2]))],
        session_policies=[_policy(rng, "session", 0.1)] if rng.random() < 0.2 else [],
        management_account=rng.random() < 0.1,
        rcps=[_rcp(rng)] if rng.random() < 0.2 else [],
    )
    return Case(principal, env, _resource_policy(rng) if rng.random() < 0.5 else None)


def random_context(rng: random.Random) -> dict[str, ContextValue]:
    ctx: dict[str, ContextValue] = {}
    for key, values in KEYS.items():
        ctx[key] = None if rng.random() < 0.3 else rng.choice([*values, "other"])
    # Every real request goes to some region (found by the AWS simulator harness).
    ctx["aws:RequestedRegion"] = rng.choice([*KEYS["aws:RequestedRegion"], "other"])
    ctx["aws:SourceIp"] = None if rng.random() < 0.2 else rng.choice(SOURCE_IPS)
    # One instant, spelled both ways, exactly as AWS populates the context.
    epoch = rng.choice(EPOCHS)
    ctx["aws:EpochTime"] = str(epoch)
    ctx["aws:CurrentTime"] = render_time(epoch, "iso")
    # Policies may test aws:TokenIssueTime, so a concrete request must decide it too: a key left out of the
    # context is unknown to the engine but absent to the reference (seed 1, case 198 in CI).
    ctx["aws:TokenIssueTime"] = None if rng.random() < 0.5 else render_time(epoch - 3600, "iso")
    # A multi-valued key: absent, or a set of tag keys.
    ctx["aws:TagKeys"] = None if rng.random() < 0.3 else sorted(rng.sample([*TAG_KEYS, "other"], k=rng.randint(1, 3)))
    return ctx


_TRI = {Verdict.ALLOWED: True, Verdict.DENIED: False, Verdict.UNKNOWN: None}


def check_concrete(case: Case, rng: random.Random, catalog: Catalog | None) -> str | None:
    action, resource, ctx = rng.choice(ACTIONS), rng.choice(RESOURCES), random_context(rng)
    result = decide(case.principal, Query(action, resource, ctx, case.resource_policy), case.env, catalog=catalog)
    expected: Tri = evaluate(case.principal, action, resource, ctx, case.env, case.resource_policy)
    if _TRI[result.verdict] != expected:
        return f"concrete {action} on {resource} ctx={ctx}: engine {result.verdict.value}, reference {expected}"
    return None


def check_denial_sound(case: Case, rng: random.Random, catalog: Catalog | None, samples: int = 25) -> str | None:
    action_pattern, resource_pattern = rng.choice(ACTION_PATTERNS), rng.choice(RESOURCE_PATTERNS)
    query = Query(action_pattern, resource_pattern, resource_policy=case.resource_policy)
    result = decide(case.principal, query, case.env, catalog=catalog)
    if result.verdict is not Verdict.DENIED:
        return None
    actions = [a for a in ACTIONS if _glob(action_pattern, ignore_case=True).fullmatch(a)]
    resources = [r for r in RESOURCES if _arn(resource_pattern).fullmatch(r)]
    if not actions or not resources:
        return None
    for _ in range(samples):
        action, resource, ctx = rng.choice(actions), rng.choice(resources), random_context(rng)
        concrete = evaluate(case.principal, action, resource, ctx, case.env, case.resource_policy)
        if concrete is not False:
            return (
                f"proof violated: {action_pattern} on {resource_pattern} was DENIED, but {action} on {resource} "
                f"ctx={ctx} evaluates to {concrete}"
            )
    return None


def run(cases: int, seed: int, verbose: bool = False) -> list[str]:
    rng = random.Random(seed)  # noqa: S311 - reproducible test data, not cryptography
    catalog = Catalog(tuple(ACTIONS), generated="fuzz")
    failures: list[str] = []
    for i in range(cases):
        case = random_case(rng)
        cat = catalog if rng.random() < 0.5 else None
        for check in (check_concrete, check_denial_sound):
            problem = check(case, rng, cat)
            if problem:
                failures.append(f"case {i} (seed {seed}): {problem}")
                if verbose:
                    print(failures[-1], file=sys.stderr)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Differential fuzzing of the Reach engine.")
    parser.add_argument("--cases", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    failures = run(args.cases, args.seed, verbose=True)
    print(f"{args.cases} cases, {len(failures)} failures", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
