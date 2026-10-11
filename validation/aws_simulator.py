"""Differential testing against AWS's own IAM policy simulator.

    python -m pip install -e ".[aws]"
    python -m validation.aws_simulator --profile reach-sim --cases 500 --seed 1 --out sim-report.jsonl

This is the only check that can catch a misreading of AWS semantics that
the engine and the reference evaluator share. Random cases come from the
fuzzer's generator; each is sent to `iam:SimulateCustomPolicy` with a
fully pinned request context and compared with Reach's verdict.

Required permission: only `iam:SimulateCustomPolicy`. The API is
read-only, creates nothing and is free.

What the simulator cannot express, and is therefore filtered out (and
counted in the report, never silently dropped):

* SCPs and session policies (not inputs of SimulateCustomPolicy);
* resource policies with a role caller (CallerArn must be an IAM user);
* required resource policies (trust and KMS key policies), which the
  simulator does not treat specially;
* cases where Reach's verdict is UNKNOWN (nothing to compare).

Status: written before an AWS account was available, so it is covered by
unit tests against a fake client only. Expect to adjust it after the
first real run.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from reach.conditions import ContextValue
from reach.engine import Environment, Query, Verdict, decide
from reach.policy import Policy, Statement
from reach.principals import Match, classify
from reach.values import BOOLEAN_KEYS, IP_KEYS, TIME_KEYS, parse_int, principal_type, username

from .fuzz import ACTIONS, RESOURCES, Case, random_case, random_context


class SimulatorClient(Protocol):
    def simulate_custom_policy(self, **kwargs: Any) -> dict[str, Any]: ...


@dataclass
class Comparison:
    case: int
    action: str
    resource: str
    context: dict[str, str | None]
    reach: str
    aws: str
    detail: str = ""


# --- policies back to JSON ------------------------------------------------------


def _statement_json(st: Statement) -> dict[str, Any]:
    out: dict[str, Any] = {"Effect": st.effect}
    out["NotAction" if st.not_actions else "Action"] = list(st.actions)
    out["NotResource" if st.not_resources else "Resource"] = list(st.resources)
    if st.principals is not None:
        if st.principals == (("*", "*"),):
            principal: Any = "*"
        else:
            principal = {}
            for kind, value in st.principals:
                principal.setdefault(kind, []).append(value)
        out["NotPrincipal" if st.not_principal else "Principal"] = principal
    if st.conditions:
        block: dict[str, dict[str, list[str]]] = {}
        for c in st.conditions:
            block.setdefault(c.operator, {})[c.key] = list(c.values)
        out["Condition"] = block
    return out


def policy_json(policy: Policy) -> str:
    doc: dict[str, Any] = {"Statement": [_statement_json(s) for s in policy.statements]}
    # Keep the policy's language version: it decides whether ${...} is a variable or literal text.
    if all(s.variables for s in policy.statements):
        doc = {"Version": "2012-10-17", **doc}
    return json.dumps(doc)


# --- context entries --------------------------------------------------------------


def context_entries(context: dict[str, ContextValue]) -> list[dict[str, Any]]:
    """Present keys only: an absent key (or an empty set) is simply not sent."""
    entries = []
    for key, value in context.items():
        if value is None or value == []:
            continue
        if isinstance(value, list):
            entries.append({"ContextKeyName": key, "ContextKeyValues": value, "ContextKeyType": "stringList"})
            continue
        k = key.lower()
        if k in IP_KEYS:
            kind = "ip"
        elif k in TIME_KEYS:
            kind = "date" if TIME_KEYS[k][1] == "iso" else "numeric"
        elif k in BOOLEAN_KEYS and value in ("true", "false"):
            kind = "boolean"
        elif parse_int(value) is not None:
            kind = "numeric"
        else:
            kind = "string"
        entries.append({"ContextKeyName": key, "ContextKeyValues": [value], "ContextKeyType": kind})
    return entries


# --- cases ---------------------------------------------------------------------------


def simulatable(case: Case) -> tuple[Case | None, str]:
    """Strip what the simulator cannot express; None with a reason when nothing comparable is left."""
    rp = case.resource_policy
    if rp is not None and rp.required:
        return None, "required resource policy"
    if rp is not None and ":user/" not in case.principal.arn:
        return None, "resource policy with a role caller"
    if rp is not None and rp.account != case.principal.account:
        return None, "cross-account resource policy"
    if rp is not None and any(r.count(":") < 5 for st in rp.policy.statements for r in st.resources):
        # The simulator rejects it, and real bucket/key policies must name ARNs anyway.
        return None, "resource policy with a non-ARN Resource"
    if rp is not None and any(
        st.effect == "Allow" and Match.ACCOUNT in classify(st, case.principal.arn) for st in rp.policy.statements
    ):
        # The simulator treats a same-account account-principal grant as sufficient on its own;
        # live S3 does not (FINDINGS.md, finding 4). Comparing would only re-measure that bug.
        return None, "account-principal grant (simulator differs from live AWS)"
    # SCPs and session policies are not simulator inputs: compare without them.
    return Case(case.principal, Environment(), rp), ""


def build_request(case: Case, action: str, resource: str, context: dict[str, str | None]) -> dict[str, Any]:
    principal = case.principal
    full = {
        "aws:PrincipalArn": principal.arn,
        "aws:PrincipalAccount": principal.account,
        "aws:PrincipalType": principal_type(principal.arn),
        # The simulator substitutes ${aws:username} only from a context entry.
        "aws:username": username(principal.arn),
    }
    full.update({f"aws:PrincipalTag/{k}": v for k, v in principal.tags.items()})
    full.update(context)
    request: dict[str, Any] = {
        "PolicyInputList": [policy_json(p) for p in principal.identity_policies],
        "ActionNames": [action],
        "ResourceArns": [resource],
        "ContextEntries": context_entries(full),
    }
    if principal.boundary is not None:
        request["PermissionsBoundaryPolicyInputList"] = [policy_json(principal.boundary)]
    if case.resource_policy is not None:
        request["ResourcePolicy"] = policy_json(case.resource_policy.policy)
        request["ResourceOwner"] = f"arn:aws:iam::{case.resource_policy.account}:root"
        request["CallerArn"] = principal.arn
    return request


def interpret(response: dict[str, Any]) -> tuple[str, str]:
    """('allowed' | 'denied' | 'unclear', detail) from a SimulateCustomPolicy response."""
    results = response.get("EvaluationResults", [])
    if len(results) != 1:
        return "unclear", f"expected one evaluation result, got {len(results)}"
    result = results[0]
    # The simulator lists keys a policy mentions but the request does not carry.
    # Reach models those as absent; the comparison shows whether AWS agrees.
    missing = result.get("MissingContextValues") or []
    note = f"missing context values: {missing}" if missing else ""
    decision = result.get("EvalDecision")
    if decision == "allowed":
        return "allowed", note
    if decision in ("explicitDeny", "implicitDeny"):
        return "denied", f"{decision} {note}".strip()
    return "unclear", f"unexpected decision {decision!r}"


def feasible_request(rng: random.Random) -> tuple[str, str, dict[str, str | None]]:
    """An action with a resource of its own service.

    The simulator implicitly denies an action on a resource of another
    service (s3:PutObject on an IAM role ARN) even under Allow "*", because
    no such request exists. Reach does not model per-action resource
    types yet (ROADMAP: needs the Service Authorization Reference), so the
    comparison sticks to requests that can exist.
    """
    action = rng.choice(ACTIONS)
    service = action.split(":")[0]
    resource = rng.choice([r for r in RESOURCES if r.split(":")[2] == service])
    if action == "iam:CreateUser":
        # Resource types matter within a service too: CreateUser acts on user ARNs.
        resource = "arn:aws:iam::123456789012:user/new-user"
    context = random_context(rng)
    if action != "s3:ListBucket":
        # Service-specific keys exist only for actions that support them: in the
        # fuzz vocabulary, s3:prefix and s3:max-keys are s3:ListBucket keys, and
        # AWS drops them from other requests (second simulator finding). Pin them
        # absent; leaving them out would let Reach's solver choose a value.
        context = {k: (v if k.startswith("aws:") else None) for k, v in context.items()}
    return action, resource, context


def _policies(case: Case) -> list[Policy]:
    policies = [*case.principal.identity_policies, *([case.principal.boundary] if case.principal.boundary else [])]
    return policies + ([case.resource_policy.policy] if case.resource_policy else [])


def _uses_variables(case: Case) -> bool:
    policies = _policies(case)
    return any(
        st.variables and any("${" in t for t in (*st.resources, *(v for c in st.conditions for v in c.values)))
        for p in policies
        for st in p.statements
    )


def run(client: SimulatorClient, cases: int, seed: int) -> tuple[list[Comparison], Counter]:
    rng = random.Random(seed)  # noqa: S311 - reproducible test data, not cryptography
    stats: Counter = Counter()
    disagreements: list[Comparison] = []
    for i in range(cases):
        case, reason = simulatable(random_case(rng))
        if case is None:
            stats[f"skipped: {reason}"] += 1
            continue
        action, resource, ctx = feasible_request(rng)
        query = Query(action, resource, ctx, case.resource_policy)
        # The bundled catalogue, as in real use: per-action resource types and condition keys.
        verdict = decide(case.principal, query, case.env).verdict
        request = build_request(case, action, resource, ctx)
        try:
            aws, detail = interpret(client.simulate_custom_policy(**request))
        except Exception as exc:  # noqa: BLE001 - botocore error classes are generated; record and continue
            if "AccessDenied" in type(exc).__name__ or "AccessDenied" in str(exc):
                raise
            stats["simulator rejected input"] += 1
            detail = f"{type(exc).__name__}: {exc} | request: {json.dumps(request)[:1500]}"
            disagreements.append(Comparison(i, action, resource, ctx, verdict.value, "rejected", detail))
            continue
        if aws == "unclear":
            stats["unclear simulator result"] += 1
            disagreements.append(Comparison(i, action, resource, ctx, verdict.value, aws, detail))
            continue
        if verdict is Verdict.UNKNOWN:
            # Nothing to compare, but what AWS says is evidence for settling Reach's open rules.
            stats[f"Reach unknown, AWS says {aws}"] += 1
            continue
        stats["compared"] += 1
        if _uses_variables(case):
            stats["  of which use policy variables"] += 1
        if any(":" in c.operator for p in _policies(case) for st in p.statements for c in st.conditions):
            stats["  of which use ForAnyValue/ForAllValues"] += 1
        flagged = "missing context" in detail
        if flagged:
            stats["  of which simulator flagged absent keys"] += 1
        if aws != verdict.value:
            stats["disagreements"] += 1
            if flagged:
                stats["  disagreements with flagged absent keys"] += 1
            disagreements.append(Comparison(i, action, resource, ctx, verdict.value, aws, detail))
    return disagreements, stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare Reach with AWS's IAM policy simulator.")
    parser.add_argument("--profile", help="AWS CLI profile with iam:SimulateCustomPolicy")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--cases", type=int, default=200)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", default="sim-report.jsonl", help="JSONL file for disagreements")
    args = parser.parse_args()
    try:
        import boto3  # noqa: PLC0415 - optional dependency, only needed here
        from botocore.config import Config  # noqa: PLC0415
    except ImportError:
        print('boto3 is required: python -m pip install -e ".[aws]"', file=sys.stderr)
        return 2
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    client = session.client("iam", config=Config(retries={"max_attempts": 10, "mode": "adaptive"}))
    from botocore.exceptions import ClientError, NoCredentialsError  # noqa: PLC0415

    try:
        disagreements, stats = run(client, args.cases, args.seed)
    except NoCredentialsError:
        print(f"no credentials for profile {args.profile!r}: run `aws configure --profile ...`", file=sys.stderr)
        return 2
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "AccessDenied":
            print(
                "access denied: the profile needs a policy allowing iam:SimulateCustomPolicy "
                f"({exc.response['Error'].get('Message', '')})",
                file=sys.stderr,
            )
            return 2
        raise
    with open(args.out, "w", encoding="utf-8") as fh:
        for d in disagreements:
            fh.write(json.dumps(asdict(d)) + "\n")
    for key, count in sorted(stats.items()):
        print(f"{key:<45} {count}", file=sys.stderr)
    print(f"details of every disagreement and unclear result: {args.out}", file=sys.stderr)
    return 1 if stats["disagreements"] else 0


if __name__ == "__main__":
    sys.exit(main())
