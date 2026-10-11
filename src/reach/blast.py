"""From an agent's credentials to what they can actually do.

The second half of agent analysis: an AWS profile an agent can reach is
resolved to an IAM principal (`sts get-caller-identity`, which needs no
permissions and changes nothing), and that principal is run through the
reasoning engine against an account snapshot for a fixed set of
high-impact questions.

Verdicts carry the engine's guarantees: DENIED is a proof, ALLOWED comes
with a witness request, UNKNOWN names what it depends on.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .engine import Environment, Principal, Query, Result, Verdict, Witness, decide
from .loaders import AuthorizationDetails, trust_policy
from .principals import classify

# (what it means, action pattern, resource pattern)
HIGH_IMPACT: tuple[tuple[str, str, str], ...] = (
    ("read secrets", "secretsmanager:GetSecretValue", "*"),
    ("read SSM parameters", "ssm:GetParameter*", "*"),
    ("decrypt with KMS", "kms:Decrypt", "*"),
    ("read S3 objects", "s3:GetObject", "*"),
    ("write S3 objects", "s3:PutObject", "*"),
    ("modify IAM", "iam:*", "*"),
    ("assume roles", "sts:AssumeRole", "*"),
    ("start compute", "ec2:RunInstances", "*"),
    ("invoke Lambda", "lambda:InvokeFunction", "*"),
)

_ASSUMED = re.compile(r"arn:(aws[a-z-]*):sts::([0-9]{12}):assumed-role/([^/]+)/.+")


@dataclass
class Resolution:
    profile: str
    arn: str = ""  # principal ARN as STS reports it
    error: str = ""


@dataclass
class Capability:
    label: str
    action: str
    verdict: Verdict
    witness: Witness | None = None
    caveats: list[str] = field(default_factory=list)


def resolve_profiles(profiles: list[str], session_factory: Callable[[str], Any] | None = None) -> list[Resolution]:
    """Who each AWS profile signs in as. Read-only: sts:GetCallerIdentity needs no permissions."""
    if session_factory is None:
        import boto3  # noqa: PLC0415 - optional dependency, only needed when resolving

        def session_factory(profile: str) -> Any:
            return boto3.Session(profile_name=profile)

    out = []
    for profile in profiles:
        try:
            arn = session_factory(profile).client("sts").get_caller_identity()["Arn"]
            out.append(Resolution(profile, arn=arn))
        except Exception as exc:  # noqa: BLE001 - expired, missing or malformed credentials are all just "unresolved"
            out.append(Resolution(profile, error=f"{type(exc).__name__}: {exc}"))
    return out


def principal_ref(arn: str) -> str:
    """The snapshot key for a caller ARN: an assumed-role session maps to its role's name."""
    m = _ASSUMED.fullmatch(arn)
    return m.group(3) if m else arn


def capabilities(details: AuthorizationDetails, arn: str, env: Environment | None = None) -> list[Capability]:
    principal = details.principal(principal_ref(arn))
    out = []
    for label, action, resource in HIGH_IMPACT:
        result = decide_in_snapshot(details, principal, action, resource, env)
        out.append(Capability(label, action, result.verdict, result.witness, result.assumptions))
    return out


def decide_in_snapshot(
    details: AuthorizationDetails, principal: Principal, action: str, resource: str, env: Environment | None = None
) -> Result:
    """decide(), with what the snapshot knows beyond the principal's own policies.

    Assuming a role needs that role's trust policy to allow it, and a trust policy can grant on its own, with no
    identity permission at all. So `sts:AssumeRole` on `*` is decided against every role in the snapshot with its
    trust policy: allowed if any role is, denied (a proof) only if every one is. Roles whose trust policy names
    no principal this one can be are skipped: without a trust grant, assuming them is impossible.
    """
    if action.lower() != "sts:assumerole" or resource != "*":
        return decide(principal, Query(action, resource), env)
    candidates = []
    for role_arn in sorted(details.roles):
        trust = trust_policy(details, role_arn)
        if trust is None:
            continue
        if any(st.effect == "Allow" and classify(st, principal.arn) for st in trust.policy.statements):
            candidates.append((role_arn, trust))
    unknown: Result | None = None
    for role_arn, trust in candidates:
        result = decide(principal, Query(action, role_arn, resource_policy=trust), env)
        if result.verdict is Verdict.ALLOWED:
            return result
        if result.verdict is Verdict.UNKNOWN and unknown is None:
            unknown = result
    if unknown is not None:
        return unknown
    return Result(
        Verdict.DENIED,
        principal.arn,
        Query(action, resource),
        reasons=[
            f"No role in the snapshot can be assumed: {len(details.roles)} roles, {len(candidates)} with a trust "
            "policy naming this principal, each proven denied. Roles in other accounts are not in the snapshot."
        ],
    )
