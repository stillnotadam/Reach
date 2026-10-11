"""A concrete, solver-free evaluator for a single fully specified request.

This is a second implementation of the same evaluation logic as engine.py,
written as plain Python over concrete strings. It shares no code with the
Z3 encoding beyond policy parsing, which makes it useful in two ways:

* every ALLOWED witness the engine produces is re-checked here before it
  is reported (engine.decide raises if they disagree);
* the fuzzer (validation/fuzz.py) generates random policies and requests
  and demands that both implementations agree exactly.

What this cannot catch is a shared misreading of AWS semantics; only the
differential harness against AWS's own simulator can do that.

Unmodelled conditions evaluate to None, and None propagates through
Kleene three-valued logic. Each opaque condition occurs exactly once in
the decision formula, and for such read-once formulas Kleene logic gives
exactly the same answer as checking every assignment: True means allowed
whatever the unmodelled conditions do, False means denied whatever they
do, None means it depends.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Iterable
from functools import lru_cache

from .conditions import MULTIVALUED_KEYS
from .engine import Environment, Principal, ResourcePolicy
from .policy import Condition, Policy, Statement
from .principals import Match, classify
from .values import IP_KEYS, TIME_KEYS, parse_int, parse_ip, parse_ipv4_network, parse_time, principal_type

Tri = bool | None  # True, False, or None for "depends on something unmodelled"


def _and(values: Iterable[Tri]) -> Tri:
    out: Tri = True
    for v in values:
        if v is False:
            return False
        if v is None:
            out = None
    return out


def _or(values: Iterable[Tri]) -> Tri:
    out: Tri = False
    for v in values:
        if v is True:
            return True
        if v is None:
            out = None
    return out


def _not(value: Tri) -> Tri:
    return None if value is None else not value


def _segment(pattern: str, any_colon: bool) -> str:
    star = ".*" if any_colon else "[^:]*"
    one = "." if any_colon else "[^:]"
    return "".join(star if c == "*" else one if c == "?" else re.escape(c) for c in pattern)


@lru_cache(maxsize=4096)
def _glob(pattern: str, ignore_case: bool = False) -> re.Pattern[str]:
    return re.compile(_segment(pattern, any_colon=True), (re.IGNORECASE if ignore_case else 0) | re.DOTALL)


@lru_cache(maxsize=4096)
def _arn(pattern: str) -> re.Pattern[str]:
    parts = pattern.split(":", 5)
    if len(parts) < 6:
        return _glob(pattern)
    body = ":".join([_segment(p, any_colon=False) for p in parts[:5]] + [_segment(parts[5], any_colon=True)])
    return re.compile(body, re.DOTALL)


class Request:
    def __init__(self, action: str, resource: str, context: dict[str, str | None]):
        self.action = action
        self.resource = resource
        # Absent keys are simply missing; a None value also means absent.
        self.context = {k.lower(): v for k, v in context.items() if v is not None}


_COMPARE = {
    "Equals": operator.eq,
    "NotEquals": operator.eq,  # the negation is applied below, like every Not operator
    "LessThan": operator.lt,
    "LessThanEquals": operator.le,
    "GreaterThan": operator.gt,
    "GreaterThanEquals": operator.ge,
}
_STRINGISH = frozenset(
    {"StringEquals", "StringNotEquals", "StringLike", "StringNotLike", "ArnEquals", "ArnLike", "ArnNotEquals",
     "ArnNotLike", "Bool"}
)  # fmt: skip


def _family(base: str) -> tuple[str, str] | None:
    """(family, comparison) for Numeric*/Date* operators."""
    for family in ("Numeric", "Date"):
        if base.startswith(family) and base[len(family) :] in _COMPARE:
            return family, base[len(family) :]
    return None


def _modelled(base: str, kind: str, values: tuple[str, ...]) -> bool:
    """Whether an operator is modelled at all, independent of the request's value."""
    if base in _STRINGISH:
        return kind == "string"
    fam = _family(base)
    if fam is not None:
        family, _ = fam
        parse = parse_int if family == "Numeric" else parse_time
        return kind == ("string" if family == "Numeric" else "time") and all(parse(v) is not None for v in values)
    if base in ("IpAddress", "NotIpAddress"):
        return kind == "ip" and all(parse_ipv4_network(v) is not None for v in values)
    return False


def _hit(base: str, value: str, values: tuple[str, ...]) -> Tri:
    """Does a present value match a modelled operator's value list (before negation)?"""
    if base in ("StringEquals", "StringNotEquals"):
        return value in values
    if base in ("StringLike", "StringNotLike"):
        return any(_glob(v).fullmatch(value) for v in values)
    if base == "Bool":
        return value in {v.lower() for v in values}
    if base in _STRINGISH:
        return any(_arn(v).fullmatch(value) for v in values)
    fam = _family(base)
    if fam is not None:
        family, comparison = fam
        parse = parse_int if family == "Numeric" else parse_time
        actual = parse(value)
        if actual is None:
            return None  # e.g. a decimal or signed number: not modelled
        bounds = [b for b in (parse(v) for v in values) if b is not None]  # _modelled already rejected None
        return any(_COMPARE[comparison](actual, b) for b in bounds)
    address = parse_ip(value)
    if address is None:
        return None
    is_v4, number = address
    networks = [n for n in (parse_ipv4_network(v) for v in values) if n is not None]
    return is_v4 and any((number & mask) == net for net, mask in networks)


def _condition(cond: Condition, req: Request) -> Tri:
    op = cond.operator
    if_exists = op.endswith("IfExists")
    base = op[: -len("IfExists")] if if_exists else op
    if ":" in base or any("${" in v for v in cond.values) or cond.key.lower() in MULTIVALUED_KEYS or not cond.values:
        return None

    k = cond.key.lower()
    kind = "ip" if k in IP_KEYS else "time" if k in TIME_KEYS else "string"
    value = req.context.get(k)
    if base == "Null":
        return any((value is None) == (v.lower() == "true") for v in cond.values)
    if not _modelled(base, kind, cond.values):
        return None
    if value is None:
        return True if "Not" in base else if_exists
    hit = _hit(base, value, cond.values)
    if hit is None:
        return None
    return not hit if "Not" in base else hit


def _statement(stmt: Statement, req: Request) -> Tri:
    action = any(_glob(a, ignore_case=True).fullmatch(req.action) for a in stmt.actions) != stmt.not_actions
    resource = any(_arn(r).fullmatch(req.resource) for r in stmt.resources) != stmt.not_resources
    if not (action and resource):
        return False
    return _and(_condition(c, req) for c in stmt.conditions)


def _allows(policies: list[Policy], req: Request) -> Tri:
    return _or(_statement(s, req) for p in policies for s in p.statements if s.effect == "Allow")


def _denies(policies: list[Policy], req: Request) -> Tri:
    return _or(_statement(s, req) for p in policies for s in p.statements if s.effect == "Deny")


def evaluate(
    principal: Principal,
    action: str,
    resource: str,
    context: dict[str, str | None],
    env: Environment | None = None,
    resource_policy: ResourcePolicy | None = None,
) -> Tri:
    env = env or Environment()
    # Principal-derived keys first, so explicitly pinned keys override them, as in the engine.
    full: dict[str, str | None] = {
        "aws:PrincipalArn": principal.arn,
        "aws:PrincipalAccount": principal.account,
        "aws:PrincipalType": principal_type(principal.arn),
    }
    full.update({f"aws:PrincipalTag/{k}": v for k, v in principal.tags.items()})
    full.update(context)
    req = Request(action, resource, full)

    scps_apply = not env.management_account and not principal.is_service_linked
    boundary = [principal.boundary] if principal.boundary else []
    every = principal.identity_policies + boundary + env.session_policies
    if scps_apply:
        every = every + [p for _, layer in env.scp_layers for p in layer]
    denied = _denies(every, req)
    if resource_policy is not None:
        applicable = [
            st for st in resource_policy.policy.statements if st.effect == "Deny" and classify(st, principal.arn)
        ]
        denied = _or([denied, *(_statement(st, req) for st in applicable)])

    scps: list[Tri] = [_allows(layer, req) for _, layer in env.scp_layers] if scps_apply else []
    caps: list[Tri] = [_allows(boundary, req)] if boundary else []
    caps.extend(_allows([sp], req) for sp in env.session_policies)
    capped = _and(caps)
    identity_path = _and([_allows(principal.identity_policies, req), capped])
    grant = (
        identity_path
        if resource_policy is None
        else _resource_grant(principal, req, resource_policy, identity_path, caps)
    )
    return _and([_not(denied), *scps, grant])


def _resource_grant(principal: Principal, req: Request, rp: ResourcePolicy, identity_path: Tri, caps: list[Tri]) -> Tri:
    by_kind: dict[Match, list[Tri]] = {m: [] for m in Match}
    for st in rp.policy.statements:
        kinds = classify(st, principal.arn) if st.effect == "Allow" else set()
        if kinds:
            value = _statement(st, req)
            for kind in kinds:
                by_kind[kind].append(value)
    granted = {m: _or(v) for m, v in by_kind.items()}
    capped = _and(caps)
    if rp.account != principal.account:
        return _and([identity_path, _or(granted.values())])
    wildcard = granted[Match.WILDCARD]
    if caps and by_kind[Match.WILDCARD]:
        # Unverified AWS rule: whether caps limit a Principal "*" grant. Unknown, unless the caps allow anyway.
        wildcard = _and([wildcard, _or([capped, None])])
    direct = _or([granted[Match.USER], granted[Match.SESSION], _and([granted[Match.ROLE], capped]), wildcard])
    if rp.required:
        return _or([direct, _and([granted[Match.ACCOUNT], identity_path])])
    # An account grant only delegates (verified on live S3; FINDINGS.md, finding 4).
    return _or([identity_path, direct])
