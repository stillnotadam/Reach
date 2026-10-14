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
from fractions import Fraction
from functools import lru_cache

from .conditions import ContextValue, is_multivalued
from .engine import Environment, Principal, ResourcePolicy
from .policy import Condition, Policy, Statement
from .principals import Match, classify
from .values import (
    IP_KEYS,
    RCP_EXEMPT_ACTIONS,
    RCP_SERVICES,
    TIME_KEYS,
    UNMODELLED,
    ignore_case_equal,
    is_base64,
    parse_bool,
    parse_ip,
    parse_ip_network,
    parse_number,
    parse_time,
    principal_type,
    request_number,
    username,
)
from .variables import literal, resolve_statement

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
    return "".join(star if c == "*" else one if c == "?" else re.escape(literal(c)) for c in pattern)


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
    def __init__(self, action: str, resource: str, context: dict[str, ContextValue]):
        self.action = action
        self.resource = resource
        # Absent keys are simply missing; None, or an empty set of values, also means absent.
        self.context = {k.lower(): v for k, v in context.items() if v is not None and v != []}


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
     "ArnNotLike", "Bool", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase", "BinaryEquals", "BinaryNotEquals"}
)  # fmt: skip


def _family(base: str) -> tuple[str, str] | None:
    """(family, comparison) for Numeric*/Date* operators."""
    for family in ("Numeric", "Date"):
        if base.startswith(family) and base[len(family) :] in _COMPARE:
            return family, base[len(family) :]
    return None


def _modelled(base: str, kind: str, values: tuple[str, ...]) -> bool:
    """Whether an operator is modelled at all, independent of the request's value."""
    if base in ("BinaryEquals", "BinaryNotEquals"):
        return kind == "string" and all(is_base64(v) for v in values)  # IAM rejects anything else, like the engine
    if base in ("StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase"):
        # IAM accepts only Latin-1 text in a policy; other text is not modelled (like the engine).
        return kind == "string" and all(ord(c) <= 0xFF for v in values for c in literal(v))
    if base in _STRINGISH:
        return kind == "string"
    fam = _family(base)
    if fam is not None:
        family, _ = fam
        if family == "Numeric":
            return kind == "string" and all(parse_number(v) is not UNMODELLED for v in values)
        return kind == "time" and all(parse_time(v) is not None for v in values)
    if base in ("IpAddress", "NotIpAddress"):
        return kind == "ip" and all(parse_ip_network(v) is not None for v in values)
    return False


def _hit(base: str, value: str, values: tuple[str, ...]) -> Tri:
    """Does a present value match a modelled operator's value list (before negation)?"""
    if base in ("StringEquals", "StringNotEquals"):
        return value in {literal(v) for v in values}
    if base in ("BinaryEquals", "BinaryNotEquals"):
        return value in values  # base64 text, not decoded
    if base in ("StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase"):
        return any(ignore_case_equal(value, literal(v)) for v in values)
    if base in ("StringLike", "StringNotLike"):
        return any(_glob(v).fullmatch(value) for v in values)
    if base == "Bool":
        return parse_bool(value) in {parse_bool(v) for v in values}
    if base in _STRINGISH:
        return any(_arn(v).fullmatch(value) for v in values)
    fam = _family(base)
    if fam is not None:
        family, comparison = fam
        if family == "Numeric":
            number = request_number(value)
            if not isinstance(number, Fraction):
                return None  # _numeric decides invalid values; other spellings are not modelled
            limits = [b for b in (parse_number(v) for v in values) if isinstance(b, Fraction)]
            return any(_COMPARE[comparison](number, b) for b in limits)
        moment = parse_time(value)
        if moment is None:
            return None
        bounds = [b for b in (parse_time(v) for v in values) if b is not None]  # _modelled already rejected None
        return any(_COMPARE[comparison](moment, b) for b in bounds)
    address = parse_ip(value)
    if address is None:
        return None
    is_v4, number = address
    networks = [n for n in (parse_ip_network(v) for v in values) if n is not None]
    return any(v4 == is_v4 and (number & mask) == net for v4, net, mask in networks)


def _set_condition(cond: Condition, req: Request, base: str, if_exists: bool) -> Tri:
    """ForAnyValue / ForAllValues: the operator applied to each request value; an absent key is the empty set."""
    qualifier, inner = base.split(":", 1)
    k = cond.key.lower()
    kind = "ip" if k in IP_KEYS else "time" if k in TIME_KEYS else "string"
    if qualifier not in ("ForAnyValue", "ForAllValues") or if_exists or inner == "Bool" or inner not in _STRINGISH:
        return None
    if not _modelled(inner, kind, cond.values):
        return None
    raw = req.context.get(k)
    elements = [] if raw is None else [raw] if isinstance(raw, str) else list(raw)
    hits: list[Tri] = []
    for e in elements:
        hit = _hit(inner, e, cond.values)
        hits.append(_not(hit) if "Not" in inner else hit)
    return _or(hits) if qualifier == "ForAnyValue" else _and(hits)


def _numeric(base: str, if_exists: bool, value: ContextValue, values: tuple[str, ...]) -> Tri:
    """Numeric operators as measured (finding 9): an invalid request value is false whatever the operator."""
    negated = "Not" in base
    if value is None:
        return True if negated else if_exists
    if not isinstance(value, str):
        return None
    if request_number(value) is None:
        return False
    hit = _hit(base, value, values)
    return None if hit is None else (not hit if negated else hit)


def _condition(cond: Condition, req: Request, variables: bool) -> Tri:
    op = cond.operator
    if_exists = op.endswith("IfExists")
    base = op[: -len("IfExists")] if if_exists else op
    if (variables and any("${" in v for v in cond.values)) or not cond.values:
        return None
    if ":" in base:
        return _set_condition(cond, req, base, if_exists)

    k = cond.key.lower()
    kind = "ip" if k in IP_KEYS else "time" if k in TIME_KEYS else "string"
    value = req.context.get(k)
    if base == "Null":
        return any((value is None) == (v.lower() == "true") for v in cond.values)
    if base.startswith("Numeric") and kind == "string" and not is_multivalued(k) and _modelled(base, kind, cond.values):
        return _numeric(base, if_exists, value, cond.values)
    if base in ("IpAddress", "NotIpAddress") and kind == "ip" and value is None:
        return True if "Not" in base else if_exists  # decided before AWS parses the networks
    if is_multivalued(k) or not _modelled(base, kind, cond.values):
        return None
    if value is None:
        return True if "Not" in base else if_exists
    if not isinstance(value, str):
        return None  # several values for a key this model treats as single-valued
    hit = _hit(base, value, cond.values)
    if hit is None:
        return None
    return not hit if "Not" in base else hit


def _statement(original: Statement, req: Request) -> Tri:
    # Every value is known here (a missing key is absent), so variables bind to plain text.
    resolved = resolve_statement(original, req.context.get)
    stmt = resolved.statement
    if stmt is None:
        return False
    # Nothing is symbolic here: the lookup above never answers FREE.
    action = any(_glob(a, ignore_case=True).fullmatch(req.action) for a in stmt.actions) != stmt.not_actions
    matched = any(_arn(r).fullmatch(req.resource) for r in stmt.resources)
    undecided: Tri = None if resolved.undecided_resources else False  # whether an undecided entry matches
    resource = _not(_or([matched, undecided])) if stmt.not_resources else _or([matched, undecided])
    if not action or resource is False:
        return False
    conditions = [_condition(c, req, stmt.variables) for c in stmt.conditions]
    return _and([resource, *conditions, *(None for _ in resolved.undecided_conditions)])


def _allows(policies: list[Policy], req: Request) -> Tri:
    return _or(_statement(s, req) for p in policies for s in p.statements if s.effect == "Allow")


def _denies(policies: list[Policy], req: Request) -> Tri:
    return _or(_statement(s, req) for p in policies for s in p.statements if s.effect == "Deny")


def _request(
    principal: Principal, action: str, resource: str, context: dict[str, ContextValue], env: Environment
) -> Request:
    # Principal-derived keys first, so explicitly pinned keys override them, as in the engine.
    full: dict[str, ContextValue] = {
        "aws:PrincipalArn": principal.arn,
        "aws:PrincipalAccount": principal.account,
        "aws:PrincipalType": principal_type(principal.arn),
        # Reach's principals are IAM users and role sessions, never AWS service principals.
        "aws:PrincipalIsAWSService": "false",
        "aws:username": username(principal.arn),
    }
    full.update({f"aws:PrincipalTag/{k}": v for k, v in principal.tags.items()})
    full.update(env.org_context)
    full.update(context)
    return Request(action, resource, full)


def evaluate(
    principal: Principal,
    action: str,
    resource: str,
    context: dict[str, ContextValue],
    env: Environment | None = None,
    resource_policy: ResourcePolicy | None = None,
) -> Tri:
    """The request's decision: True (allowed), False (denied) or None (depends on something not modelled).

    A key missing from `context` is absent.
    """
    env = env or Environment()
    req = _request(principal, action, resource, context, env)

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
    if env.rcps and not principal.is_service_linked:
        service = action.split(":", 1)[0].lower()
        if service in RCP_SERVICES and action.lower() not in RCP_EXEMPT_ACTIONS:
            rcp = _or(
                _statement(st, req)
                for p in env.rcps
                for st in p.statements
                if st.effect == "Deny" and classify(st, principal.arn)
            )
            # AWS managed KMS keys are exempt, and an ARN does not say which keys those are.
            denied = _or([denied, _and([rcp, None]) if service == "kms" else rcp])

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


def grants(
    principal: Principal,
    action: str,
    resource: str,
    context: dict[str, ContextValue],
    env: Environment | None = None,
    resource_policy: ResourcePolicy | None = None,
) -> list[str]:
    """The Allow statements that match this exact request, as "policy / Sid": what a witness is allowed by.

    Identity policies first, then the resource policy's statements that name this principal. Only statements
    that match outright are listed; one whose conditions Reach does not model is not.
    """
    req = _request(principal, action, resource, context, env or Environment())
    candidates = [st for p in principal.identity_policies for st in p.statements if st.effect == "Allow"]
    if resource_policy is not None:
        candidates += [
            st for st in resource_policy.policy.statements if st.effect == "Allow" and classify(st, principal.arn)
        ]
    out = []
    for st in candidates:
        if _statement(st, req) is True:
            label = f"{st.source} / {st.sid}" if st.sid else st.source
            if label not in out:
                out.append(label)
    return out
