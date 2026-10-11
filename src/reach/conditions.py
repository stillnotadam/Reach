"""Symbolic request context and the encoding of IAM Condition blocks.

Every condition key the policies mention gets one presence flag, shared by
every operator that looks at it, plus a value of the key's sort: a string,
an IPv4 bitvector (IP keys) or epoch seconds (time keys; see values.py).
Keys we know something about (the principal's ARN, its tags, values the
user pinned on the command line) are fixed instead.

Conditions we cannot model exactly are never guessed. Each one becomes a
fresh "opaque" boolean that the solver may set either way. Every opaque is
placed so that it occurs positively inside its statement's condition.
Allow conditions only ever appear positively in the authorization decision
and Deny conditions only negatively, so the engine can pin every opaque to
its worst case and tell a proven answer apart from one that depends on
something we did not model (see engine.decide).
"""

from __future__ import annotations

from dataclasses import dataclass

import z3

from .patterns import arn_glob, glob, has_wildcard, sval
from .policy import Condition, Statement
from .values import (
    ALWAYS_PRESENT_KEYS,
    ALWAYS_PRESENT_TIME_GROUPS,
    IP_KEYS,
    MAX_EPOCH,
    TIME_KEYS,
    parse_int,
    parse_ip,
    parse_ipv4_network,
    parse_time,
)

# Keys that carry several values per request. Single-valued operators on
# them have set semantics we do not model yet.
MULTIVALUED_KEYS = frozenset(
    k.lower()
    for k in (
        "aws:TagKeys",
        "aws:CalledVia",
        "aws:PrincipalServiceNamesList",
        "aws:PrincipalOrgPaths",
        "aws:ResourceOrgPaths",
    )
)

STRING_OPS = {
    "StringEquals": "eq",
    "StringLike": "like",
    "ArnEquals": "arn",
    "ArnLike": "arn",
    "Bool": "bool",
    "StringNotEquals": "eq",
    "StringNotLike": "like",
    "ArnNotEquals": "arn",
    "ArnNotLike": "arn",
}
COMPARISONS = {"Equals": "==", "NotEquals": "==", "LessThan": "<", "LessThanEquals": "<=",
               "GreaterThan": ">", "GreaterThanEquals": ">="}  # fmt: skip
NUMERIC_OPS = {f"Numeric{k}": v for k, v in COMPARISONS.items()}
DATE_OPS = {f"Date{k}": v for k, v in COMPARISONS.items()}
IP_OPS = frozenset({"IpAddress", "NotIpAddress"})


def is_negated(base: str) -> bool:
    """Negated operators are satisfied when the key is missing from the request."""
    return "Not" in base


def key_kind(key: str) -> str:
    k = key.lower()
    return "ip" if k in IP_KEYS else "time" if k in TIME_KEYS else "string"


_FREE = object()


@dataclass
class Opaque:
    var: z3.BoolRef
    effect: str  # effect of the statement it sits in
    reason: str
    statement: str


@dataclass
class FreeKey:
    name: str  # as first written in a policy
    kind: str  # "string" | "ip" | "time"


class Context:
    """The symbolic request context shared by every policy in one query."""

    def __init__(self, fixed: dict[str, str | None] | None = None, closed_prefixes: tuple[str, ...] = ()):
        # fixed: key -> value, or None to pin the key as absent.
        self.fixed = {k.lower(): v for k, v in (fixed or {}).items()}
        # Keys under these prefixes are absent unless listed in `fixed`
        # (e.g. aws:principaltag/ once we know all of the principal's tags).
        self.closed_prefixes = tuple(p.lower() for p in closed_prefixes)
        self.keys: dict[str, FreeKey] = {}  # free keys referenced by modelled conditions
        self.presence: dict[str, z3.BoolRef] = {}  # by slot: the key, or its time group
        self.strings: dict[str, z3.SeqRef] = {}
        self.ips: dict[str, tuple[z3.BoolRef, z3.BitVecRef]] = {}
        self.times: dict[str, z3.ArithRef] = {}  # by time group
        self.opaques: list[Opaque] = []
        # Facts about real requests (e.g. Bool keys only ever hold "true" or
        # "false"). They narrow the search to requests AWS can actually send.
        self.domain: list[z3.BoolRef] = []
        self._restricted: set[str] = set()

    # --- fixed values ---------------------------------------------------------

    def _fixed(self, k: str):
        """The pinned value of key k: a string, None for absent, or _FREE."""
        if k in TIME_KEYS:
            group = TIME_KEYS[k][0]
            pinned = {kk: v for kk, v in self.fixed.items() if kk in TIME_KEYS and TIME_KEYS[kk][0] == group}
            if not pinned:
                return _FREE
            parsed = set()
            for kk, v in pinned.items():
                epoch = None if v is None else parse_time(v)
                if v is not None and epoch is None:
                    raise ValueError(f"cannot parse {kk} value {v!r} as a time")
                parsed.add(epoch)
            if len(parsed) > 1:
                raise ValueError(f"inconsistent values pinned for the same instant: {pinned}")
            epoch = parsed.pop()
            return None if epoch is None else str(epoch)
        if k in self.fixed:
            v = self.fixed[k]
            if v is not None and k in IP_KEYS and parse_ip(v) is None:
                raise ValueError(f"cannot parse {k} value {v!r} as an IP address")
            return v
        if any(k.startswith(p) for p in self.closed_prefixes):
            return None
        return _FREE

    # --- free variables -------------------------------------------------------

    def _ensure(self, name: str) -> str:
        """Create the variables for a free key; return its presence slot."""
        k = name.lower()
        kind = key_kind(k)
        slot = TIME_KEYS[k][0] if kind == "time" else k
        if k not in self.keys:
            self.keys[k] = FreeKey(name, kind)
        if slot in self.presence:
            return slot
        n = len(self.presence)
        self.presence[slot] = z3.Bool(f"present_{n}")
        if kind == "string":
            self.strings[k] = z3.String(f"value_{n}")
            if k in ALWAYS_PRESENT_KEYS:
                self.domain.append(self.presence[slot])
        elif kind == "ip":
            self.ips[k] = (z3.Bool(f"ipv4_{n}"), z3.BitVec(f"ip_{n}", 32))
        else:
            t = z3.Int(f"time_{slot}")
            self.times[slot] = t
            self.domain.append(z3.And(t >= 0, t <= MAX_EPOCH))
            if slot in ALWAYS_PRESENT_TIME_GROUPS:
                self.domain.append(self.presence[slot])
        return slot

    def present(self, name: str) -> z3.BoolRef:
        v = self._fixed(name.lower())
        if v is not _FREE:
            return z3.BoolVal(v is not None)
        return self.presence[self._ensure(name)]

    def string(self, name: str) -> z3.SeqRef:
        v = self._fixed(name.lower())
        if v is not _FREE:
            return sval(v or "")
        self._ensure(name)
        return self.strings[name.lower()]

    def ip(self, name: str) -> tuple[z3.BoolRef, z3.BitVecRef]:
        v = self._fixed(name.lower())
        if v is not _FREE:
            parsed = parse_ip(v) if v is not None else None
            is_v4, value = parsed if parsed else (False, 0)
            return z3.BoolVal(is_v4), z3.BitVecVal(value, 32)
        self._ensure(name)
        return self.ips[name.lower()]

    def time(self, name: str) -> z3.ArithRef:
        v = self._fixed(name.lower())
        if v is not _FREE:
            return z3.IntVal(int(v) if v is not None else 0)
        return self.times[self._ensure(name)]

    def restrict(self, name: str, allowed: tuple[str, ...]) -> None:
        k = name.lower()
        if k in self._restricted or k not in self.strings:
            return
        self._restricted.add(k)
        value = self.strings[k]
        self.domain.append(z3.Implies(self.presence[k], z3.Or([value == sval(v) for v in allowed])))

    def opaque(self, stmt: Statement, reason: str) -> z3.BoolRef:
        return self.assumption(stmt.effect, reason, stmt.label)

    def assumption(self, effect: str, reason: str, where: str) -> z3.BoolRef:
        """A fresh opaque boolean. It must occur positively under an `effect` of that polarity."""
        var = z3.Bool(f"opaque_{len(self.opaques)}")
        self.opaques.append(Opaque(var, effect, reason, where))
        return var


def _compare(op: str, left: z3.ArithRef, right: int) -> z3.BoolRef:
    if op == "==":
        return left == right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    if op == ">":
        return left > right
    return left >= right


def _any(terms: list[z3.BoolRef]) -> z3.BoolRef:
    return z3.Or(terms) if len(terms) > 1 else terms[0]


def _string_match(kind: str, value: z3.SeqRef, values: tuple[str, ...]) -> z3.BoolRef:
    terms = []
    for v in values:
        if kind == "eq":
            terms.append(value == sval(v))
        elif kind == "bool":
            terms.append(value == sval(v.lower()))
        elif kind == "like":
            terms.append(z3.InRe(value, glob(v)) if has_wildcard(v) else value == sval(v))
        else:  # arn
            terms.append(z3.InRe(value, arn_glob(v)) if has_wildcard(v) else value == sval(v))
    return _any(terms)


def _wrap(base: str, if_exists: bool, present: z3.BoolRef, matched: z3.BoolRef) -> z3.BoolRef:
    """Combine "the value matches" with presence, per the operator's polarity."""
    if is_negated(base):
        return z3.Or(z3.Not(present), z3.Not(matched))
    # A missing key never satisfies a positive operator, unless IfExists.
    return z3.Or(z3.Not(present), matched) if if_exists else z3.And(present, matched)


def encode_condition(cond: Condition, ctx: Context, stmt: Statement) -> z3.BoolRef:
    op = cond.operator
    if_exists = op.endswith("IfExists")
    base = op[: -len("IfExists")] if if_exists else op
    kind = key_kind(cond.key)

    if ":" in base:  # ForAnyValue: / ForAllValues: set operators
        return ctx.opaque(stmt, f"set operator {op} on {cond.key}")
    if any("${" in v for v in cond.values):
        return ctx.opaque(stmt, f"policy variable in {op} {cond.key}")
    if cond.key.lower() in MULTIVALUED_KEYS:
        return ctx.opaque(stmt, f"multi-valued key {cond.key}")
    if not cond.values:
        return ctx.opaque(stmt, f"empty value list for {op} {cond.key}")

    # Each family is only modelled on keys of its own sort. Checking before
    # touching the context means keys that appear solely in opaque
    # conditions never leak into witnesses.
    if base == "Null":
        terms = [z3.Not(ctx.present(cond.key)) if v.lower() == "true" else ctx.present(cond.key) for v in cond.values]
        return _any(terms)

    if base in STRING_OPS and kind == "string":
        present, value = ctx.present(cond.key), ctx.string(cond.key)
        if base == "Bool":
            ctx.restrict(cond.key, ("true", "false"))
        return _wrap(base, if_exists, present, _string_match(STRING_OPS[base], value, cond.values))

    if base in NUMERIC_OPS and kind == "string":
        bounds = [parse_int(v) for v in cond.values]
        if any(b is None for b in bounds):
            return ctx.opaque(stmt, f"non-integer value in {op} {cond.key}")
        present, value = ctx.present(cond.key), ctx.string(cond.key)
        number = z3.StrToInt(value)
        matched = _any([_compare(NUMERIC_OPS[base], number, b) for b in bounds if b is not None])
        # Request values that are not plain digit strings are left to an
        # opaque, placed so it occurs positively in either polarity.
        digits = z3.InRe(value, z3.Plus(z3.Range("0", "9")))
        unknown = ctx.opaque(stmt, f"non-integer request value for {op} {cond.key}")
        if is_negated(base):
            return z3.Or(z3.Not(present), z3.If(digits, z3.Not(matched), unknown))
        inner = z3.If(digits, matched, unknown)
        return z3.Or(z3.Not(present), inner) if if_exists else z3.And(present, inner)

    if base in DATE_OPS and kind == "time":
        moments = [parse_time(v) for v in cond.values]
        if any(m is None for m in moments):
            return ctx.opaque(stmt, f"unparsable date in {op} {cond.key}")
        present, t = ctx.present(cond.key), ctx.time(cond.key)
        matched = _any([_compare(DATE_OPS[base], t, m) for m in moments if m is not None])
        return _wrap(base, if_exists, present, matched)

    if base in IP_OPS and kind == "ip":
        networks = [parse_ipv4_network(v) for v in cond.values]
        if any(n is None for n in networks):
            return ctx.opaque(stmt, f"IPv6 or malformed network in {op} {cond.key}")
        present = ctx.present(cond.key)
        is_v4, address = ctx.ip(cond.key)
        valid = [n for n in networks if n is not None]
        matched = z3.And(is_v4, _any([(address & mask) == net for net, mask in valid]))
        return _wrap(base, if_exists, present, matched)

    return ctx.opaque(stmt, f"operator {op} on {cond.key} is not modelled yet")


def encode_conditions(stmt: Statement, ctx: Context) -> z3.BoolRef:
    if not stmt.conditions:
        return z3.BoolVal(True)
    terms = [encode_condition(c, ctx, stmt) for c in stmt.conditions]
    return z3.And(terms) if len(terms) > 1 else terms[0]
