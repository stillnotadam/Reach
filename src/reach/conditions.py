"""Symbolic request context and the encoding of IAM Condition blocks.

Every condition key the policies mention gets one presence flag, shared by
every operator that looks at it, plus a value of the key's sort: a string,
a 128-bit IP bitvector (IP keys) or epoch seconds (time keys; see values.py).
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

import operator
from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache

import z3

from .patterns import arn_glob, glob, has_wildcard, literal_re, sval
from .policy import Condition, Statement
from .values import (
    ALWAYS_PRESENT_KEYS,
    ALWAYS_PRESENT_TIME_GROUPS,
    BOOLEAN_KEYS,
    IP_BITS,
    IP_KEYS,
    MAX_EPOCH,
    TIME_KEYS,
    UNMODELLED,
    decimal_places,
    ignore_case_classes,
    parse_bool,
    parse_ip,
    parse_ip_network,
    parse_number,
    parse_time,
    request_number,
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
    "StringEqualsIgnoreCase": "ieq",
    "StringNotEquals": "eq",
    "StringNotEqualsIgnoreCase": "ieq",
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


@lru_cache(maxsize=1)
def _catalogue_multivalued() -> frozenset[str]:
    from .catalog import bundled  # noqa: PLC0415 - deferred: the catalogue is large and optional

    catalog = bundled()
    return catalog.multivalued_keys if catalog is not None else frozenset()


def is_multivalued(key: str) -> bool:
    """Is the key's request value a set? Global keys from the IAM docs, service keys from AWS's reference data."""
    k = key.lower()
    return k in MULTIVALUED_KEYS or k in _catalogue_multivalued()


def key_kind(key: str) -> str:
    k = key.lower()
    if k in IP_KEYS:
        return "ip"
    if k in TIME_KEYS:
        return "time"
    return "set" if is_multivalued(k) else "string"


_FREE = object()
ContextValue = str | list[str] | None  # a list only for multi-valued keys; None = absent


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

    def __init__(
        self,
        fixed: dict[str, ContextValue] | None = None,
        closed_prefixes: tuple[str, ...] = (),
        set_bounds: dict[str, int] | None = None,
    ):
        # fixed: key -> value (a list for a multi-valued key), or None to pin the key as absent.
        self.fixed = {k.lower(): v for k, v in (fixed or {}).items()}
        # Multi-valued keys: how many elements a request's set needs at most (see set_bound in engine.py).
        self.set_bounds = {k.lower(): n for k, n in (set_bounds or {}).items()}
        self.sets: dict[str, list[tuple[z3.BoolRef, z3.SeqRef]]] = {}  # key -> (active, value) slots
        # Keys under these prefixes are absent unless listed in `fixed`
        # (e.g. aws:principaltag/ once we know all of the principal's tags).
        self.closed_prefixes = tuple(p.lower() for p in closed_prefixes)
        self.keys: dict[str, FreeKey] = {}  # free keys referenced by modelled conditions
        self.presence: dict[str, z3.BoolRef] = {}  # by slot: the key, or its time group
        self.strings: dict[str, z3.SeqRef] = {}
        self.ips: dict[str, tuple[z3.BoolRef, z3.BitVecRef]] = {}
        self.times: dict[str, z3.ArithRef] = {}  # by time group
        self.numbers: dict[str, tuple[z3.BoolRef, z3.SeqRef, z3.SeqRef]] = {}  # see number_parts
        self.opaques: list[Opaque] = []
        # Facts about real requests (e.g. Bool keys only ever hold "true" or
        # "false"). They narrow the search to requests AWS can actually send.
        self.domain: list[z3.BoolRef] = []
        self._restricted: set[str] = set()

    # --- fixed values ---------------------------------------------------------

    def _fixed(self, k: str):
        """The pinned value of key k: a string (a list for a multi-valued key), None for absent, or _FREE."""
        if isinstance(self.fixed.get(k), list) and key_kind(k) != "set":
            values = self.fixed[k]
            if not isinstance(values, list) or len(values) > 1:
                raise ValueError(f"{k} is single-valued, but several values were given: {values!r}")
            self.fixed[k] = values[0] if values else None
        if k in TIME_KEYS:
            group = TIME_KEYS[k][0]
            pinned = {kk: v for kk, v in self.fixed.items() if kk in TIME_KEYS and TIME_KEYS[kk][0] == group}
            if not pinned:
                return _FREE
            parsed = set()
            for kk, v in pinned.items():
                epoch = None if v is None else parse_time(v) if isinstance(v, str) else None
                if v is not None and epoch is None:
                    raise ValueError(f"cannot parse {kk} value {v!r} as a time")
                parsed.add(epoch)
            if len(parsed) > 1:
                raise ValueError(f"inconsistent values pinned for the same instant: {pinned}")
            epoch = parsed.pop()
            return None if epoch is None else str(epoch)
        if k in self.fixed:
            v = self.fixed[k]
            if isinstance(v, str) and k in IP_KEYS and parse_ip(v) is None:
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
        elif kind == "set":
            size = self.set_bounds.get(k, 1)
            slots = [(z3.Bool(f"member_{n}_{i}"), z3.String(f"element_{n}_{i}")) for i in range(size)]
            self.sets[k] = slots
            # A set with no elements is the key being absent, as in AWS.
            self.domain.append(self.presence[slot] == z3.Or([a for a, _ in slots]))
        elif kind == "ip":
            is_v4, address = z3.Bool(f"ipv4_{n}"), z3.BitVec(f"ip_{n}", IP_BITS)
            self.ips[k] = (is_v4, address)
            high = z3.Extract(IP_BITS - 1, 32, address)
            # An IPv4 address lives in the low 32 bits; an IPv6 source is never IPv4-mapped (values.py).
            self.domain.append(z3.If(is_v4, high == 0, high != 0xFFFF))
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
            return z3.BoolVal(v is not None and v != [])
        return self.presence[self._ensure(name)]

    def elements(self, name: str) -> list[tuple[z3.BoolRef, z3.SeqRef]]:
        """The request's values for the key, as (is a member, value) pairs.

        A single-valued key is a set of at most one element, sharing the key's own variable, which is how
        AWS evaluates ForAllValues/ForAnyValue on it.
        """
        k = name.lower()
        if key_kind(k) == "string":
            return [(self.present(name), self.string(name))]
        v = self._fixed(k)
        if v is not _FREE:
            values = [] if v is None else [v] if isinstance(v, str) else list(v)
            return [(z3.BoolVal(True), sval(x)) for x in values]
        self._ensure(name)
        return self.sets[k]

    def number_parts(self, name: str) -> tuple[z3.BoolRef, z3.SeqRef, z3.SeqRef]:
        """A free key read as a plain decimal: (negative, whole digits, fraction digits). They are tied to the
        key's string only when that string is a plain decimal, which fixes them uniquely (one sign, one point)."""
        k = name.lower()
        if k not in self.numbers:
            value, n = self.string(name), len(self.numbers)
            neg, whole, frac = z3.Bool(f"num_neg_{n}"), z3.String(f"num_whole_{n}"), z3.String(f"num_frac_{n}")
            point = z3.If(z3.Length(frac) == 0, sval(""), z3.Concat(sval("."), frac))
            digit = z3.Range("0", "9")
            self.domain.append(z3.Implies(z3.InRe(value, _number_res()[1]), z3.And(
                value == z3.Concat(z3.If(neg, sval("-"), sval("")), whole, point),
                z3.InRe(whole, z3.Plus(digit)), z3.InRe(frac, z3.Star(digit)),
            )))  # fmt: skip
            self.numbers[k] = (neg, whole, frac)
        return self.numbers[k]

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
            return z3.BoolVal(is_v4), z3.BitVecVal(value, IP_BITS)
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


_TRUE_ANY_CASE = z3.Concat(*(z3.Union(z3.Re(c), z3.Re(c.upper())) for c in "true"))


def _string_match(kind: str, value: z3.SeqRef, values: tuple[str, ...]) -> z3.BoolRef:
    terms = []
    for v in values:
        if kind == "eq":
            terms.append(value == sval(v))
        elif kind == "ieq":
            # Equal lowercase forms (finding 8): each character, in any case that lowercases to it.
            classes = ignore_case_classes(_text(v)) or []
            terms.append(z3.InRe(value, _concat_re([z3.Union(*(literal_re(m) for m in c)) for c in classes])))
        elif kind == "bool":
            # Both sides are read as booleans: "true" in any case, or anything else (finding 6).
            is_true = z3.InRe(value, _TRUE_ANY_CASE)
            terms.append(is_true if parse_bool(v) else z3.Not(is_true))
        elif kind == "like":
            terms.append(z3.InRe(value, glob(v)) if has_wildcard(v) else value == sval(v))
        else:  # arn
            terms.append(z3.InRe(value, arn_glob(v)) if has_wildcard(v) else value == sval(v))
    return _any(terms)


def _text(value: str) -> str:
    """A condition value as plain text: ${*} and ${?} arrive as private-use markers (see variables.py)."""
    return value.replace("", "*").replace("", "?")


def _latin_1(values: tuple[str, ...]) -> bool:
    return all(ignore_case_classes(_text(v)) is not None for v in values)


def _concat_re(parts: list[z3.ReRef]) -> z3.ReRef:
    if not parts:
        return z3.Re("")
    return z3.Concat(*parts) if len(parts) > 1 else parts[0]


def wrap_presence(base: str, if_exists: bool, present: z3.BoolRef, matched: z3.BoolRef) -> z3.BoolRef:
    """Combine "the value matches" with presence, per the operator's polarity."""
    if is_negated(base):
        return z3.Or(z3.Not(present), z3.Not(matched))
    # A missing key never satisfies a positive operator, unless IfExists.
    return z3.Or(z3.Not(present), matched) if if_exists else z3.And(present, matched)


@lru_cache(maxsize=1)
def _number_res() -> tuple[z3.ReRef, z3.ReRef]:
    """(maybe a number, a plain decimal) as Z3 regexes; mirror values.LOOSE_NUMBER and CANONICAL_NUMBER.
    Z3's characters stop at U+2FFFF, so "any non-ASCII character" is that range."""
    ascii_digit = z3.Range("0", "9")
    d = z3.Union(ascii_digit, z3.Range("\u0080", "\U0002ffff"))
    sign = z3.Option(z3.Union(z3.Re("+"), z3.Re("-")))
    mantissa = z3.Union(z3.Concat(z3.Plus(d), z3.Option(z3.Concat(z3.Re("."), z3.Star(d)))),
                        z3.Concat(z3.Re("."), z3.Plus(d)))  # fmt: skip
    exponent = z3.Option(z3.Concat(z3.Union(z3.Re("e"), z3.Re("E")), sign, z3.Plus(d)))
    plain = z3.Concat(z3.Option(z3.Re("-")), z3.Plus(ascii_digit),
                      z3.Option(z3.Concat(z3.Re("."), z3.Plus(ascii_digit))))  # fmt: skip
    return z3.Concat(sign, mantissa, exponent), plain


def _scaled(parts: tuple[z3.BoolRef, z3.SeqRef, z3.SeqRef], places: int) -> tuple[z3.BoolRef, z3.ArithRef, z3.BoolRef]:
    """A plain decimal, from its parts (Context.number_parts), on a grid of 10**-places: (negative, signed value
    * 10**places truncated toward zero, whether nonzero digits were cut off). Linear integer arithmetic over the
    digit strings, so Z3 decides it without searching for where the point is."""
    neg, whole, frac = parts
    head = z3.SubString(frac, 0, places)  # Z3 clamps a substring that runs past the end
    digits = z3.StrToInt(z3.Concat(whole, head)) if places else z3.StrToInt(whole)
    magnitude: z3.ArithRef = digits
    for kept in range(places):  # pad a shorter fraction: "1.5" on a 0.01 grid is 150
        magnitude = z3.If(z3.Length(head) == kept, digits * 10 ** (places - kept), magnitude)
    rest = z3.SubString(frac, places, z3.Length(frac) - places) if places else frac
    cut = z3.Not(z3.InRe(rest, z3.Star(z3.Re("0"))))
    return neg, z3.If(neg, -magnitude, magnitude), cut


_PY_COMPARE = {"==": operator.eq, "<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge}


def _numeric_compare(op: str, scaled: tuple[z3.BoolRef, z3.ArithRef, z3.BoolRef], bound: int) -> z3.BoolRef:
    """value OP bound, exactly. The value lies strictly between its truncation and the next grid point (away from
    zero) when digits were cut off; the bound is a grid point, so a strict comparison with the truncation decides."""
    neg, s, cut = scaled
    eq = z3.And(s == bound, z3.Not(cut))
    lt = z3.If(z3.And(cut, neg), s <= bound, s < bound)
    gt = z3.If(z3.And(cut, z3.Not(neg)), s >= bound, s > bound)
    return {"==": eq, "<": lt, "<=": z3.Or(lt, eq), ">": gt, ">=": z3.Or(gt, eq)}[op]


def _encode_numeric(cond: Condition, ctx: Context, stmt: Statement, base: str, if_exists: bool) -> z3.BoolRef:
    """Numeric operators as AWS evaluates them (finding 9): exact decimals; an invalid request value makes the
    condition false in either polarity; invalid policy values never match; absent keys as for any operator."""
    parsed = [parse_number(v) for v in cond.values]
    if any(b is UNMODELLED for b in parsed):
        return ctx.opaque(stmt, f"number outside the model in {cond.operator} {cond.key}")
    bounds = [b for b in parsed if isinstance(b, Fraction)]
    places = max((decimal_places(b) for b in bounds), default=0)
    op = NUMERIC_OPS[base]
    present = ctx.present(cond.key)
    # Other valid spellings (+5, 1e1, Unicode digits) are left to an opaque, placed positively in either polarity.
    reason = f"number spelled other than as a plain decimal in {cond.operator} {cond.key}"
    pinned = ctx._fixed(cond.key.lower())
    if pinned is not _FREE:
        # A known value is read here, in Python: no string reasoning for the solver.
        number = request_number(pinned) if isinstance(pinned, str) else None
        if isinstance(number, Fraction):
            hit = any(_PY_COMPARE[op](number, b) for b in bounds)
            inner: z3.BoolRef = z3.BoolVal(hit != is_negated(base))
        else:
            inner = ctx.opaque(stmt, reason) if number is UNMODELLED else z3.BoolVal(False)
    else:
        value = ctx.string(cond.key)
        loose, plain = _number_res()
        if bounds:
            scaled = _scaled(ctx.number_parts(cond.key), places)
            matched: z3.BoolRef = _any([_numeric_compare(op, scaled, int(b * 10**places)) for b in bounds])
        else:
            matched = z3.BoolVal(False)
        decided = z3.Not(matched) if is_negated(base) else matched
        unknown = ctx.opaque(stmt, reason)
        inner = z3.If(z3.InRe(value, plain), decided, z3.If(z3.InRe(value, loose), unknown, z3.BoolVal(False)))
    if is_negated(base) or if_exists:
        return z3.Or(z3.Not(present), inner)
    return z3.And(present, inner)


def encode_condition(cond: Condition, ctx: Context, stmt: Statement) -> z3.BoolRef:
    op = cond.operator
    if_exists = op.endswith("IfExists")
    base = op[: -len("IfExists")] if if_exists else op
    kind = key_kind(cond.key)

    if stmt.variables and any("${" in v for v in cond.values):
        return ctx.opaque(stmt, f"policy variable in {op} {cond.key}")
    if not cond.values:
        return ctx.opaque(stmt, f"empty value list for {op} {cond.key}")
    if ":" in base:  # ForAnyValue: / ForAllValues: set operators
        return _encode_set(cond, ctx, stmt, base, if_exists, kind)
    if kind == "set" and base != "Null":
        return ctx.opaque(stmt, f"multi-valued key {cond.key} without ForAnyValue/ForAllValues")

    # Each family is only modelled on keys of its own sort. Checking before
    # touching the context means keys that appear solely in opaque
    # conditions never leak into witnesses.
    if base == "Null":
        terms = [z3.Not(ctx.present(cond.key)) if v.lower() == "true" else ctx.present(cond.key) for v in cond.values]
        return _any(terms)

    if STRING_OPS.get(base) == "ieq" and not _latin_1(cond.values):
        return ctx.opaque(stmt, f"{op} {cond.key} with text outside Latin-1, which IAM does not accept")

    if base in STRING_OPS and kind == "string":
        present, value = ctx.present(cond.key), ctx.string(cond.key)
        if base == "Bool" and cond.key.lower() in BOOLEAN_KEYS:
            # Real requests carry only "true" or "false" for these keys; other keys keep their full range.
            ctx.restrict(cond.key, ("true", "false"))
        return wrap_presence(base, if_exists, present, _string_match(STRING_OPS[base], value, cond.values))

    if base in NUMERIC_OPS and kind == "string":
        return _encode_numeric(cond, ctx, stmt, base, if_exists)

    if base in DATE_OPS and kind == "time":
        moments = [parse_time(v) for v in cond.values]
        if any(m is None for m in moments):
            return ctx.opaque(stmt, f"unparsable date in {op} {cond.key}")
        present, t = ctx.present(cond.key), ctx.time(cond.key)
        matched = _any([_compare(DATE_OPS[base], t, m) for m in moments if m is not None])
        return wrap_presence(base, if_exists, present, matched)

    if base in IP_OPS and kind == "ip":
        networks = [parse_ip_network(v) for v in cond.values]
        present = ctx.present(cond.key)
        if any(n is None for n in networks):
            # AWS looks at presence before it parses the values (measured: validation/FINDINGS.md, finding 7),
            # so only a present key depends on how AWS reads the value. The opaque stays positive either way.
            unknown = ctx.opaque(stmt, f"malformed or IPv4-mapped network in {op} {cond.key}")
            if is_negated(base) or if_exists:
                return z3.Or(z3.Not(present), unknown)
            return z3.And(present, unknown)
        is_v4, address = ctx.ip(cond.key)
        valid = [n for n in networks if n is not None]
        family = {True: is_v4, False: z3.Not(is_v4)}
        matched = _any([z3.And(family[v4], (address & mask) == net) for v4, net, mask in valid])
        return wrap_presence(base, if_exists, present, matched)

    return ctx.opaque(stmt, f"operator {op} on {cond.key} is not modelled yet")


def _encode_set(cond: Condition, ctx: Context, stmt: Statement, base: str, if_exists: bool, kind: str) -> z3.BoolRef:
    """ForAnyValue / ForAllValues: the operator applies to each request value in turn.

    ForAnyValue holds when some value matches (so never for an absent key); ForAllValues holds when every
    value matches (so always for an absent key: the documented over-permissive case).
    """
    qualifier, inner = base.split(":", 1)
    family = STRING_OPS.get(inner)
    if qualifier not in ("ForAnyValue", "ForAllValues") or if_exists or family in (None, "bool"):
        return ctx.opaque(stmt, f"set operator {cond.operator} on {cond.key}")
    if kind not in ("string", "set") or (family == "ieq" and not _latin_1(cond.values)):
        return ctx.opaque(stmt, f"set operator {cond.operator} on {cond.key}")
    hits = []
    for member, value in ctx.elements(cond.key):
        matched = _string_match(family, value, cond.values)
        hits.append((member, z3.Not(matched) if is_negated(inner) else matched))
    if qualifier == "ForAnyValue":
        return z3.Or([z3.And(m, h) for m, h in hits]) if hits else z3.BoolVal(False)
    return z3.And([z3.Implies(m, h) for m, h in hits]) if hits else z3.BoolVal(True)


def encode_conditions(stmt: Statement, ctx: Context) -> z3.BoolRef:
    if not stmt.conditions:
        return z3.BoolVal(True)
    terms = [encode_condition(c, ctx, stmt) for c in stmt.conditions]
    return z3.And(terms) if len(terms) > 1 else terms[0]
