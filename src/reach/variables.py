"""IAM policy variables: `${aws:username}`, `${aws:PrincipalTag/team, 'default'}`, `${*}`.

AWS substitutes a variable with the value of a request-context key before it
matches a statement (IAM User Guide, "Policy variables"). The rules modelled:

* Variables apply only in policies whose Version is 2012-10-17. In older or
  versionless policies `${...}` is literal text.
* They appear in the resource part of Resource/NotResource ARNs (after the
  fifth colon) and in the values of String and ARN conditions.
* A key with no value makes the variable "effectively null": a resource entry
  containing it matches no resource, and a condition value containing it
  equals nothing (so positive operators do not match on it and negated ones
  do). A default, `${key, 'text'}`, replaces a missing value.
* `${*}`, `${?}` and `${$}` are a literal `*`, `?` and `$`.

Binding a pattern turns it into tokens: literal text, or a `Var` whose value
the request decides. The engine encodes such a `Var` symbolically, with the
key's own solver variable, so the verdict stays exact. The reference
evaluator always knows every value, so its patterns bind to plain text. Both
share `resolve_statement`, so they agree on substitution by construction.

A few uses are left undecided (raised as Unresolved, made opaque by the
engine and None by the reference evaluator), by one shared rule: variables
before the fifth colon of an ARN (AWS does not substitute there), over IP,
time or multi-valued keys, and free variables inside ARN condition operators.

Literal `*` and `?` from `${*}`/`${?}` travel as private-use characters
(LITERAL_STAR, LITERAL_QUESTION) so glob matching keeps them literal;
`literal()` turns them back into the real characters.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, replace

from .conditions import MULTIVALUED_KEYS, is_negated
from .policy import Condition, Statement
from .values import IP_KEYS, TIME_KEYS

LITERAL_STAR, LITERAL_QUESTION = "", ""
_ESCAPES = {"*": LITERAL_STAR, "?": LITERAL_QUESTION, "$": "$"}

# ${name} or ${name, 'default'}; names never contain '}' or ','.
_VARIABLE = re.compile(r"\$\{\s*([^},']+?)\s*(?:,\s*'([^']*)'\s*)?\}")

FREE = object()  # lookup result: the request decides the key's value
Lookup = Callable[[str], object]  # lowercased key -> str value, None (absent) or FREE


@dataclass(frozen=True)
class Var:
    """A variable whose value the request decides. `default` replaces a missing key; None makes it null."""

    key: str  # lowercased
    default: str | None
    name: str = ""  # as written in the policy, for witnesses


Token = str | Var
Pattern = tuple[Token, ...]


class Unresolved(Exception):
    """A variable this model leaves undecided (see the module docstring)."""


def literal(text: str) -> str:
    return text.replace(LITERAL_STAR, "*").replace(LITERAL_QUESTION, "?")


def _as_data(value: str) -> str:
    """A substituted value is data, never a pattern: its own wildcards are literal."""
    return value.replace("*", LITERAL_STAR).replace("?", LITERAL_QUESTION)


def _undecidable(key: str) -> bool:
    return key in MULTIVALUED_KEYS or key in IP_KEYS or key in TIME_KEYS


def bind(text: str, lookup: Lookup) -> Pattern | None:
    """Tokens for `text` with every known variable substituted; None if a variable is null.

    Adjacent literal text is merged, so a pattern without free variables is a single string.
    """
    tokens: list[Token] = []
    pos = 0
    null = False

    def emit(t: Token) -> None:
        if isinstance(t, str):
            if not t:
                return
            if tokens and isinstance(tokens[-1], str):
                tokens[-1] += t
                return
        tokens.append(t)

    for m in _VARIABLE.finditer(text):
        emit(text[pos : m.start()])
        pos = m.end()
        name, default = m.group(1), m.group(2)
        if name in _ESCAPES and default is None:
            emit(_ESCAPES[name])
            continue
        key = name.lower()
        if _undecidable(key):
            raise Unresolved(key)
        value = lookup(key)
        if value is FREE:
            emit(Var(key, None if default is None else _as_data(default), name))
        elif value is None:
            if default is None:
                null = True
            else:
                emit(_as_data(default))
        elif isinstance(value, str):
            emit(_as_data(value))
        else:
            raise TypeError(f"lookup returned {value!r} for {key}")
    emit(text[pos:])
    return None if null else tuple(tokens)


def bind_resource(text: str, lookup: Lookup) -> Pattern | None:
    """Like bind, for a Resource entry: AWS substitutes only after the fifth colon."""
    if "${" in text:
        parts = text.split(":", 5)
        if len(parts) < 6 or any("${" in p for p in parts[:5]):
            raise Unresolved(text)
    return bind(text, lookup)


def plain(pattern: Pattern) -> str | None:
    """The pattern as text when it has no free variable, else None."""
    if all(isinstance(t, str) for t in pattern):
        return "".join(t for t in pattern if isinstance(t, str))
    return None


@dataclass(frozen=True)
class SymbolicCondition:
    """A String condition whose values contain free variables (engine only)."""

    operator: str
    key: str
    values: tuple[Pattern, ...]


@dataclass(frozen=True)
class Resolved:
    """A statement after substitution.

    `statement` is None when the statement can never match (every Resource
    entry is null, or a positive condition has only null values). Its
    resources and conditions are the entries without free variables;
    `symbolic_resources` and `symbolic_conditions` hold those with them;
    `undecided_resources` and `undecided_conditions` are what the model
    leaves open.
    """

    statement: Statement | None
    symbolic_resources: tuple[Pattern, ...] = ()
    symbolic_conditions: tuple[SymbolicCondition, ...] = ()
    undecided_resources: tuple[str, ...] = ()
    undecided_conditions: tuple[Condition, ...] = ()


_VARIABLE_OPS = ("String", "Arn")  # the only operator families that take variables


def _resolve_condition(cond: Condition, lookup: Lookup) -> Condition | SymbolicCondition | bool | None:
    """The condition after substitution; True/False when decided outright; None when undecided."""
    base = cond.operator.removesuffix("IfExists")
    if not any("${" in v for v in cond.values) or not base.startswith(_VARIABLE_OPS) or ":" in base:
        return cond  # other operators take values literally; set operators stay opaque downstream
    patterns: list[Pattern] = []
    try:
        for v in cond.values:
            bound = bind(v, lookup)
            if bound is not None:
                patterns.append(bound)
    except Unresolved:
        return None
    texts = [plain(p) for p in patterns]
    if any(t is None for t in texts):
        if base.startswith("Arn"):
            return None  # ARN matching is segment-wise; free variables there are left undecided
        return SymbolicCondition(cond.operator, cond.key, tuple(patterns))
    if patterns:
        return replace(cond, values=tuple(t for t in texts if t is not None))
    # Every value is null: nothing equals or is like it.
    if is_negated(base):
        return True
    if cond.operator.endswith("IfExists"):
        return Condition("Null", cond.key, ("true",))  # matches only when the key itself is absent
    return False


def resolve_statement(stmt: Statement, lookup: Lookup) -> Resolved:
    if not stmt.variables:
        return Resolved(stmt)
    resources: list[str] = []
    symbolic: list[Pattern] = []
    undecided: list[str] = []
    for r in stmt.resources:
        try:
            bound = bind_resource(r, lookup)
        except Unresolved:
            undecided.append(r)
            continue
        if bound is None:
            continue  # null: this entry matches no resource
        text = plain(bound)
        if text is None:
            symbolic.append(bound)
        else:
            resources.append(text)
    if not (resources or symbolic or undecided or stmt.not_resources):
        return Resolved(None)
    conditions: list[Condition] = []
    symbolic_conditions: list[SymbolicCondition] = []
    undecided_conditions: list[Condition] = []
    for cond in stmt.conditions:
        outcome = _resolve_condition(cond, lookup)
        if outcome is None:
            undecided_conditions.append(cond)
        elif outcome is False:
            return Resolved(None)
        elif isinstance(outcome, SymbolicCondition):
            symbolic_conditions.append(outcome)
        elif isinstance(outcome, Condition):
            conditions.append(outcome)
    return Resolved(
        replace(stmt, resources=tuple(resources), conditions=tuple(conditions)),
        tuple(symbolic),
        tuple(symbolic_conditions),
        tuple(undecided),
        tuple(undecided_conditions),
    )
