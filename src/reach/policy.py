"""Parsing and normalisation of AWS IAM policy documents.

Everything downstream works on these frozen dataclasses, never on raw
JSON, so the quirks of the policy grammar (string-or-list values,
Action vs NotAction, boolean condition values, URL-encoded documents
from the IAM API) are handled exactly once, here.
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass
from typing import Any


class PolicyError(ValueError):
    """A policy document is malformed or uses a grammar we do not accept."""


@dataclass(frozen=True)
class Condition:
    operator: str  # e.g. "StringEquals", "ArnLikeIfExists", "ForAnyValue:StringLike"
    key: str  # condition key as written, e.g. "aws:MultiFactorAuthPresent"
    values: tuple[str, ...]


@dataclass(frozen=True)
class Statement:
    effect: str  # "Allow" or "Deny"
    actions: tuple[str, ...]
    not_actions: bool
    resources: tuple[str, ...]
    not_resources: bool
    conditions: tuple[Condition, ...]
    sid: str | None
    source: str  # policy name the statement came from, for explanations
    # Resource-based policies only: ((type, value), ...), e.g. (("AWS", "arn:..."),)
    # or (("*", "*"),). None when the statement has no Principal element.
    principals: tuple[tuple[str, str], ...] | None = None
    not_principal: bool = False
    # Policy variables (${aws:username}, ...) are substituted only under Version 2012-10-17;
    # in older or versionless policies they are literal text.
    variables: bool = False

    @property
    def label(self) -> str:
        return f"{self.source}#{self.sid}" if self.sid else self.source


@dataclass(frozen=True)
class Policy:
    name: str
    statements: tuple[Statement, ...]


def _as_tuple(value: Any, field: str, where: str) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        return tuple(value)
    raise PolicyError(f"{where}: {field} must be a string or a non-empty list of strings")


def _condition_value(value: Any) -> str:
    # The IAM grammar allows JSON booleans and numbers as condition values;
    # the request context always carries them as strings.
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    raise PolicyError(f"unsupported condition value {value!r}")


def _parse_conditions(raw: Any, where: str) -> tuple[Condition, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: Condition must be an object")
    out = []
    for operator, block in raw.items():
        if not isinstance(block, dict):
            raise PolicyError(f"{where}: Condition operator {operator} must map keys to values")
        for key, values in block.items():
            vals = values if isinstance(values, list) else [values]
            out.append(Condition(operator, key, tuple(_condition_value(v) for v in vals)))
    return tuple(out)


def _pick(stmt: dict[str, Any], positive: str, negative: str, where: str, default: Any = None):
    if positive in stmt and negative in stmt:
        raise PolicyError(f"{where}: cannot have both {positive} and {negative}")
    if positive in stmt:
        return _as_tuple(stmt[positive], positive, where), False
    if negative in stmt:
        return _as_tuple(stmt[negative], negative, where), True
    if default is not None:
        return default, False
    raise PolicyError(f"{where}: missing {positive} or {negative}")


def _parse_principals(stmt: dict[str, Any], where: str) -> tuple[tuple[tuple[str, str], ...] | None, bool]:
    if "Principal" in stmt and "NotPrincipal" in stmt:
        raise PolicyError(f"{where}: cannot have both Principal and NotPrincipal")
    negated = "NotPrincipal" in stmt
    raw = stmt.get("NotPrincipal" if negated else "Principal")
    if raw is None:
        return None, False
    if raw == "*":
        return (("*", "*"),), negated
    if not isinstance(raw, dict) or not raw:
        raise PolicyError(f'{where}: Principal must be "*" or an object such as {{"AWS": ...}}')
    out = []
    for kind, values in raw.items():
        for value in _as_tuple(values, f"Principal.{kind}", where):
            out.append((kind, value))
    return tuple(out), negated


def parse_statement(stmt: Any, source: str, index: int, variables: bool = False) -> Statement:
    where = f"{source} statement {index}"
    if not isinstance(stmt, dict):
        raise PolicyError(f"{where}: statement must be an object")
    effect = stmt.get("Effect")
    if effect not in ("Allow", "Deny"):
        raise PolicyError(f"{where}: Effect must be Allow or Deny, got {effect!r}")
    actions, not_actions = _pick(stmt, "Action", "NotAction", where)
    # SCPs written before AWS adopted the full IAM grammar for them may omit
    # Resource; it then means every resource.
    resources, not_resources = _pick(stmt, "Resource", "NotResource", where, default=("*",))
    sid = stmt.get("Sid")
    principals, not_principal = _parse_principals(stmt, where)
    return Statement(
        effect=effect,
        actions=actions,
        not_actions=not_actions,
        resources=resources,
        not_resources=not_resources,
        conditions=_parse_conditions(stmt.get("Condition"), where),
        sid=sid if isinstance(sid, str) and sid else None,
        source=source,
        principals=principals,
        not_principal=not_principal,
        variables=variables,
    )


def decode_document(doc: Any) -> dict[str, Any]:
    """Accept a policy as a dict, a JSON string, or the URL-encoded JSON the raw IAM API returns."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        for candidate in (doc, urllib.parse.unquote(doc)):
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
    raise PolicyError("policy document is not a JSON object")


def parse_policy(doc: Any, name: str) -> Policy:
    body = decode_document(doc)
    raw = body.get("Statement")
    if raw is None:
        raise PolicyError(f"{name}: policy has no Statement")
    statements = raw if isinstance(raw, list) else [raw]
    variables = body.get("Version") == "2012-10-17"
    return Policy(name, tuple(parse_statement(s, name, i, variables) for i, s in enumerate(statements)))


def load_policy_file(path: str, name: str | None = None) -> Policy:
    with open(path, encoding="utf-8") as fh:
        return parse_policy(json.load(fh), name or path)
