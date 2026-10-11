"""The catalogue of real IAM actions.

Without it, the solver treats the action as an arbitrary string: a query
for `s3:*` could be "allowed" through an action called `s3:O` that does
not exist. With it, wildcard queries range over real actions only, and
witnesses always name an action AWS would actually evaluate.

It also records, per action, the resource types it applies to (as ARN
globs) and the condition keys it supports. AWS's policy simulator showed
both matter: an action on a resource of the wrong type, or a
service-specific key on an action that does not support it, never occurs
in a real request (validation/FINDINGS.md, findings 2 and 3).

Every use of this data errs towards *more* possible requests, never fewer:
unknown actions and actions without resource types stay unconstrained,
and key placeholders match by prefix. A gap in the data can cost a
witness its realism, but can never fake a DENIED proof.

Verdicts on wildcard queries are relative to the catalogue's snapshot
date; build a fresh one with scripts/build_catalog.py.
"""

from __future__ import annotations

import gzip
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

BUNDLED = Path(__file__).parent / "data" / "actions.json.gz"


@lru_cache(maxsize=4096)
def iam_glob_regex(pattern: str) -> re.Pattern[str]:
    """IAM action glob as a Python regex: `*` and `?` only, case-insensitive."""
    body = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.compile(body, re.IGNORECASE | re.DOTALL)


_PLACEHOLDER = re.compile(r"\$\{[^}]*\}")


def format_glob(arn_format: str) -> str:
    """'arn:${Partition}:s3:::${BucketName}/${ObjectName}' -> 'arn:*:s3:::*/*'."""
    return _PLACEHOLDER.sub("*", arn_format)


def key_pattern(key: str) -> str:
    """A documented condition key as a case-insensitive glob.

    Keys with a per-request part ('aws:RequestTag/${TagKey}', 's3:ExistingObjectTag/<key>',
    'ec2:ResourceTag/tag-key') match anything under their prefix: the documented
    spellings of that part vary, and over-matching only ever widens the model.
    """
    if "/" in key:
        return key.split("/", 1)[0] + "/*"
    return key


@dataclass(frozen=True)
class Catalog:
    actions: tuple[str, ...]  # canonical case, e.g. "s3:GetObject"
    generated: str = "unknown"
    source: str = "unknown"
    # action (lower case) -> ARN globs of the resource types it applies to. Missing or empty: unconstrained.
    action_resources: dict[str, tuple[str, ...]] = field(default_factory=dict, compare=False, repr=False)
    # action (lower case) -> condition-key globs it supports. Missing: unknown, so unconstrained.
    action_keys: dict[str, tuple[str, ...]] = field(default_factory=dict, compare=False, repr=False)
    # Condition keys whose request value is a set (ArrayOfString, ArrayOfARN, ...), lower case.
    multivalued_keys: frozenset[str] = field(default_factory=frozenset, compare=False, repr=False)
    _by_lower: dict[str, str] = field(default_factory=dict, compare=False, repr=False)

    def __post_init__(self) -> None:
        self._by_lower.update({a.lower(): a for a in self.actions})

    def resource_globs(self, action: str) -> tuple[str, ...]:
        """ARN globs the action can apply to; empty means unconstrained."""
        return self.action_resources.get(action.lower(), ())

    def supports_key(self, action: str, key: str) -> bool:
        """Can a request for `action` carry the service-specific condition key `key`?"""
        patterns = self.action_keys.get(action.lower())
        if patterns is None:
            return True
        return any(iam_glob_regex(p).fullmatch(key) for p in patterns)

    def __contains__(self, action: str) -> bool:
        return action.lower() in self._by_lower

    def canonical(self, action: str) -> str:
        return self._by_lower.get(action.lower(), action)

    def matching(self, pattern: str) -> list[str]:
        rx = iam_glob_regex(pattern)
        return [a for a in self.actions if rx.fullmatch(a)]

    @classmethod
    def load(cls, path: str | Path) -> Catalog:
        path = Path(path)
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
        formats = data.get("resource_formats", {})
        action_resources = {
            action.lower(): tuple(sorted({format_glob(f) for r in types for f in formats.get(r, [])}))
            for action, types in data.get("action_resources", {}).items()
        }
        action_keys = {
            action.lower(): tuple(sorted({key_pattern(k) for k in keys}))
            for action, keys in data.get("action_keys", {}).items()
        }
        return cls(
            tuple(data["actions"]),
            data.get("generated", "unknown"),
            data.get("source", "unknown"),
            action_resources,
            action_keys,
            frozenset(k.lower() for k in data.get("multivalued_keys", [])),
        )


@lru_cache(maxsize=1)
def bundled() -> Catalog | None:
    return Catalog.load(BUNDLED) if BUNDLED.exists() else None
