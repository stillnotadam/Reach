"""The catalogue of real IAM actions.

Without it, the solver treats the action as an arbitrary string: a query
for `s3:*` could be "allowed" through an action called `s3:O` that does
not exist. With it, wildcard queries range over real actions only, and
witnesses always name an action AWS would actually evaluate.

Verdicts on wildcard queries are therefore relative to the catalogue's
snapshot date; build a fresh one with scripts/build_catalog.py.
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


@dataclass(frozen=True)
class Catalog:
    actions: tuple[str, ...]  # canonical case, e.g. "s3:GetObject"
    generated: str = "unknown"
    source: str = "unknown"
    _by_lower: dict[str, str] = field(default_factory=dict, compare=False, repr=False)

    def __post_init__(self) -> None:
        self._by_lower.update({a.lower(): a for a in self.actions})

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
        return cls(tuple(data["actions"]), data.get("generated", "unknown"), data.get("source", "unknown"))


@lru_cache(maxsize=1)
def bundled() -> Catalog | None:
    return Catalog.load(BUNDLED) if BUNDLED.exists() else None
