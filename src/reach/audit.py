"""Account-wide audit: every principal in a snapshot against the high-impact questions.

`reach can` answers one question for one principal. An audit answers all of
them for everyone: each user and role in a `get-account-authorization-details`
snapshot is decided against the HIGH_IMPACT questions (or a custom list), with
the same guarantees as a single query: DENIED is a proof, ALLOWED comes with a
witness request, UNKNOWN names its assumptions.

Principals are independent, so the audit fans them out across worker
processes. Z3 objects cannot cross a process boundary, so each worker is
handed the snapshot and environment once (plain, picklable dataclasses) and
returns only verdicts and witnesses as plain data. One principal's failure
(an encoding error, a solver timeout) is recorded as an error row and never
stops the audit.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .blast import HIGH_IMPACT, decide_in_snapshot
from .engine import Environment, Verdict
from .loaders import AuthorizationDetails
from .reference import grants

Question = tuple[str, str, str]  # (label, action pattern, resource pattern)


@dataclass
class Answer:
    label: str
    action: str
    resource: str
    verdict: str  # "allowed" | "denied" | "unknown" | "error"
    witness: dict[str, Any] | None = None
    assumptions: list[str] = field(default_factory=list)
    error: str = ""
    grants: list[str] = field(default_factory=list)  # ALLOWED: the statements that allow the witness
    reasons: list[str] = field(default_factory=list)  # UNKNOWN: why it could not be decided


@dataclass
class Row:
    principal: str  # ARN
    kind: str  # "user" | "role"
    answers: list[Answer]
    seconds: float


@dataclass
class Report:
    rows: list[Row]
    questions: list[Question]
    workers: int
    seconds: float  # wall clock for the whole audit

    def who_can(self, label: str) -> dict[str, list[str]]:
        """Principals per verdict for one question."""
        out: dict[str, list[str]] = {}
        for row in self.rows:
            for a in row.answers:
                if a.label == label:
                    out.setdefault(a.verdict, []).append(row.principal)
        return out

    @property
    def decisions(self) -> int:
        return sum(len(r.answers) for r in self.rows)


# --- one principal (runs in a worker process) ------------------------------------------

_STATE: dict[str, Any] = {}


def _init(details: AuthorizationDetails, env: Environment, questions: list[Question]) -> None:
    _STATE.update(details=details, env=env, questions=questions)


def _audit_one(arn: str) -> Row:
    details: AuthorizationDetails = _STATE["details"]
    env: Environment = _STATE["env"]
    started = time.perf_counter()
    answers = []
    principal = details.principal(arn)
    for label, action, resource in _STATE["questions"]:
        try:
            result = decide_in_snapshot(details, principal, action, resource, env)
        except Exception as exc:  # noqa: BLE001 - one bad question must not sink the audit; it is reported
            answers.append(Answer(label, action, resource, "error", error=f"{type(exc).__name__}: {exc}"))
            continue
        w = result.witness
        witness = {"action": w.action, "resource": w.resource, "context": w.context} if w else None
        answer = Answer(label, action, resource, result.verdict.value, witness, list(result.assumptions))
        if w and result.verdict is Verdict.ALLOWED:
            answer.grants = grants(principal, w.action, w.resource, w.context, env, result.query.resource_policy)
        if result.verdict is Verdict.UNKNOWN:
            answer.reasons = list(result.reasons)
        answers.append(answer)
    kind = "user" if arn in details.users else "role"
    return Row(arn, kind, answers, time.perf_counter() - started)


# --- the whole account -----------------------------------------------------------------


def audit(
    details: AuthorizationDetails,
    env: Environment | None = None,
    questions: Iterable[Question] = HIGH_IMPACT,
    principals: Iterable[str] | None = None,
    workers: int | None = None,
    progress: Callable[[Row], None] | None = None,
) -> Report:
    """Decide every question for every principal. workers=1 runs in this process (no pool)."""
    env = env or Environment()
    qs = list(questions)
    arns = [details.find(p) for p in principals] if principals is not None else details.principal_arns()
    n = max(1, min(workers or os.cpu_count() or 1, len(arns) or 1))
    started = time.perf_counter()
    rows: list[Row] = []
    if n == 1:
        _init(details, env, qs)
        for arn in arns:
            rows.append(_audit_one(arn))
            if progress:
                progress(rows[-1])
    else:
        with ProcessPoolExecutor(max_workers=n, initializer=_init, initargs=(details, env, qs)) as pool:
            for row in pool.map(_audit_one, arns):
                rows.append(row)
                if progress:
                    progress(row)
    return Report(rows, qs, n, time.perf_counter() - started)
