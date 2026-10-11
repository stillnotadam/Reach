"""Matching a resource-based policy's Principal element against a known principal.

The querying principal is always concrete, so this is plain Python, not
Z3. What matters is not just *whether* a statement names the principal
but *how*, because AWS treats the cases differently within one account:

* USER     - the IAM user's ARN. Not limited by an implicit deny in the
             user's identity policies or permissions boundary.
* ROLE     - the role's ARN. Still limited by the role's permissions
             boundary and session policy.
* SESSION  - an assumed-role session ARN of this role. Not limited by
             boundary or session policy. The session name is chosen by
             whoever assumes the role, so a grant to any session name of
             this role is reachable.
* ACCOUNT  - the account ID or `arn:aws:iam::ACCOUNT:root`. Delegates to
             the account: the principal also needs identity permissions.
* WILDCARD - `"*"` or `{"AWS": "*"}`.
"""

from __future__ import annotations

import re
from enum import Enum

from .policy import Statement


class Match(str, Enum):
    USER = "user"
    ROLE = "role"
    SESSION = "session"
    ACCOUNT = "account"
    WILDCARD = "wildcard"


_ACCOUNT_ID = re.compile(r"[0-9]{12}")
_ROOT = re.compile(r"arn:aws[a-z-]*:iam::([0-9]{12}):root")
_SESSION = re.compile(r"arn:aws[a-z-]*:sts::([0-9]{12}):assumed-role/([^/]+)/.+")


def _account(arn: str) -> str:
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 else ""


def _role_name(arn: str) -> str | None:
    """Role name (without path) for a role ARN, else None."""
    resource = arn.split(":", 5)[-1]
    if not resource.startswith("role/"):
        return None
    return resource.rsplit("/", 1)[-1]


def classify(statement: Statement, principal_arn: str) -> set[Match]:
    """Every way the statement's Principal element names this principal (empty set: not at all).

    For NotPrincipal the statement applies to everyone the element does
    not name, which we report as WILDCARD.
    """
    if statement.principals is None:
        return set()
    named = _named(statement.principals, principal_arn)
    if statement.not_principal:
        return set() if named else {Match.WILDCARD}
    return named


def _named(principals: tuple[tuple[str, str], ...], arn: str) -> set[Match]:
    account = _account(arn)
    is_user = ":user/" in arn
    role_name = _role_name(arn)
    out: set[Match] = set()
    for kind, value in principals:
        if kind == "*" or (kind == "AWS" and value == "*"):
            out.add(Match.WILDCARD)
            continue
        if kind != "AWS":
            continue  # Service, Federated and CanonicalUser principals never name an IAM user or role
        if value == arn:
            out.add(Match.USER if is_user else Match.ROLE)
        elif (
            _ACCOUNT_ID.fullmatch(value) and value == account or (m := _ROOT.fullmatch(value)) and m.group(1) == account
        ):
            out.add(Match.ACCOUNT)
        elif (m := _SESSION.fullmatch(value)) and role_name and m.group(1) == account and m.group(2) == role_name:
            out.add(Match.SESSION)
    return out
