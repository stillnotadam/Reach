"""Loading principals from `aws iam get-account-authorization-details` output.

That single read-only call exports every user, group, role and managed
policy in an account, which lets Reach work fully offline from a JSON
snapshot. Generate one with:

    aws iam get-account-authorization-details --output json > authz.json
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .engine import Principal, ResourcePolicy
from .policy import Policy, PolicyError, parse_policy


@dataclass
class AuthorizationDetails:
    users: dict[str, dict[str, Any]] = field(default_factory=dict)  # by ARN
    roles: dict[str, dict[str, Any]] = field(default_factory=dict)  # by ARN
    groups: dict[str, dict[str, Any]] = field(default_factory=dict)  # by name
    managed: dict[str, Policy] = field(default_factory=dict)  # by policy ARN

    @classmethod
    def load(cls, path: str) -> AuthorizationDetails:
        with open(path, encoding="utf-8") as fh:
            return cls.from_json(json.load(fh))

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> AuthorizationDetails:
        out = cls()
        for u in data.get("UserDetailList", []):
            out.users[u["Arn"]] = u
        for r in data.get("RoleDetailList", []):
            out.roles[r["Arn"]] = r
        for g in data.get("GroupDetailList", []):
            out.groups[g["GroupName"]] = g
        for p in data.get("Policies", []):
            doc = _default_version(p)
            if doc is not None:
                out.managed[p["Arn"]] = parse_policy(doc, p.get("PolicyName", p["Arn"]))
        return out

    def principal_arns(self) -> list[str]:
        return sorted(self.users) + sorted(self.roles)

    def find(self, ref: str) -> str:
        """Resolve a full ARN, or a bare user/role name, to an ARN."""
        if ref in self.users or ref in self.roles:
            return ref
        entities = {**self.users, **self.roles}
        matches = [arn for arn, e in entities.items() if e.get("UserName", e.get("RoleName")) == ref]
        if len(matches) == 1:
            return matches[0]
        if matches:
            raise KeyError(f"{ref!r} is ambiguous: {', '.join(matches)}")
        raise KeyError(f"no user or role named {ref!r} in this snapshot")

    def principal(self, ref: str) -> Principal:
        arn = self.find(ref)
        entity = self.users.get(arn) or self.roles[arn]
        is_user = arn in self.users
        inline_key = "UserPolicyList" if is_user else "RolePolicyList"

        policies: list[Policy] = []
        unresolved: list[str] = []

        def add_inline(items: list[dict[str, Any]], owner: str) -> None:
            for item in items:
                name = f"{owner}/inline/{item['PolicyName']}"
                try:
                    policies.append(parse_policy(item["PolicyDocument"], name))
                except PolicyError as exc:
                    unresolved.append(f"{name} ({exc})")

        def add_managed(items: list[dict[str, Any]]) -> None:
            for item in items:
                pol = self.managed.get(item["PolicyArn"])
                if pol is None:
                    unresolved.append(item["PolicyArn"])
                else:
                    policies.append(pol)

        add_inline(entity.get(inline_key, []), entity.get("UserName", entity.get("RoleName", arn)))
        add_managed(entity.get("AttachedManagedPolicies", []))
        if is_user:
            for group_name in entity.get("GroupList", []):
                group = self.groups.get(group_name)
                if group is None:
                    unresolved.append(f"group {group_name}")
                    continue
                add_inline(group.get("GroupPolicyList", []), f"group/{group_name}")
                add_managed(group.get("AttachedManagedPolicies", []))

        boundary = None
        pb = entity.get("PermissionsBoundary")
        if pb:
            boundary = self.managed.get(pb["PermissionsBoundaryArn"])
            if boundary is None:
                unresolved.append(f"boundary {pb['PermissionsBoundaryArn']}")

        tags = {t["Key"]: t["Value"] for t in entity.get("Tags", [])}
        return Principal(arn, policies, boundary, tags, unresolved)


def trust_policy(details: AuthorizationDetails, role_arn: str) -> ResourcePolicy | None:
    """The trust policy of a role in the snapshot, as a required resource policy (None if unknown)."""
    role = details.roles.get(role_arn)
    if role is None or "AssumeRolePolicyDocument" not in role:
        return None
    policy = parse_policy(role["AssumeRolePolicyDocument"], f"{role['RoleName']}/trust-policy")
    return ResourcePolicy(policy, role_arn.split(":")[4], required=True)


def _default_version(policy: dict[str, Any]) -> Any:
    default = policy.get("DefaultVersionId")
    for version in policy.get("PolicyVersionList", []):
        if version.get("IsDefaultVersion") or version.get("VersionId") == default:
            return version.get("Document")
    return None
