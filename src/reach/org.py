"""AWS Organizations: the SCP and RCP layers that apply to an account.

An organization is a tree: a root, organizational units (OUs) nested under it, and accounts in OUs. Service
control policies (SCPs) and resource control policies (RCPs) attach to any node. For a given account:

* every SCP layer from the root down to the account must allow a request made by its principals, and any
  Deny on the way blocks it. The management account is exempt;
* the RCPs from the root down to the account that owns the resource apply to requests on that resource.
  `RCPFullAWSAccess` is attached everywhere and cannot be detached, so in effect only their Deny statements
  matter. Resources in the management account are exempt.

The tree is read from a JSON export (scripts/export_org.py makes one with read-only Organizations calls):

    {"id": "o-a1b2c3d4e5", "management_account": "111111111111",
     "roots": [{"id": "r-ab12", "name": "Root", "policies": ["p-FullAWSAccess"]}],
     "ous": [{"id": "ou-ab12-x", "name": "Prod", "parent": "r-ab12", "policies": ["p-deny-regions"]}],
     "accounts": [{"id": "123456789012", "name": "app", "parent": "ou-ab12-x", "policies": [...]}],
     "policies": {"p-deny-regions": {"name": "DenyRegions", "type": "SERVICE_CONTROL_POLICY", "document": {...}}}}
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .conditions import ContextValue
from .engine import Environment
from .policy import Policy, parse_policy

SCP = "SERVICE_CONTROL_POLICY"
RCP = "RESOURCE_CONTROL_POLICY"


@dataclass
class Node:
    id: str
    name: str
    parent: str | None
    policies: list[str] = field(default_factory=list)


@dataclass
class Organization:
    id: str  # o-...
    management_account: str
    nodes: dict[str, Node]  # roots, OUs and accounts by id
    policies: dict[str, tuple[str, str, Policy]]  # id -> (name, type, parsed policy)

    @classmethod
    def load(cls, path: str) -> Organization:
        with open(path, encoding="utf-8") as fh:
            return cls.from_json(json.load(fh))

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Organization:
        nodes: dict[str, Node] = {}
        for kind in ("roots", "ous", "accounts"):
            for n in data.get(kind, []):
                nodes[n["id"]] = Node(n["id"], n.get("name", n["id"]), n.get("parent"), list(n.get("policies", [])))
        policies = {
            pid: (p.get("name", pid), p["type"], parse_policy(p["document"], p.get("name", pid)))
            for pid, p in data.get("policies", {}).items()
        }
        return cls(data.get("id", ""), data["management_account"], nodes, policies)

    def path(self, account: str) -> list[Node]:
        """Root first, the account last."""
        if account not in self.nodes:
            raise KeyError(f"account {account} is not in this organization")
        out: list[Node] = []
        node: Node | None = self.nodes[account]
        seen: set[str] = set()
        while node is not None:
            if node.id in seen:
                raise ValueError(f"cycle in the organization tree at {node.id}")
            seen.add(node.id)
            out.append(node)
            node = self.nodes.get(node.parent) if node.parent else None
        return out[::-1]

    def _attached(self, node: Node, kind: str) -> list[Policy]:
        missing = [pid for pid in node.policies if pid not in self.policies]
        if missing:
            raise KeyError(f"{node.name}: policies {', '.join(missing)} are attached but not in the export")
        return [self.policies[pid][2] for pid in node.policies if self.policies[pid][1] == kind]

    def scp_layers(self, account: str) -> list[tuple[str, list[Policy]]]:
        return [(n.name, self._attached(n, SCP)) for n in self.path(account)]

    def rcps(self, account: str) -> list[Policy]:
        """RCPs that apply to resources owned by `account` (none in the management account)."""
        if account == self.management_account:
            return []
        return [p for n in self.path(account) for p in self._attached(n, RCP)]

    def org_path(self, account: str) -> str:
        """aws:PrincipalOrgPaths / aws:ResourceOrgPaths form: o-id/r-id/ou-id/.../ (the account itself excluded)."""
        return "/".join([self.id, *(n.id for n in self.path(account)[:-1])]) + "/"

    def environment(self, principal_account: str, resource_account: str | None = None) -> Environment:
        """The organization's part of a request: SCPs of the caller's account, RCPs of the resource's account,
        and the org keys AWS fills in for each side.

        An account outside the organization contributes no policies, and its org keys are absent.
        """
        resource_account = resource_account or principal_account
        caller_in, resource_in = principal_account in self.nodes, resource_account in self.nodes
        context: dict[str, ContextValue] = {
            "aws:PrincipalOrgID": self.id if caller_in else None,
            "aws:PrincipalOrgPaths": [self.org_path(principal_account)] if caller_in else None,
            "aws:ResourceOrgID": self.id if resource_in else None,
            "aws:ResourceOrgPaths": [self.org_path(resource_account)] if resource_in else None,
        }
        return Environment(
            scp_layers=self.scp_layers(principal_account) if caller_in else [],
            management_account=principal_account == self.management_account,
            rcps=self.rcps(resource_account) if resource_in else [],
            org_context=context if self.id else {},
        )
