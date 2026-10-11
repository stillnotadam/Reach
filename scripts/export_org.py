"""Export an AWS Organization's tree, SCPs and RCPs for `reach --org`.

Read-only: it calls only describe/list Organizations APIs, from the management account or a delegated
administrator for Organizations policies.

    python scripts/export_org.py --profile org-readonly -o org.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

POLICY_TYPES = ("SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY")


def _pages(client: Any, method: str, key: str, **kwargs: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    token = None
    while True:
        page = getattr(client, method)(**kwargs, **({"NextToken": token} if token else {}))
        out.extend(page.get(key, []))
        token = page.get("NextToken")
        if not token:
            return out


def export(client: Any) -> dict[str, Any]:
    org = client.describe_organization()["Organization"]
    enabled = {t["Type"] for r in client.list_roots()["Roots"] for t in r.get("PolicyTypes", [])
               if t.get("Status") == "ENABLED"}  # fmt: skip
    types = [t for t in POLICY_TYPES if t in enabled]
    policies: dict[str, Any] = {}

    def attached(target: str) -> list[str]:
        ids = []
        for kind in types:
            for p in _pages(client, "list_policies_for_target", "Policies", TargetId=target, Filter=kind):
                if p["Id"] not in policies:
                    content = client.describe_policy(PolicyId=p["Id"])["Policy"]["Content"]
                    policies[p["Id"]] = {"name": p["Name"], "type": kind, "document": json.loads(content)}
                ids.append(p["Id"])
        return ids

    roots, ous, accounts = [], [], []
    stack = []
    for r in _pages(client, "list_roots", "Roots"):
        roots.append({"id": r["Id"], "name": r.get("Name", "Root"), "policies": attached(r["Id"])})
        stack.append(r["Id"])
    while stack:
        parent = stack.pop()
        for a in _pages(client, "list_accounts_for_parent", "Accounts", ParentId=parent):
            accounts.append({"id": a["Id"], "name": a.get("Name", a["Id"]), "parent": parent,
                             "policies": attached(a["Id"])})  # fmt: skip
        for ou in _pages(client, "list_organizational_units_for_parent", "OrganizationalUnits", ParentId=parent):
            ous.append({"id": ou["Id"], "name": ou.get("Name", ou["Id"]), "parent": parent,
                        "policies": attached(ou["Id"])})  # fmt: skip
            stack.append(ou["Id"])
    return {
        "id": org["Id"],
        "management_account": org["MasterAccountId"],
        "enabled_policy_types": types,
        "roots": roots,
        "ous": ous,
        "accounts": accounts,
        "policies": policies,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", help="AWS CLI profile in the management or delegated admin account")
    parser.add_argument("-o", "--output", type=Path, default=Path("org.json"))
    args = parser.parse_args()
    try:
        import boto3  # noqa: PLC0415 - optional dependency
    except ImportError:
        print('boto3 is required: python -m pip install -e ".[aws]"', file=sys.stderr)
        return 2
    client = boto3.Session(profile_name=args.profile).client("organizations")
    data = export(client)
    args.output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"wrote {len(data['accounts'])} accounts, {len(data['ous'])} OUs, {len(data['policies'])} policies "
          f"to {args.output}")  # fmt: skip
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
