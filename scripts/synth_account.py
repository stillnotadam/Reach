"""Generate a synthetic `get-account-authorization-details` snapshot of any size, for benchmarks.

The account mimics what real ones contain: team groups with managed policies, tag-based access with policy
variables, region and MFA guardrails, permissions boundaries on developers, NotAction power-user policies,
ForAllValues tag-on-create rules, service roles trusted by AWS services, CI roles trusted through OIDC, and
cross-team roles trusted by named users. Same seed, same account.

    python scripts/synth_account.py --users 400 --roles 600 --seed 1 -o synth.json
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

ACCOUNT = "123456789012"
TEAMS = ["data", "web", "payments", "platform", "ml", "mobile", "search", "infra"]
REGIONS = ["eu-west-1", "us-east-1"]


def arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:{kind}/{name}"


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def managed_policies() -> dict[str, dict[str, Any]]:
    team_tag = "${aws:PrincipalTag/team}"
    return {
        "ReadOnlyish": doc(
            {"Effect": "Allow", "Action": ["s3:Get*", "s3:List*", "ec2:Describe*", "lambda:List*", "logs:Get*"],
             "Resource": "*"}),
        "TeamData": doc(
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*",
             "Condition": {"StringEquals": {"aws:ResourceTag/team": team_tag}}},
            {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{team_tag}-*"}),
        "TeamSecrets": doc(
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
             "Resource": f"arn:aws:secretsmanager:*:{ACCOUNT}:secret:app/{team_tag}/*"}),
        "KmsViaS3": doc(
            {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*",
             "Condition": {"StringLike": {"kms:ViaService": "s3.*.amazonaws.com"}}}),
        "PowerUser": doc(
            {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["iam:CreateServiceLinkedRole", "iam:ListRoles"], "Resource": "*"}),
        "Admin": doc({"Effect": "Allow", "Action": "*", "Resource": "*"}),
        "RegionGuard": doc(
            {"Effect": "Deny", "NotAction": ["iam:*", "sts:*", "cloudfront:*", "support:*"], "Resource": "*",
             "Condition": {"StringNotEquals": {"aws:RequestedRegion": REGIONS}}}),
        "RequireMfa": doc(
            {"Effect": "Deny", "NotAction": ["iam:ChangePassword", "iam:GetUser", "sts:GetSessionToken"],
             "Resource": "*", "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}}),
        "TagOnCreate": doc(
            {"Effect": "Allow", "Action": ["ec2:RunInstances", "ec2:CreateTags"], "Resource": "*",
             "Condition": {"ForAllValues:StringEquals": {"aws:TagKeys": ["team", "env", "cost-center"]},
                           "StringEquals": {"aws:RequestTag/team": team_tag}}}),
        "LambdaDeployer": doc(
            {"Effect": "Allow", "Action": ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
             "Resource": f"arn:aws:lambda:*:{ACCOUNT}:function:{team_tag}-*"},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": arn("role", "lambda-*"),
             "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}}),
        "SsmTeamParams": doc(
            {"Effect": "Allow", "Action": ["ssm:GetParameter", "ssm:GetParametersByPath"],
             "Resource": f"arn:aws:ssm:*:{ACCOUNT}:parameter/{team_tag}/*"}),
        "DeveloperBoundary": doc(
            {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"},
            {"Effect": "Deny", "Action": ["kms:ScheduleKeyDeletion", "s3:DeleteBucket"], "Resource": "*"}),
    }  # fmt: skip


GROUPS = {
    "developers": ["ReadOnlyish", "TeamData", "TeamSecrets", "LambdaDeployer", "SsmTeamParams", "RequireMfa"],
    "data-engineers": ["ReadOnlyish", "TeamData", "KmsViaS3", "RequireMfa"],
    "operators": ["PowerUser", "RegionGuard", "RequireMfa"],
    "readonly": ["ReadOnlyish"],
    "admins": ["Admin", "RequireMfa"],
}
GROUP_WEIGHTS = [50, 20, 15, 12, 3]


def policy_entry(name: str, document: dict[str, Any]) -> dict[str, Any]:
    return {
        "PolicyName": name,
        "Arn": f"arn:aws:iam::{ACCOUNT}:policy/{name}",
        "DefaultVersionId": "v1",
        "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": document}],
    }


def attached(names: list[str]) -> list[dict[str, str]]:
    return [{"PolicyName": n, "PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/{n}"} for n in names]


def trust(*statements: dict[str, Any]) -> dict[str, Any]:
    return doc(*statements)


def generate(users: int, roles: int, seed: int) -> dict[str, Any]:
    rng = random.Random(seed)  # noqa: S311 - reproducible test data
    user_list, role_list = [], []
    user_names = [f"user-{i:04d}" for i in range(users)]
    for name in user_names:
        groups = rng.choices(list(GROUPS), weights=GROUP_WEIGHTS, k=rng.choice([1, 1, 2]))
        entry: dict[str, Any] = {
            "UserName": name, "Arn": arn("user", name), "GroupList": sorted(set(groups)),
            "AttachedManagedPolicies": [], "UserPolicyList": [],
            "Tags": [{"Key": "team", "Value": rng.choice(TEAMS)}],
        }  # fmt: skip
        if "developers" in groups and rng.random() < 0.7:
            entry["PermissionsBoundary"] = {
                "PermissionsBoundaryType": "Policy",
                "PermissionsBoundaryArn": f"arn:aws:iam::{ACCOUNT}:policy/DeveloperBoundary",
            }
        if rng.random() < 0.1:
            entry["UserPolicyList"].append({"PolicyName": "adhoc", "PolicyDocument": doc(
                {"Effect": "Allow", "Action": rng.choice(["s3:*", "dynamodb:*", "sqs:SendMessage"]),
                 "Resource": "*"})})  # fmt: skip
        user_list.append(entry)
    for i in range(roles):
        kind = rng.choices(["lambda", "ec2", "ci", "cross-team"], weights=[40, 25, 15, 20])[0]
        team = rng.choice(TEAMS)
        name = f"{kind}-{team}-{i:04d}"
        if kind in ("lambda", "ec2"):
            trust_doc = trust({"Effect": "Allow", "Principal": {"Service": f"{kind}.amazonaws.com"},
                               "Action": "sts:AssumeRole"})  # fmt: skip
            policies = rng.sample(["TeamData", "TeamSecrets", "SsmTeamParams", "KmsViaS3", "ReadOnlyish"], k=2)
        elif kind == "ci":
            trust_doc = trust({
                "Effect": "Allow",
                "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": f"repo:corp/{team}-*:*"}},
            })  # fmt: skip
            policies = rng.sample(["LambdaDeployer", "TeamData", "PowerUser"], k=1)
        else:
            trusted = rng.sample(user_names, k=min(len(user_names), rng.randint(1, 3)))
            trust_doc = trust({"Effect": "Allow", "Principal": {"AWS": [arn("user", u) for u in trusted]},
                               "Action": "sts:AssumeRole",
                               "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}})  # fmt: skip
            policies = rng.sample(["PowerUser", "TeamData", "Admin", "ReadOnlyish"], k=1)
        role_list.append({
            "RoleName": name, "Arn": arn("role", name), "AssumeRolePolicyDocument": trust_doc,
            "AttachedManagedPolicies": attached(policies), "RolePolicyList": [],
            "Tags": [{"Key": "team", "Value": team}],
        })  # fmt: skip
    group_list = [
        {"GroupName": g, "Arn": arn("group", g), "AttachedManagedPolicies": attached(p), "GroupPolicyList": []}
        for g, p in GROUPS.items()
    ]
    return {
        "UserDetailList": user_list,
        "GroupDetailList": group_list,
        "RoleDetailList": role_list,
        "Policies": [policy_entry(n, d) for n, d in managed_policies().items()],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--users", type=int, default=100)
    parser.add_argument("--roles", type=int, default=150)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("-o", "--output", type=Path, default=Path("synth.json"))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.users, args.roles, args.seed)), encoding="utf-8")
    print(f"wrote {args.users} users and {args.roles} roles to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
