"""Command-line interface.

reach can --authz authz.json --principal dev-role s3:GetObject 'arn:aws:s3:::customer-pii/*'
reach can --policy policy.json --boundary boundary.json --scp root=scp.json iam:PassRole '*'
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from . import __version__
from .catalog import Catalog, bundled
from .engine import Environment, Principal, Query, ResourcePolicy, Result, Verdict, decide
from .loaders import AuthorizationDetails, trust_policy
from .policy import PolicyError, load_policy_file

ADHOC_ARN = "arn:aws:iam::111122223333:role/reach-adhoc"

_COLOURS = {Verdict.ALLOWED: "\033[1;31m", Verdict.DENIED: "\033[1;32m", Verdict.UNKNOWN: "\033[1;33m"}
_RESET = "\033[0m"


def _parse_context(items: list[str], absent: list[str]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep:
            raise SystemExit(f"--context expects KEY=VALUE, got {item!r}")
        out[key] = value
    for key in absent:
        out[key] = None
    return out


def _environment(args: argparse.Namespace) -> Environment:
    layers: dict[str, list] = {}
    for spec in args.scp:
        layer, sep, path = spec.partition("=")
        if not sep:
            raise SystemExit(f"--scp expects LAYER=FILE (e.g. root=scp.json), got {spec!r}")
        layers.setdefault(layer, []).append(load_policy_file(path))
    return Environment(
        scp_layers=list(layers.items()),
        session_policies=[load_policy_file(p) for p in args.session_policy],
        management_account=args.management_account,
    )


def _principal(args: argparse.Namespace) -> Principal:
    if args.authz:
        if not args.principal:
            raise SystemExit("--authz needs --principal (an ARN or a user/role name)")
        details = AuthorizationDetails.load(args.authz)
        principal = details.principal(args.principal)
        if args.boundary:
            principal.boundary = load_policy_file(args.boundary)
        return principal
    if not args.policy:
        raise SystemExit("give either --authz with --principal, or one or more --policy files")
    return Principal(
        arn=args.principal or ADHOC_ARN,
        identity_policies=[load_policy_file(p) for p in args.policy],
        boundary=load_policy_file(args.boundary) if args.boundary else None,
    )


def _render(result: Result, colour: bool) -> str:
    v = result.verdict
    head = v.value.upper()
    if colour:
        head = f"{_COLOURS[v]}{head}{_RESET}"
    lines = [f"{head}  {result.query.action} on {result.query.resource}", f"  principal  {result.principal}"]
    if result.witness:
        w = result.witness
        label = "witness" if v is Verdict.ALLOWED else "if allowed"
        lines.append(f"  {label:<10} {w.action} on {w.resource}")
        for key, value in sorted(w.context.items()):
            lines.append(f"  {'':<10} {key} {'absent' if value is None else '= ' + json.dumps(value)}")
    if v is Verdict.DENIED:
        lines.append("  proof      no request context satisfies the policies (UNSAT)")
    for reason in result.reasons:
        lines.append(f"  why        {reason}")
    for assumption in result.assumptions:
        lines.append(f"  caveat     {assumption}")
    for note in result.notes:
        lines.append(f"  note       {note}")
    return "\n".join(lines)


def cmd_can(args: argparse.Namespace) -> int:
    try:
        principal = _principal(args)
        env = _environment(args)
        catalog = None if args.no_catalog else Catalog.load(args.catalog) if args.catalog else bundled()
    except (OSError, PolicyError, KeyError, json.JSONDecodeError) as exc:
        print(f"reach: {exc}", file=sys.stderr)
        return 2
    try:
        resource_policy = None
        if not args.resource_policy and args.authz and args.action.lower().startswith("sts:assumerole"):
            # The snapshot already holds every role's trust policy.
            resource_policy = trust_policy(AuthorizationDetails.load(args.authz), args.resource)
        if args.resource_policy:
            resource_policy = ResourcePolicy(
                load_policy_file(args.resource_policy),
                args.resource_account or principal.account,
                required=args.required or args.action.lower().startswith("sts:assumerole"),
            )
        query = Query(args.action, args.resource, _parse_context(args.context, args.absent), resource_policy)
        result = decide(principal, query, env, catalog=catalog)
    except (OSError, PolicyError, ValueError) as exc:
        print(f"reach: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(asdict(result), indent=2, default=str))
    else:
        print(_render(result, colour=sys.stdout.isatty() and not args.no_colour))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reach", description="Prove what cloud credentials can actually reach.")
    parser.add_argument("--version", action="version", version=f"reach {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    can = sub.add_parser("can", help="can a principal perform ACTION on RESOURCE?")
    can.add_argument("action", help="IAM action, wildcards allowed (e.g. s3:GetObject, iam:*)")
    can.add_argument("resource", help="resource ARN, wildcards allowed (e.g. 'arn:aws:s3:::bucket/*', '*')")
    src = can.add_argument_group("principal")
    src.add_argument("--authz", help="output of `aws iam get-account-authorization-details`")
    src.add_argument("--principal", help="user/role ARN or name (with --authz), or the ARN to assume for --policy")
    src.add_argument("--policy", action="append", default=[], help="identity policy JSON file (repeatable)")
    src.add_argument("--boundary", help="permissions boundary policy JSON file")
    org = can.add_argument_group("environment")
    org.add_argument(
        "--scp",
        action="append",
        default=[],
        metavar="LAYER=FILE",
        help="SCP attached at LAYER, root first (repeatable; files sharing a LAYER combine)",
    )
    org.add_argument("--session-policy", action="append", default=[], metavar="FILE")
    org.add_argument("--management-account", action="store_true", help="principal lives in the org management account")
    res = can.add_argument_group("resource-based policy")
    res.add_argument("--resource-policy", metavar="FILE", help="bucket policy, key policy, trust policy, ...")
    res.add_argument("--resource-account", metavar="ID", help="account owning the resource (default: principal's)")
    res.add_argument(
        "--required",
        action="store_true",
        help="identity permissions alone never suffice (KMS key policies; implied for sts:AssumeRole*)",
    )
    ctx = can.add_argument_group("request context")
    ctx.add_argument("--context", action="append", default=[], metavar="KEY=VALUE", help="pin a condition key")
    ctx.add_argument("--absent", action="append", default=[], metavar="KEY", help="pin a condition key as absent")
    cat = can.add_argument_group("action catalogue")
    cat.add_argument("--catalog", metavar="FILE", help="action catalogue to use instead of the bundled one")
    cat.add_argument("--no-catalog", action="store_true", help="treat actions as free strings")
    out = can.add_argument_group("output")
    out.add_argument("--json", action="store_true")
    out.add_argument("--no-colour", action="store_true")
    can.set_defaults(func=cmd_can)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
