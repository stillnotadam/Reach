"""Command-line interface.

reach can --authz authz.json --principal dev-role s3:GetObject 'arn:aws:s3:::customer-pii/*'
reach can --policy policy.json --boundary boundary.json --scp root=scp.json iam:PassRole '*'
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .agents import Inventory, discover
from .blast import capabilities, resolve_profiles
from .catalog import Catalog, bundled
from .engine import Environment, Principal, Query, ResourcePolicy, Result, Verdict, decide
from .loaders import AuthorizationDetails, trust_policy
from .policy import PolicyError, load_policy_file
from .trifecta import LEGS, Assessment, assess_all

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


def _render_inventory(inv: Inventory, colour: bool) -> str:
    red, dim, reset = ("\x1b[1;31m", "\x1b[2m", "\x1b[0m") if colour else ("", "", "")
    lines = ["Agents"]
    if not inv.agents:
        lines.append("  none found")
    for agent in inv.agents:
        where = "" if agent.local else ", runs in CI"
        lines.append(f"  {agent.name}  {dim}{agent.config}  (shell: {agent.shell_mode}{where}){reset}")
        for finding in agent.findings:
            lines.append(f"    {red}! {finding}{reset}")
        for cred in agent.credentials:
            detail = f" ({cred.detail})" if cred.detail else ""
            lines.append(f"    holds {cred.kind}: {cred.name}{detail}")
        if not agent.tools and agent.local:
            lines.append(f"    {dim}no MCP servers{reset}")
        for tool in agent.tools:
            target = tool.url or tool.command
            lines.append(f"    {tool.name}  [{tool.transport}]  {dim}{target}{reset}")
            for cred in tool.credentials:
                flag = f"  {red}HARDCODED IN CONFIG{reset}" if cred.hardcoded else ""
                detail = f" = {cred.detail}" if cred.detail else ""
                lines.append(f"      {cred.kind}: {cred.name}{detail}{flag}")
    lines.append("")
    lines.append("Ambient credentials (readable by local agents with shell access, with or without approval)")
    if not inv.ambient:
        lines.append("  none found")
    for cred in inv.ambient:
        flag = f"  {red}plaintext file{reset}" if cred.hardcoded else ""
        if cred.hardcoded and cred.detail:
            flag, cred_detail = f"  {red}{cred.detail.upper()}{reset}", ""
        else:
            cred_detail = cred.detail
        detail = f" = {cred_detail}" if cred_detail and cred_detail != cred.name else ""
        lines.append(f"  {cred.kind}: {cred.name}{detail}  {dim}{cred.source}{reset}{flag}")
    hardcoded = inv.hardcoded
    if hardcoded:
        lines += ["", f"{red}{len(hardcoded)} secret(s) hardcoded in agent configs{reset} (values not shown):"]
        lines += [f"  {a.name} / {t.name}: {c.name}  ({c.source})" for a, t, c in hardcoded]
    for error in inv.errors:
        lines.append(f"  {dim}could not read {error}{reset}")
    return "\n".join(lines)


def _aws_profiles(inv: Inventory) -> list[str]:
    """Every AWS profile an agent can use: given to a tool, or ambient for agents with a shell."""
    names = [c.detail for a in inv.agents for t in a.tools for c in t.credentials if c.kind == "aws-profile"]
    if any(a.shell for a in inv.agents):
        names += [c.detail for c in inv.ambient if c.kind == "aws-profile"]
    return list(dict.fromkeys(n for n in names if n))


def _render_reach(resolutions, results: dict[str, list], colour: bool) -> str:
    red, green, yellow, dim, reset = (
        ("\x1b[1;31m", "\x1b[1;32m", "\x1b[1;33m", "\x1b[2m", "\x1b[0m") if colour else ("",) * 5
    )
    tint = {Verdict.ALLOWED: red, Verdict.DENIED: green, Verdict.UNKNOWN: yellow}
    lines = ["", "What the agents' AWS credentials can reach"]
    for res in resolutions:
        if res.error:
            lines.append(f"  {res.profile}: {dim}not resolved ({res.error.splitlines()[0][:100]}){reset}")
            continue
        lines.append(f"  {res.profile} -> {res.arn}")
        caps = results.get(res.profile)
        if caps is None:
            lines.append(f"    {dim}(pass --authz with an account snapshot to evaluate what it can do){reset}")
            continue
        if isinstance(caps, str):
            lines.append(f"    {dim}{caps}{reset}")
            continue
        for cap in caps:
            verdict = f"{tint[cap.verdict]}{cap.verdict.value.upper():<8}{reset}"
            example = f"  {dim}e.g. {cap.witness.action} on {cap.witness.resource}{reset}" if cap.witness else ""
            lines.append(f"    {verdict} {cap.label:<20} {dim}{cap.action}{reset}{example}")
    return "\n".join(lines)


def _render_trifecta(assessments: list[Assessment], colour: bool) -> str:
    red, yellow, dim, reset = ("\x1b[1;31m", "\x1b[1;33m", "\x1b[2m", "\x1b[0m") if colour else ("",) * 4
    lines = ["", "Lethal trifecta (untrusted input + private data + exfiltration in one agent)"]
    for a in assessments:
        if not a.complete:
            missing = ", ".join(k for k in LEGS if not a.legs[k])
            lines.append(f"  {a.agent}: {dim}not complete (no {missing}){reset}")
            continue
        tint = red if a.severity == "critical" else yellow
        lines.append(f"  {tint}{a.severity.upper()}{reset}  {a.agent}")
        for kind in LEGS:
            for leg in a.legs[kind]:
                gate = f" {dim}(needs human approval){reset}" if leg.gated else ""
                lines.append(f"    {kind:<15} {leg.source}{gate}")
        fix = a.cheapest_fix()
        if fix:
            lines.append(f"    {dim}cheapest fix, break the {fix[0]} leg:{reset} {fix[1]}")
        if a.unclassified:
            lines.append(f"    {dim}unclassified MCP servers: {', '.join(a.unclassified)}{reset}")
    return "\n".join(lines)


def cmd_agents(args: argparse.Namespace) -> int:
    inv = discover(home=Path(args.home) if args.home else None, project=Path(args.project) if args.project else None)
    resolutions: list = []
    results: dict[str, object] = {}
    if args.resolve:
        resolutions = resolve_profiles(_aws_profiles(inv))
        details = AuthorizationDetails.load(args.authz) if args.authz else None
        for res in resolutions:
            if details is None or res.error:
                continue
            try:
                results[res.profile] = capabilities(details, res.arn)
            except KeyError as exc:
                results[res.profile] = f"not in the snapshot: {exc}"
    assessments = assess_all(inv, {k: v for k, v in results.items() if not isinstance(v, str)})
    if args.json:
        payload = asdict(inv)
        payload["trifecta"] = [
            {**asdict(a), "complete": a.complete, "severity": a.severity, "cheapest_fix": a.cheapest_fix()}
            for a in assessments
        ]
        payload["resolutions"] = [asdict(r) for r in resolutions]
        payload["capabilities"] = {k: v if isinstance(v, str) else [asdict(c) for c in v] for k, v in results.items()}
        print(json.dumps(payload, indent=2, default=str))
    else:
        colour = sys.stdout.isatty() and not args.no_colour
        print(_render_inventory(inv, colour))
        if args.resolve:
            print(_render_reach(resolutions, results, colour))
        print(_render_trifecta(assessments, colour))
    return 1 if args.fail_on_hardcoded and inv.hardcoded else 0


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

    agents = sub.add_parser("agents", help="inventory AI agents, their MCP tools and the credentials they can use")
    agents.add_argument("--project", help="also scan this project directory (.mcp.json, .cursor/, .vscode/, .env)")
    agents.add_argument("--home", help="home directory to scan (default: yours)")
    agents.add_argument("--json", action="store_true")
    agents.add_argument("--no-colour", action="store_true")
    agents.add_argument("--fail-on-hardcoded", action="store_true", help="exit 1 if a secret is hardcoded in a config")
    agents.add_argument(
        "--resolve",
        action="store_true",
        help="resolve each reachable AWS profile to its principal (calls sts:GetCallerIdentity; read-only)",
    )
    agents.add_argument("--authz", help="with --resolve: account snapshot to evaluate what each principal can do")
    agents.set_defaults(func=cmd_agents)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
