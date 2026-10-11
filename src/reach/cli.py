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
from .audit import Report, audit
from .blast import Capability, Resolution, capabilities, resolve_profiles
from .catalog import Catalog, bundled
from .conditions import ContextValue
from .engine import Environment, Principal, Query, ResourcePolicy, Result, Verdict, decide
from .loaders import AuthorizationDetails, trust_policy
from .org import Organization
from .policy import PolicyError, load_policy_file
from .report import to_html
from .sarif import to_sarif
from .trifecta import LEGS, Assessment, assess_all

ADHOC_ARN = "arn:aws:iam::111122223333:role/reach-adhoc"

_COLOURS = {Verdict.ALLOWED: "\033[1;31m", Verdict.DENIED: "\033[1;32m", Verdict.UNKNOWN: "\033[1;33m"}
_RESET = "\033[0m"


def _parse_context(items: list[str], absent: list[str]) -> dict[str, ContextValue]:
    """KEY=VALUE pins a value; KEY=["a","b"] (a JSON list) pins the values of a multi-valued key."""
    out: dict[str, ContextValue] = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep:
            raise SystemExit(f"--context expects KEY=VALUE, got {item!r}")
        if value.startswith("["):
            try:
                values = json.loads(value)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"--context {key}: not a JSON list of strings: {exc}") from exc
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise SystemExit(f"--context {key}: expected a JSON list of strings")
            out[key] = values
        else:
            out[key] = value
    for key in absent:
        out[key] = None
    return out


def _environment(
    args: argparse.Namespace, account: str | None = None, resource_account: str | None = None
) -> Environment:
    """--scp, --session-policy and --management-account, plus the SCP and RCP layers of --org for `account`."""
    layers: dict[str, list] = {}
    for spec in args.scp:
        layer, sep, path = spec.partition("=")
        if not sep:
            raise SystemExit(f"--scp expects LAYER=FILE (e.g. root=scp.json), got {spec!r}")
        layers.setdefault(layer, []).append(load_policy_file(path))
    env = Environment(
        scp_layers=list(layers.items()),
        session_policies=[load_policy_file(p) for p in args.session_policy],
        management_account=args.management_account,
    )
    if getattr(args, "org", None) and account:
        org = Organization.load(args.org).environment(account, resource_account)
        env.scp_layers = org.scp_layers + env.scp_layers
        env.management_account = env.management_account or org.management_account
        env.rcps = org.rcps
    return env


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
        env = _environment(args, principal.account, args.resource_account)
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


def _render_reach(resolutions: list[Resolution], results: dict[str, list[Capability] | str], colour: bool) -> str:
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
    home = Path(args.home) if args.home else None
    inv = discover(
        home=home,
        project=Path(args.project) if args.project else None,
        # A scanned home brings its own AppData, and the environment variables of the shell running Reach
        # belong to you, not to that home.
        appdata=home / "AppData" / "Roaming" if home else None,
        environ={} if home else None,
    )
    resolutions: list[Resolution] = []
    results: dict[str, list[Capability] | str] = {}  # capabilities, or why there are none
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
    assessments = assess_all(inv, {k: v for k, v in results.items() if isinstance(v, list)})
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
    if args.sarif:
        project = Path(args.project) if args.project else None
        Path(args.sarif).write_text(json.dumps(to_sarif(inv, assessments, project), indent=2), encoding="utf-8")
    failing = {"critical": ("critical",), "high": ("critical", "high")}.get(args.fail_on or "", ())
    if any(a.severity in failing for a in assessments):
        return 1
    return 1 if args.fail_on_hardcoded and inv.hardcoded else 0


_CELL = {"allowed": "ALLOW", "denied": "-", "unknown": "?", "error": "ERR"}


def _short(arn: str) -> str:
    return arn.split(":", 5)[-1]


def _render_audit(report: Report, colour: bool) -> str:
    red, dim, bold, reset = ("\033[31m", "\033[2m", "\033[1m", "\033[0m") if colour else ("", "", "", "")
    labels = [q[0] for q in report.questions]
    width = max([len(_short(r.principal)) for r in report.rows] + [9])
    cols = [max(len(label), 5) for label in labels]
    header = "  ".join(label.ljust(c) for label, c in zip(labels, cols))
    lines = [f"{bold}{'principal'.ljust(width)}  {header}{reset}"]
    style = {"allowed": red, "denied": dim}
    for row in sorted(report.rows, key=lambda r: (r.kind, r.principal)):
        cells = []
        for a, c in zip(row.answers, cols):
            colour_on = style.get(a.verdict, "")
            cells.append(f"{colour_on}{_CELL[a.verdict].ljust(c)}{reset if colour_on else ''}")
        lines.append(_short(row.principal).ljust(width) + "  " + "  ".join(cells))
    lines.append("")
    lines.append(f"{bold}Who can{reset}")
    for label in labels:
        verdicts = report.who_can(label)
        allowed = sorted(_short(p) for p in verdicts.get("allowed", []))
        unknown = verdicts.get("unknown", [])
        line = f"  {label}: {len(allowed)} proven"
        if allowed:
            line += f" ({', '.join(allowed[:8])}{', ...' if len(allowed) > 8 else ''})"
        if unknown:
            line += f", {len(unknown)} unknown"
        lines.append(line)
    errors = sum(a.verdict == "error" for r in report.rows for a in r.answers)
    lines.append("")
    lines.append(
        f"{dim}{len(report.rows)} principals x {len(report.questions)} questions = {report.decisions} decisions in "
        f"{report.seconds:.1f} s on {report.workers} worker(s)" + (f"; {errors} errors" if errors else "") + reset
    )
    lines.append(
        f"{dim}ALLOW comes with a witness request. '-' is a proof over the policies in this snapshot: identity "
        "policies, boundaries, SCPs given with --scp, and role trust policies. Bucket, key and other resource "
        f"policies are not in an IAM snapshot, and roles in other accounts are not checked.{reset}"
    )
    return "\n".join(lines)


def cmd_audit(args: argparse.Namespace) -> int:
    details = AuthorizationDetails.load(args.authz)
    total = len(args.principal) if args.principal else len(details.principal_arns())
    done = 0

    def progress(_row: object) -> None:
        nonlocal done
        done += 1
        if not args.json and sys.stderr.isatty():
            print(f"\r  {done}/{total} principals", end="", file=sys.stderr, flush=True)

    accounts = {arn.split(":")[4] for arn in details.principal_arns()}
    if args.org and len(accounts) > 1:
        raise SystemExit(f"--org: the snapshot spans several accounts ({', '.join(sorted(accounts))})")
    env = _environment(args, next(iter(accounts), None))
    report = audit(details, env, principals=args.principal or None, workers=args.workers, progress=progress)
    if not args.json and sys.stderr.isatty():
        print(file=sys.stderr)
    if args.json:
        print(json.dumps(asdict(report), indent=2, default=str))
    else:
        print(_render_audit(report, sys.stdout.isatty() and not args.no_colour))
    if args.html:
        notes = [f"Organization: {args.org}." if args.org else "No organization export given: SCPs and RCPs only "
                 "from --scp."] + [f"SCP {s}." for s in args.scp]  # fmt: skip
        Path(args.html).write_text(to_html(report, args.authz, notes), encoding="utf-8")
        if not args.json:
            print(f"wrote {args.html}", file=sys.stderr)
    return 1 if args.fail_on_allowed and any(a.verdict == "allowed" for r in report.rows for a in r.answers) else 0


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
    org.add_argument("--org", metavar="FILE", help="AWS Organizations export (scripts/export_org.py): SCPs and RCPs")
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
    agents.add_argument(
        "--home",
        help="home directory to scan instead of yours (your environment variables are then ignored too)",
    )
    agents.add_argument("--json", action="store_true")
    agents.add_argument("--no-colour", action="store_true")
    agents.add_argument("--fail-on-hardcoded", action="store_true", help="exit 1 if a secret is hardcoded in a config")
    agents.add_argument(
        "--fail-on", choices=["critical", "high"], help="exit 1 if any agent's trifecta is at least this severe"
    )
    agents.add_argument("--sarif", metavar="FILE", help="also write findings as SARIF 2.1.0 (GitHub code scanning)")
    agents.add_argument(
        "--resolve",
        action="store_true",
        help="resolve each reachable AWS profile to its principal (calls sts:GetCallerIdentity; read-only)",
    )
    agents.add_argument("--authz", help="with --resolve: account snapshot to evaluate what each principal can do")
    agents.set_defaults(func=cmd_agents)

    aud = sub.add_parser("audit", help="every user and role in a snapshot against the high-impact questions")
    aud.add_argument("--authz", required=True, help="output of `aws iam get-account-authorization-details`")
    aud.add_argument("--principal", action="append", default=[], help="only this user/role (repeatable)")
    aud.add_argument("--scp", action="append", default=[], metavar="LAYER=FILE", help="SCP at LAYER (repeatable)")
    aud.add_argument("--session-policy", action="append", default=[], metavar="FILE")
    aud.add_argument("--management-account", action="store_true")
    aud.add_argument("--org", metavar="FILE", help="AWS Organizations export: the account's SCPs and RCPs apply")
    aud.add_argument("--workers", type=int, help="worker processes (default: one per CPU)")
    aud.add_argument("--json", action="store_true")
    aud.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report")
    aud.add_argument("--no-colour", action="store_true")
    aud.add_argument(
        "--fail-on-allowed", action="store_true", help="exit 1 if any high-impact action is proven allowed"
    )
    aud.set_defaults(func=cmd_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
