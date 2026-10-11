"""The lethal trifecta: untrusted input + private data + an exfiltration channel in one agent.

An agent that reads attacker-controlled text (untrusted input), can access
something sensitive (private data), and can send data out (exfiltration)
can be told, by text an attacker planted, to send the private data out.
Simon Willison named this the lethal trifecta; no prompt-level defence
reliably prevents it, so the robust fix is to remove one leg.

For each agent this module derives each leg from evidence the inventory
already holds: the agent's kind and built-in tools, its shell mode and
denied tools, its MCP servers, the credentials it is handed, and, for
local agents with a shell, the ambient credentials on the machine. Every
leg names its source and whether a human approval stands in the way.

Tool classification is a small documented catalogue keyed on server names,
packages and URLs. A tool that matches nothing is reported as
unclassified, never assumed safe or dangerous.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .agents import Agent, Inventory, Tool
from .blast import Capability
from .engine import Verdict

UNTRUSTED, PRIVATE, EXFIL = "untrusted input", "private data", "exfiltration"
LEGS = (UNTRUSTED, PRIVATE, EXFIL)

# (pattern over "name command url", legs, what the tool exposes)
TOOL_CATALOGUE: tuple[tuple[str, frozenset[str], str], ...] = (
    (r"github|gitlab|bitbucket", frozenset({UNTRUSTED, PRIVATE, EXFIL}),
     "reads issues and PRs anyone can write, private repositories, and can post comments or push"),
    (r"slack|discord|teams|telegram", frozenset({UNTRUSTED, PRIVATE, EXFIL}),
     "reads messages others write, private channels, and can post"),
    (r"gmail|outlook|imap|email|mail", frozenset({UNTRUSTED, PRIVATE, EXFIL}),
     "reads inbound mail anyone can send, a private mailbox, and can send"),
    (r"jira|linear|notion|confluence|asana|gdrive|google-?drive|sharepoint", frozenset({UNTRUSTED, PRIVATE, EXFIL}),
     "reads shared documents or tickets others write, private workspace data, and can write"),
    (r"fetch|browser|puppeteer|playwright|brave|tavily|exa\b|firecrawl|search|scrape|web",
     frozenset({UNTRUSTED, EXFIL}), "loads web content anyone can publish, and can send data out in request URLs"),
    (r"postgres|mysql|sqlite|mongo|redis|supabase|snowflake|bigquery|database|\bdb\b|-db\b|db-",
     frozenset({PRIVATE}), "queries a database"),
    (r"filesystem|server-fs|\bfs\b|-fs\b|fs-", frozenset({PRIVATE}), "reads local files"),
    (r"\baws\b|awslabs|gcp|gcloud|azure|kubernetes|kubectl|\bk8s\b", frozenset({PRIVATE}),
     "acts on cloud resources with the credentials it is given"),
    (r"stripe|paypal|shopify", frozenset({PRIVATE}), "accesses payment or customer data"),
)  # fmt: skip

# Fixes, cheapest first, keyed by what provides the leg.
_FIX = {
    "web": 'deny "WebFetch" and "WebSearch" in the agent\'s permissions',
    "shell": "remove bypassPermissions and blanket Bash allow rules, so a human approves shell commands",
    "ci-trigger": "add an `if:` gate so only trusted authors (author_association OWNER/MEMBER) can trigger the agent",
    "ci-token": "set `permissions:` to read-only for the agent job",
    "ci-secret": "stop passing secrets the agent does not need",
    "ambient": "run the agent where these credentials are not readable (a container or a separate user)",
}


@dataclass
class Leg:
    kind: str  # UNTRUSTED | PRIVATE | EXFIL
    source: str  # what provides it, in words
    gated: bool = False  # a human must approve before it is used
    fix: str = ""


@dataclass
class Assessment:
    agent: str
    legs: dict[str, list[Leg]] = field(default_factory=dict)
    unclassified: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return all(self.legs.get(k) for k in LEGS)

    @property
    def severity(self) -> str:
        """critical: all three legs with at least one ungated way each; high: all three, but a human gate on one."""
        if not self.complete:
            return "none"
        if all(any(not leg.gated for leg in self.legs[k]) for k in LEGS):
            return "critical"
        return "high"

    def cheapest_fix(self) -> tuple[str, str] | None:
        """The leg with the fewest sources, and how to remove it."""
        if not self.complete:
            return None
        kind = min(LEGS, key=lambda k: (len(self.legs[k]), LEGS.index(k)))
        fixes = list(dict.fromkeys(leg.fix for leg in self.legs[kind] if leg.fix))
        return kind, "; ".join(fixes) or "remove: " + ", ".join(leg.source for leg in self.legs[kind])


def classify_tool(tool: Tool) -> tuple[frozenset[str], str] | None:
    text = f"{tool.name} {tool.command} {tool.url}".lower()
    for pattern, legs, what in TOOL_CATALOGUE:
        if re.search(pattern, text):
            return legs, what
    return None


def _denied(agent: Agent, *tools: str) -> bool:
    rules = {r.strip().lower() for r in agent.denied}
    return all(t.lower() in rules or f"{t.lower()}(*)" in rules for t in tools)


def assess(agent: Agent, inv: Inventory, capabilities: dict[str, list[Capability]] | None = None) -> Assessment:
    out = Assessment(agent.name, {k: [] for k in LEGS})

    def add(kind: str, source: str, gated: bool = False, fix: str = "") -> None:
        out.legs[kind].append(Leg(kind, source, gated, fix))

    approval = agent.shell_mode == "approval"
    # Built-in tools of local coding agents. Claude Code's WebFetch/WebSearch ask before first use per domain
    # by default, so they count as gated unless the agent runs unrestricted.
    if agent.kind == "claude-code" and not _denied(agent, "WebFetch"):
        gated = agent.shell_mode != "unrestricted"
        add(UNTRUSTED, "WebFetch: web pages anyone can publish", gated, _FIX["web"])
        add(EXFIL, "WebFetch: data can leave in a request URL", gated, _FIX["web"])
    if agent.kind in ("cursor", "vscode", "windsurf"):
        add(UNTRUSTED, "built-in web and repository context (assumed; not configurable from files Reach reads)", True)

    if agent.shell:
        add(EXFIL, f"shell ({agent.shell_mode}): network commands such as curl", approval, _FIX["shell"])
        ambient = inv.ambient
        if ambient:
            names = ", ".join(sorted({f"{c.kind} {c.name}" for c in ambient})[:6])
            add(PRIVATE, f"ambient credentials readable from the shell: {names}", approval, _FIX["ambient"])
        for profile, caps in (capabilities or {}).items():
            proven = [c.label for c in caps if c.verdict is Verdict.ALLOWED]
            if proven:
                add(PRIVATE, f"AWS profile {profile} can (proven): {', '.join(proven)}", approval, _FIX["ambient"])

    if agent.kind == "ci":
        if agent.triggers:
            gated = bool(agent.gate)
            how = f" behind `if: {agent.gate[:80]}`" if gated else ""
            add(UNTRUSTED, f"triggered by {', '.join(agent.triggers)}{how}", gated, _FIX["ci-trigger"])
        secrets = [c.name for c in agent.credentials if c.kind not in ("github-token",)]
        if secrets:
            add(PRIVATE, f"secrets in the job: {', '.join(secrets)}", False, _FIX["ci-secret"])
        token = next((c for c in agent.credentials if c.kind == "github-token"), None)
        if token is not None:
            add(PRIVATE, f"repository contents via GITHUB_TOKEN ({token.detail})")
            if agent.can_write:
                add(EXFIL, f"GITHUB_TOKEN can write ({token.detail}): comments, issues or pushes", False,
                    _FIX["ci-token"])  # fmt: skip
        if agent.shell_mode == "unrestricted":
            add(EXFIL, "shell on the runner with network access", False, "remove Bash from the agent's allowed tools")

    for tool in agent.tools:
        found = classify_tool(tool)
        if found is None:
            out.unclassified.append(tool.name)
            continue
        legs, what = found
        # MCP tool calls ask for approval in local agents unless the agent runs unrestricted.
        gated = agent.local and agent.shell_mode != "unrestricted"
        for kind in legs:
            add(kind, f"MCP server {tool.name}: {what}", gated, f"remove or narrow the {tool.name} MCP server")
        if tool.credentials and PRIVATE not in legs:
            add(PRIVATE, f"MCP server {tool.name} holds {', '.join(c.name for c in tool.credentials)}", gated,
                f"remove or narrow the {tool.name} MCP server")  # fmt: skip
    return out


def assess_all(inv: Inventory, capabilities: dict[str, list[Capability]] | None = None) -> list[Assessment]:
    return [assess(agent, inv, capabilities) for agent in inv.agents]
