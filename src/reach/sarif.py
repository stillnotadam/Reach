"""SARIF 2.1.0 output for `reach agents`, the format GitHub code scanning ingests.

Each finding becomes one result: a lethal trifecta per agent, a hardcoded
secret per credential, each risky agent setting, and each Husk finding in
the text agents load (planted instructions, malicious skill or server code). Results point at the
file and, where Reach can find it, the line that causes them. Files inside
the scanned project get repository-relative URIs (so code scanning can show
them on pull requests); files elsewhere keep absolute file URIs.

Every result carries a partial fingerprint built from what the finding is
about, not where it sits, so an alert keeps its identity when lines move.
Secret values never appear: results name the variable, header or argument.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from . import __version__
from .agents import Agent, Credential, Inventory, Tool
from .context import ContextFile, Issue, malicious
from .trifecta import LEGS, Assessment

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/ctrl-adam/Reach"

# id, name, short description, full description, default level, GitHub security-severity
RULES: tuple[tuple[str, str, str, str, str, str], ...] = (
    ("REACH001", "LethalTrifecta",
     "Agent combines untrusted input, private data and an exfiltration channel",
     "Text an attacker plants where the agent reads it can instruct the agent to send private data out. No "
     "prompt-level defence reliably prevents this; remove one leg. Critical: every leg is usable with no human "
     "approval. High: a human approval stands in the way of at least one leg.", "error", "9.0"),
    ("REACH002", "HardcodedSecret",
     "Secret written directly in an agent or MCP configuration",
     "The secret value is stored in the configuration file, where anything that reads the file (including the agent) "
     "can read it. Reference it from the environment or a secret store instead, and rotate it.", "error", "8.0"),
    ("REACH003", "RiskyAgentSetting",
     "Agent setting removes a human check",
     "The agent's own settings let it run tools or shell commands without approval.", "warning", "6.0"),
    ("REACH004", "CommittedSecret",
     "Secret in a .env file that is committed to git",
     "The value is in the repository history, readable by anyone with the repository and by agents working in it. "
     "Rotate it, remove the file from git and add it to .gitignore.", "error", "8.5"),
    ("REACH005", "PlantedInstructions",
     "Instructions aimed at the agent in text it loads into its context",
     "An instruction file, rule, skill, subagent, command or local MCP server's tool descriptions contain text "
     "that tells the agent what to do: override phrasing, a directive hidden in a comment, or invisible Unicode. "
     "The agent reads it with the authority of your own setup. Found by Husk.", "error", "8.8"),
    ("REACH006", "MaliciousContextCode",
     "Code in a skill or local MCP server that steals or sends data",
     "A script or server the agent runs does something Husk blocks on: sends credentials over the network, "
     "contacts a bare IP, runs a download. Remove it and review where it came from.", "error", "9.3"),
)  # fmt: skip
_LEVEL = {"critical": "error", "high": "warning"}
_SEVERITY = {"critical": "9.5", "high": "7.5"}


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:32]


def _line_of(path: str, *needles: str) -> int | None:
    """First line containing a needle (earlier needles win), or None. An unreadable file has no lines."""
    try:
        lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    for needle in needles:
        for number, line in enumerate(lines, 1):
            if needle and needle in line:
                return number
    return None


def _find(paths: list[str], needles: tuple[str, ...]) -> tuple[str, int]:
    """The file and line that best explain a finding: the first needle found, searching each file in order."""
    for needle in needles:
        for path in paths:
            line = _line_of(path, needle)
            if line is not None:
                return path, line
    return paths[0], 1


def _agent_files(agent: Agent) -> list[str]:
    """Most specific first: settings override in reverse order of reading (local project settings win)."""
    return [*reversed(agent.settings), agent.config]


# Which text in a config causes a finding, keyed by words in the finding.
_NEEDLES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("bypassPermissions", ("bypassPermissions",)),
    ("Bash is allowed", ('"Bash"', '"Bash(*)"', "Bash(:*)")),
    ("shell command pattern", ("Bash(",)),
    ("triggered by", ("on:",)),
    ("prompt injection there could use", ("permissions:", "id-token", "secrets.")),
    ("shell commands on the runner", ("Bash", "allowed_tools", "claude_args")),
)


class _Locator:
    def __init__(self, project: Path | None) -> None:
        self.root = project.resolve() if project else None

    def __call__(self, path: str, line: int = 1) -> dict[str, Any]:
        resolved = Path(path).resolve()
        artifact: dict[str, Any]
        if self.root is not None and resolved.is_relative_to(self.root):
            artifact = {"uri": resolved.relative_to(self.root).as_posix(), "uriBaseId": "%SRCROOT%"}
        else:
            artifact = {"uri": resolved.as_uri()}
        return {"physicalLocation": {"artifactLocation": artifact, "region": {"startLine": line}}}


def _trifecta_result(a: Assessment, agent: Agent, locate: _Locator) -> dict[str, Any]:
    fix = a.cheapest_fix()
    legs = "; ".join(f"{kind}: {', '.join(leg.source for leg in a.legs[kind])}" for kind in LEGS)
    text = f"{a.severity.upper()}: {agent.name} has all three trifecta legs. {legs}."
    if fix:
        text += f" Cheapest fix, break the {fix[0]} leg: {fix[1]}."
    if agent.kind == "ci":
        needles: tuple[str, ...] = ("on:",)
    else:
        needles = ("bypassPermissions", *(f'"{t.name}"' for t in agent.tools))
    return {
        "ruleId": "REACH001",
        "level": _LEVEL[a.severity],
        "message": {"text": text},
        "locations": [locate(*_find(_agent_files(agent), needles))],
        "partialFingerprints": {"reach/v1": _fingerprint("REACH001", agent.name, agent.config)},
        "properties": {"security-severity": _SEVERITY[a.severity], "severity": a.severity, "agent": agent.name},
    }


def _secret_result(agent: Agent, tool: Tool, cred: Credential, locate: _Locator) -> dict[str, Any]:
    where = f"MCP server {tool.name}" if tool.name else agent.name
    return {
        "ruleId": "REACH002",
        "level": "error",
        "message": {"text": f"{where} has a hardcoded secret in {cred.name} ({cred.kind}). The value is not shown."},
        "locations": [locate(*_find([cred.source], (cred.name, f'"{tool.name}"')))],
        "partialFingerprints": {"reach/v1": _fingerprint("REACH002", cred.source, tool.name, cred.name)},
        "properties": {"security-severity": "8.0", "agent": agent.name},
    }


def _needles(finding: str) -> tuple[str, ...]:
    return next((needles for words, needles in _NEEDLES if words in finding), ())


def _setting_result(agent: Agent, finding: str, locate: _Locator) -> dict[str, Any]:
    return {
        "ruleId": "REACH003",
        "level": "warning",
        "message": {"text": f"{agent.name}: {finding}"},
        "locations": [locate(*_find(_agent_files(agent), _needles(finding)))],
        "partialFingerprints": {"reach/v1": _fingerprint("REACH003", agent.name, finding)},
        "properties": {"security-severity": "6.0", "agent": agent.name},
    }


def _committed_result(cred: Credential, locate: _Locator) -> dict[str, Any]:
    return {
        "ruleId": "REACH004",
        "level": "error",
        "message": {"text": f"{cred.name} is set in {Path(cred.source).name}, which is committed to git. "
                            "The value is not shown."},
        "locations": [locate(*_find([cred.source], (f"{cred.name}=", cred.name)))],
        "partialFingerprints": {"reach/v1": _fingerprint("REACH004", cred.source, cred.name)},
        "properties": {"security-severity": "8.5"},
    }  # fmt: skip


def _context_result(rule: str, f: ContextFile, issue: Issue, agents: list[str], locate: _Locator) -> dict[str, Any]:
    level = "error" if issue.severity in ("critical", "high") or rule == "REACH005" else "warning"
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": f"{f.role} read by {', '.join(agents)}: {issue.message}"},
        "locations": [locate(f.path, issue.line or 1)],
        "partialFingerprints": {"reach/v1": _fingerprint(rule, f.path, issue.short)},
        "properties": {"security-severity": "8.8" if rule == "REACH005" else "9.3", "severity": issue.severity},
    }


def _context_results(inv: Inventory, locate: _Locator) -> list[dict[str, Any]]:
    """One result per finding in a file, however many agents read the file."""
    readers: dict[tuple[str, str, int | None, str], tuple[ContextFile, Issue, list[str]]] = {}
    for agent in inv.agents:
        for f in agent.context:
            for rule, issues in (("REACH005", f.injected), ("REACH006", malicious(f))):
                for issue in issues:
                    entry = readers.setdefault((rule, f.path, issue.line, issue.short), (f, issue, []))
                    if agent.name not in entry[2]:
                        entry[2].append(agent.name)
    return [_context_result(rule, f, issue, agents, locate) for (rule, *_), (f, issue, agents) in readers.items()]


def to_sarif(inv: Inventory, assessments: list[Assessment], project: Path | None = None) -> dict[str, Any]:
    locate = _Locator(project)
    by_name = {a.name: a for a in inv.agents}
    results: list[dict[str, Any]] = []
    for a in assessments:
        if a.severity in _LEVEL:
            results.append(_trifecta_result(a, by_name[a.agent], locate))
    for agent, tool, cred in inv.hardcoded:
        results.append(_secret_result(agent, tool, cred, locate))
    for agent, finding in inv.findings:
        results.append(_setting_result(agent, finding, locate))
    for cred in inv.ambient:
        if cred.hardcoded and cred.detail.startswith("tracked in git"):
            results.append(_committed_result(cred, locate))
    results.extend(_context_results(inv, locate))
    rules = [
        {
            "id": rid,
            "name": name,
            "shortDescription": {"text": short},
            "fullDescription": {"text": full},
            "helpUri": f"{INFO_URI}#{'lethal-trifecta' if rid == 'REACH001' else 'in-ci-github-code-scanning'}",
            "defaultConfiguration": {"level": level},
            "properties": {"security-severity": severity, "tags": ["security", "ai-agents"]},
        }
        for rid, name, short, full, level, severity in RULES
    ]
    run: dict[str, Any] = {
        "tool": {"driver": {"name": "Reach", "version": __version__, "informationUri": INFO_URI, "rules": rules}},
        "results": results,
    }
    if project is not None:
        run["originalUriBaseIds"] = {"%SRCROOT%": {"uri": project.resolve().as_uri() + "/"}}
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}
