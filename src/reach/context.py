"""What agents read without being asked, and whether someone has planted instructions in it.

An agent's context is not only the prompt. Coding agents load instruction files on every session (CLAUDE.md,
AGENTS.md, Cursor and Windsurf rules, Copilot instructions), pull in skills and subagents when their description
matches the task, and see every MCP tool's name and description before the first message. Text in any of these
reaches the model with the authority of the user's own setup, and whoever can write it can steer the agent: a
cloned repository's CLAUDE.md, a third-party skill or plugin, an MCP server whose tool descriptions carry
instructions (tool poisoning).

This module finds that text for each agent and, when Husk (https://github.com/ctrl-adam/Husk, `pip install
reach-security[husk]`) is installed, scans it. Husk's findings come back with a severity and are sorted here by
what they mean for the agent:

* injection: instructions aimed at the agent (override phrasing, directives hidden in comments, invisible or
  bidirectional Unicode). This is untrusted input that is already in place: the trifecta's first leg, with no
  human in the way, because the text is loaded automatically;
* exfiltration, credentials, code: what a skill's or server's own code does (sends credentials out, contacts a
  bare IP, runs a download). Reported as findings on the agent.

The source of a local MCP server is scanned because that is where its tool descriptions are written. Servers run
from a package registry (npx, uvx) are not fetched: Reach never downloads or runs anything to inspect it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .agents import _SECRET_PREFIXES, Agent, Inventory
from .descriptions import check, descriptions

INJECTION, EXFILTRATION, CREDENTIALS, CODE = "injection", "exfiltration", "credentials", "code"
SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_FILE_BYTES = 1_000_000
MAX_SERVER_FILES = 200  # per local MCP server directory
_SOURCE_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".json", ".md", ".sh", ".ps1")
_SKIP_DIRS = frozenset({"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".tox"})

# Husk's finding text, sorted by what it means for the agent. First match wins.
_CATEGORIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (INJECTION, re.compile(
        r"directive language aimed at the AI agent|instruction-override|instruction override|prompt[- ]injection|"
        r"bidirectional-override|Unicode tag character|zero-width|invisible|steganograph|secrecy|conceal|"
        r"safety[- ](confirmation|bypass)|supersede|hidden instruction|hidden comment",
        re.I,
    )),
    (EXFILTRATION, re.compile(
        r"HUSK-EXF|sent over the network|exfiltrat|beacon|bare IP|command-and-control|C2\b|network-send|"
        r"DNS[- ]covert|tunnel",
        re.I,
    )),
    (CREDENTIALS, re.compile(r"credential|wallet|password|keychain|\.aws|ssh key|private key", re.I)),
)  # fmt: skip
_LINE = re.compile(r"\bLine (\d+):")


@dataclass
class Issue:
    severity: str  # one of SEVERITIES (Husk's gate tiers)
    category: str  # INJECTION | EXFILTRATION | CREDENTIALS | CODE
    message: str  # Husk's finding, secret-shaped strings redacted
    line: int | None = None

    @property
    def short(self) -> str:
        """The finding without its line prefix, up to Husk's explanation."""
        text = _LINE.sub("", self.message, count=1).strip()
        return text.split(" - ", 1)[0]


@dataclass
class ContextFile:
    path: str
    role: str  # instructions | rules | skill | command | subagent | mcp-server
    scope: str  # user | project | plugin | local (an MCP server's own files)
    automatic: bool = True  # loaded without anyone asking (a slash command needs a person to type it)
    checked: bool = False  # its tool, skill or subagent descriptions were checked (descriptions.py)
    scanned: bool = False  # the whole file was scanned by Husk
    issues: list[Issue] = field(default_factory=list)

    @property
    def injected(self) -> list[Issue]:
        """Instructions aimed at the agent, at Husk's warning severity (medium) and above."""
        found = [i for i in self.issues if i.category == INJECTION and _at_least(i.severity, "medium")]
        found.sort(key=lambda i: SEVERITIES.index(i.severity))
        # Husk can report one line twice (overt and plain override phrasing): keep the most severe per line.
        out: list[Issue] = []
        for issue in found:
            if issue.line is None or all(issue.line != kept.line for kept in out):
                out.append(issue)
        return out


def _at_least(severity: str, floor: str) -> bool:
    return SEVERITIES.index(severity) <= SEVERITIES.index(floor)


# --- what each agent reads ---------------------------------------------------------------------------------


def _files(base: Path, patterns: Iterable[str]) -> list[Path]:
    out: list[Path] = []
    for pattern in patterns:
        out.extend(p for p in sorted(base.glob(pattern)) if p.is_file())
    return out


def _claude_dir(base: Path, scope: str) -> list[ContextFile]:
    """Skills, slash commands and subagents under a .claude directory (or a plugin root)."""
    out = [ContextFile(str(p), "skill", scope) for p in _files(base, ["skills/*/*", "skills/*/scripts/*"])]
    out += [ContextFile(str(p), "command", scope, automatic=False) for p in _files(base, ["commands/**/*.md"])]
    out += [ContextFile(str(p), "subagent", scope) for p in _files(base, ["agents/**/*.md"])]
    return out


def _plugin_roots(home: Path) -> list[Path]:
    """Install paths of Claude Code plugins, from installed_plugins.json (any version of its layout)."""
    path = home / ".claude" / "plugins" / "installed_plugins.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return []
    roots: list[Path] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "installPath" and isinstance(value, str):
                    roots.append(Path(value))
                else:
                    walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(data)
    return [r for r in dict.fromkeys(roots) if r.is_dir()]


def claude_code_context(home: Path, project: Path | None) -> list[ContextFile]:
    out = [ContextFile(str(p), "instructions", "user") for p in _files(home / ".claude", ["CLAUDE.md"])]
    out += _claude_dir(home / ".claude", "user")
    for root in _plugin_roots(home):
        out += _claude_dir(root, "plugin")
    if project is not None:
        out += [ContextFile(str(p), "instructions", "project")
                for p in _files(project, ["CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md"])]  # fmt: skip
        out += _claude_dir(project / ".claude", "project")
    return out


def project_context(kind: str, project: Path) -> list[ContextFile]:
    """Instruction and rule files other agents read from a project."""
    patterns = {
        "cursor": ["AGENTS.md", ".cursorrules", ".cursor/rules/**/*.mdc", ".cursor/rules/**/*.md"],
        "windsurf": ["AGENTS.md", ".windsurfrules", ".windsurf/rules/**/*.md"],
        "vscode": ["AGENTS.md", ".github/copilot-instructions.md", ".github/instructions/**/*.md",
                   ".github/prompts/*.prompt.md"],
        "codex": ["AGENTS.md"],
        "gemini": ["GEMINI.md", "AGENTS.md"],
    }.get(kind, [])  # fmt: skip
    return [ContextFile(str(p), "instructions" if p.name in ("AGENTS.md", "GEMINI.md") else "rules", "project")
            for p in _files(project, patterns)]  # fmt: skip


def _server_sources(paths: list[str], cwd: Path | None) -> list[Path]:
    """The local files and directories an MCP server runs: its tool descriptions are written there."""
    out: list[Path] = []
    for arg in paths:
        p = Path(arg).expanduser()
        if not p.is_absolute() and cwd is not None:
            p = cwd / p
        if (p.is_file() and p.suffix.lower() in _SOURCE_SUFFIXES) or (p.is_dir() and p != Path.home()):
            out.append(p)
    return out


def _walk_sources(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in sorted(root.rglob("*")):
        if len(out) >= MAX_SERVER_FILES:
            break
        if any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.is_file() and p.suffix.lower() in _SOURCE_SUFFIXES:
            out.append(p)
    return out


def mcp_server_context(agent: Agent, project: Path | None) -> list[ContextFile]:
    out: list[ContextFile] = []
    for tool in agent.tools:
        if tool.transport != "stdio" or not tool.command:
            continue
        cwd = Path(tool.cwd).expanduser() if tool.cwd else project
        for source in _server_sources(tool.paths, cwd):
            files = [source] if source.is_file() else _walk_sources(source)
            out += [ContextFile(str(f), "mcp-server", "local") for f in files]
    return out


def discover_context(inv: Inventory, home: Path, project: Path | None) -> None:
    """Attach to each agent the files it reads into its context. Local agents also read the project's files
    when Reach is pointed at one, since that is where they are used."""
    ci_kinds = {"Claude Code": "claude-code", "Codex": "codex", "Gemini CLI": "gemini"}
    for agent in inv.agents:
        files: list[ContextFile] = []
        kind = agent.kind
        if kind == "ci":
            kind = next((v for k, v in ci_kinds.items() if agent.name.startswith(k)), "")
            if kind == "claude-code" and project is not None:
                files += [f for f in claude_code_context(home, project) if f.scope == "project"]
            elif project is not None:
                files += project_context(kind, project)
        elif kind == "claude-code":
            own = _own_project(agent)
            files += claude_code_context(home, own or project)
        elif project is not None and kind in ("cursor", "windsurf", "vscode"):
            files += project_context(kind, project)
        files += mcp_server_context(agent, _own_project(agent) or project)
        agent.context = list({f.path: f for f in files}.values())


def _own_project(agent: Agent) -> Path | None:
    """A per-project Claude Code agent from ~/.claude.json, 'Claude Code (C:/path)', works in that project."""
    m = re.fullmatch(r"Claude Code \((.+)\)", agent.name)
    if m and m.group(1) not in ("user", "project"):
        return Path(m.group(1))
    return None


# --- scanning ----------------------------------------------------------------------------------------------


def husk_available() -> bool:
    try:
        import husk.gate  # noqa: F401, PLC0415 - optional dependency
        import husk.skill_scanner  # noqa: F401, PLC0415
    except ImportError:
        return False
    return True


def _redact(text: str) -> str:
    """Husk quotes the text it flags; a secret-shaped token must not reach Reach's output."""
    return re.sub(_SECRET_PREFIXES.pattern + r"[A-Za-z0-9_\-]*", "[redacted]", text)


def categorise(message: str) -> str:
    for category, pattern in _CATEGORIES:
        if pattern.search(message):
            return category
    return CODE


def scan_file(path: str) -> list[Issue]:
    """Husk's findings for one file. Raises ImportError when Husk is not installed."""
    from husk.gate import classify_severity  # noqa: PLC0415 - optional dependency
    from husk.skill_scanner import scan_skill_file  # noqa: PLC0415

    p = Path(path)
    if p.stat().st_size > MAX_FILE_BYTES:
        return [Issue("info", CODE, f"not scanned: larger than {MAX_FILE_BYTES // 1_000_000} MB")]
    result = scan_skill_file(str(p))
    if result.get("verdict") != "FLAGGED":
        return []
    findings: list[str] = result.get("findings", [])
    info: list[bool] = result.get("info") or [False] * len(findings)  # Husk 1.6+ marks info-only findings
    issues = []
    for message, is_info in zip(findings, info):
        severity = "info" if is_info else classify_severity(message)
        m = _LINE.search(message)
        issues.append(Issue(severity, categorise(message), _redact(message), int(m.group(1)) if m else None))
    return issues


def check_descriptions(f: ContextFile) -> list[Issue]:
    """Reach's own check of the tool, skill and subagent descriptions in a file (descriptions.py)."""
    return [
        Issue(s.severity, INJECTION, s.message, s.line) for d in descriptions(Path(f.path), f.role) for s in check(d)
    ]


def scan_inventory(inv: Inventory, husk: bool = True) -> int:
    """Check every context file once (agents share files): descriptions always, the whole file with Husk when
    `husk` is set and Husk is installed. Returns how many files were checked."""
    husk = husk and husk_available()
    cache: dict[str, list[Issue]] = {}
    for agent in inv.agents:
        for f in agent.context:
            if f.path not in cache:
                try:
                    cache[f.path] = check_descriptions(f) + (scan_file(f.path) if husk else [])
                except OSError as exc:
                    inv.errors.append(f"{f.path}: {exc}")
                    cache[f.path] = []
            f.issues = cache[f.path]
            f.checked, f.scanned = True, husk
    return len(cache)


def malicious(f: ContextFile) -> list[Issue]:
    """What the file's own code does, at Husk's blocking severity (high and above)."""
    return [i for i in f.issues if i.category != INJECTION and _at_least(i.severity, "high")]
