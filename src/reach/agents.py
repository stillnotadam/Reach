"""Discovery of AI agents, their tools, and the credentials those tools can use.

Reach answers "what can this agent actually reach?" in two halves. This
module is the first: an inventory of

* agents found on the machine or in a project (Claude Code, Claude Desktop,
  Cursor, VS Code, Windsurf),
* AI agents in GitHub Actions workflows (claude-code-action, Gemini CLI,
  Codex), with their triggers, token permissions and secrets,
* each agent's shell mode, from its own permission settings,
* the MCP servers each one is configured to run,
* the credentials each server is handed (environment variables, CLI
  arguments, HTTP headers, URLs), and
* ambient credentials: secrets on the machine that any agent with shell
  access can read (AWS profiles, the GitHub CLI login, Docker logins, ...).

The second half (what those credentials can do) feeds credentials into the
reasoning engine.

Hard rule: no secret value ever leaves this module. Findings carry names,
kinds and locations only; a hardcoded secret is reported as "hardcoded",
never shown. Values that are not secret by construction (an AWS profile
name, an MCP server's command) are kept, because they identify what to
resolve next.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --- credential classification ---------------------------------------------------

_KNOWN_ENV = {
    "aws_access_key_id": "aws-keys",
    "aws_secret_access_key": "aws-keys",
    "aws_session_token": "aws-keys",
    "aws_profile": "aws-profile",
    "github_token": "github-token",
    "gh_token": "github-token",
    "github_personal_access_token": "github-token",
    "gitlab_token": "gitlab-token",
    "slack_bot_token": "slack-token",
    "slack_user_token": "slack-token",
    "anthropic_api_key": "llm-api-key",
    "openai_api_key": "llm-api-key",
    "google_application_credentials": "gcp-credentials-file",
    "azure_client_secret": "azure-secret",
    "database_url": "database-url",
}
# Names that denote a secret. Deliberately not bare "auth": settings such as USE_LOCAL_OAUTH or
# OAUTH_SCOPES are flags, not secrets, and a scanner that cries wolf gets ignored.
_SECRETISH_NAME = re.compile(
    r"(token|secret|password|passwd|api[_-]?key|private[_-]?key|credentials?|access[_-]?key|auth[_-]?token|bearer)",
    re.I,
)
# Names that look secret-ish but describe a secret rather than hold one.
_NOT_A_VALUE = re.compile(
    r"(scopes?|_url|_uri|_file|_path|_dir|_type|_ttl|_expir|_refresh)$|^(use|has|enable|disable)_", re.I
)
# Prefixes of well-known secret formats. Used to spot secrets pasted into args or URLs.
_SECRET_PREFIXES = re.compile(
    r"(ghp_|gho_|ghu_|ghs_|github_pat_|glpat-|xox[abpors]-|AKIA[0-9A-Z]{12}|ASIA[0-9A-Z]{12}|sk-[A-Za-z0-9]|"
    r"sk_live_|rk_live_|AIza[0-9A-Za-z_-]{20})"
)
_REFERENCE = re.compile(r"^\$\{[^}]+\}$|^\$[A-Za-z_][A-Za-z0-9_]*$|^\{env:[^}]+\}$")


def _env_kind(name: str) -> str | None:
    lowered = name.lower()
    if lowered in _KNOWN_ENV:
        return _KNOWN_ENV[lowered]
    if _NOT_A_VALUE.search(lowered):
        return None
    if lowered.startswith("aws_") and _SECRETISH_NAME.search(lowered):
        return "aws-keys"
    if "github" in lowered and _SECRETISH_NAME.search(lowered):
        return "github-token"
    if "slack" in lowered and _SECRETISH_NAME.search(lowered):
        return "slack-token"
    if _SECRETISH_NAME.search(lowered):
        return "secret"
    return None


def _is_reference(value: Any) -> bool:
    """`${VAR}`, `$VAR` or `{env:VAR}`: a pointer to a secret held elsewhere, not the secret itself."""
    return isinstance(value, str) and bool(_REFERENCE.match(value.strip()))


# --- data model ------------------------------------------------------------------------


@dataclass
class Credential:
    kind: str  # e.g. "aws-profile", "aws-keys", "github-token", "secret"
    name: str  # env var, header, argument or profile name; never a secret value
    source: str  # file the credential reference was found in
    hardcoded: bool = False  # the secret itself is written in the config file
    detail: str = ""  # non-secret extra, e.g. the AWS profile name


@dataclass
class Tool:
    name: str
    transport: str  # "stdio" | "http"
    command: str = ""  # executable and arguments, secrets redacted
    url: str = ""  # scheme://host/path only: no userinfo, no query string
    credentials: list[Credential] = field(default_factory=list)


# How freely an agent can run shell commands:
#   unrestricted - with no human check (bypass mode, Bash allowed outright, CI agent with Bash)
#   approval     - a human approves each command (the default for local coding agents)
#   allowlist    - only pre-approved tools, and no human in the loop (typical CI agents)
#   denied       - shell explicitly blocked by the agent's settings
#   none         - the agent has no shell tool at all
SHELL_MODES = ("unrestricted", "approval", "allowlist", "denied", "none")


@dataclass
class Agent:
    name: str
    config: str
    shell_mode: str  # one of SHELL_MODES
    tools: list[Tool] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    local: bool = True  # runs on this machine; CI agents run on a runner and cannot read local files
    credentials: list[Credential] = field(default_factory=list)  # handed to the agent itself (CI secrets, tokens)

    @property
    def shell(self) -> bool:
        """Can this agent read the machine's ambient credentials (with or without a human approving)?"""
        return self.local and self.shell_mode in ("unrestricted", "approval")


@dataclass
class Inventory:
    agents: list[Agent] = field(default_factory=list)
    ambient: list[Credential] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def hardcoded(self) -> list[tuple[Agent, Tool, Credential]]:
        return [(a, t, c) for a in self.agents for t in a.tools for c in t.credentials if c.hardcoded]

    @property
    def findings(self) -> list[tuple[Agent, str]]:
        return [(a, f) for a in self.agents for f in a.findings]


# --- tolerant JSON ---------------------------------------------------------------------


def load_jsonc(path: Path) -> Any:
    """JSON with // and /* */ comments and trailing commas (VS Code style), respecting strings."""
    text = path.read_text(encoding="utf-8-sig")
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
        elif c == '"':
            in_string = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out))
    return json.loads(cleaned)


# --- redaction -------------------------------------------------------------------------


def _safe_url(raw: str) -> tuple[str, bool]:
    """(scheme://host/path, whether the stripped parts looked like they carried a secret)."""
    parts = urllib.parse.urlsplit(raw)
    leaked = bool(parts.username or parts.password)
    for key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        if _SECRETISH_NAME.search(key) or _SECRET_PREFIXES.search(value):
            leaked = True
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urllib.parse.urlunsplit((parts.scheme, host, parts.path, "", "")), leaked


def _redact_args(args: list[str], source: str) -> tuple[str, list[Credential]]:
    shown: list[str] = []
    found: list[Credential] = []
    previous = ""
    for arg in args:
        # Only a preceding `-x`/`--xyz` is a flag. A consumed value must never act as one:
        # an earlier version took a redacted secret for a flag name and leaked it that way.
        flag = previous.lower().lstrip("-") if previous.startswith("-") else ""
        consumed = False
        if flag in ("profile", "aws-profile"):
            found.append(Credential("aws-profile", previous, source, detail=arg))
            shown.append(arg)
            consumed = True
        elif _SECRET_PREFIXES.search(arg) or (flag and _SECRETISH_NAME.search(flag) and not _is_reference(arg)):
            found.append(Credential("secret", previous if flag else "argument", source, hardcoded=True))
            shown.append("<redacted>")
            consumed = True
        elif "=" in arg and _SECRETISH_NAME.search(arg.split("=", 1)[0]) and not _is_reference(arg.split("=", 1)[1]):
            found.append(Credential("secret", arg.split("=", 1)[0].lstrip("-"), source, hardcoded=True))
            shown.append(arg.split("=", 1)[0] + "=<redacted>")
        elif arg.startswith(("http://", "https://")):
            url, leaked = _safe_url(arg)
            if leaked:
                found.append(Credential("secret", "url", source, hardcoded=True))
            shown.append(url)
        else:
            shown.append(arg)
        previous = "" if consumed else arg
    return " ".join(shown), found


def parse_server(name: str, spec: dict[str, Any], source: str) -> Tool:
    """One MCP server entry, in any of the common config dialects."""
    url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl") or ""
    transport = "http" if url else "stdio"
    tool = Tool(name, transport)
    if url:
        tool.url, leaked = _safe_url(url)
        if leaked:
            tool.credentials.append(Credential("secret", "url", source, hardcoded=True))
    command = spec.get("command", "")
    args = [str(a) for a in spec.get("args", []) if a is not None]
    if command:
        tool.command, found = _redact_args([str(command), *args], source)
        tool.credentials.extend(found)
    for env_name, value in (spec.get("env") or {}).items():
        kind = _env_kind(env_name)
        if kind is None:
            continue
        if kind == "aws-profile":
            tool.credentials.append(Credential(kind, env_name, source, detail=str(value)))
        else:
            hardcoded = bool(value) and not _is_reference(value)
            tool.credentials.append(Credential(kind, env_name, source, hardcoded=hardcoded))
    for header, value in (spec.get("headers") or {}).items():
        if header.lower() in ("authorization", "proxy-authorization") or _SECRETISH_NAME.search(header):
            hardcoded = bool(value) and not _is_reference(str(value).split()[-1] if str(value).split() else "")
            tool.credentials.append(Credential("http-auth", header, source, hardcoded=hardcoded))
    return tool


# --- agents ----------------------------------------------------------------------------


def _servers(block: Any, source: str) -> list[Tool]:
    if not isinstance(block, dict):
        return []
    return [parse_server(name, spec, source) for name, spec in block.items() if isinstance(spec, dict)]


def _read(path: Path, inv: Inventory) -> Any:
    if not path.is_file():
        return None
    try:
        return load_jsonc(path)
    except (OSError, ValueError) as exc:
        inv.errors.append(f"{path}: {exc}")
        return None


def _add(
    inv: Inventory, name: str, path: Path, mode: str, tools: list[Tool], findings: list[str] | None = None
) -> None:
    inv.agents.append(Agent(name, str(path), mode, tools, list(findings or [])))


_ALL_BASH = frozenset({"bash", "bash(*)", "bash(:*)"})


def claude_code_mode(settings: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """Shell mode from Claude Code settings files, lowest precedence first (user, project, local)."""
    allow: list[str] = []
    deny: list[str] = []
    default_mode = None
    for data in settings:
        perms = data.get("permissions") if isinstance(data, dict) else None
        if not isinstance(perms, dict):
            continue
        allow += [r for r in perms.get("allow") or [] if isinstance(r, str)]
        deny += [r for r in perms.get("deny") or [] if isinstance(r, str)]
        default_mode = perms.get("defaultMode", default_mode)
    if any(r.strip().lower() in _ALL_BASH for r in deny):
        return "denied", []
    if default_mode == "bypassPermissions":
        return "unrestricted", [
            "defaultMode is bypassPermissions: every tool call, shell included, runs without approval"
        ]
    if any(r.strip().lower() in _ALL_BASH for r in allow):
        return "unrestricted", ["Bash is allowed for every command without approval"]
    findings = []
    pre = [r for r in allow if r.strip().lower().startswith("bash(")]
    if pre:
        findings.append(f"{len(pre)} shell command pattern(s) run without approval, e.g. {pre[0]}")
    return "approval", findings


def _claude_settings(inv: Inventory, *dirs: Path) -> list[dict[str, Any]]:
    out = []
    for d in dirs:
        for name in ("settings.json", "settings.local.json"):
            data = _read(d / name, inv)
            if isinstance(data, dict):
                out.append(data)
    return out


def discover_agents(inv: Inventory, home: Path, appdata: Path, project: Path | None) -> None:
    # Claude Code: user-level servers, per-project servers kept in ~/.claude.json, and a project's .mcp.json.
    user_settings = _claude_settings(inv, home / ".claude")
    data = _read(home / ".claude.json", inv)
    if isinstance(data, dict) or user_settings:
        data = data if isinstance(data, dict) else {}
        mode, findings = claude_code_mode(user_settings)
        tools = _servers(data.get("mcpServers"), str(home / ".claude.json"))
        _add(inv, "Claude Code (user)", home / ".claude.json", mode, tools, findings)
        for proj, cfg in (data.get("projects") or {}).items():
            if isinstance(cfg, dict) and cfg.get("mcpServers"):
                mode, findings = claude_code_mode(user_settings + _claude_settings(inv, Path(proj) / ".claude"))
                tools = _servers(cfg["mcpServers"], str(home / ".claude.json"))
                _add(inv, f"Claude Code ({proj})", home / ".claude.json", mode, tools, findings)
    for desktop in (
        appdata / "Claude",
        home / "Library" / "Application Support" / "Claude",
        home / ".config" / "Claude",
    ):
        path = desktop / "claude_desktop_config.json"
        data = _read(path, inv)
        if isinstance(data, dict):
            _add(inv, "Claude Desktop", path, "none", _servers(data.get("mcpServers"), str(path)))
            break
    path = home / ".cursor" / "mcp.json"
    data = _read(path, inv)
    if isinstance(data, dict):
        _add(inv, "Cursor (user)", path, "approval", _servers(data.get("mcpServers"), str(path)))
    path = home / ".codeium" / "windsurf" / "mcp_config.json"
    data = _read(path, inv)
    if isinstance(data, dict):
        _add(inv, "Windsurf", path, "approval", _servers(data.get("mcpServers"), str(path)))
    for user_dir in (
        appdata / "Code" / "User",
        home / "Library" / "Application Support" / "Code" / "User",
        home / ".config" / "Code" / "User",
    ):
        for name in ("mcp.json", "settings.json"):
            path = user_dir / name
            data = _read(path, inv)
            if isinstance(data, dict):
                block = data.get("servers") if name == "mcp.json" else (data.get("mcp") or {}).get("servers")
                if block:
                    _add(inv, "VS Code (user)", path, "approval", _servers(block, str(path)))

    if project is not None:
        project_settings = _claude_settings(inv, project / ".claude")
        data = _read(project / ".mcp.json", inv)
        if isinstance(data, dict) or project_settings:
            data = data if isinstance(data, dict) else {}
            mode, findings = claude_code_mode(user_settings + project_settings)
            tools = _servers(data.get("mcpServers"), str(project / ".mcp.json"))
            _add(inv, "Claude Code (project)", project / ".mcp.json", mode, tools, findings)
        for rel, agent, key in ((".cursor/mcp.json", "Cursor (project)", "mcpServers"),
                                (".vscode/mcp.json", "VS Code (project)", "servers")):  # fmt: skip
            path = project / rel
            data = _read(path, inv)
            if isinstance(data, dict):
                _add(inv, agent, path, "approval", _servers(data.get(key), str(path)))
        discover_workflows(inv, project)


# --- AI agents in GitHub Actions -------------------------------------------------------

AGENT_ACTIONS = {
    "anthropics/claude-code-action": "Claude Code",
    "anthropics/claude-code-base-action": "Claude Code",
    "google-github-actions/run-gemini-cli": "Gemini CLI",
    "openai/codex-action": "Codex",
    "actions/ai-inference": "GitHub AI Inference",
}
# Events whose payload (issue bodies, comments, PR titles from forks) anyone on the internet can write.
UNTRUSTED_TRIGGERS = frozenset({
    "issue_comment", "issues", "pull_request_target", "pull_request_review_comment", "pull_request_review",
    "discussion", "discussion_comment",
})  # fmt: skip
_SECRET_REF = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
_UNRESTRICTED_HINTS = re.compile(r"dangerously|--yolo|danger-full-access|bypassPermissions", re.I)
_BARE_BASH = re.compile(r"\bBash\b(?!\()")


def _load_yaml(path: Path, inv: Inventory) -> Any:
    from ruamel.yaml import YAML  # noqa: PLC0415 - only needed for workflows
    from ruamel.yaml.error import YAMLError  # noqa: PLC0415

    try:
        return YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8-sig"))
    except (OSError, YAMLError) as exc:
        inv.errors.append(f"{path}: {exc}")
        return None


def _triggers(on: Any) -> list[str]:
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [t for t in on if isinstance(t, str)]
    if isinstance(on, dict):
        return [t for t in on if isinstance(t, str)]
    return []


def _describe_permissions(perms: Any) -> tuple[str, bool]:
    """(human summary, whether the token can write anything)."""
    if perms is None:
        return "default token permissions (a repository setting; may be read-write)", True
    if isinstance(perms, str):
        return perms, perms == "write-all"
    if isinstance(perms, dict):
        writes = sorted(k for k, v in perms.items() if v == "write")
        if not writes:
            return "read-only", False
        return "write: " + ", ".join(writes), True
    return str(perms), True


def discover_workflows(inv: Inventory, project: Path) -> None:
    folder = project / ".github" / "workflows"
    if not folder.is_dir():
        return
    for path in sorted([*folder.glob("*.yml"), *folder.glob("*.yaml")]):
        wf = _load_yaml(path, inv)
        if not isinstance(wf, dict):
            continue
        triggers = _triggers(wf.get("on", wf.get(True)))
        untrusted = sorted(set(triggers) & UNTRUSTED_TRIGGERS)
        for job_id, job in (wf.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            perms = job.get("permissions", wf.get("permissions"))
            for step in job.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                action = str(step.get("uses", "")).split("@")[0].lower()
                if action not in AGENT_ACTIONS:
                    continue
                inv.agents.append(_workflow_agent(path, wf, job_id, job, step, AGENT_ACTIONS[action], perms, untrusted))


def _workflow_agent(path, wf, job_id, job, step, label, perms, untrusted) -> Agent:
    config_text = repr(step.get("with") or {})
    unrestricted = _UNRESTRICTED_HINTS.search(config_text) or _BARE_BASH.search(config_text)
    mode = "unrestricted" if unrestricted else "allowlist"
    agent = Agent(f"{label} in {path.name}:{job_id}", str(path), mode, local=False)

    summary, can_write = _describe_permissions(perms)
    agent.credentials.append(Credential("github-token", "GITHUB_TOKEN", str(path), detail=summary))
    if isinstance(perms, dict) and perms.get("id-token") == "write":
        agent.credentials.append(
            Credential("oidc-token", "id-token: write", str(path), detail="can request cloud credentials via OIDC")
        )
    scopes = [wf.get("env"), job.get("env"), step.get("env"), step.get("with")]
    secrets = sorted({m for scope in scopes for m in _SECRET_REF.findall(repr(scope or {}))})
    for name in secrets:
        if name != "GITHUB_TOKEN":
            agent.credentials.append(Credential(_env_kind(name) or "secret", name, str(path)))

    if untrusted:
        gate = " ".join(str(c) for c in (job.get("if"), step.get("if")) if c)
        gated = f" (gated by `if: {gate[:120]}`)" if gate else " (no `if:` gate on who can trigger it)"
        agent.findings.append(f"triggered by {', '.join(untrusted)}: text anyone can write reaches the agent{gated}")
        held = ([summary] if can_write else []) + [n for n in secrets if n != "GITHUB_TOKEN"]
        if held:
            agent.findings.append("a prompt injection there could use: " + "; ".join(held))
    if mode == "unrestricted":
        agent.findings.append("the agent may run arbitrary shell commands on the runner")
    return agent


# --- ambient credentials ---------------------------------------------------------------


def _ini_sections(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return []
    return [m.group(1).strip() for line in lines if (m := re.match(r"^\s*\[([^\]]+)\]\s*$", line))]


# Environment variables whose names look secret-ish but never hold a secret.
_NOT_SECRETS = frozenset(
    {
        "SSH_AUTH_SOCK",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "VSCODE_GIT_ASKPASS_MAIN",
        "VSCODE_GIT_ASKPASS_NODE",
        "VSCODE_GIT_ASKPASS_EXTRA_ARGS",
        "VSCODE_GIT_IPC_HANDLE",
    }
)


def discover_ambient(inv: Inventory, home: Path, environ: dict[str, str], project: Path | None) -> None:
    """Credentials any agent with shell access can read, whether or not a tool was given them."""
    seen: set[str] = set()
    for path in (home / ".aws" / "credentials", home / ".aws" / "config"):
        for section in _ini_sections(path):
            profile = section.removeprefix("profile ").strip()
            if profile not in seen:
                seen.add(profile)
                inv.ambient.append(Credential("aws-profile", profile, str(path), detail=profile))
    for name, value in environ.items():
        if name.upper() in _NOT_SECRETS:
            continue
        kind = _env_kind(name)
        if kind is not None:
            detail = value if kind == "aws-profile" else ""
            inv.ambient.append(Credential(kind, name, "environment", detail=detail))
    for path, kind in (
        (home / ".config" / "gh" / "hosts.yml", "github-cli-login"),
        (home / "AppData" / "Roaming" / "GitHub CLI" / "hosts.yml", "github-cli-login"),
        (home / ".docker" / "config.json", "docker-login"),
        (home / ".netrc", "netrc"),
        (home / "_netrc", "netrc"),
        (home / ".config" / "gcloud" / "application_default_credentials.json", "gcp-adc"),
        (home / ".azure" / "msal_token_cache.json", "azure-login"),
        (home / ".kube" / "config", "kubeconfig"),
        (home / ".ssh" / "id_ed25519", "ssh-key"),
        (home / ".ssh" / "id_rsa", "ssh-key"),
    ):
        if path.is_file():
            inv.ambient.append(Credential(kind, path.name, str(path)))
    if project is not None:
        for env_file in sorted(project.glob(".env*")):
            if env_file.is_file() and not env_file.name.endswith((".example", ".sample", ".template")):
                names = _dotenv_secret_names(env_file)
                tracked = "tracked in git: the secret is in the repository history" if _git_tracked(env_file) else ""
                for name, kind in names:
                    inv.ambient.append(Credential(kind, name, str(env_file), hardcoded=True, detail=tracked))


def _git_tracked(path: Path) -> bool:
    """Is this file committed to a git repository? False when git or a repository is missing."""
    git = shutil.which("git")
    if git is None:
        return False
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [git, "-C", str(path.parent), "ls-files", "--error-unmatch", path.name],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def _dotenv_secret_names(path: Path) -> list[tuple[str, str]]:
    out = []
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError:
        return out
    for line in lines:
        m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if m and m.group(2).strip().strip("\"'") and (kind := _env_kind(m.group(1))):
            out.append((m.group(1), kind))
    return out


def discover(
    home: Path | None = None,
    project: Path | None = None,
    environ: dict[str, str] | None = None,
    appdata: Path | None = None,
) -> Inventory:
    home = home or Path.home()
    environ = dict(os.environ) if environ is None else environ
    appdata = appdata or Path(environ.get("APPDATA") or home / "AppData" / "Roaming")
    inv = Inventory()
    discover_agents(inv, home, appdata, project)
    discover_ambient(inv, home, environ, project)
    return inv
