"""Tool poisoning: instructions hidden in the descriptions an agent reads before it does anything.

An MCP server sends the model every tool's name, description and parameter descriptions as soon as it
connects; a skill's or subagent's `description` is loaded so the model can decide when to use it. None of it
is shown to the user by default, all of it is read by the model as guidance, and whoever wrote the server or
skill wrote it. Invariant Labs showed the attack in 2025: an `add` tool whose description says to read
~/.ssh/id_rsa first, pass it in a spare parameter, and not mention it.

This module pulls those descriptions out of a local server's source (Python: docstrings and `description=` of
tool definitions; JavaScript/TypeScript: `description` strings and `server.tool(name, description, ...)`) and
out of skill and subagent frontmatter, then looks for what a description has no business saying:

* concealment from the user ("do not mention", "without telling the user");
* reading secrets: SSH keys, cloud credentials, other agents' MCP configs, .env files;
* overriding other instructions, or reaching into other tools' behaviour (shadowing);
* instruction blocks dressed as markup (<IMPORTANT>, <SYSTEM>).

A description that asks to read a secret and to hide it is high severity; each signal alone is medium.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Description:
    owner: str  # the tool, skill or subagent it describes
    line: int  # where the description starts in its file
    text: str


_CONCEAL = re.compile(
    r"\b(do\s+not|don't|never|must\s+not)\s+(mention|tell|inform|reveal|show|disclose|notify|alert)\b|"
    r"\bwithout\s+(telling|informing|notifying|alerting)\b|\bkeep\s+(this|it)\s+(secret|hidden|confidential)\b|"
    r"\bthe\s+user\s+(must|should)\s+not\s+(know|see|notice)\b|\bsilently\b",
    re.I,
)
_SECRETS = re.compile(
    r"~?/?\.ssh\b|\bid_(rsa|ed25519|ecdsa|dsa)\b|\.aws/(credentials|config)|\bmcp\.json\b|\.cursor/|"
    r"(^|[\s/'\"`])\.env\b|\.npmrc\b|\.netrc\b|\.git-credentials\b|\.kube/config|\.docker/config\.json|"
    r"\bprivate\s+key\b|\bapi[_\s-]?keys?\b|\bpasswords?\b|\bseed\s+phrase\b",
    re.I,
)
_OVERRIDE = re.compile(
    r"\bignore\s+(all\s+|any\s+)?(previous|prior|other|earlier)\s+(instructions|rules)\b|"
    r"\b(instead\s+of|regardless\s+of)\s+(what\s+)?the\s+user\b|\bthis\s+overrides\b",
    re.I,
)
_SHADOW = re.compile(
    r"\bwhen(ever)?\s+(the|any)\s+[\w-]+\s+tool\s+is\s+(used|called|invoked)\b|"
    r"\bbefore\s+(using|calling|invoking)\s+(any(\s+other)?|other|the\s+[\w-]+)\s+tools?\b",
    re.I,
)
_TAG = re.compile(r"<\s*/?\s*(important|system|instructions?|secret|hidden)\s*>", re.I)


@dataclass
class Signal:
    severity: str  # "high" | "medium"
    message: str
    line: int


def check(desc: Description) -> list[Signal]:
    """What is wrong with one description, if anything."""
    found = {
        "conceal": _CONCEAL.search(desc.text),
        "secrets": _SECRETS.search(desc.text),
        "override": _OVERRIDE.search(desc.text),
        "shadow": _SHADOW.search(desc.text),
        "tag": _TAG.search(desc.text),
    }

    def at(m: re.Match[str]) -> int:
        return desc.line + desc.text.count("\n", 0, m.start())

    out: list[Signal] = []
    conceal, secrets = found["conceal"], found["secrets"]
    named = ", ".join(dict.fromkeys(m.group(0).strip(" '\"`") for m in _SECRETS.finditer(desc.text)))
    if conceal and secrets:
        out.append(
            Signal(
                "high",
                f"tool poisoning: the description of {desc.owner} points the agent at secrets "
                f"({named}) and tells it to hide this ({conceal.group(0)!r})",
                at(secrets),
            )
        )
    else:
        if conceal:
            out.append(
                Signal(
                    "medium",
                    f"the description of {desc.owner} tells the agent to hide something from "
                    f"the user ({conceal.group(0)!r})",
                    at(conceal),
                )
            )
        if secrets:
            out.append(Signal("medium", f"the description of {desc.owner} mentions secrets ({named})", at(secrets)))
    if found["override"]:
        m = found["override"]
        out.append(
            Signal(
                "high", f"the description of {desc.owner} tries to override other instructions ({m.group(0)!r})", at(m)
            )
        )
    if found["shadow"]:
        m = found["shadow"]
        out.append(
            Signal(
                "medium",
                f"the description of {desc.owner} gives instructions about other tools "
                f"({m.group(0)!r}), which is how one server shadows another",
                at(m),
            )
        )
    if found["tag"] and out:
        m = found["tag"]
        out.append(Signal("medium", f"the description of {desc.owner} wraps instructions in a {m.group(0)} block",
                          at(m)))  # fmt: skip
    return out


# --- extraction ------------------------------------------------------------------------------------------


def _tool_decorator(node: ast.expr) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    name = target.attr if isinstance(target, ast.Attribute) else target.id if isinstance(target, ast.Name) else ""
    return name in ("tool", "prompt", "resource") or name.endswith("_tool")


def _python(text: str) -> list[Description]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    out: list[Description] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            _tool_decorator(d) for d in node.decorator_list
        ):
            doc = ast.get_docstring(node, clean=False)
            if doc and node.body and isinstance(node.body[0], ast.Expr):
                out.append(Description(node.name, node.body[0].lineno, doc))
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "description" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    owner = next((k.value.value for k in node.keywords if k.arg == "name"
                                  and isinstance(k.value, ast.Constant)), "a tool")  # fmt: skip
                    out.append(Description(str(owner), kw.value.lineno, kw.value.value))
    return out


_JS_STRING = r"""(?P<q>["'`])(?P<s>(?:\\.|(?!(?P=q)).)*)(?P=q)"""
_JS_DESCRIPTION = re.compile(r"\bdescription\s*:\s*" + _JS_STRING, re.S)
_JS_TOOL = re.compile(r"\.(?:tool|registerTool)\(\s*[\"'`](?P<name>[^\"'`]+)[\"'`]\s*,\s*" + _JS_STRING, re.S)


def _javascript(text: str) -> list[Description]:
    out = []
    for m in _JS_TOOL.finditer(text):
        out.append(Description(m.group("name"), text.count("\n", 0, m.start("s")) + 1, m.group("s")))
    for m in _JS_DESCRIPTION.finditer(text):
        out.append(Description("a tool", text.count("\n", 0, m.start("s")) + 1, m.group("s")))
    return out


_FRONTMATTER = re.compile(r"\A---\s*\n(?P<body>.*?)\n---\s*(\n|\Z)", re.S)


def _frontmatter(text: str, owner: str) -> list[Description]:
    """The `description` of a skill or subagent: always loaded, so the model can decide when to use it."""
    m = _FRONTMATTER.match(text)
    if not m:
        return []
    body = m.group("body")
    d = re.search(r"^description:\s*(?P<v>.*(?:\n[ \t]+.*)*)", body, re.M)
    if not d:
        return []
    return [Description(owner, 2 + body.count("\n", 0, d.start()), d.group("v").strip().strip("|>").strip())]


def descriptions(path: Path, role: str) -> list[Description]:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return []
    suffix = path.suffix.lower()
    if role == "mcp-server" and suffix == ".py":
        return _python(text)
    if role == "mcp-server" and suffix in (".js", ".mjs", ".cjs", ".ts", ".mts"):
        return _javascript(text)
    if role in ("skill", "subagent") and suffix == ".md":
        owner = path.parent.name if path.name.lower() == "skill.md" else path.stem
        return _frontmatter(text, owner)
    return []
