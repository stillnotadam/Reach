from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from reach.agents import _env_kind, discover, load_jsonc, parse_server
from reach.cli import _render_inventory

# Distinctive fake secrets: the redaction test fails if any of them appears anywhere in the output.
FAKE = {
    "github": "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234",
    "aws_secret": "fAkE/SeCrEt/KeY/for/reach/tests/0000000000",
    "aws_id": "AKIAFAKEFAKEFAKE1234",
    "slack": "xoxb-0000-fake-slack-token",
    "bearer": "fake-bearer-token-value-9999",
    "url_token": "fake-query-token-7777",
    "dotenv": "sk-fakeopenaikey000000000000",
    "arg": "fake-cli-arg-secret-5555",
    "db_password": "fake-db-password-3333",
}


def write(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def machine(tmp_path: Path):
    home, project, appdata = tmp_path / "home", tmp_path / "project", tmp_path / "home" / "AppData" / "Roaming"
    write(home / ".claude.json", {
        "mcpServers": {
            "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                       "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": FAKE["github"]}},
            "aws": {"command": "uvx", "args": ["awslabs.aws-api-mcp-server", "--profile", "prod-admin"]},
        },
        "projects": {"C:/work/api": {"mcpServers": {
            "remote": {"type": "http", "url": f"https://mcp.example.com/sse?token={FAKE['url_token']}",
                       "headers": {"Authorization": f"Bearer {FAKE['bearer']}"}},
        }}},
    })  # fmt: skip
    write(appdata / "Claude" / "claude_desktop_config.json", {
        "mcpServers": {"slack": {"command": "npx", "args": ["slack-mcp"],
                                 "env": {"SLACK_BOT_TOKEN": FAKE["slack"], "SLACK_TEAM_ID": "T123"}}},
    })  # fmt: skip
    cursor = """{
        // Cursor allows comments
        "mcpServers": {
            "db": {"command": "db-mcp", "args": ["--password", "ARG_SECRET", "--url=https://x.example/db"],},
            "safe": {"command": "safe-mcp", "env": {"API_KEY": "${API_KEY}"}},
            "pg": {"command": "npx", "args": ["server-postgres", "postgresql://app:DB_PASSWORD@db.internal/prod"]},
        },
    }"""
    write(
        home / ".cursor" / "mcp.json",
        cursor.replace("ARG_SECRET", FAKE["arg"]).replace("DB_PASSWORD", FAKE["db_password"]),
    )
    write(home / ".aws" / "credentials", f"[default]\naws_access_key_id = {FAKE['aws_id']}\n"
                                        f"aws_secret_access_key = {FAKE['aws_secret']}\n[prod-admin]\n")  # fmt: skip
    write(home / ".aws" / "config", "[profile prod-admin]\nregion = us-east-1\n[profile readonly]\n")
    write(home / ".config" / "gh" / "hosts.yml", "github.com:\n  oauth_token: gho_fake\n")
    write(project / ".mcp.json", {"mcpServers": {"fs": {"command": "fs-mcp", "args": ["."]}}})
    write(project / ".env", f"OPENAI_API_KEY={FAKE['dotenv']}\nPORT=3000\nEMPTY_TOKEN=\n")
    write(project / ".env.example", "OPENAI_API_KEY=changeme\n")
    environ = {"AWS_PROFILE": "readonly", "PATH": "/usr/bin", "SSH_AUTH_SOCK": "agent.sock"}
    return discover(home=home, project=project, environ=environ, appdata=appdata)


def test_finds_every_agent(machine):
    names = {a.name for a in machine.agents}
    assert names == {"Claude Code (user)", "Claude Code (C:/work/api)", "Claude Desktop", "Cursor (user)",
                     "Claude Code (project)"}  # fmt: skip
    assert next(a for a in machine.agents if a.name == "Claude Desktop").shell is False


def test_classifies_tool_credentials(machine):
    tools = {t.name: t for a in machine.agents for t in a.tools}
    github = tools["github"].credentials[0]
    assert (github.kind, github.name, github.hardcoded) == ("github-token", "GITHUB_PERSONAL_ACCESS_TOKEN", True)
    aws = tools["aws"].credentials[0]
    assert (aws.kind, aws.detail, aws.hardcoded) == ("aws-profile", "prod-admin", False)
    assert [c.name for c in tools["slack"].credentials] == ["SLACK_BOT_TOKEN"]  # SLACK_TEAM_ID is not a secret
    safe = tools["safe"].credentials[0]
    assert safe.hardcoded is False  # ${API_KEY} is a reference, not a secret
    remote = tools["remote"]
    assert remote.url == "https://mcp.example.com/sse"
    assert {(c.name, c.hardcoded) for c in remote.credentials} == {("url", True), ("Authorization", True)}


def test_ambient_credentials(machine):
    ambient = {(c.kind, c.name) for c in machine.ambient}
    assert {("aws-profile", "default"), ("aws-profile", "prod-admin"), ("aws-profile", "readonly")} <= ambient
    assert ("aws-profile", "AWS_PROFILE") in ambient
    assert ("github-cli-login", "hosts.yml") in ambient
    assert ("llm-api-key", "OPENAI_API_KEY") in ambient  # from .env
    assert not any(c.name in ("PORT", "EMPTY_TOKEN", "SSH_AUTH_SOCK") for c in machine.ambient)
    assert not any(".env.example" in c.source for c in machine.ambient)


def test_hardcoded_summary(machine):
    hardcoded = {(t.name, c.name) for _, t, c in machine.hardcoded}
    assert hardcoded == {
        ("github", "GITHUB_PERSONAL_ACCESS_TOKEN"),
        ("slack", "SLACK_BOT_TOKEN"),
        ("remote", "url"),
        ("remote", "Authorization"),
        ("db", "--password"),
        ("pg", "url"),
    }


def test_no_secret_value_ever_reaches_the_output(machine):
    outputs = [json.dumps(asdict(machine)), _render_inventory(machine, colour=False)]
    for out in outputs:
        for name, secret in FAKE.items():
            assert secret not in out, f"{name} secret leaked"
    db = next(t for a in machine.agents for t in a.tools if t.name == "db")
    assert "<redacted>" in db.command and "https://x.example/db" in db.command


def test_jsonc_keeps_slashes_inside_strings(tmp_path):
    path = write(tmp_path / "c.json", '{"url": "https://a//b", /* c */ "x": [1,2,],}')
    assert load_jsonc(path) == {"url": "https://a//b", "x": [1, 2]}


def test_secret_prefix_in_arguments_is_caught():
    tool = parse_server("t", {"command": "run", "args": ["--header", FAKE["github"]]}, "cfg")
    assert FAKE["github"] not in tool.command
    assert tool.credentials[0].hardcoded


def test_unreadable_config_is_reported_not_fatal(tmp_path):
    write(tmp_path / ".cursor" / "mcp.json", "{not json")
    inv = discover(home=tmp_path, environ={}, appdata=tmp_path / "appdata")
    assert inv.errors and "mcp.json" in inv.errors[0]


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("USE_LOCAL_OAUTH", None),
        ("CLAUDE_CODE_OAUTH_SCOPES", None),
        ("SDK_HAS_HOST_AUTH_REFRESH", None),
        ("TOKEN_URL", None),
        ("GOOGLE_APPLICATION_CREDENTIALS", "gcp-credentials-file"),
        ("CLAUDE_CODE_MESSAGING_TOKEN", "secret"),
        ("STRIPE_API_KEY", "secret"),
        ("AWS_SECRET_ACCESS_KEY", "aws-keys"),
        ("GITHUB_APP_PRIVATE_KEY", "github-token"),
        ("PATH", None),
    ],
)
def test_env_names(name, kind):
    assert _env_kind(name) == kind
