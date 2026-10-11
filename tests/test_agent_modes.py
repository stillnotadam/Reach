from __future__ import annotations

import json
from pathlib import Path

import pytest

from reach.agents import claude_code_mode, discover


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --- Claude Code permission settings ----------------------------------------------


@pytest.mark.parametrize(
    ("settings", "mode"),
    [
        ([], "approval"),
        ([{"permissions": {"defaultMode": "bypassPermissions"}}], "unrestricted"),
        ([{"permissions": {"allow": ["Bash"]}}], "unrestricted"),
        ([{"permissions": {"allow": ["Bash(npm run test:*)", "Read"]}}], "approval"),
        ([{"permissions": {"deny": ["Bash"]}}, {"permissions": {"defaultMode": "bypassPermissions"}}], "denied"),
        # Later files (project, local) override the user's defaultMode.
        ([{"permissions": {"defaultMode": "bypassPermissions"}}, {"permissions": {"defaultMode": "default"}}],
         "approval"),
    ],
)  # fmt: skip
def test_claude_code_mode(settings, mode):
    assert claude_code_mode(settings)[0] == mode


def test_pre_approved_commands_are_reported():
    _, findings = claude_code_mode([{"permissions": {"allow": ["Bash(curl:*)"]}}])
    assert findings and "Bash(curl:*)" in findings[0]


def test_project_settings_apply_to_the_project_agent(tmp_path):
    home, project = tmp_path / "home", tmp_path / "project"
    write(home / ".claude" / "settings.json", json.dumps({"permissions": {"allow": ["Read"]}}))
    write(
        project / ".claude" / "settings.local.json", json.dumps({"permissions": {"defaultMode": "bypassPermissions"}})
    )
    inv = discover(home=home, project=project, environ={}, appdata=tmp_path / "appdata")
    agents = {a.name: a for a in inv.agents}
    assert agents["Claude Code (user)"].shell_mode == "approval"
    assert agents["Claude Code (project)"].shell_mode == "unrestricted"
    assert "bypassPermissions" in agents["Claude Code (project)"].findings[0]


def test_denied_shell_cannot_read_ambient_credentials(tmp_path):
    home = tmp_path / "home"
    write(home / ".claude" / "settings.json", json.dumps({"permissions": {"deny": ["Bash"]}}))
    inv = discover(home=home, environ={}, appdata=tmp_path / "appdata")
    assert inv.agents[0].shell_mode == "denied" and not inv.agents[0].shell


# --- AI agents in GitHub Actions ---------------------------------------------------------

TRIAGE = """
name: triage
on:
  issues:
    types: [opened]
  issue_comment:
    types: [created]
permissions:
  contents: write
  issues: write
  id-token: write
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          claude_args: --allowedTools "Bash,Read,Edit"
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
"""

GATED = """
on: issue_comment
jobs:
  review:
    if: github.event.comment.author_association == 'OWNER'
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
"""

SAFE = """
on:
  push:
    branches: [main]
permissions: read-all
jobs:
  summary:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/ai-inference@v1
      - uses: actions/setup-node@v4
"""


@pytest.fixture
def workflows(tmp_path):
    project = tmp_path / "project"
    for name, text in (("triage.yml", TRIAGE), ("review.yaml", GATED), ("summary.yml", SAFE)):
        write(project / ".github" / "workflows" / name, text)
    write(project / ".github" / "workflows" / "broken.yml", "on: [push\n")
    inv = discover(home=tmp_path / "home", project=project, environ={}, appdata=tmp_path / "appdata")
    return {a.name: a for a in inv.agents}, inv


def test_finds_agent_steps_only(workflows):
    agents, inv = workflows
    assert set(agents) == {"Claude Code in triage.yml:claude", "Gemini CLI in review.yaml:review",
                           "GitHub AI Inference in summary.yml:summary"}  # fmt: skip
    assert any("broken.yml" in e for e in inv.errors)
    assert all(not a.local and not a.shell for a in agents.values())


def test_untrusted_trigger_with_write_token_and_secrets(workflows):
    agent = workflows[0]["Claude Code in triage.yml:claude"]
    assert agent.shell_mode == "unrestricted"  # bare Bash in the allowed tools
    held = {(c.kind, c.name) for c in agent.credentials}
    assert ("github-token", "GITHUB_TOKEN") in held
    assert ("oidc-token", "id-token: write") in held
    assert ("llm-api-key", "ANTHROPIC_API_KEY") in held and ("secret", "DEPLOY_TOKEN") in held
    text = " | ".join(agent.findings)
    assert "issue_comment, issues" in text and "no `if:` gate" in text
    assert "write: contents, id-token, issues" in text and "DEPLOY_TOKEN" in text
    assert "arbitrary shell commands" in text


def test_gate_and_read_only_token_are_reported(workflows):
    agent = workflows[0]["Gemini CLI in review.yaml:review"]
    assert agent.shell_mode == "allowlist"
    assert "author_association" in agent.findings[0]
    # Read-only token: what the injection could use is just the API key secret.
    assert agent.findings[1] == "a prompt injection there could use: GEMINI_API_KEY"


def test_trusted_trigger_has_no_injection_finding(workflows):
    agent = workflows[0]["GitHub AI Inference in summary.yml:summary"]
    assert agent.findings == []
    assert agent.credentials[0].detail == "read-all"


def test_env_file_tracked_in_git_is_flagged(tmp_path):
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    if shutil.which("git") is None:
        pytest.skip("git not installed")
    project = tmp_path / "repo"
    write(project / ".env", "STRIPE_API_KEY=sk_live_fake\n")
    write(project / ".env.local", "OTHER_TOKEN=fake\n")
    for argv in (["git", "init", "-q"], ["git", "add", ".env"]):
        subprocess.run(argv, cwd=project, check=True, capture_output=True)  # noqa: S603
    inv = discover(home=tmp_path / "home", project=project, environ={}, appdata=tmp_path / "appdata")
    by_file = {Path(c.source).name: c for c in inv.ambient}
    assert "tracked in git" in by_file[".env"].detail
    assert by_file[".env.local"].detail == ""
