from __future__ import annotations

import json
from pathlib import Path

from reach.agents import Agent, Credential, Inventory, Tool, discover
from reach.blast import Capability
from reach.engine import Verdict
from reach.trifecta import EXFIL, PRIVATE, UNTRUSTED, assess, classify_tool

AMBIENT = [Credential("aws-profile", "prod", "~/.aws/credentials", detail="prod")]


def inventory(*agents: Agent, ambient=AMBIENT) -> Inventory:
    return Inventory(agents=list(agents), ambient=list(ambient))


def claude(mode="approval", tools=(), denied=(), allowed=()) -> Agent:
    return Agent("Claude Code", "~/.claude.json", mode, list(tools), kind="claude-code", denied=list(denied),
                 allowed=list(allowed))  # fmt: skip


GITHUB = Tool("github", "stdio", "npx -y @modelcontextprotocol/server-github",
              credentials=[Credential("github-token", "GITHUB_PERSONAL_ACCESS_TOKEN", "cfg")])  # fmt: skip
POSTGRES = Tool("analytics", "stdio", "npx @modelcontextprotocol/server-postgres postgresql://db/prod")


def test_unrestricted_agent_with_web_and_credentials_is_critical():
    a = assess(claude("unrestricted"), inventory())
    assert a.complete and a.severity == "critical"
    # Untrusted input and private data each have one source; ties break towards untrusted input, whose
    # fix (deny WebFetch) is one settings line rather than moving credentials off the machine.
    assert a.cheapest_fix()[0] == UNTRUSTED


def test_default_agent_is_high_because_a_human_approves_each_leg():
    a = assess(claude("approval"), inventory())
    assert a.severity == "high"
    assert all(leg.gated for legs in a.legs.values() for leg in legs)


def test_denying_web_tools_breaks_the_untrusted_leg():
    a = assess(claude("approval", denied=["WebFetch", "WebSearch"]), inventory())
    assert not a.complete and not a.legs[UNTRUSTED]


def test_denied_shell_removes_ambient_credentials_and_curl():
    a = assess(claude("denied"), inventory())
    assert not a.legs[PRIVATE]
    assert [leg.source for leg in a.legs[EXFIL]] == ["WebFetch: data can leave in a request URL"]


def test_a_github_mcp_server_alone_completes_the_trifecta():
    desktop = Agent("Claude Desktop", "cfg", "none", [GITHUB], kind="claude-desktop")
    a = assess(desktop, inventory(desktop, ambient=[]))
    assert a.complete and a.severity == "high"  # Claude Desktop asks before each tool call
    assert all("github" in leg.source for legs in a.legs.values() for leg in legs)
    assert "github" in a.cheapest_fix()[1]


def test_database_tool_supplies_private_data():
    a = assess(claude("denied", tools=[POSTGRES], denied=["WebFetch"]), inventory(ambient=[]))
    assert [leg.source.split(":")[0] for leg in a.legs[PRIVATE]] == ["MCP server analytics"]
    assert not a.complete


def test_proven_aws_capabilities_strengthen_the_private_leg():
    caps = {"prod": [Capability("read secrets", "secretsmanager:GetSecretValue", Verdict.ALLOWED),
                     Capability("modify IAM", "iam:*", Verdict.DENIED)]}  # fmt: skip
    a = assess(claude("unrestricted"), inventory(), caps)
    proven = [leg.source for leg in a.legs[PRIVATE] if "proven" in leg.source]
    assert proven == ["AWS profile prod can (proven): read secrets"]


def test_unknown_tools_are_reported_not_guessed():
    weird = Tool("acme-internal", "stdio", "acme-mcp")
    assert classify_tool(weird) is None
    a = assess(claude(tools=[weird]), inventory())
    assert a.unclassified == ["acme-internal"]


def test_preapproved_curl_makes_exfiltration_ungated():
    a = assess(claude(allowed=["Bash(curl:*)"]), inventory())
    exfil = [leg for leg in a.legs[EXFIL] if leg.source.startswith("shell")]
    assert len(exfil) == 1 and not exfil[0].gated and "curl" in exfil[0].fix
    assert a.severity == "high"  # WebFetch and ambient reads still need approval


def test_preapprovals_on_every_leg_make_a_default_agent_critical():
    allowed = ["WebFetch", "Bash(curl *)", "Bash(aws:*)"]
    a = assess(claude(allowed=allowed), inventory())
    assert a.severity == "critical"
    assert any("aws pre-approved" in leg.source and not leg.gated for leg in a.legs[PRIVATE])


def test_domain_scoped_webfetch_rule_is_not_a_blanket_preapproval():
    a = assess(claude(allowed=["WebFetch(domain:docs.python.org)"]), inventory())
    assert all(leg.gated for leg in a.legs[UNTRUSTED])


def test_harmless_preapproved_commands_keep_the_shell_gated():
    a = assess(claude(allowed=["Bash(npm test:*)", "Bash(git status)"]), inventory())
    assert all(leg.gated for legs in a.legs.values() for leg in legs)


def test_preapproving_a_whole_mcp_server_removes_its_gate():
    a = assess(claude("denied", tools=[GITHUB], denied=["WebFetch"], allowed=["mcp__github"]), inventory())
    assert a.severity == "critical"
    assert "every tool pre-approved" in a.legs[UNTRUSTED][0].source


def test_preapproving_single_mcp_tools_is_reported_but_stays_gated():
    a = assess(claude("denied", tools=[GITHUB], denied=["WebFetch"], allowed=["mcp__github__get_issue"]),
               inventory())  # fmt: skip
    assert a.severity == "high"
    assert "e.g. get_issue" in a.legs[UNTRUSTED][0].source


def test_denying_a_whole_mcp_server_removes_it():
    a = assess(claude("denied", tools=[GITHUB], denied=["WebFetch", "mcp__github__*"]), inventory())
    assert not any(a.legs.values())


def test_preapprovals_are_read_from_settings_files(tmp_path):
    settings = tmp_path / "p" / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"permissions": {"allow": ["Bash(curl:*)", "mcp__github"]}}), encoding="utf-8")
    inv = discover(home=tmp_path / "h", project=tmp_path / "p", environ={}, appdata=tmp_path / "a")
    agent = next(a for a in inv.agents if a.kind == "claude-code")
    assert agent.allowed == ["Bash(curl:*)", "mcp__github"]


TRIAGE = """
on: issue_comment
permissions:
  contents: write
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
"""
GATED_READ_ONLY = """
on: issue_comment
permissions:
  contents: read
jobs:
  claude:
    if: github.event.comment.author_association == 'OWNER'
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
"""


def ci_assessment(tmp_path: Path, text: str):
    workflow = tmp_path / "p" / ".github" / "workflows" / "w.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(text, encoding="utf-8")
    inv = discover(home=tmp_path / "h", project=tmp_path / "p", environ={}, appdata=tmp_path / "a")
    agent = next(a for a in inv.agents if a.kind == "ci")
    return assess(agent, inv)


def test_ci_agent_on_untrusted_trigger_with_write_token_is_critical(tmp_path):
    a = ci_assessment(tmp_path, TRIAGE)
    assert a.severity == "critical"
    assert any("issue_comment" in leg.source for leg in a.legs[UNTRUSTED])
    assert any("ANTHROPIC_API_KEY" in leg.source for leg in a.legs[PRIVATE])
    assert any("can write" in leg.source for leg in a.legs[EXFIL])


def test_gated_read_only_ci_agent_has_no_exfiltration_leg(tmp_path):
    a = ci_assessment(tmp_path, GATED_READ_ONLY)
    assert not a.complete and not a.legs[EXFIL]
    assert a.legs[UNTRUSTED][0].gated


def test_ci_agents_never_get_the_machines_ambient_credentials(tmp_path):
    a = ci_assessment(tmp_path, TRIAGE)
    assert not any("ambient" in leg.source for leg in a.legs[PRIVATE])


def test_json_output_includes_assessments(tmp_path, capsys):
    from reach.cli import main  # noqa: PLC0415

    (tmp_path / "h" / ".claude").mkdir(parents=True)
    (tmp_path / "h" / ".claude" / "settings.json").write_text('{"permissions": {"defaultMode": "bypassPermissions"}}')
    assert main(["agents", "--home", str(tmp_path / "h"), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["trifecta"][0]["agent"] == "Claude Code (user)"
    assert payload["trifecta"][0]["severity"] in ("critical", "high", "none")
