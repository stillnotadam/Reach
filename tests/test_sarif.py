from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from reach.agents import discover
from reach.cli import main
from reach.sarif import RULES, to_sarif
from reach.trifecta import assess_all

GOAT = Path(__file__).resolve().parent.parent / "examples" / "reach-goat"


@pytest.fixture
def goat(tmp_path: Path) -> Path:
    project = tmp_path / "goat"
    shutil.copytree(GOAT, project)
    (tmp_path / "home").mkdir()
    return project


def sarif_for(project: Path) -> dict:
    inv = discover(home=project.parent / "home", project=project, environ={}, appdata=project.parent / "home")
    return to_sarif(inv, assess_all(inv), project)


def located(result: dict) -> tuple[str, int]:
    loc = result["locations"][0]["physicalLocation"]
    return loc["artifactLocation"]["uri"], loc["region"]["startLine"]


def test_document_shape_and_rules(goat):
    doc = sarif_for(goat)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert ids == [r[0] for r in RULES]
    assert {r["ruleId"] for r in run["results"]} <= set(ids)
    for rule in run["tool"]["driver"]["rules"]:
        float(rule["properties"]["security-severity"])  # GitHub needs a number in a string
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].endswith("/")


def test_findings_point_at_the_line_that_causes_them(goat):
    results = sarif_for(goat)["runs"][0]["results"]
    by_text = {r["message"]["text"]: located(r) for r in results}

    def where(fragment: str) -> tuple[str, int]:
        return next(loc for text, loc in by_text.items() if fragment in text)

    settings = (goat / ".claude" / "settings.json").read_text().splitlines()
    uri, line = where("bypassPermissions")
    assert uri == ".claude/settings.json" and "bypassPermissions" in settings[line - 1]
    workflow = (goat / ".github" / "workflows" / "triage.yml").read_text().splitlines()
    uri, line = where("triggered by")
    assert uri == ".github/workflows/triage.yml" and workflow[line - 1].startswith("on:")
    uri, line = where("GITHUB_PERSONAL_ACCESS_TOKEN")
    assert (
        uri == ".mcp.json" and "GITHUB_PERSONAL_ACCESS_TOKEN" in (goat / ".mcp.json").read_text().splitlines()[line - 1]
    )


def test_trifecta_levels_follow_severity(goat):
    results = [r for r in sarif_for(goat)["runs"][0]["results"] if r["ruleId"] == "REACH001"]
    assert len(results) == 2
    assert all(r["level"] == "error" and r["properties"]["severity"] == "critical" for r in results)


def test_fingerprints_survive_moved_lines(goat):
    before = {r["partialFingerprints"]["reach/v1"] for r in sarif_for(goat)["runs"][0]["results"]}
    mcp = goat / ".mcp.json"
    mcp.write_text("\n\n\n" + mcp.read_text())
    after = {r["partialFingerprints"]["reach/v1"] for r in sarif_for(goat)["runs"][0]["results"]}
    assert before == after


def test_no_secret_value_in_sarif(tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    (tmp_path / "h").mkdir()
    secret = "ghp_" + "Q" * 36
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "github": {"command": "npx", "args": ["server-github"], "env": {"GITHUB_TOKEN": secret}},
        "db": {"command": "npx", "args": ["server-postgres", "postgresql://admin:hunter2pass@db/prod"]},
    }}))  # fmt: skip
    out = json.dumps(sarif_for(project))
    assert secret not in out and "hunter2pass" not in out
    assert out.count('"REACH002"') >= 2


def test_files_outside_the_project_get_absolute_uris(tmp_path):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text('{"permissions": {"defaultMode": "bypassPermissions"}}')
    (tmp_path / "p").mkdir()
    inv = discover(home=home, project=tmp_path / "p", environ={}, appdata=home)
    results = to_sarif(inv, assess_all(inv), tmp_path / "p")["runs"][0]["results"]
    uri, _ = located(next(r for r in results if r["ruleId"] == "REACH003"))
    assert uri.startswith("file://") and uri.endswith("/.claude/settings.json")


def test_cli_writes_sarif_and_fails_on_severity(goat, capsys):
    out = goat.parent / "reach.sarif"
    home = str(goat.parent / "home")
    assert main(["agents", "--home", home, "--project", str(goat), "--sarif", str(out), "--fail-on", "critical"]) == 1
    assert json.loads(out.read_text())["runs"][0]["results"]
    assert main(["agents", "--home", home, "--project", str(goat)]) == 0
    empty = goat.parent / "empty"
    empty.mkdir()
    assert main(["agents", "--home", home, "--project", str(empty), "--fail-on", "high"]) == 0


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_committed_env_secret_is_reported_with_its_line(tmp_path):
    import subprocess  # noqa: PLC0415

    project = tmp_path / "p"
    project.mkdir()
    (tmp_path / "h").mkdir()
    (project / ".env").write_text("DEBUG=1\nSTRIPE_API_KEY=sk_live_" + "x" * 24 + "\n")
    git = ["git", "-C", str(project), "-c", "user.email=t@t", "-c", "user.name=t"]
    for step in (["init", "-q"], ["add", ".env"], ["commit", "-qm", "oops"]):
        subprocess.run([*git, *step], check=True, capture_output=True)  # noqa: S603
    results = sarif_for(project)["runs"][0]["results"]
    committed = [r for r in results if r["ruleId"] == "REACH004"]
    assert [located(r) for r in committed] == [(".env", 2)]
    assert "sk_live_" not in json.dumps(results)
