"""The HTML audit report: what it carries, and that policy text cannot inject markup into it."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from reach.audit import Answer, Report, Row, audit
from reach.cli import main
from reach.loaders import AuthorizationDetails
from reach.report import payload, to_html

GOAT = Path(__file__).resolve().parent.parent / "examples" / "reach-goat" / "authz.json"


@pytest.fixture(scope="module")
def goat() -> Report:
    return audit(AuthorizationDetails.load(str(GOAT)), workers=1)


def _data(page: str) -> dict:
    block = re.search(r'<script type="application/json" id="data">(.*?)</script>', page, re.S)
    assert block
    return json.loads(block.group(1))


def test_allowed_answers_name_the_statements_that_allow_the_witness(goat):
    rows = {r.principal.rsplit("/", 1)[-1]: {a.label: a for a in r.answers} for r in goat.rows}
    assert rows["agent-dev"]["read secrets"].grants == ["goat-agent / ReadAppSecrets"]
    write = rows["agent-dev"]["write S3 objects"]
    assert write.grants == ["goat-agent / WriteOnlyFromTheOffice"]
    assert "aws:SourceIp" in write.witness["context"]  # the condition the grant depends on, pinned
    # Assuming deploy works through its trust policy alone.
    assert rows["agent-dev"]["assume roles"].grants == ["deploy/trust-policy"]
    assert all(not a.grants for r in goat.rows for a in r.answers if a.verdict != "allowed")


def test_page_embeds_the_whole_audit(goat):
    data = _data(to_html(goat, "authz.json"))
    assert len(data["rows"]) == 2 and len(data["questions"]) == 9
    assert data["meta"]["accounts"] == ["123456789012"]
    cells = [a["v"] for r in data["rows"] for a in r["a"]]
    assert cells.count("allowed") == 12
    # Denied cells carry nothing but the verdict, which keeps a 5,000-principal page small.
    assert all(set(a) == {"v"} for r in data["rows"] for a in r["a"] if a["v"] == "denied")


def test_policy_text_cannot_break_out_of_the_page():
    evil = "</script><img src=x onerror=alert(1)><!--"
    answer = Answer("read secrets", "secretsmanager:GetSecretValue", "*", "allowed",
                    {"action": "secretsmanager:GetSecretValue", "resource": evil, "context": {evil: evil}},
                    grants=[evil])  # fmt: skip
    report = Report([Row(f"arn:aws:iam::123456789012:user/{evil}", "user", [answer], 0.0)],
                    [("read secrets", "secretsmanager:GetSecretValue", "*")], 1, 0.1)  # fmt: skip
    page = to_html(report, authz=evil)
    body = page.split('id="data">', 1)[1].split("</script>", 1)[0]
    assert "<" not in body  # nothing in the data block can end it or open a tag
    assert page.count("</script>") == 2  # the data block and the page script, nothing injected
    assert _data(page)["rows"][0]["a"][0]["g"] == [evil]  # and the text survives intact
    # The script never parses data as HTML.
    assert "innerHTML" not in page and "insertAdjacentHTML" not in page


def test_cli_writes_the_report(tmp_path, capsys):
    out = tmp_path / "report.html"
    assert main(["audit", "--authz", str(GOAT), "--workers", "1", "--html", str(out)]) == 0
    capsys.readouterr()
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>") and "Reach audit" in page
    assert _data(page)["meta"]["authz"] == str(GOAT)


def test_payload_is_json_serialisable(goat):
    json.dumps(payload(goat))
