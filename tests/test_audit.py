from __future__ import annotations

import json
from pathlib import Path

import pytest

from reach import audit as audit_module
from reach.audit import audit
from reach.blast import capabilities
from reach.cli import main
from reach.engine import Verdict
from reach.loaders import AuthorizationDetails

GOAT = Path(__file__).resolve().parent.parent / "examples" / "reach-goat" / "authz.json"
AGENT = "arn:aws:iam::123456789012:user/agent-dev"
DEPLOY = "arn:aws:iam::123456789012:role/deploy"


@pytest.fixture(scope="module")
def details() -> AuthorizationDetails:
    return AuthorizationDetails.load(str(GOAT))


def verdicts(report) -> dict[tuple[str, str], str]:
    return {(row.principal, a.label): a.verdict for row in report.rows for a in row.answers}


def test_goat_matrix(details):
    v = verdicts(audit(details, workers=1))
    assert v[(AGENT, "read secrets")] == "allowed"
    assert v[(AGENT, "modify IAM")] == "denied"
    assert v[(AGENT, "read SSM parameters")] == "denied"
    assert all(v[(DEPLOY, label)] == "allowed" for label in ("modify IAM", "start compute", "decrypt with KMS"))


def test_assume_roles_uses_every_trust_policy(details):
    # deploy trusts agent-dev by name: no identity permission is needed, so a plain "*" query would miss it.
    report = audit(details, workers=1)
    answer = next(a for r in report.rows if r.principal == AGENT for a in r.answers if a.label == "assume roles")
    assert answer.verdict == "allowed" and answer.witness["resource"] == DEPLOY
    # No role trusts deploy itself.
    assert verdicts(report)[(DEPLOY, "assume roles")] == "denied"
    caps = {c.label: c.verdict for c in capabilities(details, AGENT)}
    assert caps["assume roles"] is Verdict.ALLOWED


def test_parallel_and_serial_agree(details):
    assert verdicts(audit(details, workers=2)) == verdicts(audit(details, workers=1))


def test_one_failing_question_is_reported_not_fatal(details, monkeypatch):
    real = audit_module.decide_in_snapshot

    def flaky(details, principal, action, resource, env=None):
        if action == "kms:Decrypt":
            raise RuntimeError("solver exploded")
        return real(details, principal, action, resource, env)

    monkeypatch.setattr(audit_module, "decide_in_snapshot", flaky)
    v = verdicts(audit(details, workers=1))
    assert v[(AGENT, "decrypt with KMS")] == "error"
    assert v[(AGENT, "read secrets")] == "allowed"


def test_cli_json_and_fail_on_allowed(capsys):
    assert main(["audit", "--authz", str(GOAT), "--workers", "1", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert {r["principal"] for r in payload["rows"]} == {AGENT, DEPLOY}
    assert main(["audit", "--authz", str(GOAT), "--workers", "1", "--fail-on-allowed"]) == 1
    out = capsys.readouterr().out
    assert "assume roles: 1 proven (user/agent-dev)" in out
    assert main(["audit", "--authz", str(GOAT), "--workers", "1", "--principal", "agent-dev", "--json"]) == 0
    assert [r["principal"] for r in json.loads(capsys.readouterr().out)["rows"]] == [AGENT]


def test_synthetic_account_audits_without_unknowns():
    import sys  # noqa: PLC0415

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    from synth_account import generate  # noqa: PLC0415

    details = AuthorizationDetails.from_json(generate(users=6, roles=9, seed=3))
    report = audit(details, workers=1)
    assert len(report.rows) == 15
    assert {a.verdict for r in report.rows for a in r.answers} <= {"allowed", "denied"}
