"""Build the project website into _site/: the static pages in site/, plus a live demo report.

The demo is not a screenshot: it is `reach audit --html` run, at build time, on a synthetic account
(scripts/synth_account.py), so the page always shows what the current engine actually proves.

    python scripts/build_site.py            # then open _site/index.html
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from synth_account import generate  # noqa: E402

from reach import __version__  # noqa: E402
from reach.audit import audit  # noqa: E402
from reach.engine import Query, Verdict, decide  # noqa: E402
from reach.loaders import AuthorizationDetails, trust_policy  # noqa: E402
from reach.reference import grants  # noqa: E402
from reach.report import to_html  # noqa: E402

# The questions the home page lets a visitor ask about examples/reach-goat: (label, action, resource, context).
QUESTIONS = [
    ("read a secret", "secretsmanager:GetSecretValue", "*", {}),
    ("create an access key for anyone", "iam:CreateAccessKey", "*", {}),
    ("assume the deploy role", "sts:AssumeRole", "arn:aws:iam::123456789012:role/deploy", {}),
    ("upload to goat-uploads", "s3:PutObject", "arn:aws:s3:::goat-uploads/report.csv", {}),
    ("upload to goat-uploads from 8.8.8.8", "s3:PutObject", "arn:aws:s3:::goat-uploads/report.csv",
     {"aws:SourceIp": "8.8.8.8"}),
]  # fmt: skip


def answers() -> list[dict[str, object]]:
    """Reach's real answers for the home page's question panel, computed now with the current engine."""
    goat = ROOT / "examples" / "reach-goat" / "authz.json"
    details = AuthorizationDetails.load(str(goat))
    out = []
    for arn in details.principal_arns():
        principal = details.principal(arn)
        name = arn.split(":", 5)[-1]
        for label, action, resource, context in QUESTIONS:
            policy = trust_policy(details, resource) if action == "sts:AssumeRole" else None
            result = decide(principal, Query(action, resource, context, policy))
            w = result.witness
            allowed_by = (grants(principal, w.action, w.resource, w.context, None, policy)
                          if w and result.verdict is Verdict.ALLOWED else [])  # fmt: skip
            command = ["reach can --authz authz.json --principal", name.split("/")[-1]]
            command += [f"--context {k}={v}" for k, v in context.items()] + [action, f"'{resource}'"]
            out.append({
                "principal": name, "question": label, "action": action, "resource": resource,
                "verdict": result.verdict.value,
                "witness": {"action": w.action, "resource": w.resource, "context": w.context} if w else None,
                "allowed_by": allowed_by, "reasons": result.reasons, "assumptions": result.assumptions,
                "command": " ".join(command),
            })  # fmt: skip
    return out


def build(out: Path, users: int, roles: int, workers: int | None) -> dict[str, object]:
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(ROOT / "site", out)
    page = out / "index.html"
    data = json.dumps(answers(), separators=(",", ":")).replace("<", "\\u003c")
    page.write_text(page.read_text(encoding="utf-8").replace("__ANSWERS__", data), encoding="utf-8")
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / "synthetic-account.json"
        snapshot.write_text(json.dumps(generate(users, roles, seed=1)), encoding="utf-8")
        report = audit(AuthorizationDetails.load(str(snapshot)), workers=workers)
    notes = [f"A synthetic account of {users} users and {roles} roles (scripts/synth_account.py, seed 1), audited "
             f"when this site was built with reach {__version__}. No real account data."]  # fmt: skip
    filled = page.read_text(encoding="utf-8")
    for key, value in (("PRINCIPALS", len(report.rows)), ("DECISIONS", f"{report.decisions:,}"),
                       ("SECONDS", f"{report.seconds:.1f}")):  # fmt: skip
        filled = filled.replace(f"__DEMO_{key}__", str(value))
    page.write_text(filled, encoding="utf-8")
    (out / "demo").mkdir(exist_ok=True)
    (out / "demo" / "report.html").write_text(to_html(report, "synthetic-account.json", notes), encoding="utf-8")
    allowed = sum(a.verdict == "allowed" for r in report.rows for a in r.answers)
    unknown = sum(a.verdict == "unknown" for r in report.rows for a in r.answers)
    return {"principals": len(report.rows), "decisions": report.decisions, "allowed": allowed,
            "unknown": unknown, "seconds": round(report.seconds, 1), "workers": report.workers}  # fmt: skip


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-o", "--output", type=Path, default=ROOT / "_site")
    parser.add_argument("--users", type=int, default=200)
    parser.add_argument("--roles", type=int, default=300)
    parser.add_argument("--workers", type=int)
    args = parser.parse_args()
    stats = build(args.output, args.users, args.roles, args.workers)
    print(f"built {args.output}: {stats}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
