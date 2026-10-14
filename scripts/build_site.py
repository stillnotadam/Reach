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
from reach.loaders import AuthorizationDetails  # noqa: E402
from reach.report import to_html  # noqa: E402


def build(out: Path, users: int, roles: int, workers: int | None) -> dict[str, object]:
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(ROOT / "site", out)
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / "synthetic-account.json"
        snapshot.write_text(json.dumps(generate(users, roles, seed=1)), encoding="utf-8")
        report = audit(AuthorizationDetails.load(str(snapshot)), workers=workers)
    notes = [f"A synthetic account of {users} users and {roles} roles (scripts/synth_account.py, seed 1), audited "
             f"when this site was built with reach {__version__}. No real account data."]  # fmt: skip
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
