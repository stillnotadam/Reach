"""Benchmark `reach audit` on synthetic accounts of growing size.

    python scripts/benchmark.py                       # default sizes, prints a Markdown table
    python scripts/benchmark.py --sizes 100 1000 --workers 1 8

Each size is a synthetic account (scripts/synth_account.py) with 40% users and 60% roles. Every principal is
decided against the nine high-impact questions; times are wall clock, including process start-up.
"""

from __future__ import annotations

import argparse
import os
import platform
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from synth_account import generate  # noqa: E402

from reach.audit import audit  # noqa: E402
from reach.loaders import AuthorizationDetails  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sizes", type=int, nargs="+", default=[250, 1000, 2500, 5000])
    parser.add_argument("--workers", type=int, nargs="+", default=[1, os.cpu_count() or 1])
    parser.add_argument("--serial-limit", type=int, default=1000, help="skip 1-worker runs above this size")
    args = parser.parse_args()
    cpu = platform.processor() or platform.machine()
    print(f"{cpu}, {os.cpu_count()} logical CPUs, Python {platform.python_version()}")
    print()
    print("| Principals | Roles | Workers | Decisions | Seconds | Decisions/s | Allowed | Denied | Unknown | Errors |")
    print("|-----------:|------:|--------:|----------:|--------:|------------:|--------:|-------:|--------:|-------:|")
    for size in args.sizes:
        users, roles = size * 2 // 5, size - size * 2 // 5
        details = AuthorizationDetails.from_json(generate(users, roles, seed=1))
        for workers in args.workers:
            if workers == 1 and size > args.serial_limit:
                continue
            report = audit(details, workers=workers)
            mix = Counter(a.verdict for r in report.rows for a in r.answers)
            print(
                f"| {size} | {roles} | {report.workers} | {report.decisions} | {report.seconds:.1f} | "
                f"{report.decisions / report.seconds:.0f} | {mix['allowed']} | {mix['denied']} | {mix['unknown']} | "
                f"{mix['error']} |",
                flush=True,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
