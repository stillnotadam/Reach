"""Build Reach's action catalogue from AWS's Service Authorization Reference.

AWS publishes the reference in machine-readable form: an index of
services, each pointing at a JSON document that lists its actions.

    python scripts/build_catalog.py                 # writes src/reach/data/actions.json.gz
    python scripts/build_catalog.py -o other.json.gz

Only public, unauthenticated AWS documentation endpoints are contacted.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

INDEX = "https://servicereference.us-east-1.amazonaws.com/"
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "src" / "reach" / "data" / "actions.json.gz"


def fetch(url: str) -> Any:
    if not url.startswith("https://servicereference.us-east-1.amazonaws.com/"):
        raise ValueError(f"refusing to fetch unexpected URL {url}")
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - scheme and host checked above
        return json.load(resp)


def service_actions(entry: dict[str, Any]) -> list[str]:
    doc = fetch(entry["url"])
    prefix = doc.get("Name") or entry["service"]
    return [f"{prefix}:{a['Name']}" for a in doc.get("Actions", [])]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    index = fetch(INDEX)
    print(f"{len(index)} services in the reference", file=sys.stderr)
    actions: set[str] = set()
    failed: list[str] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for entry, result in zip(index, pool.map(lambda e: _safe(service_actions, e), index)):
            if result is None:
                failed.append(entry.get("service", "?"))
            else:
                actions.update(result)
    if failed:
        print(f"failed to fetch {len(failed)} services: {', '.join(failed)}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated": dt.date.today().isoformat(),
        "source": INDEX,
        "services": len(index),
        "actions": sorted(actions, key=str.lower),
    }
    with gzip.open(args.output, "wt", encoding="utf-8") as fh:
        json.dump(payload, fh, separators=(",", ":"))
    print(f"wrote {len(actions)} actions to {args.output}", file=sys.stderr)
    return 0


def _safe(fn, entry):
    try:
        return fn(entry)
    except Exception as exc:  # noqa: BLE001 - report every failing service, then fail the whole build
        print(f"  {entry.get('service', '?')}: {exc}", file=sys.stderr)
        return None


if __name__ == "__main__":
    sys.exit(main())
