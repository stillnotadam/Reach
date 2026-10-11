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


def service_actions(entry: dict[str, Any]) -> dict[str, Any]:
    """Actions of one service, with the resource types and condition keys each one supports."""
    doc = fetch(entry["url"])
    prefix = doc.get("Name") or entry["service"]
    resources = {r["Name"]: r for r in doc.get("Resources", [])}
    out: dict[str, Any] = {"actions": [], "action_resources": {}, "action_keys": {}, "resource_formats": {}}
    for name, r in resources.items():
        out["resource_formats"][f"{prefix}:{name}"] = r.get("ARNFormats", [])
    for action in doc.get("Actions", []):
        full = f"{prefix}:{action['Name']}"
        out["actions"].append(full)
        names = [r["Name"] for r in action.get("Resources", [])]
        # No resource types means the action only ever applies to "*".
        out["action_resources"][full] = [f"{prefix}:{n}" for n in names]
        keys = set(action.get("ActionConditionKeys", []))
        for n in names:
            keys.update(resources.get(n, {}).get("ConditionKeys", []))
        out["action_keys"][full] = sorted(keys)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    index = fetch(INDEX)
    print(f"{len(index)} services in the reference", file=sys.stderr)
    actions: set[str] = set()
    action_resources: dict[str, list[str]] = {}
    action_keys: dict[str, list[str]] = {}
    resource_formats: dict[str, list[str]] = {}
    failed: list[str] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for entry, result in zip(index, pool.map(lambda e: _safe(service_actions, e), index)):
            if result is None:
                failed.append(entry.get("service", "?"))
            else:
                actions.update(result["actions"])
                action_resources.update(result["action_resources"])
                action_keys.update(result["action_keys"])
                resource_formats.update(result["resource_formats"])
    if failed:
        print(f"failed to fetch {len(failed)} services: {', '.join(failed)}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated": dt.date.today().isoformat(),
        "source": INDEX,
        "services": len(index),
        "actions": sorted(actions, key=str.lower),
        "action_resources": action_resources,
        "action_keys": action_keys,
        "resource_formats": resource_formats,
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
