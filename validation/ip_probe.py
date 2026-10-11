"""IP conditions against AWS's policy simulator: IPv4 and IPv6, mixed families, mapped addresses, bad values.

    python -m validation.ip_probe --profile reach-sim

Every combination of operator, network list and source address below is sent to iam:SimulateCustomPolicy
(read-only) and compared with Reach's reference evaluator. A disagreement is a case where Reach decided
(True or False) and AWS decided the other way; Reach answering None (depends on how AWS reads a value) is
never one. FINDINGS.md, finding 7, records what this measured.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from typing import Any

from reach.engine import Principal
from reach.policy import parse_policy
from reach.reference import evaluate

OPERATORS = ["IpAddress", "NotIpAddress", "IpAddressIfExists", "NotIpAddressIfExists"]
NETWORKS: list[list[str]] = [
    ["10.0.0.0/8"], ["0.0.0.0/0"], ["::/0"], ["2001:db8::/32"], ["2001:DB8:0:0:0:0:0:0/32"], ["2001:db8::1"],
    ["2001:db8:1234::/48"], ["203.0.113.5/32"], ["10.1.2.3/8"], ["10.0.0.0/08"], ["::a00:0/104"],
    ["10.0.0.0/8", "2001:db8::/32"],
    # Values AWS does not accept: what happens to the rest of the list, and to an absent key.
    ["::ffff:10.0.0.0/104"], [" 10.0.0.0/8"], ["bogus"], ["10.0.0.0/33"], ["2001:db8::/129"],
    [" 10.0.0.0/8", "10.0.0.0/8"], ["10.0.0.0/8", "bogus"],
]  # fmt: skip
SOURCES: list[str | None] = [
    "10.1.2.3", "192.0.2.1", "203.0.113.5", "2001:db8::1", "2001:0db8:0000::0001", "2001:db8:1234:5::9",
    "::ffff:10.1.2.3", "::a00:1", None,
]  # fmt: skip
ARN = "arn:aws:iam::123456789012:role/probe"


def probe(client: Any) -> tuple[int, list[str]]:
    compared, disagreements = 0, []
    for op, networks, source in itertools.product(OPERATORS, NETWORKS, SOURCES):
        doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
               "Condition": {op: {"aws:SourceIp": networks}}}]}  # fmt: skip
        entries = [] if source is None else [
            {"ContextKeyName": "aws:SourceIp", "ContextKeyValues": [source], "ContextKeyType": "ip"}
        ]  # fmt: skip
        response = client.simulate_custom_policy(
            PolicyInputList=[json.dumps(doc)], ActionNames=["s3:GetObject"], ResourceArns=["arn:aws:s3:::b/k"],
            ContextEntries=entries,
        )  # fmt: skip
        aws = response["EvaluationResults"][0]["EvalDecision"] == "allowed"
        principal = Principal(ARN, [parse_policy(doc, "probe")])
        reach = evaluate(principal, "s3:GetObject", "arn:aws:s3:::b/k", {"aws:SourceIp": source})
        if reach is None:
            continue
        compared += 1
        if reach != aws:
            disagreements.append(f"{op} {networks} source={source}: AWS {aws}, Reach {reach}")
    return compared, disagreements


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", help="AWS CLI profile with iam:SimulateCustomPolicy")
    args = parser.parse_args()
    import boto3  # noqa: PLC0415 - optional dependency

    client = boto3.Session(profile_name=args.profile, region_name="us-east-1").client("iam")
    compared, disagreements = probe(client)
    total = len(OPERATORS) * len(NETWORKS) * len(SOURCES)
    print(f"{total} cases, {compared} decided by Reach and compared, {len(disagreements)} disagreements")
    for line in disagreements:
        print(f"  {line}")
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
