"""StringEqualsIgnoreCase against AWS's policy simulator: which characters count as the same letter.

    python -m validation.case_probe --profile reach-sim

Each (policy value, request value) pair is sent to iam:SimulateCustomPolicy (read-only) under both
StringEqualsIgnoreCase and StringNotEqualsIgnoreCase, and compared with Reach's reference evaluator. The pairs
separate the candidate rules: ASCII-only folding, Java's equalsIgnoreCase (upper then lower, character by
character), and comparing full Unicode lowercase forms. FINDINGS.md, finding 8, records what this measured.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from reach.engine import Principal
from reach.policy import parse_policy
from reach.reference import evaluate

PAIRS = [
    ("abc", "ABC"), ("abc", "aBc"), ("abc", "abc "), ("abc", "ab"), ("", ""), ("a*", "A*"), ("a*", "Abc"),
    ("k", "K"),  # Kelvin sign: lowercases to k
    ("å", "Å"),  # Angstrom sign: lowercases to a-ring
    ("ß", "ẞ"),  # capital sharp s: lowercases to sharp s
    ("ÿ", "Ÿ"),  # Y with diaeresis
    ("s", "ſ"),  # long s: Java's equalsIgnoreCase says equal (its uppercase is S)
    ("i", "ı"), ("I", "ı"),  # dotless i: likewise
    ("i", "İ"),  # dotted capital I: simple lowercase is i, full lowercase is i + combining dot
    ("µ", "Μ"), ("µ", "μ"),  # micro sign vs Greek mu
    ("é", "É"), ("ß", "SS"), ("ß", "ss"), ("Straße", "STRAẞE"),
]  # fmt: skip
OPERATORS = ["StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase"]


def probe(client: Any) -> tuple[int, list[str]]:
    compared, disagreements = 0, []
    for op in OPERATORS:
        for policy_value, request_value in PAIRS:
            doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket",
                   "Resource": "*", "Condition": {op: {"s3:prefix": policy_value}}}]}  # fmt: skip
            response = client.simulate_custom_policy(
                PolicyInputList=[json.dumps(doc, ensure_ascii=False)], ActionNames=["s3:ListBucket"],
                ResourceArns=["arn:aws:s3:::b"],
                ContextEntries=[{"ContextKeyName": "s3:prefix", "ContextKeyValues": [request_value],
                                 "ContextKeyType": "string"}],
            )  # fmt: skip
            aws = response["EvaluationResults"][0]["EvalDecision"] == "allowed"
            principal = Principal("arn:aws:iam::123456789012:role/probe", [parse_policy(doc, "probe")])
            reach = evaluate(principal, "s3:ListBucket", "arn:aws:s3:::b", {"s3:prefix": request_value})
            compared += 1
            if reach != aws:
                disagreements.append(f"{op} {policy_value!r} vs {request_value!r}: AWS {aws}, Reach {reach}")
    return compared, disagreements


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", help="AWS CLI profile with iam:SimulateCustomPolicy")
    args = parser.parse_args()
    import boto3  # noqa: PLC0415 - optional dependency

    client = boto3.Session(profile_name=args.profile, region_name="us-east-1").client("iam")
    compared, disagreements = probe(client)
    print(f"{compared} cases compared, {len(disagreements)} disagreements")
    for line in disagreements:
        print(f"  {line}")
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
