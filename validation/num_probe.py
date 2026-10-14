"""Numeric operators against AWS's policy simulator: decimals, signs, exponents, precision, invalid values.

    python -m validation.num_probe --profile reach-sim

Every (operator, policy values, request value) combination below is sent to iam:SimulateCustomPolicy
(read-only) and compared with Reach's reference evaluator. Reach answering None (a spelling it leaves
unmodelled, such as `+5` or Unicode digits in a request) is never a disagreement. FINDINGS.md, finding 9,
records what this measured.
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

OPERATORS = ["NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericGreaterThanEquals",
             "NumericLessThanIfExists"]  # fmt: skip
POLICY_VALUES: list[list[str]] = [
    ["10"], ["10.5"], ["-3"], ["+5"], ["5.0"], ["1e1"], ["1E-1"], ["007"], [".5"], ["-0"], ["9007199254740993"],
    ["0.10000000000000000001"], ["0x10"], [" 5"], ["abc"], ["Infinity"], ["1_000"], ["abc", "10"], ["10", "abc"],
]  # fmt: skip
REQUEST_VALUES: list[str | None] = [
    "10", "10.0", "10.50", "-3", "-3.0", "5", "7", "0", "-0.5", "0.1", "9007199254740992", "0.5",
    "+5", "1e1", ".5", "5.", "١٠", "0x10", " 5", "abc", "", None,
]  # fmt: skip
ARN = "arn:aws:iam::123456789012:role/probe"


def probe(client: Any) -> tuple[int, int, list[str]]:
    total = compared = 0
    disagreements: list[str] = []
    for op, values, request in itertools.product(OPERATORS, POLICY_VALUES, REQUEST_VALUES):
        doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*",
               "Condition": {op: {"s3:max-keys": values}}}]}  # fmt: skip
        entries = [] if request is None else [
            {"ContextKeyName": "s3:max-keys", "ContextKeyValues": [request], "ContextKeyType": "string"}
        ]  # fmt: skip
        response = client.simulate_custom_policy(
            PolicyInputList=[json.dumps(doc)], ActionNames=["s3:ListBucket"], ResourceArns=["arn:aws:s3:::b"],
            ContextEntries=entries,
        )  # fmt: skip
        total += 1
        aws = response["EvaluationResults"][0]["EvalDecision"] == "allowed"
        principal = Principal(ARN, [parse_policy(doc, "probe")])
        reach = evaluate(principal, "s3:ListBucket", "arn:aws:s3:::b", {"s3:max-keys": request})
        if reach is None:
            continue
        compared += 1
        if reach != aws:
            disagreements.append(f"{op} {values} request={request!r}: AWS {aws}, Reach {reach}")
    return total, compared, disagreements


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", help="AWS CLI profile with iam:SimulateCustomPolicy")
    args = parser.parse_args()
    import boto3  # noqa: PLC0415 - optional dependency

    client = boto3.Session(profile_name=args.profile, region_name="us-east-1").client("iam")
    total, compared, disagreements = probe(client)
    print(f"{total} cases, {compared} decided by Reach and compared, {len(disagreements)} disagreements")
    for line in disagreements:
        print(f"  {line}")
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
