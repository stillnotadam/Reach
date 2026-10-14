"""BinaryEquals against AWS's policy simulator: is the base64 decoded, or compared as text?

    python -m validation.binary_probe --profile reach-sim

Each (operator, policy values, request value) combination is sent to iam:SimulateCustomPolicy (read-only) and
compared with Reach's reference evaluator. Policy values are valid base64 only: IAM rejects anything else, so
there is nothing to compare. FINDINGS.md, finding 10, records what this measured.
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

OPERATORS = ["BinaryEquals", "BinaryNotEquals", "BinaryEqualsIfExists"]
POLICY_VALUES: list[list[str]] = [["YWJj"], ["YWI="], ["YWJjZA=="], [""], ["YWJj", "eHl6"]]
# "YWJ=" decodes to the same bytes as "YWI=" (non-canonical padding bits); "YWI" is "YWI=" without padding.
REQUEST_VALUES: list[str | None] = ["YWJj", "abc", "ywjj", "YWJj ", "YWI=", "YWJ=", "YWI", "YWJjZA==", "YWJjZA",
                                    "eHl6", "", None]  # fmt: skip


def probe(client: Any) -> tuple[int, list[str]]:
    compared, disagreements = 0, []
    for op, values, request in itertools.product(OPERATORS, POLICY_VALUES, REQUEST_VALUES):
        doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*",
               "Condition": {op: {"s3:prefix": values}}}]}  # fmt: skip
        entries = [] if request is None else [
            {"ContextKeyName": "s3:prefix", "ContextKeyValues": [request], "ContextKeyType": "string"}
        ]  # fmt: skip
        response = client.simulate_custom_policy(
            PolicyInputList=[json.dumps(doc)], ActionNames=["s3:ListBucket"], ResourceArns=["arn:aws:s3:::b"],
            ContextEntries=entries,
        )  # fmt: skip
        aws = response["EvaluationResults"][0]["EvalDecision"] == "allowed"
        principal = Principal("arn:aws:iam::123456789012:role/probe", [parse_policy(doc, "probe")])
        reach = evaluate(principal, "s3:ListBucket", "arn:aws:s3:::b", {"s3:prefix": request})
        compared += 1
        if reach != aws:
            disagreements.append(f"{op} {values} request={request!r}: AWS {aws}, Reach {reach}")
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
