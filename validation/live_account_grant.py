"""Live test for FINDINGS.md finding 4: does a same-account S3 bucket policy that names the
*account* principal let an IAM user with no identity policies read an object?

    python -m validation.live_account_grant --admin-profile reach-sim --probe-profile reach-prob

* admin profile: may create, configure and delete the test bucket (and nothing else);
* probe profile: an IAM user in the same account with no permissions at all.

Three cases against one bucket, always cleaned up afterwards:

    A  no bucket policy                      -> must be denied (proves the probe has no permissions)
    B  policy grants the account principal   -> the open question
    C  policy grants the probe user's ARN    -> must be allowed (proves the setup works)

Bucket policy changes take a while to apply everywhere. A first version of
this test sampled for only ~12 seconds and recorded "denied" before the
policy was live, which made even control C fail. Each case now waits a full
settle period after the change, then requires several identical reads.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import boto3
from botocore.exceptions import ClientError

KEY = "reach-probe.txt"
SETTLE_S = 60  # wait after every bucket policy change before sampling
STABLE_READS = 5  # identical consecutive answers required after settling
MAX_WAIT_S = 120


LAST_DENIAL: dict[str, str] = {}


def read_settles(probe, bucket: str) -> str:
    """'allowed' or 'denied', once consecutive reads agree after the settle period."""
    time.sleep(SETTLE_S)
    deadline = time.monotonic() + MAX_WAIT_S
    streak: list[str] = []
    while time.monotonic() < deadline:
        try:
            probe.get_object(Bucket=bucket, Key=KEY)["Body"].read()
            outcome = "allowed"
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDenied", "403"):
                raise
            outcome = "denied"
            LAST_DENIAL["message"] = exc.response["Error"].get("Message", "")
        streak = [*streak, outcome][-STABLE_READS:]
        if len(streak) == STABLE_READS and len(set(streak)) == 1:
            return outcome
        time.sleep(3)
    raise TimeoutError(f"reads never settled: last answers {streak}")


def policy(bucket: str, principal: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "ReachProbe",
            "Effect": "Allow",
            "Principal": {"AWS": principal},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
        }],
    })  # fmt: skip


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--admin-profile", required=True)
    parser.add_argument("--probe-profile", required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    admin_session = boto3.Session(profile_name=args.admin_profile, region_name=args.region)
    probe_session = boto3.Session(profile_name=args.probe_profile, region_name=args.region)
    admin_arn = admin_session.client("sts").get_caller_identity()["Arn"]
    probe_identity = probe_session.client("sts").get_caller_identity()
    account, probe_arn = probe_identity["Account"], probe_identity["Arn"]
    if probe_arn == admin_arn:
        print("the probe profile signs in as the admin user; it must be a separate user", file=sys.stderr)
        return 2
    print(f"admin {admin_arn}\nprobe {probe_arn}")

    bucket = f"reach-probe-{account}"
    s3 = admin_session.client("s3")
    probe = probe_session.client("s3")
    results: dict[str, str] = {}
    try:
        s3.create_bucket(Bucket=bucket)
    except ClientError as exc:
        print(f"could not create the test bucket, nothing was created: {exc}", file=sys.stderr)
        return 2
    try:
        s3.put_object(Bucket=bucket, Key=KEY, Body=b"reach live test\n")
        results["A no bucket policy"] = read_settles(probe, bucket)
        s3.put_bucket_policy(Bucket=bucket, Policy=policy(bucket, f"arn:aws:iam::{account}:root"))
        results["B account principal"] = read_settles(probe, bucket)
        s3.put_bucket_policy(Bucket=bucket, Policy=policy(bucket, probe_arn))
        results["C probe user ARN"] = read_settles(probe, bucket)
    finally:
        for cleanup in (
            lambda: s3.delete_bucket_policy(Bucket=bucket),
            lambda: s3.delete_object(Bucket=bucket, Key=KEY),
            lambda: s3.delete_bucket(Bucket=bucket),
        ):
            try:
                cleanup()
            except ClientError as exc:
                print(f"cleanup step failed: {exc}", file=sys.stderr)
        print(f"cleaned up bucket {bucket}")

    for case, outcome in results.items():
        print(f"{case:<22} {outcome}")
    if LAST_DENIAL:
        print(f"last denial message: {LAST_DENIAL['message']}")
    valid = results.get("A no bucket policy") == "denied" and results.get("C probe user ARN") == "allowed"
    print("controls valid" if valid else "CONTROLS FAILED: the result for B cannot be trusted")
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
