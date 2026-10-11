from __future__ import annotations

from pathlib import Path

import pytest

from reach.blast import HIGH_IMPACT, capabilities, principal_ref, resolve_profiles
from reach.engine import Verdict
from reach.loaders import AuthorizationDetails

FIXTURE = Path(__file__).parent / "fixtures" / "authz.json"


class FakeSession:
    IDENTITIES = {"dev": "arn:aws:iam::123456789012:user/alice"}

    def __init__(self, profile):
        self.profile = profile

    def client(self, name):
        assert name == "sts"
        return self

    def get_caller_identity(self):
        if self.profile not in self.IDENTITIES:
            raise RuntimeError("The config profile could not be found")
        return {"Arn": self.IDENTITIES[self.profile]}


def test_resolve_profiles_reports_failures_without_raising():
    out = resolve_profiles(["dev", "missing"], FakeSession)
    assert out[0].arn == "arn:aws:iam::123456789012:user/alice" and not out[0].error
    assert out[1].arn == "" and "could not be found" in out[1].error


@pytest.mark.parametrize(
    ("arn", "ref"),
    [
        ("arn:aws:iam::123456789012:user/alice", "arn:aws:iam::123456789012:user/alice"),
        ("arn:aws:sts::123456789012:assumed-role/data-pipeline/session-1", "data-pipeline"),
    ],
)
def test_principal_ref(arn, ref):
    assert principal_ref(arn) == ref


def test_capabilities_for_a_snapshot_principal():
    details = AuthorizationDetails.load(str(FIXTURE))
    caps = {c.label: c for c in capabilities(details, "arn:aws:iam::123456789012:user/alice")}
    assert set(caps) == {label for label, _, _ in HIGH_IMPACT}
    # alice: PowerUserAccess minus IAM, an explicit iam:* deny, and a boundary of s3:* + ec2:Describe*.
    assert caps["read S3 objects"].verdict is Verdict.ALLOWED
    assert caps["read S3 objects"].witness is not None
    assert caps["modify IAM"].verdict is Verdict.DENIED
    assert caps["start compute"].verdict is Verdict.DENIED  # the boundary has no ec2:RunInstances
    assert caps["read secrets"].verdict is Verdict.DENIED


def test_capabilities_for_an_assumed_role_session():
    details = AuthorizationDetails.load(str(FIXTURE))
    caps = {c.label: c for c in capabilities(details, "arn:aws:sts::123456789012:assumed-role/data-pipeline/s")}
    assert caps["read S3 objects"].verdict is Verdict.ALLOWED
    assert caps["write S3 objects"].verdict is Verdict.DENIED
