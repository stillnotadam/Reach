# Findings from differential testing against AWS

Reach is compared against AWS's IAM policy simulator (`iam:SimulateCustomPolicy`) with
`validation/aws_simulator.py`. Every finding below came from a disagreement between Reach and AWS. Each one is either a
Reach bug that is now fixed and covered by a test, a documented limitation, or a quirk of the simulator itself.

## Reach bugs (fixed)

### 1. `aws:RequestedRegion` is never absent

- **Found:** seed 1, case 195. Reach said DENIED, AWS said allowed.
- **Cause:** Reach treated `aws:RequestedRegion` as an optional key. A Deny with `StringLikeIfExists` on it therefore
  applied to a request with no region, but no such request exists. Every request goes to a region, and the simulator
  fills in its endpoint region (`us-east-1`).
- **Probe:** with the key not supplied, `Null: {"aws:RequestedRegion": "false"}` fires in the simulator, so the key is
  present. The same probe shows `aws:PrincipalType`, `aws:userid` and `aws:ResourceAccount` are always present too.
- **Fix:** these keys are always present in Reach's model, and `aws:PrincipalType` is pinned from the principal
  (`User` / `AssumedRole`). Tests: `test_requested_region_is_never_absent`,
  `test_if_exists_deny_on_region_cannot_use_a_regionless_request`, `test_principal_type_is_pinned`.

## Reach limitations (documented, on the roadmap)

### 2. Actions apply only to their own resource types

- **Found:** seed 1, smoke run. `s3:PutObject` on an IAM role ARN, and `iam:CreateUser` on a role ARN.
- **AWS behaviour:** the simulator implicitly denies an action on a resource type the action does not use, even under
  `Allow *`, with zero matched statements.
- **Impact on Reach:** DENIED proofs stay sound, because Reach searches a superset of real requests. An ALLOWED witness,
  though, could pair an action with an impossible resource.
- **Fix needs:** per-action resource types from the Service Authorization Reference.

### 3. Service-specific condition keys exist only for the actions that support them

- **Found:** seed 1, case 29. `s3:max-keys` was pinned on an `s3:GetObject` request.
- **AWS behaviour:** AWS drops the key, so an `IfExists` condition on it passes.
- **Impact and fix:** same as finding 2. This needs per-action condition keys from the same reference data.

## Unsettled AWS rules (Reach reports UNKNOWN)

### 4. Same-account grants to the account principal

- **Found:** seed 2. All 7 disagreements in 1,157 compared cases. Reach said DENIED, AWS said allowed.
- **What happened:** in every case the only grant was a same-account resource policy naming the *account*
  (`"123456789012"` or `arn:aws:iam::123456789012:root`), and no identity policy allowed the action. Reach followed the
  delegation rule ("an account grant needs identity permissions too"). The simulator allowed all 7.
- **Why it is unsettled:** delegation is documented for KMS key policies and for cross-account access. For a
  same-account bucket policy, the simulator says the account grant suffices alone. The simulator is AWS's own
  evaluator, but it is known to differ from live services in places.
- **What Reach does now:** a proof cannot rest on a rule AWS's own simulator contradicts, so these cases are `UNKNOWN`,
  with the caveat named. Required policies (trust, KMS) keep delegation, and cross-account is unchanged. Test:
  `test_same_account_account_grant_is_unsettled`.
- **How to settle it:** a live test. Create one S3 bucket whose policy grants `s3:GetObject` to the account principal,
  then read an object as an IAM user with no identity policy.

## Simulator quirks (not Reach bugs)

- **Missing keys:** keys a policy mentions but the request does not carry are reported as `MissingContextValues`. In
  hundreds of compared cases the simulator's decision matched treating them as absent, which is how Reach and AWS
  model them.
- **`aws:CurrentTime`:** the simulator leaves it absent when not supplied. Real AWS always sets it, and Reach models it
  as always present. The harness always supplies it.
- **Input validation:** resource policies whose `Resource` is not a full ARN (`*`, `arn:aws:s3*`) are rejected as
  invalid input.
- **Limits of the simulator:** it cannot evaluate SCPs, session policies, required resource policies (trust, KMS), or
  resource policies with a role caller. Those parts of Reach are covered by the reference-evaluator fuzzer only.

## Runs

| Seed | Cases | Compared | Disagreements | Notes |
|------|-------|----------|---------------|-------|
| 1 | 500 | 281 | 0 | after finding 1 was fixed |
| 2 | 2000 | 1157 | 7 | all finding 4 (account-principal grants) |
| 2 | 2000 | 1150 | 0 | after finding 4: 49 cases UNKNOWN in Reach (AWS: 21 allowed, 28 denied) |
