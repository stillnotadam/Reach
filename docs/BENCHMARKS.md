# Benchmarks

`reach audit` decides every user and role in an account against nine high-impact questions: read secrets, read SSM
parameters, decrypt with KMS, read and write S3 objects, modify IAM, assume roles, start compute, invoke Lambda.
Each answer is a proof (DENIED), a witness request replayed through the independent reference evaluator (ALLOWED),
or UNKNOWN with the assumptions it depends on.

## Results

An Intel 13th/14th-generation Core desktop CPU (family 6, model 183), 32 logical CPUs, Python 3.15, z3-solver 5.1. Wall-clock time including worker
start-up. Synthetic accounts are 40% users and 60% roles.

| Principals | Workers | Decisions | Seconds | Decisions/s | Allowed | Denied | Unknown | Errors |
|-----------:|--------:|----------:|--------:|------------:|--------:|-------:|--------:|-------:|
| 250 | 1 | 2,250 | 17.8 | 127 | 1,052 | 1,198 | 0 | 0 |
| 250 | 32 | 2,250 | 2.7 | 836 | 1,052 | 1,198 | 0 | 0 |
| 1,000 | 1 | 9,000 | 69.5 | 130 | 4,037 | 4,963 | 0 | 0 |
| 1,000 | 32 | 9,000 | 8.6 | 1,041 | 4,037 | 4,963 | 0 | 0 |
| 2,500 | 32 | 22,500 | 18.9 | 1,192 | 10,095 | 12,405 | 0 | 0 |
| 5,000 | 32 | 45,000 | 40.5 | 1,110 | 20,233 | 24,767 | 0 | 0 |

Time grows linearly with the number of principals. Serial and parallel runs produce identical verdicts.

## The synthetic account

`scripts/synth_account.py` builds what real accounts contain, not toy policies:

- team groups (developers, data engineers, operators, read-only, admins) with managed policies;
- tag-based access with policy variables (`aws:ResourceTag/team` equal to `${aws:PrincipalTag/team}`, secrets and
  SSM parameters under `app/${aws:PrincipalTag/team}/`);
- guardrails: a region-restricting `Deny` with `NotAction`, an MFA `Deny` with `BoolIfExists`;
- a `NotAction` power-user policy, a `ForAllValues:StringEquals` tag-on-create rule on `aws:TagKeys`, `iam:PassRole`
  limited by `iam:PassedToService`, `kms:ViaService` conditions;
- permissions boundaries on most developers;
- Lambda and EC2 service roles, GitHub OIDC CI roles, and cross-team roles trusted by named users with MFA.

## Reproduce

```bash
python scripts/benchmark.py --sizes 250 1000 2500 5000 --workers 1 32
```

## What made it fast

- **Action classes.** A wildcard action is split into groups of real actions that every policy treats alike;
  one solver problem decides each group.
- **Resource-type split.** An action that applies to several resource types is decided once per type.
  `ec2:RunInstances` applies to 18; as one disjunction it took 2 to 60 seconds depending on Z3's heuristics,
  split it takes about 16 milliseconds: roughly a thousand times faster, and stable.
- **Segment-wise ARNs.** A resource is six solver variables, one per ARN segment, rather than one long string.
- **Trust-policy pruning.** "Assume roles" checks only roles whose trust policy can name the principal; any other
  role cannot be assumed by it, so skipping it keeps the answer exact.
- **Processes, not threads.** Principals are independent, so they are spread across worker processes, each given
  the snapshot once.
