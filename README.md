# Reach

**Prove what cloud credentials, and the AI agents holding them, can actually reach.**

Reach compiles AWS IAM policies into SMT constraints and asks Z3 whether a
principal can perform an action on a resource. Every answer is one of three
verdicts, and Reach never rounds an `unknown` up or down:

| Verdict   | Meaning |
|-----------|---------|
| `DENIED`  | **Proof.** No request, no context value and no reading of the unmodelled conditions allows it (UNSAT). Comes with the reason: which layer blocks it, or which Deny covers it. |
| `ALLOWED` | **Witness.** A concrete request that is allowed even when every condition Reach does not model goes against the attacker. |
| `UNKNOWN` | Allowed only if some unmodelled condition goes the attacker's way. Reach lists exactly which assumptions that relies on. |

> Status: pre-alpha. This is the reasoning core (Phase 1 of the [roadmap](ROADMAP.md)). Agent discovery and attack paths build on top of it.

## Example

```console
$ aws iam get-account-authorization-details --output json > authz.json
$ reach can --authz authz.json --principal alice ec2:RunInstances '*'
DENIED  ec2:RunInstances on *
  principal  arn:aws:iam::123456789012:user/alice
  proof      no request context satisfies the policies (UNSAT)
  why        Implicitly denied by permissions boundary dev-boundary: it allows no request the identity policies allow.

$ reach can --policy admin-with-mfa.json iam:CreateAccessKey '*'
ALLOWED  iam:CreateAccessKey on *
  principal  arn:aws:iam::111122223333:role/reach-adhoc
  witness    iam:CreateAccessKey on arn:aws:iam::…
             aws:MultiFactorAuthPresent = "true"
```

Queries are existential: `reach can … 's3:*' 'arn:aws:s3:::customer-pii/*'` asks whether *any* S3 action on *any*
object in the bucket is reachable, and the witness shows one.

## What is modelled

- Identity-based policies (inline, managed, group), permissions boundaries, session policies.
- SCPs as layers (root → OU → account), each of which must allow; the management account and service-linked roles are exempt.
- Explicit Deny from every policy type.
- Resource-based policies (bucket, key, trust policies): `Principal`/`NotPrincipal` matching, same-account grant paths
  (direct user, role and session grants; account grants delegate), required policies (role trust, KMS), and
  cross-account access needing both sides. With `--authz`, `sts:AssumeRole` queries load the role's trust policy.
- `Action`/`NotAction`, `Resource`/`NotResource`, IAM wildcards. Actions match case-insensitively; resource ARNs match segment by segment.
- Conditions: `String(Not)Equals`, `String(Not)Like`, `Arn(Not)Equals`, `Arn(Not)Like`, `Bool`, `Null`, `Numeric*`,
  `Date*`, `IpAddress`/`NotIpAddress`, and the `…IfExists` forms. Missing keys follow AWS semantics: positive operators
  fail, negated ones pass.
  - IP keys are 32-bit bitvectors, so CIDR matching is exact; time keys are epoch seconds, and `aws:CurrentTime` and
    `aws:EpochTime` share one clock, so a policy cannot be satisfied by two inconsistent times.
- The principal's own context is pinned: `aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:PrincipalTag/*`.
- A catalogue of real IAM actions, built from AWS's Service Authorization Reference, so wildcard queries range over actions that exist.

## Not modelled yet

These are always reported as `UNKNOWN` rather than guessed: `ForAnyValue`/`ForAllValues`; policy variables
(`${aws:username}`); multi-valued keys; IPv6 networks; decimal or signed numbers; `StringEqualsIgnoreCase` and `Binary*`. RCPs are not part of the decision yet. Whether a `Principal: "*"` grant is
capped by a permissions boundary or session policy is reported as `UNKNOWN` until verified against AWS. See the [roadmap](ROADMAP.md).

## How Reach checks itself

- Every `ALLOWED`/`UNKNOWN` witness is replayed through a second, solver-free implementation of the evaluation logic
  (`reach.reference`). If they disagree, Reach raises an error instead of reporting a verdict.
- `validation/fuzz.py` generates random principals (identity policies, boundaries, SCP layers, session policies,
  modelled and unmodelled conditions) and demands exact agreement between the two implementations, plus soundness of
  every `DENIED` proof against sampled concrete requests.
- `validation/aws_simulator.py` compares Reach with AWS's own IAM policy simulator, the only check that can catch a
  misreading of AWS semantics that both implementations share. It has already found one real Reach bug and two
  modelling gaps; see [validation/FINDINGS.md](validation/FINDINGS.md).

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m validation.fuzz --cases 5000   # longer differential fuzzing campaign
python scripts/build_catalog.py   # refresh the action catalogue
```

## License

AGPL-3.0-or-later.
