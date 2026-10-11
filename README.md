# Reach

[![CI](https://github.com/ctrl-adam/Reach/actions/workflows/ci.yml/badge.svg)](https://github.com/ctrl-adam/Reach/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/reach-security.svg)](https://pypi.org/project/reach-security/)
[![Python](https://img.shields.io/pypi/pyversions/reach-security.svg)](https://pypi.org/project/reach-security/)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

**Prove what cloud credentials, and the AI agents holding them, can actually reach.**

AI agents run with real credentials: an AWS profile on a laptop, a GitHub token in an MCP config, a write token in a CI
job. Reach finds those agents and the credentials they can use. It proves what those credentials can do in AWS. And it
reports the agents that combine untrusted input, private data and a way to send data out (the *lethal trifecta*), with
the cheapest way to break each one.

```bash
pip install reach-security
reach agents --project .                      # agents, tools, credentials, trifecta findings
reach can --authz authz.json --principal dev secretsmanager:GetSecretValue '*'
```

Try it on the deliberately vulnerable [`examples/reach-goat`](examples/reach-goat).

## How the reasoning works

Reach compiles AWS IAM policies into SMT constraints and asks Z3 whether a principal can perform an action on a
resource. Every answer is one of three verdicts, and Reach never rounds an `unknown` up or down:

| Verdict   | Meaning |
|-----------|---------|
| `DENIED`  | **Proof.** No request, no context value and no reading of the unmodelled conditions allows it (UNSAT). Comes with the reason: which layer blocks it, or which Deny covers it. |
| `ALLOWED` | **Witness.** A concrete request that is allowed even when every condition Reach does not model goes against the attacker. |
| `UNKNOWN` | Allowed only if some unmodelled condition goes the attacker's way. Reach lists exactly which assumptions that relies on. |

Every verdict is checked three ways. A second, solver-free implementation replays each witness. A fuzzer checks the two
implementations against each other. And AWS's own policy simulator plus a live S3 test check both against AWS: see
[validation/FINDINGS.md](validation/FINDINGS.md), which includes an error in AWS's simulator that Reach found.

> Status: alpha (0.1.0). See the [roadmap](ROADMAP.md).

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

## Audit a whole account

```console
$ aws iam get-account-authorization-details --output json > authz.json
$ reach audit --authz authz.json
```

`reach audit` decides every user and role against nine high-impact questions (read secrets, decrypt with KMS, write
S3, modify IAM, assume roles, start compute, ...) and prints a matrix plus, per question, who can. `sts:AssumeRole` is
checked against every role's trust policy, since a trust policy can grant on its own. Principals run in parallel
across worker processes: 5,000 principals, 45,000 decisions, in about 40 seconds on a 32-thread desktop, with no
UNKNOWN verdicts ([benchmarks](docs/BENCHMARKS.md)). `--json` for machine output, `--fail-on-allowed` for CI,
`--scp LAYER=FILE` to apply SCPs.

## Agents

```console
$ reach agents --project . --resolve --authz authz.json
```

`reach agents` finds AI agents (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf), the MCP servers each one runs,
and the credentials each server is handed, plus ambient credentials that any agent with shell access can read. It reads
each agent's shell mode from its own permission settings, finds AI agents in GitHub Actions workflows (and flags those
triggered by text anyone can write while holding write tokens or secrets), flags secrets hardcoded in agent configs or
committed in `.env` files, and never prints a secret value. With `--resolve` it signs each reachable AWS profile
in to find its principal (read-only `sts:GetCallerIdentity`). With `--authz` it then asks the engine what that principal
can do: read secrets, decrypt with KMS, read or write S3, modify IAM, assume roles, start compute.

### Lethal trifecta

For every agent, Reach then checks for Simon Willison's *lethal trifecta*: **untrusted input** (text an attacker can
write reaches the agent), **private data** (it can read something sensitive) and an **exfiltration channel** (it can
send data out). Each leg is derived from evidence: built-in tools and the agent's own denied tools, its shell mode, its
MCP servers (classified by a small documented catalogue; unknown servers are reported, not guessed), credentials it is
handed, ambient credentials when it has a shell, proven AWS capabilities from `--authz`, and for CI agents their
triggers, `if:` gates, token permissions and secrets. All three legs with an ungated way each is **critical**; all
three behind a human approval is **high**. Reach names the cheapest leg to break.

Pre-approvals count: a Claude Code `allow` rule for `WebFetch`, a network command (`Bash(curl:*)`), a credential reader
(`Bash(aws:*)`) or a whole MCP server (`mcp__github`) removes the human gate on that leg. Not covered yet: injected text
inside files the agent reads (a cloned repository, a dependency).

### In CI: GitHub code scanning

```yaml
permissions:
  contents: read
  security-events: write  # to upload the report
steps:
  - uses: actions/checkout@v5
  - uses: ctrl-adam/Reach@v0.2.0
    with:
      fail-on: critical  # optional: fail the job on a critical trifecta
```

The action writes a SARIF 2.1.0 report and uploads it to code scanning, so findings show up in the Security tab and on
pull requests, each pointing at the line that causes it. Locally: `reach agents --project . --sarif reach.sarif`.

| Rule | Finding | Level |
|------|---------|-------|
| REACH001 | Lethal trifecta in one agent | error (critical) or warning (high) |
| REACH002 | Secret hardcoded in an agent or MCP config | error |
| REACH003 | Agent setting that removes a human check | warning |
| REACH004 | Secret in a `.env` file committed to git | error |

Alerts keep their identity when lines move, and no secret value is ever written to the report.

## What is modelled

- Identity-based policies (inline, managed, group), permissions boundaries, session policies.
- SCPs as layers (root → OU → account), each of which must allow; the management account and service-linked roles are exempt.
- RCPs of the account that owns the resource, for the services that support them; resources in the management account,
  service-linked roles and `kms:RetireGrant` are exempt. AWS managed KMS keys are exempt too, and an ARN does not say
  which keys those are, so an RCP on KMS can block a witness but never proves DENIED on its own.
- `--org org.json` loads an organization (`scripts/export_org.py`, read-only API calls): the SCP layers of the caller's
  account, the RCPs of the resource's account, and `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, `aws:ResourceOrgID`
  and `aws:ResourceOrgPaths`, so data-perimeter policies are decided exactly.
- Explicit Deny from every policy type.
- Resource-based policies (bucket, key, trust policies): `Principal`/`NotPrincipal` matching, same-account grant paths
  (direct user, role and session grants; account grants delegate), required policies (role trust, KMS), and
  cross-account access needing both sides. With `--authz`, `sts:AssumeRole` queries load the role's trust policy.
- `Action`/`NotAction`, `Resource`/`NotResource`, IAM wildcards. Actions match case-insensitively; resource ARNs match segment by segment.
- Conditions: `String(Not)Equals`, `String(Not)Like`, `Arn(Not)Equals`, `Arn(Not)Like`, `Bool`, `Null`, `Numeric*`,
  `Date*`, `IpAddress`/`NotIpAddress`, and the `…IfExists` forms. Missing keys follow AWS semantics: positive operators
  fail, negated ones pass. `Bool` reads both sides as booleans, as measured against AWS (`TRUE` is true, `other` false).
- `ForAnyValue`/`ForAllValues` with the String and ARN operators, over multi-valued keys (`aws:TagKeys` and the 207
  keys AWS's reference data types as `ArrayOf…`) and over single-valued keys (a set of at most one value, which is why
  `ForAllValues` on them passes when the key is absent). Each multi-valued key is a bounded set; the bound is one
  element per set condition on that key plus one, which is enough for any satisfying request to have a satisfying
  subset of that size, so DENIED stays a proof.
  - IP keys are 32-bit bitvectors, so CIDR matching is exact; time keys are epoch seconds, and `aws:CurrentTime` and
    `aws:EpochTime` share one clock, so a policy cannot be satisfied by two inconsistent times.
- The principal's own context is pinned: `aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:PrincipalTag/*`,
  `aws:username`.
- Policy variables (`${aws:username}`, `${aws:PrincipalTag/team, 'default'}`, `${*}`) in `Resource` and String
  conditions, under `Version: 2012-10-17` only. Known values are substituted; a value the request decides is
  substituted symbolically (the key's own solver variable inside a regular expression), so verdicts stay exact.
- A catalogue of real IAM actions, built from AWS's Service Authorization Reference, so wildcard queries range over actions that exist.

## Not modelled yet

These are always reported as `UNKNOWN` rather than guessed: set operators with numeric, date, IP or `Bool` operators,
or with `IfExists`; multi-valued keys without a set operator; policy variables over IP, time or multi-valued keys or
inside ARN operators; IPv6 networks; decimal or signed numbers; `StringEqualsIgnoreCase` and `Binary*`. Whether a `Principal: "*"` grant is
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
