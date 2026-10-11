# Changelog

## Unreleased

### Added

- `reach audit --html FILE`: a self-contained HTML report. Every ALLOWED cell shows its witness request, the
  statements that allow it (found by the reference evaluator), and a `reach can` command that reproduces it.
- Planted instructions and tool poisoning: `reach agents` finds the text each agent loads (instruction files, rules,
  skills, subagents, commands, installed plugins, and local MCP servers' source) and checks it. Tool, skill and
  subagent descriptions are checked by Reach itself (secrets plus concealment, override phrasing, shadowing,
  `<IMPORTANT>` blocks); whole files are scanned with Husk when installed (`reach-security[husk]`). Planted
  instructions complete the trifecta's untrusted-input leg with no human gate. SARIF rules REACH005 and REACH006.
- IPv6: IP keys are 128-bit, so IPv6 networks and sources are decided exactly. Mixed families, IPv4-mapped sources
  and malformed networks follow AWS as measured with `validation/ip_probe.py` (finding 7: 460 cases, 0
  disagreements). A malformed network is now decided exactly when the key is absent.
- `StringEqualsIgnoreCase` and `StringNotEqualsIgnoreCase`, also under `ForAnyValue`/`ForAllValues`: equal full
  Unicode lowercase forms, as measured with `validation/case_probe.py` (finding 8).

### Fixed

- Witness ARNs could have empty or blank names (`arn:aws:s3:::accesspoint//object/`, `arn:aws:kms: : :key/ `). ARN
  placeholders from the action catalogue now match one character or more, the plainest resource type is tried
  first, and witnesses are tidied to a real region, the principal's account and `example` names, each rewrite kept
  only if the reference evaluator gives the same answer.
- Witness preferences (printable strings, an ARN shape) could use the full 30 s solver budget before the real
  check ran: one fuzz case took 68 s. Each preference now gets 2 s; the test suite runs in about a sixth of the time.

## 0.2.0 (2026-10-11)

### Fixed

- `aws:PrincipalIsAWSService` was free, so a policy conditioned on it could get an ALLOWED witness no IAM user or role
  can produce. It is now pinned to `false`.
- "Assume roles" in `reach agents --authz` asked `sts:AssumeRole` on `*` without any trust policy, so a principal
  that a role's trust policy names directly was reported DENIED. It is now decided against every role's trust policy.
- Actions with many resource types were slow and erratic in Z3 (`ec2:RunInstances` on `*`: 2 to 60 s). They are now
  decided once per resource type: about 16 ms, exact. The test suite runs 2.5 times faster.
- Policy variables in `Resource` elements were read as literal text, so Reach could prove DENIED a request AWS allows
  (`validation/FINDINGS.md`, finding 5).
- `Bool` compared lowercase strings and restricted any key under it to `true`/`false`, which could prove DENIED a
  request AWS allows. It now reads both sides as booleans, as measured against AWS (finding 6).

### Added

- AWS Organizations: `--org org.json` (from `scripts/export_org.py`, read-only) applies the SCP layers of the caller's
  account and the RCPs of the resource's account, and pins `aws:PrincipalOrgID`/`aws:PrincipalOrgPaths` and
  `aws:ResourceOrgID`/`aws:ResourceOrgPaths`. RCPs cover the 62 services that support them, with every documented
  exemption. `examples/org/org.json` shows a data perimeter.
- `reach audit`: every user and role in a snapshot against the high-impact questions, in parallel, with a matrix,
  per-question "who can", JSON and `--fail-on-allowed`. 5,000 principals in about 40 s on 32 threads
  (`docs/BENCHMARKS.md`, `scripts/synth_account.py`, `scripts/benchmark.py`).
- Policy variables, exact: `${aws:username}`, principal tags, pinned keys, `${key, 'default'}`, `${*}`/`${?}`/`${$}`,
  and symbolic substitution for values the request decides. Only under `Version: 2012-10-17`, as in AWS.
- `ForAnyValue`/`ForAllValues` over multi-valued and single-valued keys, with a bound on set sizes that keeps DENIED
  a proof. The catalogue now records the 207 keys AWS types as `ArrayOf…`. `--context 'aws:TagKeys=["a","b"]'` pins a
  set.
- `reach agents --sarif FILE` (SARIF 2.1.0 for GitHub code scanning) and `--fail-on critical|high`.
- A GitHub Action (`uses: ctrl-adam/Reach@v0.2.0`) that runs Reach and uploads the report to code scanning.

## 0.1.0 (2026-10-11)

First release.

### Reasoning engine (`reach can`)

- Compiles AWS IAM policies to Z3 and answers "can this principal do this?" with three verdicts:
  - DENIED comes with a proof.
  - ALLOWED comes with a concrete witness request.
  - UNKNOWN names the exact assumptions it depends on.
- Covers identity policies, permissions boundaries, SCP layers, session policies and resource-based policies:
  - principal matching;
  - same-account grant paths;
  - required trust and KMS policies;
  - cross-account access.
- Conditions: String, ARN, Bool, Null, Numeric, Date and IpAddress, with `IfExists`. IP keys are bitvectors and time
  keys are one shared clock.
- Bundles AWS's Service Authorization Reference: 22,080 actions across 456 services, with per-action resource types and
  condition keys.
- Action classes make `*` queries over every action fast: about 0.1 s when allowed, about 4 s for a full DENIED proof.
- Loads offline from `aws iam get-account-authorization-details`.

### Agent analysis (`reach agents`)

- Discovers Claude Code, Claude Desktop, Cursor, VS Code and Windsurf, their MCP servers, and AI agents in GitHub
  Actions workflows.
- For each agent, records:
  - its shell mode, read from its own permission settings;
  - the credentials handed to its tools;
  - ambient credentials, for local agents with a shell.
- Flags secrets hardcoded in configs or committed in `.env` files. No secret value is ever output.
- `--home` scans another home directory, with its own AppData and none of your environment variables.
- `--resolve` maps AWS profiles to principals. `--authz` evaluates high-impact capabilities for each principal.
- Lethal-trifecta analysis per agent (untrusted input, private data, exfiltration), with a severity and the cheapest leg
  to break.
- Reads Claude Code's `allow` rules:
  - Pre-approved `WebFetch`, network commands (`Bash(curl:*)`) or credential readers (`Bash(aws:*)`) remove the human
    gate, so an approval-mode agent can still be CRITICAL.
  - A pre-approved MCP server (`mcp__github`) is ungated. A server denied as a whole (`mcp__github__*`) provides no leg.

### Validation

- A solver-free reference evaluator replays every witness before it is reported.
- A differential fuzzer checks the engine against the reference evaluator.
- A harness compares Reach with AWS's IAM policy simulator, and a live S3 test settles one rule. See
  `validation/FINDINGS.md`: one Reach bug fixed, two modelling gaps closed, and one AWS simulator error confirmed on
  live S3.
