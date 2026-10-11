# Changelog

## Unreleased

### Fixed

- Policy variables in `Resource` elements were read as literal text, so Reach could prove DENIED a request AWS allows
  (`validation/FINDINGS.md`, finding 5).
- `Bool` compared lowercase strings and restricted any key under it to `true`/`false`, which could prove DENIED a
  request AWS allows. It now reads both sides as booleans, as measured against AWS (finding 6).

### Added

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
