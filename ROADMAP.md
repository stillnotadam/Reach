# Roadmap

Reach is built in phases. Each one ships something usable on its own.

## Phase 1: one-step reasoning engine (in progress)

- [x] Policy parsing (string-or-list values, URL-encoded API documents, malformed-input errors)
- [x] Z3 encoding of IAM globs, with segment-wise ARN matching
- [x] Identity policies, permissions boundaries, SCP layers, session policies, explicit Deny
- [x] String, ARN, Bool and Null conditions, plus `IfExists`; missing-key semantics
- [x] Three-valued verdicts: opaque conditions pinned to their worst case to separate proofs from guesses
- [x] Denial explanations (blocking layer, or covering Deny statement)
- [x] Offline loading from `get-account-authorization-details`
- [x] Action catalogue from AWS's Service Authorization Reference (22,080 actions across 456 services, bundled)
- [x] Solver-free reference evaluator; every witness is replayed through it before being reported
- [x] Differential fuzzer: engine vs reference evaluator on random principals (exact verdict agreement, proof soundness)
- [x] Segment-wise resource encoding (six ARN segment variables): ~1000x faster on queries that timed out
- [x] Exact string literals (Z3 `StringVal` escape handling) and exact witness decoding
- [x] Simulator harness written (`validation/aws_simulator.py`), tested against a fake client
- [x] **First real runs** against the IAM policy simulator: 1 Reach bug fixed (`aws:RequestedRegion` and other always-present keys), 2 modelling gaps recorded ([FINDINGS](validation/FINDINGS.md))
- [x] Live test on real S3: same-account account-principal grants only delegate; AWS's simulator is wrong (finding 4)
- [x] `Bool` value handling, verified against the simulator (finding 6)
- [ ] Keep running the harness on new seeds and after every semantic change. Still to verify:
  - segment-wise wildcard matching in the `Resource` element (documented for `ArnLike`; to confirm for `Resource`)
- [x] Bundled Service Authorization Reference: per-action resource types and condition keys (simulator findings 2 and 3)
- [x] Action classes: one concrete solver problem per group of actions policies treat alike (`*` over 22,080 actions: ~0.1 s allowed, ~4 s full DENIED proof)
- [ ] Free ARN-valued condition keys (e.g. `aws:SourceArn`) still use the slower single-string encoding
- [x] Numeric, Date and IpAddress operators (Z3 integer and bit-vector theories), one presence flag per key across sorts
- [x] UNKNOWN verdicts list only the assumptions the witness actually depends on
- [x] IPv6 networks and `StringEqualsIgnoreCase`, both measured against AWS (findings 7 and 8)
- [x] Decimal and signed numbers, exact, measured against AWS (finding 9)
- [ ] `Binary*` operators
- [x] `ForAnyValue` / `ForAllValues` over multi-valued keys: bounded sets with a small-model bound, 207 `ArrayOf…` keys from AWS's reference data
- [x] Policy variables (`${aws:username}`, `${aws:PrincipalTag/…}`, defaults, `${*}`), symbolic when the request decides them
- [x] Resource-based policies: principal matching, same-account grant paths, required policies (trust, KMS), cross-account
- [x] Trust policies loaded from `get-account-authorization-details` for `sts:AssumeRole` queries
- [ ] Verify against AWS: whether boundaries/session policies cap `Principal: "*"` grants; role-ARN vs session-ARN grants
- [x] RCPs (only for the services they apply to, with the documented exemptions)
- [x] Load an organization's SCP tree from `organizations` API exports (`scripts/export_org.py`, `--org`)

## Phase 2: multi-step privilege escalation, then v0.1

- [ ] Escalation primitives as transitions: `iam:PassRole` + compute, `AttachUserPolicy`, `PutRolePolicy`, `UpdateAssumeRolePolicy`, `CreateAccessKey`, `CreatePolicyVersion`, …
- [ ] Role chaining through trust policies
- [ ] Bounded search for paths, reporting each step with its witness
- [ ] **Benchmark** against Datadog's pathfinding.cloud catalogue and other open-source tools, with published methodology

## Scale

- [x] `reach audit`: every principal against the high-impact questions, in parallel; benchmarks to 5,000 principals
- [x] Per-resource-type solving: ~1000x faster on actions with many resource types
- [x] `--org` for `reach can` and `reach audit`: SCP layers, RCPs and the org context keys

## Phase 3: agent discovery

- [x] `reach agents`: Claude Code (user and per-project), Claude Desktop, Cursor, VS Code, Windsurf; MCP servers over stdio and HTTP
- [x] Credentials per tool (env, args, headers, URLs) and ambient ones (`~/.aws` profiles, environment, `gh`, Docker, kube, SSH, `.env`)
- [x] Hardcoded-secret findings; no secret value is ever output (tested by planting fake secrets in every location)
- [x] `--resolve`: AWS profiles to principals via `sts:GetCallerIdentity`; `--authz`: high-impact capabilities per principal
- [x] Agentic GitHub workflows (`claude-code-action`, Gemini CLI, Codex, AI Inference): untrusted triggers, `if:` gates, token permissions, OIDC, secrets
- [x] `.env` files tracked in git flagged as committed secrets
- [ ] GitHub token scopes and app permissions; Slack scopes
- [x] Shell modes per agent (unrestricted / approval / allowlist / denied / none) from Claude Code `permissions` and CI agent configs

## Phase 4: lethal-trifecta paths, then v1.0

- [x] Label capabilities as untrusted input, private data or exfiltration, per agent, with the source of each leg
- [x] Severity (critical: every leg has an ungated way; high: a human approval stands in the way) and the cheapest leg to break
- [x] Text the agent loads as untrusted input: instruction files, rules, skills, subagents, commands, plugins, local MCP servers' tool descriptions (tool poisoning), with Husk for whole files
- [ ] Remote MCP servers' tool descriptions (needs a read-only `tools/list` without running the server); files the agent reads on demand (a cloned repository's source, dependencies)
- [x] Pre-approvals in agent settings (`WebFetch`, `Bash(curl:*)`, `Bash(aws:*)`, a whole MCP server) are ungated legs
- [x] SARIF 2.1.0 output and a GitHub Action that uploads it to code scanning
- [ ] BloodHound OpenGraph and HTML output

## Phase 5: launch

- [x] `reach-goat` vulnerable lab
- [x] v0.1.0 on PyPI via Trusted Publishing, with signed attestations
- [ ] Research write-up, talks
