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
- [x] Action catalogue from AWS's Service Authorization Reference (builder script; snapshot not yet bundled)
- [x] Solver-free reference evaluator; every witness is replayed through it before being reported
- [x] Differential fuzzer: engine vs reference evaluator on random principals (exact verdict agreement, proof soundness)
- [x] Segment-wise resource encoding (six ARN segment variables): ~1000x faster on queries that timed out
- [x] Exact string literals (Z3 `StringVal` escape handling) and exact witness decoding
- [x] Simulator harness written (`validation/aws_simulator.py`), tested against a fake client
- [x] **First real runs** against the IAM policy simulator: 1 Reach bug fixed (`aws:RequestedRegion` and other always-present keys), 2 modelling gaps recorded ([FINDINGS](validation/FINDINGS.md))
- [ ] Keep running the harness on new seeds and after every semantic change (`simulate-custom-policy`) and a live sandbox account: thousands of generated policy/request pairs, every disagreement either a Reach bug or a documented AWS quirk. In particular, verify:
  - segment-wise wildcard matching in the `Resource` element (documented for `ArnLike`; to confirm for `Resource`)
  - `Bool` value case handling
- [ ] **Per-action resource types** (first AWS-simulator finding): an action only applies to the resource types
  the Service Authorization Reference lists for it; today Reach treats action and resource as independent, so a
  witness could pair `s3:PutObject` with an IAM role ARN. Needs the reference data (same download as the catalogue).
- [ ] Free ARN-valued condition keys (e.g. `aws:SourceArn`) still use the slower single-string encoding
- [x] Numeric, Date and IpAddress operators (Z3 integer and bit-vector theories), one presence flag per key across sorts
- [x] UNKNOWN verdicts list only the assumptions the witness actually depends on
- [ ] IPv6 networks, decimal numbers, `StringEqualsIgnoreCase`
- [ ] `ForAnyValue` / `ForAllValues` over multi-valued keys (bounded sequences)
- [ ] Policy variables (`${aws:username}`, `${aws:PrincipalTag/…}`)
- [x] Resource-based policies: principal matching, same-account grant paths, required policies (trust, KMS), cross-account
- [x] Trust policies loaded from `get-account-authorization-details` for `sts:AssumeRole` queries
- [ ] Verify against AWS: whether boundaries/session policies cap `Principal: "*"` grants; role-ARN vs session-ARN grants
- [ ] RCPs (only for the services they apply to)
- [ ] Load an organization's SCP tree from `organizations` API exports

## Phase 2: multi-step privilege escalation, then v0.1

- [ ] Escalation primitives as transitions: `iam:PassRole` + compute, `AttachUserPolicy`, `PutRolePolicy`, `UpdateAssumeRolePolicy`, `CreateAccessKey`, `CreatePolicyVersion`, …
- [ ] Role chaining through trust policies
- [ ] Bounded search for paths, reporting each step with its witness
- [ ] **Benchmark** against Datadog's pathfinding.cloud catalogue and other open-source tools, with published methodology

## Phase 3: agent discovery

- [ ] Configs for Claude Code, Claude Desktop, Cursor and VS Code MCP; `.env` files; `~/.aws` profiles; `gh` auth; agentic GitHub workflows
- [ ] Resolve credentials: GitHub token scopes and app permissions; AWS caller identity fed into the engine. Secret values are never printed.

## Phase 4: lethal-trifecta paths, then v1.0

- [ ] Label capabilities as private data, untrusted input or exfiltration channel
- [ ] Attack-path search with the smallest fix that breaks each path
- [ ] SARIF, BloodHound OpenGraph and HTML output

## Phase 5: launch

- [ ] `reach-goat` vulnerable lab, research write-up, talks
