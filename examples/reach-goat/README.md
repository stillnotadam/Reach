# reach-goat

A deliberately vulnerable AI-agent setup for trying Reach. Every secret in it is a placeholder.

| File | What is wrong with it |
|------|------------------------|
| `.claude/settings.json` | Claude Code runs with `bypassPermissions`: every tool call, shell included, runs without approval |
| `.mcp.json` | a GitHub token hardcoded in the config; a database password inside a connection URL; a web-fetch server next to private data |
| `.github/workflows/triage.yml` | `claude-code-action` triggered by any issue comment, with no `if:` gate, holding a write token, OIDC and a deploy key |
| `authz.json` | an AWS account snapshot: the agent's IAM user can read secrets and assume an all-powerful `deploy` role |

## Agents and the lethal trifecta

```bash
reach agents --home examples/reach-goat/.no-home --project examples/reach-goat
```

Reach reports both agents as **CRITICAL**. Each one combines untrusted input, private data and an exfiltration channel
with no human approval in the way. For each, it names the cheapest leg to break. It also flags the hardcoded GitHub
token, and prints neither that token nor the database password.

`--home` points at an empty directory, so the scan ignores your own config files and your shell's environment
variables. Drop it to scan your real setup.

## What the agent's AWS identity can do

```bash
reach can --authz examples/reach-goat/authz.json --principal agent-dev secretsmanager:GetSecretValue '*'
reach can --authz examples/reach-goat/authz.json --principal agent-dev iam:CreateAccessKey '*'
reach can --authz examples/reach-goat/authz.json --principal agent-dev sts:AssumeRole arn:aws:iam::123456789012:role/deploy
reach can --authz examples/reach-goat/authz.json --principal agent-dev s3:PutObject arn:aws:s3:::goat-uploads/report.csv
```

* **`secretsmanager:GetSecretValue`:** ALLOWED, with a witness secret under `app/`.
* **`iam:CreateAccessKey`:** DENIED, with a proof. The explicit `iam:*` deny and the missing grant both rule it out.
* **`sts:AssumeRole` on `deploy`:** ALLOWED. The trust policy names the user directly, so no identity permission is
  needed. `deploy` can do anything.
* **`s3:PutObject` on `goat-uploads`:** ALLOWED only from the office network. The witness shows
  `aws:SourceIp = 203.0.113.x`, and pinning `--context aws:SourceIp=8.8.8.8` proves it DENIED.
