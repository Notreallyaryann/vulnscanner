---
name: hunting-hardcoded-secrets-and-keys
description: Identify leaked API keys, tokens, database credentials, and private keys using Shannon entropy analysis and high-confidence signature patterns.
---

# Hunting Hardcoded Secrets and API Keys

## Purpose
Detect sensitive credentials, private keys, database passwords, OAuth tokens, and cloud provider API keys embedded directly in source code, configuration files, and commit histories.

## Safe operating rules
- Only test authorized repositories.
- Never log, display in plain text, or transmit live production secrets.
- Redact secrets when generating findings (e.g. `sk_live_...482f`).
- Advise immediate key revocation, rotation, and migration to secure secret managers (e.g. AWS Secrets Manager, HashiCorp Vault).

## Workflow
1. Scan source files, `.env` files, config files (`.json`, `.yaml`), and docs for known provider signatures (AWS, Stripe, GitHub, OpenAI, Slack, Google).
2. Calculate Shannon entropy on quoted strings to catch generic unformatted high-entropy secret strings.
3. Exclude mock keys, test placeholders (`foo`, `dummy`, `xxxx`), and known public identifiers (e.g. public Stripe publishable keys `pk_live_`).

## Remediation Guidance
- Immediately rotate and revoke exposed keys in the relevant provider dashboard.
- Remove the secret from Git history (using tools like `git-filter-repo` or BFG Repo-Cleaner) if pushed to version control.
- Load secrets strictly at runtime via environment variables or secret management services.
