---
name: auditing-github-actions-and-cicd
description: Audit GitHub Actions workflows and CI/CD pipelines for script injection, dangerous pull_request_target triggers, unpinned actions, and secret exposure.
---

# Auditing GitHub Actions and CI/CD Security

## Purpose
Audit `.github/workflows/*.yml` files to discover common CI/CD security pitfalls, including script injection via `${{ github.event... }}`, unpinned third-party actions susceptible to supply chain compromise, and excessive token permissions.

## Safe operating rules
- Passively audit workflow YAML files.
- Do not trigger unauthorized workflow dispatches.
- Document insecure trigger contexts and provide hardened workflow templates.

## Workflow
1. Locate all workflow files in `.github/workflows/`.
2. Check for `pull_request_target` triggers combined with explicit repository checkouts of untrusted pull request code.
3. Check for inline script execution using unescaped event contexts (e.g. `run: echo "${{ github.event.issue.title }}"`).
4. Verify whether external actions are pinned to immutable commit SHAs instead of mutable branch tags (e.g. `actions/checkout@v4` vs `actions/checkout@b4ffde...`).
5. Check if default workflow permissions are restricted with top-level `permissions: read-all` or `permissions: contents: read`.

## Remediation Guidance
- Never interpolate untrusted GitHub event expressions into `run:` scripts. Pass them via environment variables:
  ```yaml
  # Vulnerable:
  - run: echo "Title: ${{ github.event.issue.title }}"

  # Secure:
  - env:
      ISSUE_TITLE: ${{ github.event.issue.title }}
    run: echo "Title: $ISSUE_TITLE"
  ```
- Pin third-party actions to full commit hashes:
  ```yaml
  uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
  ```
- Explicitly set minimal `permissions` for `GITHUB_TOKEN`.
