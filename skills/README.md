# VulnScanner Security Skills

45 modular defensive security skills for an authorized web vulnerability scanner and source code security engine.

Each skill contains:
- `SKILL.md` — purpose, workflow, safe operating rules, and remediation guidance
- `scripts/*.py` — a non-destructive reference implementation returning structured JSON

## Skill Library (45 Skills)

### Web & Injection Vulnerabilities (DAST / Sinks)
- `detecting-sql-injection`
- `detecting-cross-site-scripting`
- `detecting-command-injection`
- `detecting-ssrf-vulnerabilities`
- `detecting-ssti-vulnerabilities`
- `detecting-xxe-injection`
- `detecting-path-traversal-and-lfi`
- `detecting-csrf-vulnerabilities`
- `detecting-insecure-file-uploads`
- `detecting-cors-misconfiguration`
- `detecting-http-request-smuggling`

### Authentication & Authorization
- `analyzing-authentication-security`
- `analyzing-session-cookie-security`
- `detecting-jwt-and-session-flaws`
- `detecting-idor-and-broken-object-authorization`
- `detecting-broken-function-level-authorization-bfla`
- `auditing-oauth-and-oidc-flows`
- `evaluating-rate-limiting-and-brute-force`

### Static Code Analysis (SAST) & Supply Chain (SCA)
- `analyzing-javascript-dependencies`
- `hunting-hardcoded-secrets-and-keys`
- `detecting-insecure-deserialization`
- `detecting-prototype-pollution`
- `detecting-cryptographic-weaknesses`
- `detecting-mass-assignment`
- `auditing-github-actions-and-cicd`

### Network, TLS & API
- `analyzing-security-headers`
- `analyzing-ssl-tls-configuration`
- `conducting-port-and-service-enumeration`
- `conducting-api-security-testing`
- `auditing-graphql-security`
- `auditing-websocket-security`

### Cloud & DevSecOps (IaC & Containers)
- `auditing-docker-and-containerfile-security`
- `auditing-infrastructure-as-code`
- `detecting-security-misconfiguration`
- `detecting-sensitive-data-exposure`
- `detecting-subdomain-takeover`

### AI & LLM Security (OWASP Top 10 for LLM)
- `auditing-llm-prompt-injection-and-leakage`

### Triage, Intelligence, Compliance & Remediation
- `conducting-web-vulnerability-scan`
- `conducting-vulnerability-triage`
- `prioritizing-vulnerabilities-with-cvss`
- `enriching-findings-with-cisa-kev-and-epss`
- `mapping-owasp-asvs-compliance`
- `generating-vulnerability-remediation-report`
- `generating-git-patch-remediations`
- `exporting-sarif-security-reports`

## Safe Usage
These scripts are intentionally non-destructive reference implementations and are integrated into VulnScanner's RAG and LLM remediation pipeline.
