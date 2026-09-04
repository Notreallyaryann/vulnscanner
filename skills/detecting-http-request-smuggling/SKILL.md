---
name: detecting-http-request-smuggling
description: Detect HTTP request smuggling and desynchronization risks (CL.TE, TE.CL, TE.TE) across reverse proxies and origin backends using non-destructive differential probes.
---

# Detecting HTTP Request Smuggling

## Purpose
Detect potential HTTP request smuggling and desynchronization vulnerabilities caused by inconsistent interpretation of `Content-Length` (CL) and `Transfer-Encoding` (TE) headers between frontend proxies/load balancers and backend web application servers.

## Safe operating rules
- Only assess systems you own or have explicit authorization to test.
- Use strictly non-destructive differential probes (e.g. harmless header variations or benign body prefixes) that do not poison cache or hijack concurrent user sessions.
- Do not transmit malicious prefixes that alter downstream requests from other real users.
- Treat automated results as leads that require verification.
- Record target URL, timing delays, proxy headers, severity, and remediation guidance for every finding.

## Workflow
1. Validate target URL, frontend reverse proxy headers (e.g. `Via`, `Server`, `X-Cache`), and HTTP protocol versions.
2. Probe `Transfer-Encoding: chunked` support and obfuscation variants (e.g. `Transfer-Encoding: chunked`, `Transfer-Encoding: \x0bchunked`, `Transfer-Encoding: identity`).
3. Send differential timing and response probes (CL.TE and TE.CL candidate checks) using non-destructive sentinel values.
4. Normalize evidence into the VulnScanner finding schema.
5. Assign CVSS severity (typically High to Critical for reproducible desync) and confidence level.
6. Provide clear remediation guidance (standardizing on HTTP/2 end-to-end, disabling TE normalization, or rejecting ambiguous dual-header requests).

## Script
The `scripts/test_smuggle_probe.py` script performs safe non-destructive probing using raw sockets or standard HTTP connections to check for dual-header handling and TE parsing ambiguities.
