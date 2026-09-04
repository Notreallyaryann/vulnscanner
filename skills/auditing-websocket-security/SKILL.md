---
name: auditing-websocket-security
description: Audit WebSocket endpoints for Cross-Site WebSocket Hijacking (CSWSH), missing Origin header validation, unencrypted schemes, and authentication bypasses.
---

# Auditing WebSocket Security

## Purpose
Evaluate WebSocket connections (`ws://` and `wss://`) for common implementation flaws, notably Cross-Site WebSocket Hijacking (CSWSH), unvalidated `Origin` headers during the HTTP upgrade handshake, lack of TLS transport encryption, and missing token verification.

## Safe operating rules
- Only assess systems you own or have explicit authorization to test.
- Probe the WebSocket upgrade handshake with benign synthetic `Origin` headers (e.g., `Origin: https://evil-attacker.example.com`).
- Do not flood sockets with high-frequency frames or attempt denial of service.
- Treat automated results as leads that require verification.
- Record endpoint, handshake headers, status codes, and remediation guidance for every finding.

## Workflow
1. Identify WebSocket connection endpoints from application JS bundles, network logs, or HTML markup (looking for `ws://`, `wss://`, or socket libraries like Socket.io / ws).
2. Check transport protocol scheme (`ws://` vs `wss://`). Flag plaintext `ws://` in production as high risk.
3. Perform handshake upgrade requests with spoofed or untrusted `Origin` headers.
4. Verify whether the server accepts the connection (`101 Switching Protocols`) without validating the `Origin` or requiring anti-CSRF/session tokens.
5. Assign CVSS severity and confidence.
6. Provide remediation guidance (validating the `Origin` header against an explicit whitelist on handshake and employing ephemeral challenge tokens).

## Script
The `scripts/audit_websocket.py` script executes safe HTTP Upgrade requests against target endpoints to check Origin enforcement and transport encryption.
