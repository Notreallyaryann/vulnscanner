---
name: detecting-jwt-and-session-flaws
description: Analyze JSON Web Token (JWT) implementations for cryptographic weaknesses, algorithm confusion, missing expiration, and session tampering vulnerabilities.
---

# Detecting JWT and Session Flaws

## Purpose
Inspect JWT generation, verification, and decoding routines to detect vulnerabilities including algorithm confusion (e.g., `alg: "none"`, HMAC verification using RSA public keys), weak symmetric signing secrets, missing claims validation (`exp`, `nbf`, `iss`), and unencrypted sensitive payload data.

## Safe operating rules
- Only test systems with authorization.
- Do not forge production admin tokens to perform unauthorized actions.
- Audit token structures passively by inspecting token headers and payload claims without tampering.

## Workflow
1. Decode the JWT header and payload (base64url).
2. Check if the algorithm is set to `"none"`, `"NONE"`, or deprecated algorithms.
3. Check for standard expiration (`exp`) and not-before (`nbf`) claims.
4. Verify if backend verification explicitly defines `algorithms: ["HS256"]` or `["RS256"]` to prevent algorithm confusion attacks.
5. In source code, check for hardcoded signing secrets or secrets with low entropy.

## Remediation Guidance
- Always enforce strict algorithm whitelisting in verification libraries:
  ```typescript
  jwt.verify(token, publicKey, { algorithms: ["RS256"], issuer: "https://auth.example.com" });
  ```
- Reject tokens with `alg: "none"`.
- Never store secrets or sensitive PII (passwords, social security numbers) inside unencrypted JWT payloads.
- Ensure JWT signing keys are at least 256 bits of cryptographically secure random data and stored in environment variables or key vaults.
