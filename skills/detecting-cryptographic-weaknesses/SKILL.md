---
name: detecting-cryptographic-weaknesses
description: Audit source code and configurations for insecure cryptographic algorithms, weak ciphers, low-entropy RNG, and broken padding schemes.
---

# Detecting Cryptographic Weaknesses

## Purpose
Identify insecure cryptographic practices including broken hash functions (MD5, SHA1), obsolete ciphers (DES, 3DES, RC4), ECB block mode, hardcoded cryptographic keys/IVs, and non-cryptographic pseudo-random number generators (`Math.random()`, `random.random()`).

## Safe operating rules
- Only test systems with authorization.
- In source code analysis, flag broken algorithms and low-entropy random generators.
- Recommend modern NIST-approved cryptographic primitives and robust password hashing functions (Argon2id, bcrypt, PBKDF2).

## Workflow
1. Search code for deprecated hash functions: `crypto.createHash('md5')`, `hashlib.sha1()`.
2. Inspect symmetric encryption modes for ECB (`AES/ECB/PKCS5Padding`, `aes-128-ecb`).
3. Check token/nonce generation functions to ensure `crypto.randomBytes()` or `secrets.token_hex()` is used rather than `Math.random()`.
4. Check password hashing algorithms to ensure general-purpose fast hashes (SHA-256) are replaced with slow key-derivation functions (`argon2id`, `bcrypt`).

## Remediation Guidance
- Password Hashing: Use `argon2id` (memory-hard) or `bcrypt` with appropriate work factor (cost >= 12).
- Symmetric Encryption: Use AES-GCM or ChaCha20-Poly1305 (authenticated encryption) with a unique initialization vector (IV) per message.
- Cryptographically Secure Random:
  - Node.js: `crypto.randomBytes(32).toString('hex')`
  - Python: `secrets.token_urlsafe(32)`
