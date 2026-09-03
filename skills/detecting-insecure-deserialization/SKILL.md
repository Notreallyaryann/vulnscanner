---
name: detecting-insecure-deserialization
description: Identify insecure object deserialization vulnerabilities in Python, Java, Node.js, and PHP applications.
---

# Detecting Insecure Deserialization

## Purpose
Detect the deserialization of untrusted user input that allows attackers to instantiate arbitrary objects, execute remote code, or tamper with application state (e.g. Python `pickle`, `yaml.unsafe_load`, Java `ObjectInputStream`, Node.js `node-serialize`, PHP `unserialize`).

## Safe operating rules
- Only test systems with authorization.
- Do not transmit gadget-chain exploit payloads (e.g. Ysoserial payloads).
- Statically verify deserialization libraries and parameters across source code.

## Workflow
1. Search codebases for native object serialization sinks:
   - Python: `pickle.loads()`, `yaml.load()`, `shelve`, `marshal`
   - Node.js: `serialize-javascript`, `node-serialize`, `eval()` in JSON parsers
   - Java: `readObject()`, `XMLDecoder`, `XStream`
   - PHP: `unserialize()`
2. Trace the serialized byte stream back to untrusted endpoints (cookies, request body, cache).
3. Recommend safe data formats (e.g. JSON, Protocol Buffers) or signed/HMAC-protected serialization streams.

## Remediation Guidance
- Use standard, language-neutral data formats such as JSON (`JSON.parse()`) instead of binary object serialization.
- In Python: Use `yaml.safe_load()` instead of `yaml.load()`. Never use `pickle` on untrusted input.
- In Java: Implement `ValidatingObjectInputStream` with strict class allowlisting or migrate to Jackson/Gson with typing safeguards.
