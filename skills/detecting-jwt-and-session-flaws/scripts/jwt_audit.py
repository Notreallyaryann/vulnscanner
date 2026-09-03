#!/usr/bin/env python3
"""
jwt_audit.py - Safe Passive JWT Token & Implementation Auditor
Decodes token headers and payloads, analyzes security claims, and flags algorithm vulnerabilities.
"""
import sys, json, base64, time

def b64url_decode(segment):
    rem = len(segment) % 4
    if rem > 0:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment.encode("utf-8"))

def audit_jwt(token_str):
    parts = token_str.strip().split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT format - expected 3 dot-separated segments"}

    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception as e:
        return {"error": f"Failed to decode token segments: {str(e)}"}

    findings = []
    alg = header.get("alg", "").lower()
    
    if alg in ["none", ""]:
        findings.append({"issue": "Algorithm 'none' accepted / defined in header", "severity": "CRITICAL", "cwe": "CWE-327"})
    
    if "exp" not in payload:
        findings.append({"issue": "Missing 'exp' (expiration) claim in payload", "severity": "MEDIUM", "cwe": "CWE-613"})
    elif payload["exp"] < time.time():
        findings.append({"issue": "Token is expired", "severity": "INFO", "cwe": "CWE-613"})

    if "jti" not in payload and "sub" not in payload:
        findings.append({"issue": "Missing unique identifier ('sub' or 'jti') for revocation", "severity": "LOW", "cwe": "CWE-287"})

    sensitive_keys = [k for k in payload.keys() if any(s in k.lower() for s in ["pass", "secret", "ssn", "credit"])]
    if sensitive_keys:
        findings.append({"issue": f"Sensitive attributes exposed in unencrypted payload: {sensitive_keys}", "severity": "HIGH", "cwe": "CWE-312"})

    return {
        "header": header,
        "payload": payload,
        "findings": findings,
        "safe_to_use": len([f for f in findings if f["severity"] in ["CRITICAL", "HIGH"]]) == 0
    }

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python jwt_audit.py <jwt_token_string>"}))
        sys.exit(1)
    print(json.dumps(audit_jwt(sys.argv[1]), indent=2))

if __name__ == "__main__":
    main()
