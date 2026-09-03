#!/usr/bin/env python3
"""
oauth_config_audit.py - Non-destructive OAuth2 / OIDC Flow Auditor
Parses authorization URLs and evaluates security parameters (state, PKCE, response_type).
"""
import sys, json
from urllib.parse import urlparse, parse_qs

def audit_oauth_url(auth_url):
    parsed = urlparse(auth_url)
    params = parse_qs(parsed.query)

    findings = []
    
    # 1. State parameter check
    if "state" not in params or not params["state"][0]:
        findings.append({
            "issue": "Missing 'state' parameter - vulnerable to Login CSRF",
            "severity": "HIGH",
            "cwe": "CWE-352"
        })
    elif len(params["state"][0]) < 16:
        findings.append({
            "issue": "Low-entropy 'state' parameter (length < 16)",
            "severity": "MEDIUM",
            "cwe": "CWE-330"
        })

    # 2. PKCE check
    if "code_challenge" not in params:
        findings.append({
            "issue": "Missing PKCE code_challenge parameter",
            "severity": "MEDIUM",
            "cwe": "CWE-287"
        })
    elif params.get("code_challenge_method", [""])[0].lower() != "s256":
        findings.append({
            "issue": "PKCE method is not S256 (e.g. plain)",
            "severity": "HIGH",
            "cwe": "CWE-327"
        })

    # 3. Redirect URI
    if "redirect_uri" in params:
        redirect = params["redirect_uri"][0]
        if redirect.startswith("http://") and "localhost" not in redirect:
            findings.append({
                "issue": "Insecure HTTP redirect_uri specified",
                "severity": "HIGH",
                "cwe": "CWE-319"
            })

    return {
        "authorization_endpoint": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
        "params": {k: v[0] for k, v in params.items()},
        "findings": findings,
        "secure": len(findings) == 0
    }

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python oauth_config_audit.py <oauth_auth_url>"}))
        sys.exit(1)
    print(json.dumps(audit_oauth_url(sys.argv[1]), indent=2))

if __name__ == "__main__":
    main()
