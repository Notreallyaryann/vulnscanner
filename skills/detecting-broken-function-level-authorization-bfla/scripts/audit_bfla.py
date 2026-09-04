#!/usr/bin/env python3
"""
audit_bfla.py - Safe Non-Destructive BFLA & Privilege Escalation Auditor
Audits API endpoints for missing server-side role enforcement by comparing
unauthenticated and low-privilege token access to sensitive routes.
"""
import sys
import json
import urllib.request
from urllib.error import HTTPError, URLError

SENSITIVE_PATH_PATTERNS = [
    "/admin", "/api/admin", "/manage", "/api/users", "/api/system",
    "/api/v1/config", "/api/v1/audit", "/dashboard/admin", "/metrics"
]

def check_endpoint_access(url, auth_header=None):
    headers = {
        "User-Agent": "VulnScanner/1.0",
        "Accept": "application/json, text/plain, */*"
    }
    if auth_header:
        headers["Authorization"] = auth_header

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=6) as response:
            status = response.getcode()
            body_sample = response.read(512).decode("utf-8", errors="ignore")
            return {"status": status, "accessible": True, "preview": body_sample[:120]}
    except HTTPError as e:
        return {"status": e.code, "accessible": False, "error": str(e.reason)}
    except URLError as e:
        return {"status": None, "accessible": False, "error": str(e.reason)}
    except Exception as e:
        return {"status": None, "accessible": False, "error": str(e)}

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python audit_bfla.py BASE_URL [OPTIONAL_LOW_PRIV_BEARER_TOKEN]"}))
        sys.exit(2)

    base_url = sys.argv[1].rstrip("/")
    token = sys.argv[2] if len(sys.argv) > 2 else None
    auth_header = f"Bearer {token}" if token else None

    findings = []
    for pattern in SENSITIVE_PATH_PATTERNS:
        test_url = f"{base_url}{pattern}"
        # Test 1: Unauthenticated
        unauth_res = check_endpoint_access(test_url, auth_header=None)

        if unauth_res.get("accessible") and unauth_res.get("status") in [200, 201]:
            findings.append({
                "endpoint": test_url,
                "role_tested": "Unauthenticated (Anonymous)",
                "status_code": unauth_res["status"],
                "issue": "Sensitive endpoint accessible without authentication (BFLA/Missing Auth)",
                "severity": "Critical",
                "preview": unauth_res.get("preview")
            })
            continue

        # Test 2: Low privilege token if provided
        if auth_header:
            auth_res = check_endpoint_access(test_url, auth_header=auth_header)
            if auth_res.get("accessible") and auth_res.get("status") in [200, 201]:
                findings.append({
                    "endpoint": test_url,
                    "role_tested": "Low-Privilege User",
                    "status_code": auth_res["status"],
                    "issue": "Administrative route accessible by standard authenticated user (BFLA)",
                    "severity": "High",
                    "preview": auth_res.get("preview")
                })

    print(json.dumps({
        "base_url": base_url,
        "scanned_endpoints_count": len(SENSITIVE_PATH_PATTERNS),
        "bfla_findings_count": len(findings),
        "findings": findings,
        "remediation": (
            "Enforce strict server-side authorization checks using centralized RBAC middleware. "
            "Do not rely on client-side routing guards or URL obscurity."
        )
    }, indent=2))

if __name__ == "__main__":
    main()
