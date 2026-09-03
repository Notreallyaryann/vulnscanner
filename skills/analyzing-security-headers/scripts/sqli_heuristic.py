#!/usr/bin/env python3
import sys, json, requests

RECOMMENDED = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

def main():
    if len(sys.argv) != 2:
        print("Usage: python headers.py URL")
        raise SystemExit(2)
    r = requests.get(sys.argv[1], timeout=10, allow_redirects=True,
                     headers={"User-Agent":"VulnScanner/1.0"})
    h = {k.lower(): v for k,v in r.headers.items()}
    findings = []
    for key, label in RECOMMENDED.items():
        if key not in h:
            findings.append({"header": label, "status": "missing"})
        else:
            value = h[key]
            weak = key == "content-security-policy" and "'unsafe-inline'" in value
            findings.append({"header": label, "status": "present", "value": value, "potentially_weak": weak})
    print(json.dumps({"url": r.url, "findings": findings}, indent=2))
if __name__ == "__main__":
    main()
