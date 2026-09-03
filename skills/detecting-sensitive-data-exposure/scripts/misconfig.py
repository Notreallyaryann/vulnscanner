#!/usr/bin/env python3
import sys, re, json, requests

PATTERNS = {
    "private_key_marker": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "aws_access_key_like": r"\bAKIA[0-9A-Z]{16}\b",
    "jwt_like": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "password_assignment": r"(?i)\b(password|passwd|secret)\s*[:=]\s*['\"][^'\"]{6,}['\"]"
}

def main():
    if len(sys.argv) != 2:
        print("Usage: python secret_scan.py URL")
        raise SystemExit(2)
    r = requests.get(sys.argv[1], timeout=10, headers={"User-Agent":"VulnScanner/1.0"})
    findings = []
    for name, pattern in PATTERNS.items():
        count = len(re.findall(pattern, r.text))
        if count:
            findings.append({"type": name, "matches": count})
    print(json.dumps({"url": r.url, "findings": findings,
                      "note": "Patterns are heuristic; verify findings manually."}, indent=2))
if __name__ == "__main__":
    main()
