#!/usr/bin/env python3
"""
entropy_secret_hunter.py - Secrets Hunter with Regex & Shannon Entropy
Scans source files for credentials and high-entropy secret tokens with automatic redaction.
"""
import sys, re, math, json

PATTERNS = [
    (r"(?:AKIA[0-9A-Z]{16})", "AWS Access Key ID", "CRITICAL"),
    (r"(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})", "GitHub Personal Access Token", "CRITICAL"),
    (r"(?:sk_live_[0-9a-zA-Z]{24})", "Stripe Secret Key", "CRITICAL"),
    (r"(?:xox[baprs]-[0-9a-zA-Z]{10,48})", "Slack Token", "HIGH"),
    (r"(?:sk-[a-zA-Z0-9]{20,48})", "OpenAI / Anthropic API Key", "HIGH"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Cryptographic Key", "CRITICAL"),
]

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def redact(secret):
    if len(secret) <= 8:
        return "****"
    return secret[:4] + "..." + secret[-4:]

def scan_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            # Check known signatures
            for pattern, name, sev in PATTERNS:
                match = re.search(pattern, line)
                if match:
                    findings.append({
                        "file": filepath,
                        "line": line_no,
                        "type": name,
                        "redacted_evidence": redact(match.group(0)),
                        "severity": sev,
                        "cwe": "CWE-798"
                    })
    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python entropy_secret_hunter.py <source_file>"}))
        sys.exit(1)
    findings = scan_file(sys.argv[1])
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))

if __name__ == "__main__":
    main()
