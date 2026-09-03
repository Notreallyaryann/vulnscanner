#!/usr/bin/env python3
"""
crypto_audit.py - Static Auditor for Insecure Cryptography & Broken Randomness
"""
import sys, re, json

CRYPTO_PATTERNS = [
    (r"\b(?:createHash|hashlib\.)\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)", "Broken hash algorithm (MD5/SHA1) used"),
    (r"\bMath\.random\s*\(\s*\)", "Insecure pseudo-random number generator (Math.random) used in security context"),
    (r"\brandom\.(?:random|randint|choice)\s*\(", "Insecure Python random module used (use 'secrets' module for security)"),
    (r"['\"]aes-\d+-ecb['\"]", "Insecure ECB block cipher mode used (lacks diffusion and integrity)"),
    (r"\bDES\b|\b3DES\b|\bRC4\b", "Deprecated cipher algorithm (DES/3DES/RC4)"),
]

def analyze_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            for pattern, desc in CRYPTO_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "file": filepath,
                        "line": line_no,
                        "evidence": line.strip()[:160],
                        "rule": desc,
                        "cwe": "CWE-327",
                        "severity": "MEDIUM"
                    })
    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python crypto_audit.py <source_file>"}))
        sys.exit(1)
    findings = analyze_file(sys.argv[1])
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))

if __name__ == "__main__":
    main()
