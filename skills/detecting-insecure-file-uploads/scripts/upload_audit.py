#!/usr/bin/env python3
"""
upload_audit.py - Static Auditor for File Upload Handlers and Multer Configurations
"""
import sys, re, json

UPLOAD_PATTERNS = [
    (r"multer\.diskStorage\s*\(\s*\{[\s\S]*?destination\s*:\s*['\"].*public", "File uploads stored directly inside public web directory"),
    (r"filename\s*:\s*function\s*\([^)]*\)\s*\{[\s\S]*?file\.originalname", "Using raw un-sanitized client file.originalname in storage path"),
    (r"multer\s*\(\s*\{(?![^}]*limits)", "Multer configured without fileSize limits"),
    (r"multer\s*\(\s*\{(?![^}]*fileFilter)", "Multer configured without fileFilter extension validation"),
    (r"\bfile\.save\s*\(\s*os\.path\.join\s*\([^)]*file\.filename\)", "Flask file.save with un-sanitized filename (missing secure_filename)"),
]

def audit_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
        for pattern, desc in UPLOAD_PATTERNS:
            match = re.search(pattern, content)
            if match:
                findings.append({
                    "file": filepath,
                    "evidence": match.group(0)[:160].strip(),
                    "rule": desc,
                    "cwe": "CWE-434",
                    "severity": "HIGH"
                })
    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python upload_audit.py <source_file>"}))
        sys.exit(1)
    findings = audit_file(sys.argv[1])
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))

if __name__ == "__main__":
    main()
