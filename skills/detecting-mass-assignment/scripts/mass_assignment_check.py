#!/usr/bin/env python3
"""
mass_assignment_check.py - Static AST/Regex Analyzer for Mass Assignment Sinks
"""
import sys, re, json

MASS_ASSIGNMENT_PATTERNS = [
    (r"\.(?:create|update|updateMany|upsert)\s*\(\s*\{\s*(?:data|where\s*:\s*\{[^}]*\}\s*,\s*data)\s*:\s*req\.body\s*\}?\s*\)", "Prisma update/create using raw req.body"),
    (r"\.(?:updateAttributes|update|create)\s*\(\s*req\.body\s*\)", "Sequelize/Mongoose model mutation with raw req.body"),
    (r"\bUser\.objects\.create\s*\(\s*\*\*request\.POST", "Django model instantiation with raw request.POST dict"),
    (r"\bObject\.assign\s*\(\s*(?:user|account|profile|model)\s*,\s*req\.body\s*\)", "Direct Object.assign into model from req.body"),
]

def analyze_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            for pattern, desc in MASS_ASSIGNMENT_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": line_no,
                        "evidence": line.strip()[:160],
                        "rule": desc,
                        "cwe": "CWE-915",
                        "severity": "HIGH"
                    })
    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python mass_assignment_check.py <source_file>"}))
        sys.exit(1)
    findings = analyze_file(sys.argv[1])
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))

if __name__ == "__main__":
    main()
