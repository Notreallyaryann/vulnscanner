#!/usr/bin/env python3
"""
idor_probe.py - Static AST/Regex Analyzer for Missing Tenancy & IDOR Sinks
Audits backend route handlers for queries using user-supplied parameters without tenancy scoping.
"""
import sys, re, json

UNSCOPED_QUERY_PATTERNS = [
    (r"\.(?:findUnique|findOne|findByPk|findById)\s*\(\s*\{\s*(?:where\s*:\s*\{)?\s*id\s*:\s*(?:req\.params|params|req\.query)\.\w+\s*\}?\s*\)", "Unscoped findUnique without user session constraint"),
    (r"SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+id\s*=\s*(?:\$|:|\?)\w+;?\s*(?!.*\bAND\s+user_id\b)", "SQL query filtering only by primary key without user tenant filter"),
    (r"\.destroy|\.deleteMany|\.delete\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*:\s*(?:req\.)", "Unscoped record deletion from request param without ownership check"),
]

def analyze_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            for pattern, desc in UNSCOPED_QUERY_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "file": filepath,
                        "line": idx,
                        "evidence": line.strip()[:160],
                        "rule": desc,
                        "cwe": "CWE-639",
                        "severity": "HIGH"
                    })
    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python idor_probe.py <source_file>"}))
        sys.exit(1)
    findings = analyze_file(sys.argv[1])
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))

if __name__ == "__main__":
    main()
