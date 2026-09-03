#!/usr/bin/env python3
"""
path_traversal_check.py - Static Auditor for Filesystem Path Traversal Sinks
"""
import sys, re, json

PATH_SINKS = [
    (r"\b(?:fs\.readFile|fs\.readFileSync|fs\.createReadStream)\s*\(\s*(?:path\.join\(|.*\+|`)[^)]*(?:req\.|params|query)", "Node.js file read using unsanitized request parameter"),
    (r"\bopen\s*\(\s*(?:os\.path\.join\(|.*\+|f[\"'])[^)]*(?:request\.|params|filename)", "Python open() using unverified path variable"),
    (r"\b(?:readfile|file_get_contents|include|require)\s*\(\s*\$_(?:GET|POST|REQUEST)", "PHP unvalidated file inclusion"),
    (r"\bres\.sendFile\s*\(\s*[^)]*(?:req\.|params|query)", "Express res.sendFile without root confinement option"),
]

def analyze_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            for pattern, desc in PATH_SINKS:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": line_no,
                        "evidence": line.strip()[:160],
                        "rule": desc,
                        "cwe": "CWE-22",
                        "severity": "HIGH"
                    })
    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python path_traversal_check.py <source_file>"}))
        sys.exit(1)
    findings = analyze_file(sys.argv[1])
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))

if __name__ == "__main__":
    main()
