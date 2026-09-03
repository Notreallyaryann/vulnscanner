#!/usr/bin/env python3
"""
prototype_pollution_check.py - Static Scanner for Prototype Pollution Patterns in JS/TS
"""
import sys, re, json

POLLUTION_PATTERNS = [
    (r"target\[(?:key|prop|k|attr)\]\s*=\s*(?:source|val|v)\[(?:key|prop|k|attr)\]", "Unchecked recursive object property assignment"),
    (r"(?:obj|target)\[(?:a|p|part|keys\[\w+\])\]\s*=\s*\{\}", "Unchecked object path traversal expansion"),
    (r"Object\.assign\s*\(\s*\{\}\s*,\s*JSON\.parse\s*\(", "Unvalidated JSON parsed object assignment"),
    (r"\[\"__proto__\"\]|\[\"constructor\"\]|\[\"prototype\"\]", "Direct reference to prototype manipulation properties"),
]

def analyze_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            for pattern, desc in POLLUTION_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": line_no,
                        "evidence": line.strip()[:160],
                        "rule": desc,
                        "cwe": "CWE-1321",
                        "severity": "HIGH"
                    })
    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python prototype_pollution_check.py <source_file>"}))
        sys.exit(1)
    findings = analyze_file(sys.argv[1])
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))

if __name__ == "__main__":
    main()
