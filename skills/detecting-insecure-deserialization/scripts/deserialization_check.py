#!/usr/bin/env python3
"""
deserialization_check.py - Static Scanner for Insecure Deserialization Sinks
"""
import sys, re, json

DESERIALIZATION_SINKS = [
    (r"\bpickle\.(?:loads?|load)\s*\(", "Python unsafe pickle deserialization"),
    (r"\byaml\.(?:load|unsafe_load)\s*\([^)]*(?!Loader=SafeLoader|Loader=yaml\.SafeLoader)", "Python unsafe YAML load (use safe_load)"),
    (r"\bnode-serialize\.unserialize\s*\(", "Node.js unsafe node-serialize unserialize call"),
    (r"\bserialize-to-js\b", "Node.js serialize-to-js usage"),
    (r"\bunserialize\s*\(\s*\$_(?:GET|POST|COOKIE|REQUEST)", "PHP unserialize on untrusted input"),
    (r"\bObjectInputStream\s*\([^)]*\)\.readObject\s*\(", "Java ObjectInputStream.readObject without validation filter"),
]

def analyze_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            for pattern, desc in DESERIALIZATION_SINKS:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": line_no,
                        "evidence": line.strip()[:160],
                        "rule": desc,
                        "cwe": "CWE-502",
                        "severity": "CRITICAL"
                    })
    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python deserialization_check.py <source_file>"}))
        sys.exit(1)
    findings = analyze_file(sys.argv[1])
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))

if __name__ == "__main__":
    main()
