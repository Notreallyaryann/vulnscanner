#!/usr/bin/env python3
"""
command_injection_check.py - Passive & Static Auditor for Command Injection Sinks
Scans code snippets or file contents for dangerous shell execution patterns.
"""
import sys, re, json

DANGEROUS_SINKS = [
    (r"\b(exec|execSync|spawn|execFile)\s*\(\s*[`'\"].*\$\{", "Node.js dynamic command template literal"),
    (r"\b(exec|execSync)\s*\(\s*[^)]*(?:req\.|params\.|query\.|body\.)", "Node.js exec with request object"),
    (r"\b(os\.system|os\.popen|subprocess\.call|subprocess\.Popen|subprocess\.run)\s*\([^)]*shell\s*=\s*True", "Python subprocess with shell=True"),
    (r"\b(os\.system|os\.popen)\s*\(.*(?:\+|\%|\.format|f[\"'])", "Python os.system string formatting"),
    (r"\b(system|passthru|shell_exec|exec|popen)\s*\(\s*\$_(?:GET|POST|REQUEST)", "PHP unescaped shell call"),
    (r"\bRuntime\.getRuntime\(\)\.exec\s*\(", "Java Runtime.exec call"),
]

def analyze_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            for pattern, desc in DANGEROUS_SINKS:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": line_no,
                        "evidence": line.strip()[:160],
                        "rule": desc,
                        "cwe": "CWE-78",
                        "severity": "CRITICAL"
                    })
    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python command_injection_check.py <target_source_file>"}))
        sys.exit(1)
    
    results = analyze_file(sys.argv[1])
    print(json.dumps({"findings": results, "count": len(results)}, indent=2))

if __name__ == "__main__":
    main()
