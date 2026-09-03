#!/usr/bin/env python3
"""
workflow_audit.py - Security Linter for GitHub Actions Workflows
"""
import sys, re, json, glob

INJECTION_PATTERNS = [
    r"\$\{\{\s*github\.event\.issue\.(?:title|body)\s*\}\}",
    r"\$\{\{\s*github\.event\.pull_request\.(?:title|body|head\.ref)\s*\}\}",
    r"\$\{\{\s*github\.event\.comment\.body\s*\}\}",
    r"\$\{\{\s*github\.head_ref\s*\}\}",
]

def audit_workflow(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
        lines = content.splitlines()

    # Check 1: pull_request_target
    if "pull_request_target:" in content or "pull_request_target" in content:
        findings.append({
            "file": filepath,
            "rule": "Trigger 'pull_request_target' detected - ensures elevated repository secrets are not exposed to untrusted PR code",
            "severity": "HIGH",
            "cwe": "CWE-284"
        })

    # Check 2: Expression injection in run steps
    in_run_step = False
    for idx, line in enumerate(lines, 1):
        if line.strip().startswith("run:"):
            in_run_step = True
        elif line.strip().startswith("- ") or (line and line[0].isalnum()):
            in_run_step = False

        if in_run_step:
            for pattern in INJECTION_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": idx,
                        "evidence": line.strip(),
                        "rule": "Untrusted GitHub context variable interpolated directly into run: command",
                        "severity": "CRITICAL",
                        "cwe": "CWE-78"
                    })

    # Check 3: Unpinned external actions
    for idx, line in enumerate(lines, 1):
        match = re.search(r"uses:\s*([a-zA-Z0-9_\-\./]+)@(v\d+|main|master)", line)
        if match and not match.group(1).startswith("actions/"):
            findings.append({
                "file": filepath,
                "line": idx,
                "evidence": line.strip(),
                "rule": f"Third-party action '{match.group(1)}' unpinned (uses mutable tag '@{match.group(2)}' instead of SHA)",
                "severity": "LOW",
                "cwe": "CWE-829"
            })

    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python workflow_audit.py <workflow.yml or dir>"}))
        sys.exit(1)
    
    target = sys.argv[1]
    all_findings = []
    if "*" in target:
        for f in glob.glob(target):
            all_findings.extend(audit_workflow(f))
    else:
        all_findings = audit_workflow(target)
    
    print(json.dumps({"findings": all_findings, "count": len(all_findings)}, indent=2))

if __name__ == "__main__":
    main()
