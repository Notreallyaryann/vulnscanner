#!/usr/bin/env python3
"""
dockerfile_linter.py - Static Linter for Dockerfiles & Docker Compose files
"""
import sys, re, json

def audit_dockerfile(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    has_user_directive = False
    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        # Check 1: Base image using latest
        if re.match(r"^FROM\s+[\w\-\./]+:latest\b", stripped, re.IGNORECASE) or re.match(r"^FROM\s+[\w\-\./]+\s*$", stripped):
            findings.append({
                "file": filepath,
                "line": line_no,
                "evidence": stripped,
                "rule": "Base image uses mutable ':latest' or unspecified tag - pin to specific version/digest",
                "severity": "LOW",
                "cwe": "CWE-1104"
            })

        # Check 2: USER directive
        if stripped.startswith("USER ") and "root" not in stripped.lower():
            has_user_directive = True

        # Check 3: Sensitive socket mount or secret in ENV / ARG
        if re.search(r"/var/run/docker\.sock", stripped):
            findings.append({
                "file": filepath,
                "line": line_no,
                "evidence": stripped,
                "rule": "Docker socket (/var/run/docker.sock) exposed - allows root host takeover",
                "severity": "CRITICAL",
                "cwe": "CWE-250"
            })

        if re.search(r"^(?:ENV|ARG)\s+(?:.*(?:PASSWORD|SECRET|API_KEY|TOKEN))\s*=", stripped, re.IGNORECASE):
            findings.append({
                "file": filepath,
                "line": line_no,
                "evidence": stripped[:120],
                "rule": "Sensitive secret baked into image layer via ENV/ARG directive",
                "severity": "HIGH",
                "cwe": "CWE-798"
            })

    if not has_user_directive:
        findings.append({
            "file": filepath,
            "rule": "Missing non-root USER instruction in Dockerfile - container executes as root by default",
            "severity": "MEDIUM",
            "cwe": "CWE-250"
        })

    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python dockerfile_linter.py <Dockerfile>"}))
        sys.exit(1)
    findings = audit_dockerfile(sys.argv[1])
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))

if __name__ == "__main__":
    main()
