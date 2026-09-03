#!/usr/bin/env python3
"""
iac_security_audit.py - Static Linter for Terraform (.tf) and Cloud Configs
"""
import sys, re, json, glob

IAC_PATTERNS = [
    (r"cidr_blocks\s*=\s*\[\s*[\"']0\.0\.0\.0/0[\"']\s*\][\s\S]*?(?:22|3389|5432|3306)", "Security group exposes SSH/RDP/DB port to world (0.0.0.0/0)", "HIGH"),
    (r"acl\s*=\s*[\"'](?:public-read|public-read-write)[\"']", "S3 bucket configured with public ACL", "CRITICAL"),
    (r"encrypted\s*=\s*false", "Resource storage encryption explicitly disabled", "MEDIUM"),
    (r"\"Action\":\s*\"\*\",\s*\"Resource\":\s*\"\*\"", "Overly permissive wildcard IAM policy (* on *)", "CRITICAL"),
    (r"privileged\s*:\s*true", "Kubernetes pod container running in privileged mode", "CRITICAL"),
]

def audit_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
        for pattern, desc, sev in IAC_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                findings.append({
                    "file": filepath,
                    "evidence": match.group(0)[:160].strip(),
                    "rule": desc,
                    "severity": sev,
                    "cwe": "CWE-16"
                })
    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python iac_security_audit.py <file.tf or dir>"}))
        sys.exit(1)
    
    target = sys.argv[1]
    all_findings = []
    if "*" in target:
        for f in glob.glob(target):
            all_findings.extend(audit_file(f))
    else:
        all_findings = audit_file(target)

    print(json.dumps({"findings": all_findings, "count": len(all_findings)}, indent=2))

if __name__ == "__main__":
    main()
