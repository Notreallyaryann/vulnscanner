#!/usr/bin/env python3
"""
asvs_matcher.py - Maps findings and CWEs to OWASP ASVS v4.0 Requirement Chapters
"""
import sys, json

ASVS_MAP = {
    "CWE-89": {"chapter": "V5 Validation, Sanitization and Encoding", "req": "5.3.1", "level": "L1", "title": "Parameterized Queries"},
    "CWE-79": {"chapter": "V5 Validation, Sanitization and Encoding", "req": "5.3.3", "level": "L1", "title": "Context-aware Output Encoding"},
    "CWE-78": {"chapter": "V5 Validation, Sanitization and Encoding", "req": "5.3.8", "level": "L1", "title": "Command Injection Prevention"},
    "CWE-22": {"chapter": "V5 Validation, Sanitization and Encoding", "req": "5.5.2", "level": "L1", "title": "Path Traversal Protection"},
    "CWE-639": {"chapter": "V4 Access Control", "req": "4.1.1", "level": "L1", "title": "Object Level Authorization"},
    "CWE-915": {"chapter": "V4 Access Control", "req": "4.2.1", "level": "L2", "title": "Mass Assignment Prevention"},
    "CWE-611": {"chapter": "V5 Validation, Sanitization and Encoding", "req": "5.5.1", "level": "L1", "title": "XXE Injection Protection"},
    "CWE-798": {"chapter": "V14 Build and Deployment", "req": "14.1.1", "level": "L1", "title": "No Hardcoded Secrets"},
    "CWE-327": {"chapter": "V2 Authentication", "req": "2.10.1", "level": "L1", "title": "Modern Cryptographic Algorithms"},
    "CWE-613": {"chapter": "V3 Session Management", "req": "3.3.1", "level": "L1", "title": "Session Expiration & Lifetime"},
    "CWE-352": {"chapter": "V4 Access Control", "req": "4.2.2", "level": "L1", "title": "Anti-CSRF Defense"},
    "CWE-1321": {"chapter": "V5 Validation, Sanitization and Encoding", "req": "5.2.8", "level": "L2", "title": "Prototype Pollution Protection"},
    "CWE-502": {"chapter": "V5 Validation, Sanitization and Encoding", "req": "5.5.3", "level": "L1", "title": "Safe Deserialization"},
}

def map_cwe(cwe_id):
    normalized = cwe_id.strip().upper()
    return ASVS_MAP.get(normalized, {
        "chapter": "V1 Architecture, Design and Threat Modeling",
        "req": "1.1.1",
        "level": "L1",
        "title": "General Security Control Requirement"
    })

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python asvs_matcher.py <CWE-ID>"}))
        sys.exit(1)
    print(json.dumps({"cwe": sys.argv[1], "asvs": map_cwe(sys.argv[1])}, indent=2))

if __name__ == "__main__":
    main()
