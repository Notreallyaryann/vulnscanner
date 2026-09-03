---
name: mapping-owasp-asvs-compliance
description: Map discovered vulnerabilities to OWASP Application Security Verification Standard (ASVS v4.0) control chapters and verification levels.
---

# Mapping OWASP ASVS Compliance

## Purpose
Map vulnerability findings directly to OWASP ASVS v4.0 verification requirements across all 14 chapters (V1 Architecture, V2 Authentication, V3 Session Management, V4 Access Control, V5 Input Validation, V14 Configuration) to generate compliance audit scorecards.

## Safe operating rules
- Provide standardized control mappings based on verified findings and CWE taxonomy.
- Categorize findings into ASVS Level 1 (Opportunistic/Basic), Level 2 (Standard/Commercial), and Level 3 (Advanced/Critical).

## ASVS Chapter Reference Mapping
- **V2 Authentication**: Broken auth, default credentials, weak password hashing (CWE-287, CWE-306, CWE-521).
- **V3 Session Management**: Insecure cookies, JWT flaws, session fixation (CWE-613, CWE-384).
- **V4 Access Control**: IDOR, BOLA, missing role authorization, mass assignment (CWE-639, CWE-285, CWE-915).
- **V5 Validation, Sanitization and Encoding**: SQLi, XSS, Command Injection, XXE, SSRF, Path Traversal (CWE-89, CWE-79, CWE-78, CWE-611, CWE-918, CWE-22).
- **V14 Build and Deployment**: Secrets in code, unpinned dependencies, Docker root execution, CI/CD flaws (CWE-798, CWE-1104, CWE-250).

## Remediation Guidance
- Use ASVS requirements as an engineering baseline for pull request reviews and security gate criteria.
