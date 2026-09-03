#!/usr/bin/env python3
"""
xxe_audit.py - Static Scanner for Unsafe XML Parser Configurations
Checks source code for XML parsers initialized without safe flags.
"""
import sys, re, json

UNSAFE_XML_PATTERNS = [
    (r"\bxml\.etree\.ElementTree\b", "Python standard ElementTree is vulnerable to entity expansion. Use 'defusedxml'."),
    (r"\bminidom\.parse\b", "Python minidom.parse is vulnerable to entity expansion. Use 'defusedxml.minidom'."),
    (r"\blibxmljs\.parseXml\s*\(\s*[^)]*noent\s*:\s*true", "Node libxmljs configured with noent: true (substitutes entities)"),
    (r"\bDocumentBuilderFactory\.newInstance\(\)", "Java DocumentBuilderFactory - verify disallow-doctype-decl feature is set"),
    (r"\bSAXParserFactory\.newInstance\(\)", "Java SAXParserFactory - verify external entity features are disabled"),
    (r"\bsimplexml_load_string\s*\(", "PHP simplexml_load_string - verify libxml_disable_entity_loader(true) is invoked"),
]

def audit_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            for pattern, desc in UNSAFE_XML_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": line_no,
                        "evidence": line.strip()[:160],
                        "rule": desc,
                        "cwe": "CWE-611",
                        "severity": "HIGH"
                    })
    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python xxe_audit.py <source_file>"}))
        sys.exit(1)
    findings = audit_file(sys.argv[1])
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))

if __name__ == "__main__":
    main()
