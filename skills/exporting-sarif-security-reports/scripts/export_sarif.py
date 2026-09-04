#!/usr/bin/env python3
"""
export_sarif.py - Transforms VulnScanner findings into OASIS SARIF v2.1.0 standard
Compatible with GitHub Code Scanning alerts (upload-sarif action) and CI/CD pipelines.
"""
import sys
import json

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none"
}

def build_sarif(findings):
    rules = {}
    results = []

    for f in findings:
        rule_id = f.get("ruleId") or f.get("type", "vulnscanner-finding").replace(" ", "-").lower()
        title = f.get("title") or f.get("type", "Security Finding")
        description = f.get("description") or f.get("issue") or title
        severity = f.get("severity", "medium").lower()
        level = SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {"text": description},
                "defaultConfiguration": {"level": level}
            }

        file_path = f.get("filePath") or f.get("file") or f.get("target") or "unknown-target"
        line_no = int(f.get("line") or f.get("lineNumber") or 1)

        result_item = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": line_no,
                            "startColumn": 1
                        }
                    }
                }
            ]
        }
        results.append(result_item)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnScanner Engine",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/Notreallyaryann/vulnscanner",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }
        ]
    }
    return sarif_doc

def main():
    if len(sys.argv) < 2:
        # Default mock test mode
        sample_findings = [
            {
                "ruleId": "SEC001",
                "type": "SQL Injection Heuristic",
                "severity": "High",
                "description": "Unescaped database input parameter detected in query construction",
                "filePath": "src/api/users.ts",
                "line": 42
            }
        ]
        print(json.dumps(build_sarif(sample_findings), indent=2))
        return

    input_file = sys.argv[1]
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data if isinstance(data, list) else data.get("findings", [])
    sarif = build_sarif(findings)

    if len(sys.argv) > 2:
        out_file = sys.argv[2]
        with open(out_file, "w", encoding="utf-8") as out:
            json.dump(sarif, out, indent=2)
        print(json.dumps({"status": "success", "written_to": out_file}))
    else:
        print(json.dumps(sarif, indent=2))

if __name__ == "__main__":
    main()
