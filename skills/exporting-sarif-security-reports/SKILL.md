---
name: exporting-sarif-security-reports
description: Export VulnScanner findings into the OASIS SARIF v2.1.0 standard for GitHub Code Scanning, GitLab Security Dashboard, and DefectDojo integrations.
---

# Exporting SARIF Security Reports

## Purpose
Convert vulnerability assessment findings and static analysis outputs into the industry-standard OASIS Static Analysis Results Interchange Format (SARIF v2.1.0 JSON). This enables direct ingestion into GitHub Code Scanning alerts, GitLab DevSecOps pipelines, and central SIEM/ASPM portals.

## Safe operating rules
- Handle finding data confidentially and avoid transmitting unencrypted reports over untrusted channels.
- Validate generated SARIF structure against the official SARIF JSON Schema v2.1.0.
- Accurately map severity ratings (Critical, High, Medium, Low) to SARIF levels (`error`, `warning`, `note`).

## Workflow
1. Ingest raw scanner findings (from VulnScanner database, JSON export, or triage pipeline).
2. Construct SARIF root object with schema `$schema: https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json` and version `2.1.0`.
3. Populate `runs[0].tool.driver` with scanner metadata, name, version, and defined rule descriptors (`rules[]`).
4. Map each finding to a `result` object:
   - `ruleId`
   - `level`: `error` (High/Critical), `warning` (Medium), `note` (Low/Info)
   - `message.text`
   - `locations[].physicalLocation.artifactLocation.uri` and line ranges (if code finding) or URL target.
5. Export formatted SARIF JSON file for upload to GitHub via `github/codeql-action/upload-sarif`.

## Script
The `scripts/export_sarif.py` script transforms input finding JSON files into compliant SARIF v2.1.0 JSON format.
