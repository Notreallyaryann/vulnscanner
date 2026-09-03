---
name: enriching-findings-with-cisa-kev-and-epss
description: Enrich vulnerability findings by querying CISA Known Exploited Vulnerabilities (KEV) catalog and FIRST Exploit Prediction Scoring System (EPSS).
---

# Enriching Findings with CISA KEV and EPSS

## Purpose
Prioritize vulnerability remediation based on real-world threat intelligence. By cross-referencing CVE identifiers against CISA's Known Exploited Vulnerabilities (KEV) catalog and FIRST's EPSS probability score, security teams can focus on vulnerabilities actively weaponized in the wild.

## Safe operating rules
- Use public, rate-limited REST APIs (CISA KEV JSON feed, FIRST EPSS API).
- Cache threat intelligence responses locally to minimize network latency and API requests.
- Escalate findings present in CISA KEV to `CRITICAL` priority regardless of base CVSS score.

## Workflow
1. Extract CVE identifiers (`CVE-YYYY-NNNNN`) from SCA and scanner findings.
2. Query the FIRST EPSS API: `https://api.first.org/data/v1/epss?cve={cve_id}`.
3. Check the CISA KEV catalog for active exploitation status.
4. Calculate composite risk priority:
   - **KEV Listed**: Immediate Critical Priority (Active Exploitation Confirmed).
   - **EPSS > 0.35 (35th percentile)**: High Likelihood of Exploitation in Next 30 Days.
   - **CVSS >= 9.0**: Critical Severity.

## Remediation Guidance
- Prioritize zero-day and KEV-listed vulnerabilities within 24–48 hour emergency remediation windows.
