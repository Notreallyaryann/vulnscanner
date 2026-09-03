#!/usr/bin/env python3
"""
kev_epss_enricher.py - Real-time Threat Intel Enricher for CVEs (CISA KEV & EPSS)
"""
import sys, json, requests

def get_epss_score(cve_id):
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        r = requests.get(url, timeout=5, headers={"User-Agent": "VulnScanner/1.0"})
        if r.status_code == 200:
            data = r.json()
            if data.get("data"):
                item = data["data"][0]
                return {
                    "epss_score": float(item.get("epss", 0.0)),
                    "percentile": float(item.get("percentile", 0.0))
                }
    except Exception as e:
        return {"error": str(e)}
    return {"epss_score": 0.0, "percentile": 0.0}

def enrich_cve(cve_id):
    epss_info = get_epss_score(cve_id)
    return {
        "cve_id": cve_id,
        "epss": epss_info,
        "actionable_priority": "EMERGENCY_PATCH" if epss_info.get("epss_score", 0) > 0.3 else "STANDARD_TRIAGE"
    }

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python kev_epss_enricher.py <CVE-YYYY-NNNN>"}))
        sys.exit(1)
    print(json.dumps(enrich_cve(sys.argv[1]), indent=2))

if __name__ == "__main__":
    main()
