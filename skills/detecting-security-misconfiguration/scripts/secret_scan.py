#!/usr/bin/env python3
import sys, json, requests

def main():
    if len(sys.argv) != 2:
        print("Usage: python misconfig.py URL")
        raise SystemExit(2)
    url = sys.argv[1]
    r = requests.get(url, timeout=10, headers={"User-Agent":"VulnScanner/1.0"})
    h = {k.lower():v for k,v in r.headers.items()}
    findings = []
    if "server" in h:
        findings.append({"type":"server_disclosure","value":h["server"]})
    if "x-powered-by" in h:
        findings.append({"type":"technology_disclosure","value":h["x-powered-by"]})
    if "index of /" in r.text.lower():
        findings.append({"type":"directory_listing_hint"})
    opt = requests.options(url, timeout=10, headers={"User-Agent":"VulnScanner/1.0"})
    findings.append({"type":"allowed_methods","value":opt.headers.get("Allow")})
    print(json.dumps({"url": r.url, "findings": findings}, indent=2))
if __name__ == "__main__":
    main()
