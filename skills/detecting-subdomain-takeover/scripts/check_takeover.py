#!/usr/bin/env python3
"""
check_takeover.py - Safe Non-Destructive Subdomain Takeover Auditor
Inspects CNAME records and non-destructively matches provider unclaimed signatures.
"""
import sys
import json
import urllib.request
import socket
from urllib.error import HTTPError, URLError

TAKEOVER_FINGERPRINTS = {
    "github.io": {
        "service": "GitHub Pages",
        "fingerprint": "There isn't a GitHub Pages site here."
    },
    "herokuapp.com": {
        "service": "Heroku",
        "fingerprint": "No such app"
    },
    "s3.amazonaws.com": {
        "service": "AWS S3 Bucket",
        "fingerprint": "NoSuchBucket"
    },
    "azurewebsites.net": {
        "service": "Azure App Service",
        "fingerprint": "404 Web Site not found"
    },
    "ghost.io": {
        "service": "Ghost",
        "fingerprint": "The thing you were looking for is no longer here"
    },
    "surge.sh": {
        "service": "Surge.sh",
        "fingerprint": "project not found"
    }
}

def check_subdomain(domain):
    results = {
        "domain": domain,
        "cname": None,
        "provider": None,
        "takeover_possible": False,
        "evidence": None
    }

    try:
        # Standard socket lookup
        canonical_name = socket.getfqdn(domain)
        if canonical_name != domain:
            results["cname"] = canonical_name
    except Exception:
        pass

    # HTTP verification probe
    for suffix, conf in TAKEOVER_FINGERPRINTS.items():
        if (results["cname"] and suffix in results["cname"]) or (suffix in domain):
            results["provider"] = conf["service"]
            try:
                req = urllib.request.Request(
                    f"http://{domain}",
                    headers={"User-Agent": "VulnScanner/1.0"}
                )
                with urllib.request.urlopen(req, timeout=6) as response:
                    body = response.read(1024).decode("utf-8", errors="ignore")
                    if conf["fingerprint"].lower() in body.lower():
                        results["takeover_possible"] = True
                        results["evidence"] = conf["fingerprint"]
            except HTTPError as e:
                err_body = e.read(1024).decode("utf-8", errors="ignore")
                if conf["fingerprint"].lower() in err_body.lower():
                    results["takeover_possible"] = True
                    results["evidence"] = f"HTTP {e.code} matching '{conf['fingerprint']}'"
            except Exception:
                pass
            break

    return results

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python check_takeover.py sub.example.com"}))
        sys.exit(2)

    domain = sys.argv[1].strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//")[1].split("/")[0]

    res = check_subdomain(domain)
    output = {
        "result": res,
        "severity": "High" if res.get("takeover_possible") else "Info",
        "remediation": (
            "Remove dangling DNS CNAME records or reclaim the orphaned asset under an authorized account "
            "to prevent external takeover and domain reputation hijacking."
        )
    }

    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
