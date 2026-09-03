#!/usr/bin/env python3
import sys, json, requests
from urllib.parse import urlparse

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

def main():
    if len(sys.argv) != 2:
        print("Usage: python api_probe.py https://example.com/api/resource")
        raise SystemExit(2)
    url = sys.argv[1]
    if urlparse(url).scheme not in ("http", "https"):
        raise SystemExit("HTTP(S) URL required")
    out = []
    for method in METHODS:
        try:
            r = requests.request(method, url, timeout=8, allow_redirects=False,
                                 headers={"User-Agent": "VulnScanner/1.0"})
            out.append({"method": method, "status": r.status_code,
                        "allow": r.headers.get("Allow"),
                        "content_type": r.headers.get("Content-Type")})
        except requests.RequestException as e:
            out.append({"method": method, "error": str(e)})
    print(json.dumps(out, indent=2))
if __name__ == "__main__":
    main()
