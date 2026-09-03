#!/usr/bin/env python3
import sys, json, requests
from urllib.parse import urlparse

def main():
    if len(sys.argv) != 2:
        print("Usage: python auth_review.py LOGIN_URL")
        raise SystemExit(2)
    url = sys.argv[1]
    r = requests.get(url, timeout=10, allow_redirects=False,
                     headers={"User-Agent":"VulnScanner/1.0"})
    h = {k.lower(): v for k,v in r.headers.items()}
    cookies = h.get("set-cookie", "")
    checks = {
        "https": urlparse(url).scheme == "https",
        "cache_control_no_store": "no-store" in h.get("cache-control","").lower(),
        "secure_cookie_flag": "secure" in cookies.lower() if cookies else None,
        "httponly_cookie_flag": "httponly" in cookies.lower() if cookies else None,
        "samesite_cookie_flag": "samesite=" in cookies.lower() if cookies else None,
    }
    print(json.dumps({"url": r.url, "status": r.status_code, "checks": checks}, indent=2))
if __name__ == "__main__":
    main()
