#!/usr/bin/env python3
import sys, json, requests

def main():
    if len(sys.argv) != 2:
        print("Usage: python cookie_review.py URL")
        raise SystemExit(2)
    r = requests.get(sys.argv[1], timeout=10, allow_redirects=False,
                     headers={"User-Agent":"VulnScanner/1.0"})
    raw = r.raw.headers.get_all("Set-Cookie") if hasattr(r.raw.headers, "get_all") else []
    cookies = []
    for c in raw:
        first = c.split(";",1)[0]
        attrs = c.lower()
        name = first.split("=",1)[0].strip()
        cookies.append({
            "name": name,
            "secure": "secure" in attrs,
            "httponly": "httponly" in attrs,
            "samesite": next((x.strip() for x in c.split(";") if x.strip().lower().startswith("samesite=")), None),
            "path": next((x.strip() for x in c.split(";") if x.strip().lower().startswith("path=")), None),
            "domain": next((x.strip() for x in c.split(";") if x.strip().lower().startswith("domain=")), None),
        })
    print(json.dumps({"url": r.url, "cookies": cookies}, indent=2))
if __name__ == "__main__":
    main()
