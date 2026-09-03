#!/usr/bin/env python3
import sys, json, requests, ipaddress
from urllib.parse import urlparse, parse_qs

URL_NAMES = {"url","uri","link","target","dest","destination","redirect","callback","webhook","endpoint","image","feed"}

def main():
    if len(sys.argv) != 2:
        print("Usage: python ssrf_surface.py URL")
        raise SystemExit(2)
    url = sys.argv[1]
    r = requests.get(url, timeout=10, headers={"User-Agent":"VulnScanner/1.0"})
    params = parse_qs(urlparse(url).query)
    candidates = []
    for name, vals in params.items():
        if name.lower() in URL_NAMES or any(v.startswith(("http://","https://")) for v in vals):
            candidates.append({"parameter": name, "values": vals[:3]})
    host = urlparse(url).hostname
    host_class = None
    if host:
        try:
            ip = ipaddress.ip_address(host)
            host_class = {"private": ip.is_private, "loopback": ip.is_loopback, "link_local": ip.is_link_local}
        except ValueError:
            pass
    print(json.dumps({"url": r.url, "url_like_inputs": candidates, "target_host_classification": host_class,
                      "note": "No internal/metadata destinations were contacted."}, indent=2))
if __name__ == "__main__":
    main()
