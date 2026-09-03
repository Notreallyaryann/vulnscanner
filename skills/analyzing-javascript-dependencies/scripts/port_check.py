#!/usr/bin/env python3
"""
port_check.py (js_inventory) - Extracts remote script tags from a web page
Uses Python standard library (HTMLParser & urllib) with zero external dependencies.
"""
import sys, json, re
from html.parser import HTMLParser
import urllib.request
from urllib.parse import urljoin

class ScriptTagParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            attr_dict = {k.lower(): v for k, v in attrs}
            src = attr_dict.get("src")
            if src:
                full_src = urljoin(self.base_url, src)
                m = re.search(r"/([A-Za-z0-9_.-]+)@([0-9][^/]+)", full_src)
                self.scripts.append({
                    "src": full_src,
                    "npm_style_match": m.groups() if m else None
                })

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python port_check.py URL"}))
        raise SystemExit(2)
    url = sys.argv[1]
    req = urllib.request.Request(url, headers={"User-Agent": "VulnScanner/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            html_text = resp.read().decode("utf-8", errors="ignore")
            actual_url = resp.geturl()
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    parser = ScriptTagParser(actual_url)
    parser.feed(html_text)

    print(json.dumps({
        "url": actual_url,
        "javascript_files": parser.scripts,
        "note": "Inventory only; vulnerability matching should use a current advisory database."
    }, indent=2))

if __name__ == "__main__":
    main()
