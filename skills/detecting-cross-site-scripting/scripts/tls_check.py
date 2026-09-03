#!/usr/bin/env python3
"""
tls_check.py (xss_reflection) - Parameter Reflection Inspector
Uses Python standard library (HTMLParser & urllib) with zero external dependencies.
"""
import sys, re, json
from html.parser import HTMLParser
import urllib.request
from urllib.parse import urlparse, parse_qs

class InlineScriptCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_script = False
        self.inline_scripts = []
        self._current_data = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            attr_dict = {k.lower(): v for k, v in attrs}
            if "src" not in attr_dict:
                self.in_script = True
                self._current_data = []

    def handle_data(self, data):
        if self.in_script:
            self._current_data.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self.in_script:
            self.in_script = False
            self.inline_scripts.append("".join(self._current_data).strip()[:120])

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python tls_check.py 'https://example.com/?q=test'"}))
        raise SystemExit(2)
    url = sys.argv[1]
    req = urllib.request.Request(url, headers={"User-Agent": "VulnScanner/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
            actual_url = resp.geturl()
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    params = parse_qs(urlparse(url).query)
    findings = []
    for key, vals in params.items():
        for value in vals:
            if value and value in text:
                idx = text.find(value)
                context = text[max(0, idx - 120): idx + 120]
                findings.append({"parameter": key, "reflected": True, "context": context})

    parser = InlineScriptCollector()
    parser.feed(text)

    print(json.dumps({
        "url": actual_url,
        "reflections": findings,
        "inline_script_blocks": len(parser.inline_scripts)
    }, indent=2))

if __name__ == "__main__":
    main()
