#!/usr/bin/env python3
import sys, re, json, requests
from urllib.parse import urlparse, parse_qs

PATTERNS = [
    r"\{\{.*\}\}", r"\{%.*%\}", r"\$\{.*\}", r"<%.*%>",
    r"Jinja", r"Twig", r"Freemarker", r"Velocity", r"Thymeleaf"
]

def main():
    if len(sys.argv) != 2:
        print("Usage: python ssti_heuristic.py URL")
        raise SystemExit(2)
    url = sys.argv[1]
    r = requests.get(url, timeout=10, headers={"User-Agent":"VulnScanner/1.0"})
    hits = [p for p in PATTERNS if re.search(p, r.text, re.I|re.S)]
    params = list(parse_qs(urlparse(url).query).keys())
    print(json.dumps({"url": r.url, "template_indicators": hits,
                      "query_parameters": params,
                      "confidence": "low"}, indent=2))
if __name__ == "__main__":
    main()
