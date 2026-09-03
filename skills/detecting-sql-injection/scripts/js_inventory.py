#!/usr/bin/env python3
"""
sqli_heuristic.py - Safe Non-destructive SQL Error & Form Inspector
Uses Python standard library (HTMLParser & urllib) with zero external dependencies.
"""
import sys, re, json
from html.parser import HTMLParser
import urllib.request

DB_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"PostgreSQL.*ERROR",
    r"SQLite.*error", r"ORA-\d{5}", r"Microsoft SQL Server.*Driver",
    r"ODBC SQL Server Driver"
]

class SimpleFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "get").lower(),
                "inputs": []
            }
        elif tag in ["input", "textarea"] and self._current_form is not None:
            name = attr_dict.get("name")
            if name:
                self._current_form["inputs"].append(name)

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python js_inventory.py https://example.com/page"}))
        sys.exit(2)
    url = sys.argv[1]
    req = urllib.request.Request(url, headers={"User-Agent": "VulnScanner/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
            actual_url = resp.geturl()
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    parser = SimpleFormParser()
    parser.feed(text)

    matches = [p for p in DB_ERRORS if re.search(p, text, re.I)]
    print(json.dumps({
        "url": actual_url,
        "potential_db_errors": matches,
        "forms": parser.forms,
        "confidence": "low" if not matches else "medium"
    }, indent=2))

if __name__ == "__main__":
    main()
