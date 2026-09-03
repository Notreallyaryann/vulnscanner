#!/usr/bin/env python3
"""
csrf_audit.py - Non-destructive CSRF Defense Auditor
Inspects HTML forms and response headers for CSRF defenses (Anti-CSRF tokens, SameSite cookies).
Zero-dependency implementation using Python standard library.
"""
import sys, json, re
from html.parser import HTMLParser
import urllib.request
import urllib.error

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
                "inputs": []
            }
        elif tag in ["input", "textarea"] and self._current_form is not None:
            name = attr_dict.get("name", "")
            elem_id = attr_dict.get("id", "")
            input_type = attr_dict.get("type", "text").lower()
            self._current_form["inputs"].append({
                "name": name,
                "id": elem_id,
                "type": input_type
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

def is_csrf_token(name, elem_id):
    combined = f"{name} {elem_id}".lower()
    return any(k in combined for k in ["csrf", "xsrf", "token", "_token", "authenticity_token"])

def audit_url(url):
    results = {"url": url, "vulnerable_forms": [], "missing_samesite_cookies": []}

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "VulnScanner/1.0"}
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            html_text = resp.read().decode("utf-8", errors="ignore")
            # Parse Set-Cookie headers
            cookie_headers = resp.headers.get_all("Set-Cookie") or []
            for cookie_str in cookie_headers:
                name = cookie_str.split(";")[0].split("=")[0].strip()
                samesite_match = re.search(r"SameSite=(Strict|Lax|None)", cookie_str, re.IGNORECASE)
                samesite = samesite_match.group(1) if samesite_match else "None/Unset"
                secure = "secure" in cookie_str.lower()
                if samesite.lower() not in ["strict", "lax"]:
                    results["missing_samesite_cookies"].append({
                        "name": name,
                        "samesite": samesite,
                        "secure": secure
                    })
    except Exception as e:
        return {"error": str(e)}

    # Parse HTML forms using standard library parser
    parser = FormParser()
    parser.feed(html_text)

    for form in parser.forms:
        if form["method"] in ["POST", "PUT", "DELETE"]:
            token_present = any(
                is_csrf_token(inp["name"], inp["id"])
                for inp in form["inputs"]
            )
            if not token_present:
                results["vulnerable_forms"].append({
                    "action": form["action"] or url,
                    "method": form["method"],
                    "missing_token": True,
                    "inputs_count": len(form["inputs"])
                })

    return results

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python csrf_audit.py <target_url>"}))
        sys.exit(1)
    print(json.dumps(audit_url(sys.argv[1]), indent=2))

if __name__ == "__main__":
    main()
