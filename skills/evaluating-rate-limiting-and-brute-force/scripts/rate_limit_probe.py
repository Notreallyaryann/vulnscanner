#!/usr/bin/env python3
"""
rate_limit_probe.py - Non-destructive Rate Limit & Header Probe
Sends a small burst (5 requests) to detect if rate limiting is enforced on an endpoint.
"""
import sys, json, requests

def probe_endpoint(url):
    results = {"url": url, "responses": [], "rate_limit_detected": False}
    session = requests.Session()
    session.headers.update({"User-Agent": "VulnScanner/1.0"})

    for i in range(5):
        try:
            r = session.post(url, json={"test": "probe"}, timeout=5)
            headers = {k: v for k, v in r.headers.items() if "ratelimit" in k.lower() or "retry-after" in k.lower()}
            results["responses"].append({
                "attempt": i + 1,
                "status_code": r.status_code,
                "rate_headers": headers
            })
            if r.status_code == 429 or len(headers) > 0:
                results["rate_limit_detected"] = True
        except Exception as e:
            results["responses"].append({"attempt": i + 1, "error": str(e)})

    return results

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python rate_limit_probe.py <endpoint_url>"}))
        sys.exit(1)
    print(json.dumps(probe_endpoint(sys.argv[1]), indent=2))

if __name__ == "__main__":
    main()
