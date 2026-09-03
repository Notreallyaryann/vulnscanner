#!/usr/bin/env python3
import sys, json, requests

def main():
    if len(sys.argv) != 3:
        print("Usage: python cors_check.py URL TEST_ORIGIN")
        raise SystemExit(2)
    url, origin = sys.argv[1], sys.argv[2]
    r = requests.get(url, timeout=10, headers={"Origin": origin, "User-Agent":"VulnScanner/1.0"})
    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = r.headers.get("Access-Control-Allow-Credentials")
    print(json.dumps({
        "url": r.url, "test_origin": origin,
        "allow_origin": acao, "allow_credentials": acac,
        "wildcard_with_credentials_risk": acao == "*" and str(acac).lower() == "true",
        "reflects_test_origin": acao == origin
    }, indent=2))
if __name__ == "__main__":
    main()
