#!/usr/bin/env python3
"""
graphql_introspection_audit.py - Non-destructive GraphQL Endpoint Auditor
Tests if schema introspection is enabled on a target GraphQL endpoint.
"""
import sys, json, requests

INTROSPECTION_QUERY = """
query SafeIntrospectionCheck {
  __schema {
    queryType { name }
    types { name kind }
  }
}
"""

def audit_graphql(endpoint_url):
    headers = {"Content-Type": "application/json", "User-Agent": "VulnScanner/1.0"}
    try:
        r = requests.post(
            endpoint_url,
            json={"query": INTROSPECTION_QUERY},
            headers=headers,
            timeout=10
        )
    except Exception as e:
        return {"error": f"Failed to connect to GraphQL endpoint: {str(e)}"}

    if r.status_code == 200 and "__schema" in r.text:
        data = r.json().get("data", {}).get("__schema", {})
        types_count = len(data.get("types", []))
        return {
            "endpoint": endpoint_url,
            "introspection_enabled": True,
            "schema_types_count": types_count,
            "severity": "MEDIUM",
            "cwe": "CWE-200",
            "remediation": "Disable introspection in production deployments."
        }
    else:
        return {
            "endpoint": endpoint_url,
            "introspection_enabled": False,
            "status_code": r.status_code,
            "notes": "Introspection is disabled or endpoint returned non-200"
        }

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python graphql_introspection_audit.py <graphql_endpoint_url>"}))
        sys.exit(1)
    print(json.dumps(audit_graphql(sys.argv[1]), indent=2))

if __name__ == "__main__":
    main()
