#!/usr/bin/env python3
"""
test_smuggle_probe.py - Safe Non-Destructive HTTP Request Smuggling & Desync Prober
Tests for ambiguous Content-Length / Transfer-Encoding handling and header obfuscation.
"""
import sys
import json
import socket
import ssl
from urllib.parse import urlparse

def probe_raw_dual_headers(host, port, use_ssl, path):
    """
    Sends a safe dual-header probe (both Content-Length and Transfer-Encoding present).
    Validates whether the server rejects ambiguous RFC 7230/9112 requests with 400 Bad Request
    or processes them inconsistently.
    """
    results = {
        "dual_header_rejected": False,
        "status_code": None,
        "server_banner": None,
        "risk_indicators": []
    }

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: VulnScanner/1.0\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
        f"0\r\n\r\n"
    ).encode("ascii")

    try:
        raw_sock = socket.create_connection((host, port), timeout=6)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        sock.sendall(req)
        response_bytes = sock.recv(2048)
        sock.close()

        res_str = response_bytes.decode("latin1", errors="ignore")
        if res_str.startswith("HTTP/"):
            parts = res_str.split("\r\n")
            first_line = parts[0]
            status_match = first_line.split(" ")
            if len(status_match) >= 2 and status_match[1].isdigit():
                results["status_code"] = int(status_match[1])

            for line in parts[1:]:
                if line.lower().startswith("server:"):
                    results["server_banner"] = line.split(":", 1)[1].strip()

            # RFC 7230 specifies servers MUST treat dual CL/TE as 400 or prioritize TE
            if results["status_code"] == 400:
                results["dual_header_rejected"] = True
            elif results["status_code"] in [200, 301, 302, 404]:
                results["risk_indicators"].append(
                    "Server accepted request with conflicting Content-Length and Transfer-Encoding headers (Status: "
                    + str(results["status_code"]) + "). Potential CL/TE desync risk."
                )
    except Exception as e:
        results["connection_error"] = str(e)

    return results

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python test_smuggle_probe.py https://example.com/path"}))
        sys.exit(2)

    url = sys.argv[1]
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        print(json.dumps({"error": "Invalid URL provided"}))
        sys.exit(2)

    use_ssl = parsed.scheme.lower() == "https"
    port = parsed.port or (443 if use_ssl else 80)
    host = parsed.hostname
    path = parsed.path or "/"

    probe_result = probe_raw_dual_headers(host, port, use_ssl, path)

    confidence = "medium" if probe_result.get("risk_indicators") else "low"
    severity = "High" if probe_result.get("risk_indicators") else "Info"

    output = {
        "url": url,
        "host": host,
        "port": port,
        "use_ssl": use_ssl,
        "probe_result": probe_result,
        "severity": severity,
        "confidence": confidence,
        "remediation": (
            "Ensure reverse proxies and backend servers strictly reject ambiguous HTTP/1.1 requests containing "
            "both Content-Length and Transfer-Encoding (RFC 7230 / RFC 9112 compliant 400 Bad Request). "
            "Where possible, standardize on HTTP/2 end-to-end to eliminate framing ambiguity."
        )
    }

    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
