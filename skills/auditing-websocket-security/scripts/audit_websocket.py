#!/usr/bin/env python3
"""
audit_websocket.py - Safe Non-Destructive WebSocket Handshake & CSWSH Auditor
Inspects WebSocket endpoints for missing Origin validation and unencrypted protocols.
"""
import sys
import json
import socket
import ssl
from urllib.parse import urlparse

def test_websocket_upgrade(host, port, use_ssl, path, origin="https://untrusted-attacker.example.com"):
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: {origin}\r\n"
        f"User-Agent: VulnScanner/1.0\r\n\r\n"
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
        status_line = res_str.split("\r\n")[0] if "\r\n" in res_str else res_str
        status_code = None
        parts = status_line.split(" ")
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])

        return {
            "status_line": status_line,
            "status_code": status_code,
            "switched_protocol": status_code == 101,
            "raw_preview": res_str[:200]
        }
    except Exception as e:
        return {"error": str(e)}

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python audit_websocket.py wss://example.com/ws"}))
        sys.exit(2)

    url = sys.argv[1]
    parsed = urlparse(url)

    scheme = parsed.scheme.lower() if parsed.scheme else "ws"
    use_ssl = scheme in ["wss", "https"]
    host = parsed.hostname
    port = parsed.port or (443 if use_ssl else 80)
    path = parsed.path or "/"

    findings = []
    if scheme == "ws" or not use_ssl:
        findings.append({
            "type": "Insecure WebSocket Protocol (Cleartext)",
            "severity": "Medium",
            "detail": "WebSocket uses unencrypted 'ws://' instead of TLS-encrypted 'wss://'."
        })

    handshake = test_websocket_upgrade(host, port, use_ssl, path)
    if handshake.get("switched_protocol"):
        findings.append({
            "type": "Cross-Site WebSocket Hijacking (CSWSH) Risk",
            "severity": "High",
            "detail": "Server returned '101 Switching Protocols' for untrusted arbitrary Origin header.",
            "handshake": handshake.get("status_line")
        })

    print(json.dumps({
        "target": url,
        "host": host,
        "port": port,
        "scheme": scheme,
        "handshake_result": handshake,
        "findings": findings,
        "remediation": (
            "1. Enforce strict origin checking on the server during the WebSocket HTTP Upgrade handshake.\n"
            "2. Mandate wss:// (TLS) transport encryption.\n"
            "3. Use short-lived, CSRF-resistant challenge tokens for initial connection authorization."
        )
    }, indent=2))

if __name__ == "__main__":
    main()
