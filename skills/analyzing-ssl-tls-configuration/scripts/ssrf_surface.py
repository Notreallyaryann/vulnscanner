#!/usr/bin/env python3
import sys, ssl, socket, json
from urllib.parse import urlparse
from datetime import datetime

def main():
    if len(sys.argv) != 2:
        print("Usage: python tls_check.py https://example.com")
        raise SystemExit(2)
    p = urlparse(sys.argv[1])
    if p.scheme != "https":
        raise SystemExit("HTTPS URL required")
    host = p.hostname; port = p.port or 443
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            not_after = cert.get("notAfter")
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").isoformat() if not_after else None
            print(json.dumps({"host": host, "tls_version": ssock.version(),
                              "cipher": ssock.cipher(), "subject": cert.get("subject"),
                              "issuer": cert.get("issuer"), "expires": expiry}, default=str, indent=2))
if __name__ == "__main__":
    main()
