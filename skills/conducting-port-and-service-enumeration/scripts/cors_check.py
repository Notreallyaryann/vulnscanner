#!/usr/bin/env python3
import socket, sys, json

DEFAULT_PORTS = [21,22,25,53,80,110,143,443,445,3306,5432,6379,8080,8443]

def main():
    if len(sys.argv) not in (2,3):
        print("Usage: python port_check.py HOST [comma-separated-ports]")
        raise SystemExit(2)
    host = sys.argv[1]
    ports = DEFAULT_PORTS if len(sys.argv) == 2 else [int(x) for x in sys.argv[2].split(",")]
    results = []
    for port in ports:
        s = socket.socket()
        s.settimeout(1.5)
        try:
            state = "open" if s.connect_ex((host, port)) == 0 else "closed_or_filtered"
        except OSError as e:
            state = f"error: {e}"
        finally:
            s.close()
        results.append({"port": port, "state": state})
    print(json.dumps({"host": host, "results": results}, indent=2))
if __name__ == "__main__":
    main()
