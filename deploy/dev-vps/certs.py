#!/usr/bin/env python3
"""Exports ws.<domain> and turn.<domain> from Coolify's Traefik ACME store into
/opt/songbird/tls/{ws,turn}/{tls.crt,tls.key}, and restarts delivery or LiveKit when one changed.
Exit 2 if a certificate is not issued yet (deploy.sh waits on it).
    songbird-certs <domain>
"""
import base64
import json
import os
import subprocess
import sys

ACME = "/data/coolify/proxy/acme.json"
OUT = "/opt/songbird/tls"
SERVICE_UID = 65532  # delivery runs as nonroot


def main() -> int:
    domain = sys.argv[1]
    with open(ACME, encoding="utf-8") as f:
        store = json.load(f)
    certs = {}
    for resolver in store.values():
        for c in (resolver or {}).get("Certificates") or []:
            certs[c["domain"]["main"]] = c
    missing = 0
    for name, container in (("ws", "songbird-delivery"), ("turn", "songbird-livekit")):
        c = certs.get(f"{name}.{domain}")
        if c is None:
            print(f"{name}.{domain}: not issued yet")
            missing += 1
            continue
        crt = base64.b64decode(c["certificate"])
        key = base64.b64decode(c["key"])
        d = os.path.join(OUT, name)
        os.makedirs(d, mode=0o755, exist_ok=True)
        crt_path, key_path = os.path.join(d, "tls.crt"), os.path.join(d, "tls.key")
        old = open(crt_path, "rb").read() if os.path.exists(crt_path) else b""
        if old == crt:
            continue
        fd = os.open(key_path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        os.chown(key_path + ".new", SERVICE_UID, SERVICE_UID)
        os.replace(key_path + ".new", key_path)
        with open(crt_path + ".new", "wb") as f:
            f.write(crt)
        os.chmod(crt_path + ".new", 0o644)
        os.replace(crt_path + ".new", crt_path)
        print(f"{name}.{domain}: exported")
        if old:
            subprocess.run(["docker", "restart", container], check=False)
    return 2 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
