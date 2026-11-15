# Run a Songbird proxy

Where Songbird is blocked, anyone can run a proxy to help people connect, in the style of Signal's
and WhatsApp's proxy support. You need a small Linux server outside the blocking country, a domain
name pointing at it, and Docker.

## What the proxy can and cannot see

- It **cannot read messages, calls or anything else**: the app's connection to Songbird is
  end-to-end TLS *inside* the connection to your proxy. The proxy only forwards encrypted bytes.
- It sees the IP addresses of people connecting to it and when they connect, like any server.
  **It writes no logs and stores nothing**: there is no logging code in it, and the compose file
  below disables Docker's own logs too.
- It can only reach Songbird's servers. It refuses every other destination, so it cannot be abused
  as an open relay.
- To a network observer, your proxy looks like an ordinary HTTPS server on your domain.

## Set it up

1. Point a DNS name (for example `proxy.example.org`) at your server.
2. Get a TLS certificate for that name with any ACME client, for example:
   ```bash
   sudo certbot certonly --standalone -d proxy.example.org
   sudo install -d -m 0750 /etc/songbird-proxy
   sudo cp /etc/letsencrypt/live/proxy.example.org/fullchain.pem /etc/songbird-proxy/
   sudo install -m 0600 -o 65532 /etc/letsencrypt/live/proxy.example.org/privkey.pem /etc/songbird-proxy/
   ```
   The image runs as uid 65532; the key must be readable by it and not by anyone else.
3. Copy [`proxy.example.toml`](proxy.example.toml) to `/etc/songbird-proxy/proxy.toml`.
   The upstream list is published by the Songbird project; do not add other destinations.
4. Start it:
   ```bash
   export SONGBIRD_PROXY_VERSION=0.1.0
   docker compose -f compose.yaml up -d
   ```
5. Make your proxy link and share it:
   ```bash
   docker run --rm ghcr.io/songbirdchat/songbird-proxy:$SONGBIRD_PROXY_VERSION --print-link proxy.example.org
   # songbird://proxy#proxy.example.org
   ```
   People open the link, or enter the host name under Settings > Storage and data > Proxy.

Renew the certificate before it expires and restart the container afterwards
(`docker compose restart`). Only TCP 443 needs to be open.

## Verify the image

Release images are signed. Check before running:

```bash
cosign verify ghcr.io/songbirdchat/songbird-proxy:$SONGBIRD_PROXY_VERSION \
  --certificate-identity-regexp '^https://github.com/songbirdchat/songbird/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Operating notes

- Limits (connections, timeouts, maximum ClientHello size) are in `[limits]`; defaults suit a
  small VPS. Over the connection limit, new connections are closed at once.
- `SIGTERM` stops accepting and lets open connections finish for up to 30 seconds.
- The proxy has no metrics or admin port by design. Check it is up with
  `openssl s_client -connect proxy.example.org:443 -servername proxy.example.org </dev/null`.

How it works, for reviewers: [`services/proxy`](../../services/proxy/src/lib.rs),
the link format in [`docs/PROTOCOL.md`](../../docs/PROTOCOL.md) §1.1, threats in
[`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md) §3.4.
