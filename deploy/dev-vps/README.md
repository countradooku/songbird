# Test environment on one Coolify server (D-0135)

For trying the app on a phone against real services. Not `beta`: no mTLS, no worker, no backups,
`environment = "dev"`. Production-shaped environments use `deploy/bin/env-up`.

```bash
deploy/dev-vps/deploy.sh root@<server> <domain> <ipv4>          # build on the server, configure, start
deploy/dev-vps/deploy.sh root@<server> <domain> <ipv4> invite   # one invite code
deploy/dev-vps/deploy.sh root@<server> <domain> <ipv4> status
```

Before the first run: A records (DNS only, not proxied) for `api.`, `ws.`, `livekit.` and `turn.`
pointing at the server, and inbound TCP 7881, UDP 7882, TCP 5349 and UDP 3478 in its firewall.

| Name | Served by | TLS |
| --- | --- | --- |
| `api.<domain>` | api | Traefik |
| `ws.<domain>:443` | delivery | delivery itself (SNI passthrough: the device signs the TLS exporter, D-0018) |
| `livekit.<domain>` | LiveKit signalling | Traefik |
| `turn.<domain>:5349` | LiveKit TURN | LiveKit (certificate exported from Traefik by `certs.py`) |

No HTTP router may match `ws.<domain>`: Traefik would answer it instead of passing it through.

The app, built for this server:

```bash
cd apps/ui
IPHONEOS_DEPLOYMENT_TARGET=17.0 SONGBIRD_SERVER=<domain> nsh package --target ios \
  --sign "Apple Development: …" --profile <profile.mobileprovision>
```

Then You → Server connection: turn it on, enter an invite code and a username, Register.
