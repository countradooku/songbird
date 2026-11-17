# Calls: LiveKit, its Valkey, TURN and webhooks (Prompt 7)

PROTOCOL §8; D-0085 to D-0089. Covers the SFU, LiveKit's own Valkey, TURN over TLS, webhooks and
the LiveKit API secret. **No server holds a media key**: none of these failures exposes a call's
content; they stop or degrade calls.

## A LiveKit node is down

- **Detection:** `POST /v1/calls…` answers 503 (the room service is unreachable) and `api_errors`
  rises; `songbird_calls_webhooks_total` on that host stops growing; apps report "can't connect".
- **Impact:** rooms on that node end (participants reconnect and get a new room only if they start
  a new call); new rooms are placed on the other nodes by LiveKit's routing through Valkey.
  Messaging is unaffected.
- **Immediate actions:**
  1. `docker logs songbird-livekit --tail 200` on the host; `docker restart songbird-livekit`.
  2. If the host is gone, remove it from DNS for `calls_domain` (signalling); LiveKit's other nodes
     keep serving.
- **Recovery:** redeploy the calls role (`ansible-playbook site.yml --limit calls`).
- **Verification:** a test call through `api` gets a ticket (200) and connects; on another host,
  `songbird_calls_rooms_started_total` grows.

## LiveKit's Valkey is down

- **Detection:** every LiveKit node logs Redis errors; `POST /v1/calls…` answers 503.
- **Impact:** with multi-node routing, new rooms cannot be placed and nodes cannot route
  signalling; live rooms on a node may continue until participants reconnect. It holds no user
  data (no persistence): room routing only.
- **Immediate actions:** `docker restart songbird-valkey-livekit` on the first calls host; check
  its certificate (`/etc/songbird/tls/valkey-livekit`) has not expired (`mtls-rotation.md`).
- **Recovery:** restart LiveKit on every calls host after Valkey is back, so routing re-registers.
- **Verification:** `valkey-cli --tls … KEYS nodes` lists every LiveKit node; a test call connects.

## TURN over TLS fails (restrictive networks cannot call)

- **Detection:** reports from users behind corporate or hotel networks; LiveKit logs TLS handshake
  errors on `turn_ip:443`; the certificate in `/etc/songbird/public-tls/turn` is expired or for
  another name.
- **Impact:** only clients that cannot use UDP or ICE/TCP 7881 fail to connect media.
- **Immediate actions:** renew the certificate for `turn_domain`, put it in
  `/etc/songbird/public-tls/turn/{tls.crt,tls.key}`, `docker restart songbird-livekit`.
- **Verification:** `openssl s_client -connect <turn_ip>:443 -servername <turn_domain>` shows the
  new certificate; a test client with UDP blocked connects.

## Webhooks failing

- **Detection:** `songbird_calls_webhooks_refused_total` grows (signature, age) or
  `songbird_calls_webhooks_total` stops while rooms start; LiveKit logs "failed to send webhook".
- **Impact:** call records are not deleted when rooms finish; they expire after 24 h on their own,
  and a group's stale pointer is replaced at the next start (`ListRooms`). No call fails.
- **Immediate actions:**
  1. Refused for signature: LiveKit and `calls` disagree on the API key or secret; compare
     `LIVEKIT_KEYS` and `[calls.livekit] api_key`/`api_secret` (SOPS).
  2. Refused for age: the clocks differ by more than 5 minutes; fix NTP on the host.
  3. Not sent: `docker ps` for `songbird-calls`; it must listen on `127.0.0.1:9106`.
- **Verification:** `songbird_calls_webhooks_total` grows with `songbird_calls_rooms_started_total`.

## Rotating the LiveKit API secret

1. Generate a new secret (`openssl rand -hex 32`); put it in SOPS (`livekit_api_secret`) for
   LiveKit, `api` (`[api.calls] api_secret`) and `calls` (`[calls.livekit] api_secret`).
2. Deploy LiveKit and `calls` first, then `api`. Tokens already issued (2 minutes) and connected
   participants are cut off when LiveKit restarts: do it in a quiet hour, or add the new key under
   a new key ID beside the old one in `LIVEKIT_KEYS` first, move `api` to it, then remove the old.
3. **Verification:** a test call connects; `songbird_calls_webhooks_refused_total` stays flat.

## A participant must be removed from every call now (abuse, a compromised device)

- Remove the device from its account (`DELETE /v1/devices/self` or the primary's device list); its
  groups' next commits drop it from the roster, and `api` disconnects it from any live group call
  at that commit. For a 1:1 call, end the room: `songbird-admin` has no call tool yet; use
  LiveKit's `DeleteRoom` with an admin token minted from the API secret on an admin host.
