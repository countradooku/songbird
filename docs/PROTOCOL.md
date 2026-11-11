# Songbird protocol

Skeleton. Each section is filled by the prompt that builds it; every encoding has published test vectors.

## 1. Transport and framing (Prompt 2)

### 1.1 Reaching Songbird through a proxy (Prompt 1)

Clients that cannot reach Songbird directly may connect through a `songbird-proxy`
(`services/proxy`, operator guide `deploy/proxy/README.md`).

**Connection.** The client opens TCP to the proxy host and port, then TLS with SNI set to the proxy
host, validating the proxy's certificate against the system roots. Inside that TLS session it
opens its normal TLS session to the Songbird endpoint, with SNI set to that endpoint's name,
exactly as it would directly. The proxy routes by the inner SNI to an allowlist of Songbird
endpoints and refuses anything else by closing the connection without a response. Everything after
the inner `ClientHello` is opaque to the proxy. The inner `ClientHello` must fit in
`max_client_hello_bytes` (default 16 KiB) and arrive within the handshake timeout (default 10 s).

**Proxy links.** UTF-8, at most 300 bytes, one of:

```
songbird://proxy#<host>[:<port>]
https://<web-domain>/proxy#<host>[:<port>]
```

- The address is in the fragment so web servers never receive it.
- `<host>`: DNS name, 1–253 bytes, labels 1–63 bytes of `[A-Za-z0-9-]`, no leading or trailing
  `-`, no trailing dot; compared case-insensitively and stored lower-case. IP literals are not
  accepted.
- `<port>`: decimal 1–65535, default 443.
- `<web-domain>`: from a fixed list compiled into the app (owner decision open, D-0011).
- Anything else (other schemes, paths, user info, query strings, extra characters) is rejected.

Test vectors (from `services/proxy/src/link.rs`):

| Input | Result |
| --- | --- |
| `songbird://proxy#Proxy.Example.org` | host `proxy.example.org`, port 443 |
| `https://songbird.example/proxy#proxy.example.org:8443` (web domain `songbird.example`) | host `proxy.example.org`, port 8443 |
| `songbird://proxy#p.example:0` | rejected (port) |
| `songbird://proxy#user@p.example` | rejected (host) |
| `https://evil.example/proxy#p.example` | rejected (domain not allowed) |

## 2. Device authentication and sessions (Prompts 2, 3)

## 3. Envelopes, mailbox and delivery (Prompt 2)

## 4. Identity, devices and key directory (Prompt 3)

## 5. Encrypted content schemas (Prompt 4)

## 6. Groups, roles and channels (MLS) (Prompt 5)

## 7. Attachments and packs (Prompt 6)

## 8. Calls and the call key schedule (Prompt 7)

## 9. Push (Prompt 8)

## 10. Settings sync and presence (Prompt 9)

## 11. Backup format and vault access (Prompt 10)

## 12. Versioning and compatibility rules

## 13. Test vectors
