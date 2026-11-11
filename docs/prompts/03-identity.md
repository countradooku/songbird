# Prompt 3 — Identity, accounts, devices, keys and privacy primitives

*File: `docs/prompts/03-identity.md` · Skills: applied cryptography review, Rust security, API design, testing.*

**Goal:** accounts without phone numbers, multi-device, post-quantum key distribution, and the server-side privacy primitives the rest of the system relies on.

**Build:**

- **Accounts and usernames.** Random account IDs. Usernames are changeable and found only by exact match. Evaluate libsignal's username scheme (the server stores a hash plus a proof, never the username itself) and adopt it unless a recorded reason says otherwise. Username lookups are rate-limited per account and per IP range.
- **Registration abuse controls.** Argon2id proof-of-work challenge at sign-up, tuned so a phone solves it in a few seconds; per-IP-range throttles; evaluate privacy-preserving tokens (Privacy Pass style) as a later option.
- **Account credentials.** Each device authenticates with its own key (challenge signature, Prompt 2). Account recovery when every device is lost works only through the recovery key from the backup system (Prompt 10); there is no email or SMS reset.
- **Devices.** A primary device links new devices with a QR-based provisioning flow: the new device shows an ephemeral public key, the primary sends it an encrypted provisioning message through a short-lived provisioning channel on the server. A signed, versioned device list per account (signed by the account identity key); device limits per plan; device removal triggers MLS removal in every group (Prompt 5).
- **Key directory.** Per device: identity key, signed prekey, last-resort post-quantum (Kyber/ML-KEM) prekey, one-time EC and post-quantum prekeys, as required by libsignal's PQXDH. One-time prekeys are claimed atomically and never handed out twice; refill signals; signature validation with libsignal's own crates. Same pattern for MLS KeyPackages (single use, plus a last-resort package).
- **Encrypted profiles.** Profile name, avatar pointer, about and status line are one encrypted, versioned blob under a profile key the user shares with contacts. Encrypted avatars live in Garage.
- **Sealed sender.** Short-lived server-signed sender certificates and unidentified-access keys derived from the profile key, so the server can authorize a send without learning who sent it. Ship behind a flag; Prompt 12 verifies it.
- **Key transparency.** An append-only, auditable log mapping account and username hash to identity keys, with inclusion and consistency proofs served by `api`. Evaluate Meta's `akd` crate.
- **GDPR.** Export of everything the server holds about an account; full deletion through the outbox job (every store, every backup within its retention); optional deletion after long inactivity (period decided by the owner).

**Also build (WhatsApp parity):**

- **Username key.** An optional short numeric key the user can require before strangers can start a chat by username (WhatsApp shows it next to the username). Checked server-side, rate-limited, rotatable.
- **Two-step verification (account lock PIN).** An optional PIN required to link a new device or recover the account. Stored only as a slow hash with strict attempt limits and lockout, so it cannot be brute-forced on the server.
- **Passkeys.** Optional WebAuthn passkeys as a second factor for device linking and recovery. Record the trade-off that passkeys sync through Apple or Google accounts.
- **Multiple accounts on one device.** Device auth, keys and mailboxes are per account. Document that one push token shared by several accounts links them on the server, and offer per-account push registrations where the platform allows.
- **Profile links** (website, social handles) as another field of the encrypted profile.
- **Security notifications.** When a contact's identity key changes, every client is told through the device-list and key-transparency paths so the app can warn the user.

**Security:** prekey exhaustion protection (rate limits on fetches per requester and per target), constant-time comparisons for secrets, no enumeration through error messages or timing.

**Gate:** concurrency tests prove no one-time prekey is ever served twice under parallel claims; fuzzed decoders for every key and certificate format; published test vectors; a written threat model for account takeover, enumeration and key substitution, each with its mitigation and test.
