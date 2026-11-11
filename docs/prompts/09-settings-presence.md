# Prompt 9 — Settings, presence, statuses and Yahoo-style features

*File: `docs/prompts/09-settings-presence.md` · Skills: sync and CRDT design, privacy engineering, Rust testing.*

**Goal:** user settings that sync across devices, presence and custom statuses that only the right people see, and the playful Yahoo Messenger features, all without the server learning more than it must.

**Build:**

- **Encrypted settings sync:** an account-level store of encrypted records (theme, wallpapers and chat scenes, notification preferences, read-receipt and typing-indicator toggles, last-seen visibility, per-chat mute, ringtone, scene and default disappearing timer, buddy-list groups). Each setting is its own encrypted record under a random ID, so updates are partial. Conflicts resolve per record with last-writer-wins on a hybrid logical clock carried inside the ciphertext; the server stores and serves opaque records with versions. Prove convergence with property tests across devices, offline edits and reordering.
- **Server-enforced settings (minimal plaintext):** username discoverability on or off; who may reach you through message requests (everyone or nobody; "contacts only" is enforced cryptographically through sealed-sender access keys); inactivity deletion period; plan. Document each in the threat model.
- **Presence and last seen:** the server never reveals connection state to anyone. Clients send encrypted presence (online, away, busy, invisible) and last-seen to the contacts their settings allow, through the ephemeral lane, with debouncing and rate limits. Invisible mode simply sends nothing. Provide a batched presence fan-out call that reuses the send path.
- **Custom statuses** (Yahoo-style "In a meeting until 3", with an expiry) and the "about" line live in the encrypted profile (Prompt 3); contacts get an encrypted "profile changed" signal to refetch.
- **Nudge (Yahoo Buzz):** a content type sent through the ephemeral lane in a distinct "attention" class so the server can rate-limit it per sender and recipient pair. Record in the threat model that the server learns a nudge happened, but not its content.
- **Chat scenes (IMVironments), sound stickers and emoticon packs:** delivered through the pack service (Prompt 6) and referenced from content messages.
- **Ignore list:** this is blocking (Prompt 4).

**Also build (WhatsApp parity):**

- **More synced settings** as encrypted records: custom chat lists and favourites, archived chats and "keep chats archived", default quick reactions, default chat theme and animations, app icon and app theme (Plus entitlement checked by the client), per-chat notification sound and reaction-notification toggles, media auto-download and upload-quality preferences.
- **Encrypted contacts sync:** the user's saved contacts (names, notes, lists) as encrypted records, so "Save to contacts" works across devices without the server seeing an address book.
- **Parental controls (supervised accounts):**
  - A parent account links to a child account in person (QR on both devices, both confirm).
  - The parent sets a policy signed with the parent's key: who may contact the child (approved contacts only, or contacts plus message requests), whether group invites need parent approval, calls from non-contacts blocked, username discoverability off, nudges off.
  - The server enforces every rule it can see (message-request gating, discoverability, group invite acceptance); clients enforce the rest.
  - The parent can never read messages, see call content or browse the child's contacts. The child's app always shows which rules apply.
  - Unlinking needs the parent, or happens automatically at an age the child set at linking time.
  - Respect GDPR Article 8: the age of digital consent differs by EU country (13 to 16). Record the per-country rules in the threat model and the compliance notes.

**Gate:** convergence property tests pass; integration tests prove presence reaches only allowed contacts and that invisible mode sends nothing; nudge rate limits tested; the server's view of every setting matches the threat model.
