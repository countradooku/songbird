# Prompt 14 — WhatsApp interoperability (EU third-party chats)

*File: `docs/prompts/14-whatsapp-interop.md` · Skills: protocol integration, applied cryptography review, secure parsing, privacy engineering. Starts only after the owner clears the legal gate below.*

**Goal:** let Songbird users chat with WhatsApp users through WhatsApp's "Third-party chats" (the EU Digital Markets Act interoperability), so people can switch without losing their WhatsApp contacts.

**What is known (verify against the current documents before building):** third parties must sign Meta's interoperability agreement (the WhatsApp Reference Offer); Meta prefers the Signal Protocol and allows alternatives only with its approval; messages are Signal-encrypted and packaged as XML stanzas; one-to-one chats and file sharing came first, with group chats and then calls following on Meta's timeline ([UC Today](https://uctoday.com/meta-details-whatsapps-interoperability-plan), [Android Central](https://www.androidcentral.com/apps-software/how-whatsapp-will-become-interoperable-in-eu)). Element has already connected 1:1 chats this way while keeping end-to-end encryption ([Element](https://element.io/blog/the-eu-digital-markets-act-is-here)). Songbird already uses libsignal, which removes the hardest part.

**Gate 0 (owner, legal and privacy):** obtain and review the current Reference Offer and developer documentation; sign the agreement; write down exactly what Meta will learn about Songbird users who opt in (their interop identifier and the metadata of chats with WhatsApp users). Interop is opt-in per user and clearly labelled in the app.

**Build `services/interop-whatsapp`** (its own binary; the only holder of Meta credentials):

- A gateway translating between Songbird envelopes and Meta's interop protocol. Encryption stays end-to-end between the Songbird app and the WhatsApp app (libsignal on both sides); the gateway never holds message keys or plaintext.
- Identity mapping between a Songbird account and its WhatsApp-facing identifier: opt-in, revocable, deleted with the account. An identity provider for Meta's token-based identity verification.
- Prekey bundle and device-list bridging; encrypted media relayed between Garage and Meta's media servers without decryption.
- **Hardened XML handling:** a streaming parser with strict size and depth limits and no DTDs or external entities (blocking XML entity attacks), fuzzed continuously.
- Separate rate limits, spam controls and reporting for interop traffic; a separate section in the threat model.

**Gate:** end-to-end 1:1 text and media with a WhatsApp test account in Meta's test environment; Meta's certification steps passed; the privacy review and threat-model section accepted by the owner.
