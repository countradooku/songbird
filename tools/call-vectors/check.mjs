// An independent implementation of Songbird's call key schedule (PROTOCOL §8, D-0086), written
// from the specification with Node.js's crypto (OpenSSL), not from the Rust code. It rebuilds
// every line of crates/content/vectors/call/v1.txt: the 1:1 derivation, sender keys, link
// secrets and their stored hash, and sealed cards (whose protobuf it also encodes by hand). It
// then opens each card again and checks that a flipped byte is refused.
//
// Run: node tools/call-vectors/check.mjs   (Node 20 or later; no packages)
import {
  createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ctx = (s) => Buffer.from(`songbird.v1/${s}\0`, "latin1");
const ONE_TO_ONE = ctx("call-1to1");
const SENDER = ctx("call-sender");
const LINK_ID = ctx("call-link-id");
const LINK_KEY = ctx("call-link-key");
const LINK_HASH = ctx("call-link-hash");
const CARD_AAD = ctx("call-link-card");

const hex = (s) => Buffer.from(s, "hex");

// HKDF-Expand (RFC 5869 §2.3) for one block: T(1) = HMAC(PRK, info || 0x01).
function expand32(prk, info) {
  return createHmac("sha256", prk).update(Buffer.concat([info, Buffer.from([1])])).digest();
}

function senderKey(epochSecret, identity) {
  if (identity.length < 1 || identity.length > 64) throw new Error("identity length");
  return expand32(epochSecret, Buffer.concat([SENDER, Buffer.from([identity.length]), identity]));
}

function oneToOne(callId, callSecret) {
  return Buffer.from(hkdfSync("sha256", callSecret, callId, ONE_TO_ONE, 32));
}

function link(root) {
  const id = Buffer.from(hkdfSync("sha256", root, Buffer.alloc(0), LINK_ID, 32));
  const key = Buffer.from(hkdfSync("sha256", root, Buffer.alloc(0), LINK_KEY, 32));
  const hash = createHash("sha256").update(LINK_HASH).update(id).digest();
  return { id, key, hash };
}

// CallLinkCard { bytes account = 1; bytes device = 2; string identity = 3; string name = 4; }
// proto3: empty fields are omitted; every length here is below 128 (one-byte varint).
function encodeCard({ account, device, identity, name }) {
  const field = (tag, b) => (b.length ? Buffer.concat([Buffer.from([(tag << 3) | 2, b.length]), b]) : Buffer.alloc(0));
  return Buffer.concat([field(1, account), field(2, device), field(3, identity), field(4, name)]);
}

function decodeCard(b) {
  const out = {};
  let i = 0;
  while (i < b.length) {
    const tag = b[i] >> 3, len = b[i + 1];
    out[tag] = b.subarray(i + 2, i + 2 + len);
    i += 2 + len;
  }
  return out;
}

function seal(key, nonce, plain) {
  const c = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  c.setAAD(CARD_AAD, { plaintextLength: plain.length });
  return Buffer.concat([Buffer.from([1]), nonce, c.update(plain), c.final(), c.getAuthTag()]);
}

function open(key, sealed) {
  if (sealed[0] !== 1) throw new Error("version");
  const nonce = sealed.subarray(1, 13);
  const body = sealed.subarray(13, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  const d = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  d.setAAD(CARD_AAD, { plaintextLength: body.length });
  d.setAuthTag(tag);
  return Buffer.concat([d.update(body), d.final()]);
}

const here = dirname(fileURLToPath(import.meta.url));
const path = join(here, "..", "..", "crates", "content", "vectors", "call", "v1.txt");
const lines = readFileSync(path, "utf8").split(/\r?\n/).filter(Boolean);
let n = 0;
const eq = (a, b, what) => {
  if (!a.equals(b)) throw new Error(`${what}: ${a.toString("hex")} != ${b.toString("hex")}`);
};

for (const line of lines) {
  const [kind, ...f] = line.split(" ");
  switch (kind) {
    case "1to1": {
      const [callId, secret, identity, want] = f.map(hex);
      eq(senderKey(oneToOne(callId, secret), identity), want, "1to1");
      break;
    }
    case "sender": {
      const [secret, identity, want] = f.map(hex);
      eq(senderKey(secret, identity), want, "sender");
      break;
    }
    case "link": {
      const [root, id, key, hash] = f.map(hex);
      const l = link(root);
      eq(l.id, id, "link id");
      eq(l.key, key, "link key");
      eq(l.hash, hash, "link hash");
      break;
    }
    case "card": {
      const [key, nonce, card, sealed] = f.map(hex);
      // The cards in the vectors: account A1×16, device D1×16, and an identity and name the
      // encoding carries; re-encode them by hand and compare.
      const fields = decodeCard(card);
      eq(fields[1], Buffer.alloc(16, 0xa1), "card account");
      eq(fields[2], Buffer.alloc(16, 0xd1), "card device");
      eq(encodeCard({ account: fields[1], device: fields[2], identity: fields[3], name: fields[4] ?? Buffer.alloc(0) }), card, "card encoding");
      eq(seal(key, nonce, card), sealed, "card seal");
      eq(open(key, sealed), card, "card open");
      for (const i of [0, 5, 13, sealed.length - 1]) {
        const t = Buffer.from(sealed);
        t[i] ^= 1;
        let refused = false;
        try { open(key, t); } catch { refused = true; }
        if (!refused) throw new Error(`card: flipped byte ${i} opened`);
      }
      break;
    }
    default:
      throw new Error(`unknown line kind ${kind}`);
  }
  n++;
}
console.log(`call vectors: ${n} lines rebuilt independently, all match`);
