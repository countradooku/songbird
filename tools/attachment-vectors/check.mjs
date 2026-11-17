// An independent implementation of Songbird's attachment format (PROTOCOL §7.1, D-0080), written
// from the specification with Node.js's crypto (OpenSSL), not from the Rust code. It rebuilds
// every line of crates/content/vectors/attachment/v1.txt, opens each ciphertext again, and checks
// that a flipped byte is refused.
//
// Run: node tools/attachment-vectors/check.mjs   (Node 20 or later; no packages)
import { createCipheriv, createDecipheriv, createHash, hkdfSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const CHUNK = 65536, TAG = 16, MIN_PADDED = 1024;
const CONTEXT = Buffer.from("songbird.v1/attachment\0", "latin1");
const SUITES = { 1: "chacha20-poly1305", 2: "aes-256-gcm" };

// Padmé, from the PURBs paper (with BigInt to keep it exact).
function padme(n) {
  if (n < 2) return n;
  const e = Math.floor(Math.log2(n));
  const s = Math.floor(Math.log2(e)) + 1;
  const z = e - s;
  const mask = 2 ** z - 1;
  return Number((BigInt(n) + BigInt(mask)) & ~BigInt(mask));
}
const paddedLen = (n) => padme(Math.max(n, MIN_PADDED));
const chunks = (p) => Math.max(1, Math.ceil(p / CHUNK));

function derive(version, key, salt) {
  const okm = Buffer.from(
    hkdfSync("sha256", key, salt, Buffer.concat([CONTEXT, Buffer.from([version])]), 64),
  );
  return { key: okm.subarray(0, 32), commitment: okm.subarray(32) };
}

function nonce(i, last) {
  const n = Buffer.alloc(12);
  n.writeBigUInt64BE(BigInt(i), 3);
  n[11] = last ? 1 : 0;
  return n;
}

function encrypt(version, key, salt, plain) {
  const k = derive(version, key, salt);
  const padded = Buffer.concat([plain, Buffer.alloc(paddedLen(plain.length) - plain.length)]);
  const parts = [Buffer.from([version]), salt];
  const n = chunks(padded.length);
  for (let i = 0; i < n; i++) {
    const c = createCipheriv(SUITES[version], k.key, nonce(i, i === n - 1), { authTagLength: TAG });
    parts.push(c.update(padded.subarray(i * CHUNK, (i + 1) * CHUNK)), c.final(), c.getAuthTag());
  }
  return { ct: Buffer.concat(parts), digest: k.commitment };
}

function decrypt(key, digest, n, ct) {
  const version = ct[0];
  if (!SUITES[version]) throw new Error("version");
  const k = derive(version, key, ct.subarray(1, 33));
  if (!k.commitment.equals(digest)) throw new Error("commitment");
  const p = paddedLen(n), m = chunks(p);
  let off = 33;
  const out = [];
  for (let i = 0; i < m; i++) {
    const len = Math.min(CHUNK, p - i * CHUNK);
    const d = createDecipheriv(SUITES[version], k.key, nonce(i, i === m - 1), { authTagLength: TAG });
    d.setAuthTag(ct.subarray(off + len, off + len + TAG));
    out.push(d.update(ct.subarray(off, off + len)), d.final());
    off += len + TAG;
  }
  if (off !== ct.length) throw new Error("trailing");
  const all = Buffer.concat(out);
  if (all.subarray(n).some((b) => b !== 0)) throw new Error("padding");
  return all.subarray(0, n);
}

const here = dirname(fileURLToPath(import.meta.url));
const file = join(here, "../../crates/content/vectors/attachment/v1.txt");
const key = Buffer.alloc(64, 0x11), salt = Buffer.alloc(32, 0x22);
let checked = 0;
for (const line of readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean)) {
  const [v, n, len, digest, sha, first] = line.split(" ");
  const plain = Buffer.from(Array.from({ length: Number(n) }, (_, i) => i % 256));
  const { ct, digest: d } = encrypt(Number(v), key, salt, plain);
  const fields = [ct.length, d.toString("hex"), createHash("sha256").update(ct).digest("hex"),
    ct.subarray(33, 65).toString("hex")];
  const want = [Number(len), digest, sha, first];
  for (let i = 0; i < 4; i++) {
    if (fields[i] !== want[i]) throw new Error(`suite ${v}, ${n} bytes: field ${i} differs`);
  }
  if (!decrypt(key, d, Number(n), ct).equals(plain)) throw new Error("round trip");
  const bad = Buffer.from(ct);
  bad[bad.length - 20] ^= 1;
  let refused = false;
  try { decrypt(key, d, Number(n), bad); } catch { refused = true; }
  if (!refused) throw new Error("tampering accepted");
  checked++;
}
console.log(`${checked} vectors match the independent implementation`);
