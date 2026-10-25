// Independent `encimg:v1` opener (SUR-1259, ADR 0008) — node:crypto only, built from the ADR's
// §Wire format text, NOT from aead::stream or the Rust code. `src/image_encryption.rs` spawns it:
//
//   node tests/encimg_oracle.mjs <v1-vectors.json> <dir with <case>.bin for the large cases>
//
// For every case it derives K_wrap, parses the path, unwraps the data key, opens the chunks with
// `prefix ‖ u32be(i) ‖ last-flag` nonces, checks the canonical length and the plaintext rule, and
// checks that a copy with its last byte flipped does NOT open. Prints one JSON report on stdout.
import { createDecipheriv, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const [vectorsPath, largeDir] = process.argv.slice(2);
const v = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const CHUNK = 262144;
const TAG = 16;
const HEADER = 76;
const MAGIC = Buffer.from('encimg:v1', 'ascii');
const PATH_RULE =
  /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/([A-Za-z0-9-]{1,64})\.jpg$/;

const kWrap = Buffer.from(
  hkdfSync('sha256', Buffer.from(v.mk, 'hex'), Buffer.alloc(32), Buffer.from('braird-image-key-wrap-v1'), 32),
);

function aad(uid, imageId) {
  const u = Buffer.from(uid, 'utf8');
  const i = Buffer.from(imageId, 'utf8');
  return Buffer.concat([MAGIC, Buffer.from([u.length >> 8, u.length & 0xff]), u, Buffer.from([i.length >> 8, i.length & 0xff]), i]);
}

function gcmOpen(key, iv, data, a) {
  if (data.length < TAG) throw new Error('short');
  const d = createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(a);
  d.setAuthTag(data.subarray(data.length - TAG));
  return Buffer.concat([d.update(data.subarray(0, data.length - TAG)), d.final()]);
}

function open(uid, path, sealed) {
  const m = path.match(PATH_RULE);
  if (!m || m[1] !== uid) throw new Error('path rule');
  if (sealed.length < HEADER + TAG || !sealed.subarray(0, 9).equals(MAGIC)) throw new Error('header');
  const a = aad(m[1], m[2]);
  const dek = gcmOpen(kWrap, sealed.subarray(9, 21), sealed.subarray(21, 69), a);
  const prefix = sealed.subarray(69, 76);
  const body = sealed.subarray(HEADER);
  const piece = CHUNK + TAG;
  const rem = body.length % piece;
  const beforeLast = rem === 0 ? body.length / piece - 1 : Math.floor(body.length / piece);
  const lastLen = rem === 0 ? piece : rem;
  if (lastLen < TAG || (lastLen === TAG && beforeLast > 0)) throw new Error('layout');
  const out = [];
  for (let i = 0; i <= beforeLast; i++) {
    const last = i === beforeLast;
    const nonce = Buffer.concat([prefix, Buffer.from([i >>> 24, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff, last ? 1 : 0])]);
    const ct = last ? body.subarray(i * piece) : body.subarray(i * piece, (i + 1) * piece);
    out.push(gcmOpen(dek, nonce, ct, a));
  }
  return Buffer.concat(out);
}

const expected = (n) => Buffer.from(Array.from({ length: n }, (_, i) => i % 251));
const report = { k_wrap_ok: kWrap.toString('hex') === v.k_wrap, results: [] };
for (const c of v.cases) {
  const r = { name: c.name, ok: false };
  try {
    const sealed = c.sealed ? Buffer.from(c.sealed, 'hex') : readFileSync(join(largeDir, `${c.name}.bin`));
    const pt = open(v.user_id, c.path, sealed);
    const canonical = sealed.length === HEADER + c.len + TAG * Math.max(1, Math.ceil(c.len / CHUNK));
    const tampered = Buffer.from(sealed);
    tampered[tampered.length - 1] ^= 0x01;
    let tamperRejected = false;
    try {
      open(v.user_id, c.path, tampered);
    } catch {
      tamperRejected = true;
    }
    r.ok = pt.equals(expected(c.len)) && canonical && tamperRejected;
    if (!r.ok) r.error = { plaintext: pt.equals(expected(c.len)), canonical, tamperRejected };
  } catch (e) {
    r.error = String(e.message);
  }
  report.results.push(r);
}
console.log(JSON.stringify(report));
