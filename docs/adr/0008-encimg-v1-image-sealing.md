# ADR 0008 — `encimg:v1` image sealing for note photos and ink crops

- **Status:** Accepted (crypto-reviewer + architecture-decision-reviewer + naming-reviewer +
  founder sign-off, 2026-10-25 — SUR-1259 gate, braird-core#110). `GATING.md` §3.2 routes
  `docs/adr/**` to `architecture-decision-reviewer` only; `crypto-reviewer` (§4 item 6) and
  `naming-reviewer` (this record freezes protocol words) were dispatched by hand.
- **Date:** 2026-10-25
- **Supersedes:** none. Departs from `crypto-reviewer` rule 1 (counter nonces — reasoned below)
  and from ADR 0002's throughput premise (see Consequences).
- **Context tickets:** SUR-1259 (this), epic SUR-1258, found by SUR-1211. Consumed by SUR-1260
  (surfc `image-upload` sniffs the magic), SUR-1261 (Android), SUR-1262 (iOS), SUR-1263 (backfill),
  SUR-1270 (PWA placeholder). Pressure-tested on the SUR-1259 / SUR-1260 decomposition (Linear,
  2026-10-25: founder decisions D1–D4 on SUR-1258) and on two review rounds of this record
  (founder decisions E1–E7, same day, also on SUR-1258). Builds on ADR 0005 and ADR 0006
  (plaintext never rests; domain separation) and the SUR-1112 key-separation precedent
  (`braird-book-url-v1`).

## Context

Terms: an **image** is a note photo (`notes.image_path`) or a margin ink crop
(`notes.ink_crop_path`); "photo" and "ink crop" name the two kinds.

Note photos and margin ink crops are uploaded as plaintext JPEG to the private `note-images`
bucket, protected only by RLS. The privacy policy says they are end-to-end encrypted. Decision
2026-10-21: make that true. The server does not need the bytes: transcription already receives
the photo inline from the device (verified 2026-10-25 against surfc `2d59412` — no Edge Function
reads the bucket), and idea discovery is text-only.

Constraints:

- No image record exists. A photo is a plaintext storage path in `notes.image_path` /
  `notes.ink_crop_path`, written by `image-upload` as `<uid>/<id>.jpg` since its first release;
  iOS margins requires exactly that shape. Dedup reconcile gives a surviving note the loser's
  `image_path` (`src/sync/reconcile.rs`), so a path's id is not always its note's id.
- During the transition the server must tell a sealed object from a plaintext one, without a key.
- Key material never crosses the FFI.
- Uploads are base64 JSON, so the whole photo is in memory on both sides today.

## The posture change this ADR names

**Core seals bulk binary for the first time, in a self-describing object.** Until now every
sealed value was a short string or a small byte vector under the Master Key or a subkey. An image
gets its own random 256-bit data key (DEK), which encrypts the image in 256 KiB chunks. The DEK
is wrapped under a new HKDF subkey of the MK and travels **inside the object header**, not in a
database column (D1). The server stores an object it can identify by its magic but cannot open.

**Counter nonces, on purpose.** Every production AES-GCM call in core uses a random 12-byte IV.
Here a chunk nonce is `prefix ‖ counter ‖ last-flag` — the STREAM construction (Hoang,
Reyhanitabar, Rogaway, Vizár, CRYPTO 2015), as implemented by `aead::stream::StreamBE32`
(aead 0.5.2, `src/stream.rs`: 7-byte prefix, big-endian `u32` position from 0, one flag byte).
It is safe because **a DEK seals exactly one plaintext, once**: the counter guarantees nonce
uniqueness under that key. The random 7-byte prefix is defence in depth (it guards a future
writer that reuses a DEK by mistake, and it denies a multi-target search a shared nonce).
`crypto-reviewer` rule 1 ("no counter-derived values") targets nonce reuse across messages under
one key; this ADR is the reasoned exception for a single-use key. `crypto-reviewer` reads no repo
profile, so a gce PR amends rule 1 itself with a scoped exception (a single-use key in a STREAM
construction that an ADR records, citing this one), and the code PR's `crypto-reviewer` dispatch
attaches this ADR.

**Every header byte is authenticated.** The `enc:v1`, `enc:v2` and `0x02` headers are not
(ADR 0006). Here the magic and both ids are in both AADs; `wrap_iv` and `wrapped_dek` are under
the wrap tag (a changed byte fails the unwrap, and a wrap of a different DEK fails every chunk —
only a holder of `K_wrap` can make a wrap at all, and a re-wrap of the same DEK opens, by
design); and `nonce_prefix` is part of every chunk nonce (a changed byte fails every chunk).

**Opened images are display content, and they never rest on the device (E3).** As for note text
(ADR 0005) and embedding input (ADR 0006), the host must not write the bytes `open_image`
returns to disk, logs, analytics or any network call. The one exception is the transcription
request to `anthropic-proxy` (disclosed in the policy, SUR-1258). Hosts cache the **sealed**
bytes and open them into memory for each view. Plaintext that exists before a seal (a capture
draft, a share in staging) and legacy plaintext downloads are covered by host rules 3 and 5.

## Wire format (frozen)

After acceptance this section is not edited: a change to the bytes is a new ADR with a new magic,
and a change to the path rule is a new ADR.

```
offset  size  field
0       9     magic         "encimg:v1" (65 6e 63 69 6d 67 3a 76 31) — also the version
9       12    wrap_iv       random
21      48    wrapped_dek   AES-256-GCM(K_wrap, wrap_iv, DEK, aad)  (32 B ct ‖ 16 B tag)
69      7     nonce_prefix  random
76      …     chunk_0 ‖ … ‖ chunk_last
```

- `aad = magic ‖ u16be(len user_id) ‖ user_id ‖ u16be(len image_id) ‖ image_id` — one value,
  used for the wrap and for every chunk.
- **The ids bind the object to its storage key** `<user_id>/<image_id>.jpg` (E1). `user_id` is
  the session's Supabase auth user id, exactly as the path holds it and matching
  `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`. `image_id` is the path's
  file stem, matching `^[A-Za-z0-9-]{1,64}$`. Both are the exact bytes, with no case folding or
  normalization. Core requires the stored path to be exactly `user_id ‖ "/" ‖ image_id ‖ ".jpg"`
  — the whole string, ASCII only, with no prefix (no bucket name) and no trailing newline — and
  takes `image_id` from it, not from a note row. The `.jpg` suffix belongs to this path rule, not
  to the bytes: a sealed object at another suffix needs a new ADR, not a new magic. surfc
  `image-upload` validates the same `image_id` pattern (SUR-1260) and must never widen it, or it
  would accept uploads that core cannot seal.
- `K_wrap = HKDF-SHA256(ikm = MK, salt = absent, info = "braird-image-key-wrap-v1", L = 32)`. An
  absent salt is 32 zero bytes (RFC 5869 §2.2; Node's `hkdfSync` needs them explicitly). Same
  derivation as `braird-book-url-v1` (`hkdf32_unsalted`). The subkey belongs to this format
  only: a future media format gets its own subkey, not this one.
- `DEK` = 32 bytes from the OS RNG, made inside core for every seal; never a caller input.
- `chunk_i = AES-256-GCM(DEK, nonce_i, pt_i, aad)` with
  `nonce_i = nonce_prefix ‖ u32be(i) ‖ (0x01 if last else 0x00)`, `i` from 0.
- `CHUNK = 262 144` plaintext bytes (frozen, not in the header). The writer emits
  `max(1, ceil(n / CHUNK))` chunks; all but the last are exactly `CHUNK`; the last is
  `0..=CHUNK` bytes and flagged. Empty plaintext = one empty final chunk.
- Sealed length = `76 + n + 16 × max(1, ceil(n / CHUNK))`; minimum 92 bytes. At most
  2³² − 1 chunks: the writer checks this itself (aead's `encrypt_last` would allow one more),
  and the opener rejects a body that needs more.
- No later magic is a prefix of, or starts with, an existing magic (`encimg:v2` … `encimg:v9`
  keep 9 bytes; a tenth version starts a new magic family). Readers and the server sniff the
  7-byte family prefix `encimg:`, so a build that knows only v1 treats a later version as a sealed
  object it cannot open, never as plaintext.

**Open, fail closed, canonical.** Reject if the length is under 92 or the magic is not
`encimg:v1`. Unwrap the DEK. Split the body into `CHUNK + 16`-byte pieces; the final piece is the
last chunk. Reject a remainder of 1..15 bytes, and reject a 16-byte (empty) final piece when a
full piece comes before it — so the opener accepts exactly the writer's layouts. Decrypt each
piece with its counter and flag. Every failure — a malformed id or path included — returns
`CryptoError::DecryptFailed` and no partial plaintext. This is deliberately not `open_bytes`'s
`BadInput` for structural rejects: one error for every open failure.

This catches: a flipped byte anywhere (GCM tags); a reordered or duplicated chunk (counter); a
truncation at a chunk boundary (the new final chunk was sealed with flag 0); appended bytes (the
final piece moves, so a tag or the flag fails); an object presented under another storage key
(the ids in the AAD); and a wrapped DEK presented as another format (separate subkey). A move to
another user already fails at the unwrap, because each user has their own MK; `user_id` in the
AAD is defence in depth for the case where one MK ever serves two accounts.

## API

`Vault::seal_image(user_id: String, path: String, plaintext: Vec<u8>) -> Result<Vec<u8>, CryptoError>`
and `Vault::open_image(user_id: String, path: String, sealed: Vec<u8>) -> Result<Vec<u8>, CryptoError>`,
exported over UniFFI for **native targets only** (`hkdf32_unsalted` is native-only, and the PWA
does not open photos, D4). `user_id` is the session uid as the auth library returns it (the JWT
`sub`), never a UUID formatted again; core cannot check that it is the session's uid, and the
doc comment says so (the per-user MK still stops a cross-user object). `path` is the storage
path: for a seal, the path the
upload will create (`<user_id>/<image_id>.jpg`, the shape `image-upload` returns); for an open,
the stored `notes.image_path` / `ink_crop_path`. Core checks that `path` is exactly
`<user_id>/<image_id>.jpg` with both ids valid, and takes `image_id` from it (E6) — one parser
for every host, and a swapped argument fails the check. Seal refuses a bad id or path with
`CryptoError::BadInput` (a seal has no secret-dependent output); open fails with `DecryptFailed`.
Three arguments each, well under the arm64 slot limit (`scripts/check-ffi-arg-slots.mjs`). The
exported doc comments name the `encimg:v1` format and the path rule, because UniFFI copies them
into Kotlin and Swift. The DEK and `K_wrap` live in `Zeroizing` buffers inside core and never
cross the FFI. There is no fixed-input seam: the frozen vectors reproduce through
`src/image_encryption.rs`'s own tests against the module's pure seal, so no fixed-key path exists
behind `test-seams` either (implementation note, SUR-1259 code PR).

Calls are one-shot (D3). A later streaming API is additive over the same format, with two
constraints it must keep: a streaming seal makes its DEK internally and never restarts, and a
streaming open releases verified chunks before the end — so a truncated object could show part
of a photo before the error. That second point changes fail-closed behaviour and needs its own
decision.

## Host rules

1. **Ids from the path, in core.** Hosts pass the session uid and the stored path; core does the
   check and the parse (API). The rule applies to sealed objects; a legacy plaintext object is
   shown under host rule 3 and needs no id.
2. **One stem, one object kind.** No two kinds of object share a stem; a derivative (for example
   a future thumbnail) gets its own `image_id`. A new object at the same storage key is a new
   version of that object (see the rollback residual).
3. **Dispatch.** Bytes that start with the family prefix `encimg:` go to `open_image`, and any
   error is shown as an error — never the raw bytes. Bytes without it are legacy plaintext, shown
   (and cacheable, E7) only until that user's backfill completes on the device; from then on, a
   photo or ink-crop path without the prefix is an error, and the legacy plaintext cache is
   deleted. The switch is device-local and only moves one way: this device sets it after its own
   backfill pass finds no plaintext image for that user, and no synced or server data can clear
   it. SUR-1263 owns this switch, and also decides what happens to a legacy object the backfill
   cannot seal (one outside the path rule) before the switch — the code has always written the
   valid shape, so the legacy data check below expects none. Link covers (`books.cover_url`) stay
   plaintext (D2) and keep their own loader.
4. **Opened bytes never rest** (E3). They are decoded in memory only — never through an image
   library's disk cache — and never written to disk, logs, analytics or a network call other
   than the transcription request.
5. **Plaintext before the seal** (E7). A capture draft and a share in staging (the iOS share
   extension has no unlocked vault) stay plaintext on the device until the sealed copy is queued
   or uploaded — after transcription, which needs the plaintext. The host deletes them then,
   when the user discards the draft, and at sign-out.
6. **Check before delete.** Before it deletes a plaintext draft, the host compares the `path`
   that `image-upload` returns with the path it sealed under, and opens the sealed bytes it sent
   with `open_image(user_id, returned path, …)` in memory. If either check fails, the upload
   counts as failed: the draft stays and the host reports the error. A seal under the wrong path
   would otherwise leave an object nobody can open after its only plaintext is gone.

## Options considered

| Decision | Chosen | Rejected alternative | Why rejected |
|---|---|---|---|
| **1. Where the wrapped key lives** | Object header | Columns on `notes` (migration + synced schema) · a `note_images` table | The key and the bytes cannot disagree; no migration, no sync-schema change, no last-write-wins race between path and key (D1). Cost: the backfill overwrites the plaintext original in place, so a seal bug would lose the photo; the guard is SUR-1263's step "open the sealed bytes and compare them with the original before upload". |
| **2. Key per object** | Random DEK wrapped under `K_wrap` | Per-object key derived by HKDF from a random header salt (Tink style) | Equal security. A random DEK can be re-wrapped in place (new `wrap_iv` + `wrapped_dek`, chunks untouched — row 7 keeps that possible), for example after an MK change; a derived key is tied to the MK forever. A change of the subkey or of the format re-seals the image. Sharing a photo would need more than a re-wrap: a second wrap outside the object, a change to host rule 1 (the AAD holds the owner's uid), and key commitment (see residuals). |
| **3. Wrap key** | HKDF subkey `braird-image-key-wrap-v1`, this format only | Wrap directly under the MK, kept apart only by the AAD encoding | Under the MK, a wrap sent to the exported `open_bytes` as `0x02 ‖ wrap_iv ‖ wrapped_dek` with the `encimg` AAD (valid UTF-8: ASCII ids, short lengths) would hand the raw DEK across the FFI. An AAD encoding is not domain separation when a hostile server picks the inputs (SUR-1112). A separate key removes the dependence on encodings. |
| **4. Construction** | 256 KiB STREAM chunks with a final flag | One GCM message per photo · the existing `0x02` `seal_bytes` under a subkey | Both are simpler, and the `0x02` seal has a WebCrypto twin in surfc, so the PWA could have opened photos. But neither streams: a later streaming need (a binary upload body, larger photos) would cost a new magic and a second reader in every client. The PWA does not open photos anyway (D4, sunset). |
| **5. FFI shape** | One-shot `seal_image` / `open_image` | Streaming objects now | Uploads are base64 JSON, so streaming saves no memory today; objects add misuse states (push after finish) with no caller (D3). |
| **6. Version marker** | ASCII magic `encimg:v1` at offset 0 | A version byte · a database column | The server must sniff the format without a key (SUR-1260). A one-byte marker can collide with core's own `0x02` header and matches random bytes 1 time in 256; nine ASCII bytes are distinct from `0x02`, `enc:v1:` / `enc:v2:`, JPEG (`FF D8`), PNG, HEIC and WebP, and read in a hex dump. The magic is image-only (photos and ink crops); other media get their own magic and subkey. |
| **7. What the chunk AAD covers** | `magic ‖ ids` (same as the wrap) | The whole header + ids | The header is already authenticated (see the posture section). Putting `wrap_iv` / `wrapped_dek` in the chunk AAD would block an in-place re-wrap and tempt a re-wrap that recomputes chunk tags under the same DEK and nonces — GCM nonce reuse (E2). |
| **8. What the ids bind** | Session uid + path stem | + an object kind · the note row id | Reconcile moves paths between notes, so the row id cannot open an adopted photo without a re-seal in core (a new network path). A kind field would stop only a photo-to-crop swap, and the repointing residual below accepts that swap (E1). |
| **9. Object path** | Same `<uid>/<id>.jpg` | A distinct suffix such as `.enc` | A suffix needs one `notes.image_path` write per photo during the backfill, and a last-write-wins edit on another device can revert that write to the deleted plaintext path. iOS margins also requires `.jpg`. |
| **10. Device cache** | Sealed bytes only for sealed objects, opened per view (legacy plaintext until that user's backfill, E7) | Plaintext cache, wiped on lock | Matches ADR 0005; no wipe-on-lock logic to get right. Cost: one AES-GCM pass per view (E3). |
| **11. API ids** | `(user_id, path, plaintext)`, core parses the path | `(user_id, image_id, plaintext)` | Two adjacent string ids can be swapped silently (a lowercase UUID passes both checks), and each host would parse the path its own way (E6). |
| **12. Padding** | None | Pad to size buckets | Photo size is low-value metadata next to existence and timing. v1 has no internal length field, so in-format padding needs a new magic; a host can still pad the JPEG itself. |

## Reversibility

- **The wire format is a one-way door** once one sealed photo exists. A change is a new magic
  that readers dispatch on; retiring v1 also needs a re-seal sweep — and only a client can sweep,
  per user, with an unlocked vault. Accounts nobody opens again never sweep, so v1 readers may be
  needed for as long as those accounts exist.
- **The FFI is cheap to extend:** a streaming object is additive (with the constraints in the API
  section).
- **The layout is frozen by reference in `GATING.md`** (the frozen-constants paragraph names
  `braird-image-key-wrap-v1` and this record's §Wire format) and in `AGENTS.md` / `CLAUDE.md`
  "Crypto rules", in this PR.

## Accepted residuals

- **Length:** the object size gives the exact photo size. No padding (row 12).
- **Existence and timing:** the server sees that a note has a photo, its path and upload time.
- **Repointing (E1):** a hostile server can point a note's `image_path` or `ink_crop_path` at any
  other sealed object of the same user (a photo or an ink crop). It cannot read or forge one.
- **Rollback:** a hostile server can serve an older sealed object for the same storage key, or
  delete it. The same holds for `enc:v2` notes.
- **Downgrade during the transition:** while a host accepts legacy plaintext for a user (host
  rule 3), a hostile server can put any plaintext JPEG at that user's photo path — an older copy,
  a cover, another user's photo — and the host shows it; an old build can also upload a cached
  plaintext copy over a sealed object (`upsert`). For a user, this ends when that user's backfill
  completes on the device; for the server, when SUR-1263 makes `image-upload` refuse plaintext.
- **Old builds (E4):** an old app build cannot open a photo that a newer build sealed and shows a
  broken image until it updates. As of 2026-10-25 only internal- and closed-test Android builds
  and TestFlight builds exist, and their testers hold real photos.
- **Plaintext on the device before the seal (E7):** capture drafts and share staging, until
  upload (host rule 5); legacy plaintext downloads, until that user's backfill (host rule 3).
- **Copies from before the backfill:** photos uploaded before SUR-1263 were plaintext on the
  server; the in-place overwrite fixes only the live object, not provider backups or earlier
  downloads.
- **Transcription exception:** the device decrypts the photo and sends it over TLS to
  `anthropic-proxy`, which holds it in memory only (SUR-1258). Anthropic's retention applies: the
  public commercial terms (privacy.claude.com, dated 2026-07-01) delete API inputs and outputs
  within 30 days and keep flagged content longer. The account's own data-retention setting is not
  yet confirmed (founder check, SUR-1260); the surfc policy says there is no zero-retention
  arrangement.
- **Link covers stay plaintext** in the same bucket (2026-10-08, kept as D2).
- **The PWA does not open sealed photos** (D4, sunset): it shows a placeholder (SUR-1270) and can
  upload plaintext until SUR-1263 removes that path.
- **The whole photo is in memory** during a seal or an open (D3), as today.
- **Not key-committing:** AES-GCM does not commit to its key. With one owner per object this has
  no effect; it is a precondition to solve before photos are ever shared (row 2).
- **Wrap IVs are random** under one long-lived `K_wrap` per user; keep below 2³² wraps per user
  (NIST SP 800-38D). Real counts are far below it.

## Consequences

- `Vault` gains two native-only exports; core enables `aes-gcm`'s `stream` feature (no new crate)
  and adds `src/image_encryption.rs`.
- **Key schedules:** `Aes256Gcm` keeps the expanded key and the GHASH key, and the `zeroize`
  features of `aes` / `aes-gcm` are off today, for every format. The code PR turns those features
  on unless a reviewer finds a cost.
- **ADR 0002's premise changes:** it accepted software AES-GCM because "throughput is not the
  constraint" for sealing note text. The code PR measures a seal and an open of a 4 MB photo on
  an arm64 device and records the result (record only; no threshold is set here).
- **The gate (`GATING.md` §5 applies).** The `src/**` row's primary gate (surfc parity vectors)
  and its fallback (a round-trip against a surfc-written ciphertext) cannot run: surfc never
  writes `encimg:v1` (D4). The code PR builds the replacement gate, and a §5.3 gate-debt ticket
  opens only if it lands without it:
  - frozen vectors in `vendored/encimg/v1-vectors.json` (core-owned, like `vendored/source-url/`;
    the directory joins the `src/**` row): positive cases n ∈ {0, 1, CHUNK−1, CHUNK, CHUNK+1,
    2×CHUNK}, large plaintexts from a deterministic generator with SHA-256-pinned sealed bytes,
    and a re-wrap case (same DEK, prefix and chunks under a second `wrap_iv` / `wrapped_dek`) that
    must open; negative cases — a flipped byte in each header field and each chunk, two chunks
    swapped, a duplicated chunk, the final chunk removed, a cut at a chunk boundary, 16 bytes
    appended, a 1..15-byte remainder, the non-canonical empty final chunk, a header from another
    object sealed under the same ids, a wrong `user_id`, a wrong path, a wrong MK, 91 bytes, a
    malformed id or path at seal (`BadInput`) and at open (`DecryptFailed`), with these path
    cases named: a newline after the stem or after `.jpg`, `.JPG`, a leading `/`, `//`, `..`, an
    empty stem (`<uid>/.jpg`), a 65-byte stem, a non-ASCII letter in the stem, an uppercase uid,
    a `note-images/` prefix, a path whose uid is not `user_id`, and swapped arguments;
  - a `K_wrap` known-answer test, like `the_url_subkey_is_frozen`;
  - an independent Node `node:crypto` oracle, `tests/encimg_oracle.mjs` (so the `src/**` row
    routes it to `crypto-reviewer`), that builds the nonces and the AAD from this record's text —
    not from `aead::stream` — opens every vector, checks the canonical length, and runs in
    `cargo test --all-features` on `parity.yml`'s pinned Node; it fails instead of skipping when
    Node is absent in CI;
  - Kotlin and Swift round-trip tests that open one vector and reject one tamper each — binding
    checks, not format evidence (the Swift leg needs the `touches-ffi` label). No test seam is
    added (see API), so the test-seams rules in `GATING.md` and AGENTS / CLAUDE are unchanged.
- **Legacy data check:** before SUR-1261 ships, the founder counts prod `note-images` object names
  that do not match `<uuid>/<image_id>.jpg`. Such an object can be shown as legacy plaintext but
  can never be sealed; if the count is not zero, SUR-1263 decides its fate before any user's
  sealed-only switch (host rule 3).
- **Other repos:** surfc `image-upload` sniffs the magic, stores sealed objects as
  `application/octet-stream`, and `anthropic-proxy` answers sealed bytes with 400
  `sealed_image` (SUR-1260); the SUR-1263 progress count reads that label, which a direct Storage
  write can set, so the final check reads the first nine bytes. Android and iOS follow the host
  rules (SUR-1261 / SUR-1262). surfc-intranet documents the format in `architecture/e2ee.md` §4
  and corrects §11 in lockstep, with a word other than "per-blob" (§2 already uses it for wrapped
  Master Key blobs). The PWA shows a placeholder (SUR-1270). A gce PR amends `crypto-reviewer`
  rule 1 (see the posture section).
- Planned for v0.20.0 (MINOR: new exports).
