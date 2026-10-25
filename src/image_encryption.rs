//! `encimg:v1` image seal (SUR-1259, ADR 0008) — note photos and margin ink crops.
//!
//! `magic ‖ wrap_iv ‖ wrapped_dek ‖ nonce_prefix ‖ chunks`: a fresh 256-bit data key (DEK) per
//! image, wrapped with AES-256-GCM under an HKDF subkey of the MK; the image in 256 KiB AES-256-GCM
//! chunks with STREAM nonces (`aead::stream::StreamBE32`: prefix ‖ u32be counter ‖ last-chunk
//! flag). Counter nonces are safe because a DEK seals exactly one image, once. One AAD — the magic
//! and the length-prefixed session uid + path stem — binds the wrap and every chunk. ADR 0008
//! §Wire format is the frozen authority for every constant here.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::aead::{AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key};
use zeroize::Zeroizing;

use crate::primitives::{aes_decrypt, aes_encrypt};
use crate::CryptoError;

/// HKDF info for the image key-wrap subkey. Frozen: changing it orphans every sealed image.
pub(crate) const KEY_WRAP_INFO: &[u8] = b"braird-image-key-wrap-v1";

const MAGIC: &[u8; 9] = b"encimg:v1";
const CHUNK: usize = 262_144;
const TAG_LEN: usize = 16;
const WRAP_IV_AT: usize = MAGIC.len(); // 9
const WRAPPED_DEK_AT: usize = WRAP_IV_AT + 12; // 21
const NONCE_PREFIX_AT: usize = WRAPPED_DEK_AT + 32 + TAG_LEN; // 69
const HEADER_LEN: usize = NONCE_PREFIX_AT + 7; // 76
const MIN_SEALED_LEN: usize = HEADER_LEN + TAG_LEN; // 92: one empty final chunk
const MAX_CHUNKS: u64 = u32::MAX as u64; // 2^32 − 1; aead's `encrypt_last` would allow one more

/// `image_id` from a storage path that is exactly `<user_id>/<image_id>.jpg` — the whole string,
/// ASCII only, no prefix, no trailing newline — or `None`. One parser for every host (E6).
pub(crate) fn image_id_for_path<'p>(user_id: &str, path: &'p str) -> Option<&'p str> {
    if !is_user_id(user_id) {
        return None;
    }
    let image_id = path
        .strip_prefix(user_id)?
        .strip_prefix('/')?
        .strip_suffix(".jpg")?;
    is_image_id(image_id).then_some(image_id)
}

/// `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, exact bytes.
pub(crate) fn is_user_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// `^[A-Za-z0-9-]{1,64}$` — the rule surfc `image-upload` enforces on `noteId` (SUR-1260).
fn is_image_id(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

/// `magic ‖ u16be(len) ‖ user_id ‖ u16be(len) ‖ image_id` — the one AAD for the wrap and chunks.
/// Both ids are validated (≤ 64 bytes), so the `u16` lengths cannot truncate.
fn aad(user_id: &str, image_id: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(MAGIC.len() + 4 + user_id.len() + image_id.len());
    a.extend_from_slice(MAGIC);
    for id in [user_id, image_id] {
        a.extend_from_slice(&(id.len() as u16).to_be_bytes());
        a.extend_from_slice(id.as_bytes());
    }
    a
}

/// Whether `n` plaintext bytes fit in at most 2^32 − 1 chunks.
fn fits_chunk_cap(n: usize) -> bool {
    n as u64 <= MAX_CHUNKS * CHUNK as u64
}

fn dek_cipher(dek: &[u8]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek))
}

/// Seal `pt` under a fresh data key, wrap IV and nonce prefix drawn here from the OS CSPRNG on
/// every call. This is the only way the crate seals, so a data key can never be reused or passed
/// in (rule 1's STREAM exception, condition (b)). The ids must already be validated (see
/// [`image_id_for_path`]).
pub(crate) fn seal(
    k_wrap: &[u8],
    user_id: &str,
    image_id: &str,
    pt: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // The `GenericArray` moved into `Zeroizing` may leave an unwiped stack copy (accepted; a zeroed
    // buffer filled in place would be a CodeQL hard-coded-key alert).
    let dek = Zeroizing::new(<[u8; 32]>::from(Aes256Gcm::generate_key(&mut OsRng)));
    let wrap_iv: [u8; 12] = Aes256Gcm::generate_nonce(&mut OsRng).into();
    let nonce_prefix: [u8; 7] = Aes256Gcm::generate_nonce(&mut OsRng)[..7]
        .try_into()
        .expect("7 of 12 nonce bytes");
    seal_with(k_wrap, &dek, &wrap_iv, &nonce_prefix, user_id, image_id, pt)
}

/// [`seal`] with the key material given — private, so only this module's tests pass fixed values.
fn seal_with(
    k_wrap: &[u8],
    dek: &[u8; 32],
    wrap_iv: &[u8; 12],
    nonce_prefix: &[u8; 7],
    user_id: &str,
    image_id: &str,
    pt: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if !fits_chunk_cap(pt.len()) {
        return Err(CryptoError::BadInput("image too large".into()));
    }
    let aad = aad(user_id, image_id);
    let mut out =
        Vec::with_capacity(HEADER_LEN + TAG_LEN + pt.len() + TAG_LEN * (pt.len() / CHUNK));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(wrap_iv);
    out.extend_from_slice(&aes_encrypt(k_wrap, wrap_iv, dek, Some(&aad)));
    out.extend_from_slice(nonce_prefix);

    let mut enc = EncryptorBE32::from_aead(dek_cipher(dek), GenericArray::from_slice(nonce_prefix));
    // Full chunks while more than one chunk's worth remains; the rest (0..=CHUNK bytes, possibly
    // empty) is the flagged final chunk — one layout per plaintext.
    let mut rest = pt;
    while rest.len() > CHUNK {
        let (piece, tail) = rest.split_at(CHUNK);
        let ct = enc
            .encrypt_next(Payload {
                msg: piece,
                aad: &aad,
            })
            .expect("stream encrypt (counter capped above)");
        out.extend_from_slice(&ct);
        rest = tail;
    }
    let ct = enc
        .encrypt_last(Payload {
            msg: rest,
            aad: &aad,
        })
        .expect("stream encrypt last");
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open [`seal`]'s output under the same ids. Fails closed with `DecryptFailed` — one error for
/// every failure, deliberately not `open_bytes`'s `BadInput` for structural rejects — and accepts
/// exactly the writer's layouts: a 1..15-byte remainder, an empty final chunk after a full one, or
/// more than 2^32 − 1 chunks never open. No partial plaintext is returned or left un-wiped.
pub(crate) fn open(
    k_wrap: &[u8],
    user_id: &str,
    image_id: &str,
    sealed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < MIN_SEALED_LEN || &sealed[..MAGIC.len()] != MAGIC {
        return Err(CryptoError::DecryptFailed);
    }
    let aad = aad(user_id, image_id);
    let dek = Zeroizing::new(
        aes_decrypt(
            k_wrap,
            &sealed[WRAP_IV_AT..WRAPPED_DEK_AT],
            &sealed[WRAPPED_DEK_AT..NONCE_PREFIX_AT],
            Some(&aad),
        )
        .map_err(|_| CryptoError::DecryptFailed)?,
    );

    let body = &sealed[HEADER_LEN..];
    let piece = CHUNK + TAG_LEN;
    let (before_last, last_len) = match body.len() % piece {
        0 => (body.len() / piece - 1, piece),
        rem => (body.len() / piece, rem),
    };
    let noncanonical = last_len < TAG_LEN || (last_len == TAG_LEN && before_last > 0);
    if noncanonical || before_last as u64 >= MAX_CHUNKS {
        return Err(CryptoError::DecryptFailed);
    }

    let mut dec = DecryptorBE32::from_aead(
        dek_cipher(&dek),
        GenericArray::from_slice(&sealed[NONCE_PREFIX_AT..HEADER_LEN]),
    );
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() - TAG_LEN * (before_last + 1)));
    let last_at = before_last * piece;
    for ct in body[..last_at].chunks(piece) {
        let pt = Zeroizing::new(
            dec.decrypt_next(Payload { msg: ct, aad: &aad })
                .map_err(|_| CryptoError::DecryptFailed)?,
        );
        out.extend_from_slice(&pt);
    }
    let pt = Zeroizing::new(
        dec.decrypt_last(Payload {
            msg: &body[last_at..],
            aad: &aad,
        })
        .map_err(|_| CryptoError::DecryptFailed)?,
    );
    out.extend_from_slice(&pt);
    Ok(std::mem::take(&mut *out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::hkdf32_unsalted;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    // Fixed key material comes only from the vectors JSON, and anything else from the OS RNG —
    // never a literal in the code (CodeQL `rust/hard-coded-cryptographic-value`).
    const VECTORS: &str = include_str!("../vendored/encimg/v1-vectors.json");
    const UID: &str = "3f2b8c1e-9d4a-4e6f-8b7c-0a1d2e3f4a5b";

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("v1-vectors.json")
    }
    fn hex_of<const N: usize>(v: &Value, key: &str) -> [u8; N] {
        hex::decode(v[key].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
    fn random_dek() -> [u8; 32] {
        Aes256Gcm::generate_key(&mut OsRng).into()
    }
    /// The vectors' plaintext rule: byte i = i % 251.
    fn plaintext(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }
    /// `K_wrap` under the vectors' MK; `vault::image_seal` pins its value as a known answer.
    fn k_wrap() -> Zeroizing<[u8; 32]> {
        hkdf32_unsalted(&hex_of::<32>(&vectors(), "mk"), KEY_WRAP_INFO)
    }
    /// Seal `n` plaintext bytes under the vectors' fixed data key, nonce prefix and `wrap_iv`.
    fn seal_fixed_iv(path: &str, n: usize, wrap_iv: [u8; 12]) -> Vec<u8> {
        let v = vectors();
        let id = image_id_for_path(UID, path).expect("valid path");
        let pt = plaintext(n);
        let (dek, prefix) = (hex_of(&v, "dek"), hex_of(&v, "nonce_prefix"));
        seal_with(&*k_wrap(), &dek, &wrap_iv, &prefix, UID, id, &pt).unwrap()
    }
    fn seal_fixed(path: &str, n: usize) -> Vec<u8> {
        seal_fixed_iv(path, n, hex_of(&vectors(), "wrap_iv"))
    }
    fn open_at(path: &str, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let id = image_id_for_path(UID, path).unwrap();
        open(&*k_wrap(), UID, id, sealed)
    }
    fn case_seal(c: &Value) -> Vec<u8> {
        let n = c["len"].as_u64().unwrap() as usize;
        let path = c["path"].as_str().unwrap();
        match c.get("wrap_iv") {
            Some(_) => seal_fixed_iv(path, n, hex_of(c, "wrap_iv")),
            None => seal_fixed(path, n),
        }
    }
    /// The writer's sealed length: header + plaintext + one tag per chunk, at least one chunk.
    fn sealed_len(n: usize) -> usize {
        HEADER_LEN + n + TAG_LEN * n.div_ceil(CHUNK).max(1)
    }

    /// The independent node:crypto generator's bytes (or their SHA-256 for the large cases) are
    /// exactly what this seal produces under the same fixed inputs.
    #[test]
    fn the_frozen_vectors_reproduce() {
        let v = vectors();
        assert_eq!(v["user_id"], UID);
        assert_eq!(v["chunk"].as_u64(), Some(CHUNK as u64));
        for c in v["cases"].as_array().unwrap() {
            let sealed = case_seal(c);
            match c["sealed"].as_str() {
                Some(h) => assert_eq!(hex::encode(&sealed), h, "{}", c["name"]),
                None => {
                    assert_eq!(sealed.len() as u64, c["sealed_len"].as_u64().unwrap());
                    assert_eq!(
                        hex::encode(Sha256::digest(&sealed)),
                        c["sealed_sha256"].as_str().unwrap(),
                        "{}",
                        c["name"]
                    );
                }
            }
        }
    }

    #[test]
    fn every_vector_opens() {
        for c in vectors()["cases"].as_array().unwrap() {
            let sealed = match c["sealed"].as_str() {
                Some(h) => hex::decode(h).unwrap(),
                None => case_seal(c),
            };
            let n = c["len"].as_u64().unwrap() as usize;
            let opened = open_at(c["path"].as_str().unwrap(), &sealed).unwrap();
            assert_eq!(opened, plaintext(n), "{}", c["name"]);
        }
    }

    /// A re-wrap changes only `wrap_iv` + `wrapped_dek`; the chunks are untouched and it opens (E2).
    #[test]
    fn a_rewrap_leaves_the_chunks_untouched() {
        let v = vectors();
        let get = |name: &str| {
            let cases = v["cases"].as_array().unwrap();
            let c = cases.iter().find(|c| c["name"] == name).unwrap();
            hex::decode(c["sealed"].as_str().unwrap()).unwrap()
        };
        let (small, rewrap) = (get("small"), get("rewrap"));
        assert_eq!(small[..WRAP_IV_AT], rewrap[..WRAP_IV_AT]);
        let wrap = WRAP_IV_AT..NONCE_PREFIX_AT;
        assert_ne!(small[wrap.clone()], rewrap[wrap]);
        assert_eq!(small[NONCE_PREFIX_AT..], rewrap[NONCE_PREFIX_AT..]);
    }

    /// Every way to damage an object fails closed with `DecryptFailed`: never a panic, never
    /// partial plaintext. Base: three chunks (two full, one of 1 byte).
    #[test]
    fn every_tamper_fails_closed() {
        let path = format!("{UID}/note-tamper.jpg");
        let base = seal_fixed(&path, 2 * CHUNK + 1);
        let piece = CHUNK + TAG_LEN;
        let (c0, c1, c2) = (HEADER_LEN, HEADER_LEN + piece, HEADER_LEN + 2 * piece);
        assert_eq!(open_at(&path, &base).unwrap(), plaintext(2 * CHUNK + 1));
        assert_eq!(base.len(), sealed_len(2 * CHUNK + 1));

        let flip = |at: usize| {
            let mut b = base.clone();
            b[at] ^= 0x01;
            b
        };
        let mut damaged: Vec<(String, Vec<u8>)> = [0, 8, 9, 20, 21, 68, 69, 75]
            .into_iter()
            .map(|at| (format!("header byte {at}"), flip(at)))
            .collect();
        for (name, at) in [
            ("chunk 0 byte", c0),
            ("chunk 0 tag", c1 - 1),
            ("chunk 1 byte", c1 + CHUNK / 2),
            ("last chunk byte", c2),
            ("last tag byte", base.len() - 1),
        ] {
            damaged.push((name.into(), flip(at)));
        }
        let swapped = [&base[..c0], &base[c1..c2], &base[c0..c1], &base[c2..]].concat();
        let duplicated = [&base[..c2], &base[c0..c1], &base[c2..]].concat();
        damaged.push(("chunks 0 and 1 swapped".into(), swapped));
        damaged.push(("chunk 0 duplicated".into(), duplicated));
        damaged.push(("final chunk removed".into(), base[..c2].to_vec()));
        damaged.push(("cut at a chunk boundary".into(), base[..c1].to_vec()));
        damaged.push(("cut mid-chunk".into(), base[..c1 + 100].to_vec()));
        damaged.push((
            "16 bytes appended".into(),
            [&base[..], &[0u8; 16][..]].concat(),
        ));
        // A 1..15-byte remainder after a body that is an exact chunk multiple (n = CHUNK), so the
        // remainder check itself is what rejects it.
        let exact = seal_fixed(&path, CHUNK);
        for r in 1..TAG_LEN {
            let longer = [&exact[..], &vec![0u8; r][..]].concat();
            damaged.push((format!("{r}-byte remainder"), longer));
        }
        damaged.push(("91 bytes".into(), base[..MIN_SEALED_LEN - 1].to_vec()));
        damaged.push(("header only".into(), base[..HEADER_LEN].to_vec()));
        damaged.push(("magic only".into(), MAGIC.to_vec()));
        damaged.push(("empty".into(), Vec::new()));
        for (name, bytes) in damaged {
            assert!(
                matches!(open_at(&path, &bytes), Err(CryptoError::DecryptFailed)),
                "{name} must fail closed"
            );
        }
    }

    #[test]
    fn the_wrong_ids_or_key_fail() {
        let path = format!("{UID}/note-a.jpg");
        let sealed = seal_fixed(&path, 37);
        let other_uid = "00000000-0000-4000-8000-000000000000";
        let wrong = [
            open(&*k_wrap(), other_uid, "note-a", &sealed),
            open(&*k_wrap(), UID, "note-b", &sealed),
            open(&random_dek(), UID, "note-a", &sealed),
        ];
        for r in wrong {
            assert!(matches!(r, Err(CryptoError::DecryptFailed)));
        }
    }

    /// A header from another object sealed under the SAME ids reaches the chunk check and fails:
    /// its wrap opens to a different data key.
    #[test]
    fn a_header_from_another_object_under_the_same_ids_fails() {
        let path = format!("{UID}/note-a.jpg");
        let a = seal_fixed(&path, 100);
        let id = image_id_for_path(UID, &path).unwrap();
        let b = seal(&*k_wrap(), UID, id, &plaintext(100)).unwrap();
        assert!(open_at(&path, &b).is_ok());
        let spliced = [&a[..HEADER_LEN], &b[HEADER_LEN..]].concat();
        assert!(matches!(
            open_at(&path, &spliced),
            Err(CryptoError::DecryptFailed)
        ));
    }

    /// The opener accepts exactly the writer's layouts: `CHUNK` bytes sealed as one full flagged
    /// chunk opens; the same bytes as a full unflagged chunk + an empty flagged chunk do not.
    #[test]
    fn a_noncanonical_empty_final_chunk_is_rejected() {
        let path = format!("{UID}/note-c.jpg");
        let canonical = seal_fixed(&path, CHUNK);
        assert!(open_at(&path, &canonical).is_ok());

        let v = vectors();
        let (dek, prefix): ([u8; 32], [u8; 7]) = (hex_of(&v, "dek"), hex_of(&v, "nonce_prefix"));
        let (a, pt) = (aad(UID, "note-c"), plaintext(CHUNK));
        let mut enc = EncryptorBE32::from_aead(dek_cipher(&dek), GenericArray::from_slice(&prefix));
        let full = enc.encrypt_next(Payload { msg: &pt, aad: &a }).unwrap();
        let empty = enc.encrypt_last(Payload { msg: &[], aad: &a }).unwrap();
        let noncanonical = [&canonical[..HEADER_LEN], &full[..], &empty[..]].concat();
        let opened = open_at(&path, &noncanonical);
        assert!(matches!(opened, Err(CryptoError::DecryptFailed)));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn the_chunk_cap() {
        let cap = u32::MAX as usize;
        assert!(fits_chunk_cap(cap * CHUNK));
        assert!(!fits_chunk_cap(cap * CHUNK + 1));
    }

    /// The frozen path rule (ADR 0008): the whole string, ASCII only, exact bytes.
    #[test]
    fn the_path_rule() {
        let uuid = "9c1d4e2f-6a7b-4c8d-9e0f-1a2b3c4d5e6f";
        for (path, id) in [
            (format!("{UID}/note-a.jpg"), "note-a"),
            (format!("{UID}/k3x9a0bq.jpg"), "k3x9a0bq"),
            (format!("{UID}/{uuid}.jpg"), uuid),
        ] {
            assert_eq!(image_id_for_path(UID, &path), Some(id));
        }
        let max = "a".repeat(64);
        assert!(image_id_for_path(UID, &format!("{UID}/{max}.jpg")).is_some());

        let upper = UID.to_uppercase();
        let bad = [
            format!("{UID}/note-a\n.jpg"),
            format!("{UID}/note-a.jpg\n"),
            format!("{UID}/note-a.JPG"),
            format!("/{UID}/note-a.jpg"),
            format!("{UID}//note-a.jpg"),
            format!("{UID}/../note-a.jpg"),
            format!("{UID}/.jpg"),
            format!("{UID}/{max}a.jpg"),
            format!("{UID}/not\u{e8}-a.jpg"),
            format!("{upper}/note-a.jpg"),
            format!("note-images/{UID}/note-a.jpg"),
            "00000000-0000-4000-8000-000000000000/note-a.jpg".to_string(),
            format!("{UID}/note.a.jpg"),
            format!("{UID}/note_a.jpg"),
            format!("{UID}/note-a.jpg?x"),
        ];
        for (i, path) in bad.iter().enumerate() {
            assert_eq!(image_id_for_path(UID, path), None, "bad path #{i}");
        }
        // Swapped arguments, and malformed user ids.
        let path = format!("{UID}/note-a.jpg");
        assert_eq!(image_id_for_path(&path, UID), None);
        assert_eq!(
            image_id_for_path(&upper, &format!("{upper}/note-a.jpg")),
            None
        );
        assert_eq!(image_id_for_path("not-a-uid", "not-a-uid/note-a.jpg"), None);
        assert!(is_user_id(UID) && !is_user_id(&upper) && !is_user_id(&path));
    }

    /// The independent node:crypto oracle (tests/encimg_oracle.mjs, written from the ADR text)
    /// opens every vector, confirms each is canonical, and rejects a tampered copy. Skips without
    /// Node locally; FAILS without Node in CI, where `CI` is set and parity.yml pins Node.
    #[test]
    fn the_node_oracle_opens_every_vector() {
        let v = vectors();
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("braird_encimg_oracle_{pid}"));
        std::fs::create_dir_all(&dir).unwrap();
        for c in v["cases"].as_array().unwrap() {
            if c["sealed"].is_null() {
                let name = c["name"].as_str().unwrap();
                std::fs::write(dir.join(format!("{name}.bin")), case_seal(c)).unwrap();
            }
        }
        let output = std::process::Command::new("node")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/encimg_oracle.mjs"
            ))
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/vendored/encimg/v1-vectors.json"
            ))
            .arg(&dir)
            .output();
        let _ = std::fs::remove_dir_all(&dir);
        let output = match output {
            Ok(o) => o,
            Err(e) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "CI must run the encimg oracle: {e}"
                );
                eprintln!("SKIP: `node` not on PATH - the encimg oracle needs Node (CI has it)");
                return;
            }
        };
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "oracle failed: {stderr}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("oracle JSON");
        assert_eq!(report["k_wrap_ok"], true);
        let results = report["results"].as_array().unwrap();
        assert_eq!(results.len(), v["cases"].as_array().unwrap().len());
        for r in results {
            assert_eq!(r["ok"], true, "{r}");
        }
    }
}
