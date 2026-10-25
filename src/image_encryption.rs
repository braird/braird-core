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
use aes_gcm::aead::{KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key};
use zeroize::Zeroizing;

use crate::primitives::{aes_decrypt, aes_encrypt};
use crate::CryptoError;

/// HKDF info for the image key-wrap subkey. Frozen: changing it orphans every sealed image.
pub(crate) const KEY_WRAP_INFO: &[u8] = b"braird-image-key-wrap-v1";

const MAGIC: &[u8; 9] = b"encimg:v1";
const CHUNK: usize = 262_144;
const TAG: usize = 16;
const WRAP_IV_AT: usize = MAGIC.len(); // 9
const WRAPPED_AT: usize = WRAP_IV_AT + 12; // 21
const PREFIX_AT: usize = WRAPPED_AT + 32 + TAG; // 69
const HEADER: usize = PREFIX_AT + 7; // 76
const MIN_SEALED: usize = HEADER + TAG; // 92: one empty final chunk
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
fn is_user_id(s: &str) -> bool {
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

/// `max(1, ceil(n / CHUNK))`, or `None` past the 2^32 − 1 chunk cap.
fn chunk_count(n: usize) -> Option<usize> {
    let chunks = (n as u64).div_ceil(CHUNK as u64).max(1);
    (chunks <= MAX_CHUNKS).then_some(chunks as usize)
}

fn stream_cipher(dek: &[u8]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek))
}

/// Seal `pt` with the caller's fresh random `dek`, `wrap_iv` and `nonce_prefix` (the Vault draws
/// them from the OS CSPRNG on every call; fixed values appear only in this module's tests).
/// The ids must already be validated (see [`image_id_for_path`]).
pub(crate) fn seal(
    k_wrap: &[u8],
    dek: &[u8; 32],
    wrap_iv: &[u8; 12],
    nonce_prefix: &[u8; 7],
    user_id: &str,
    image_id: &str,
    pt: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let chunks =
        chunk_count(pt.len()).ok_or_else(|| CryptoError::BadInput("image too large".into()))?;
    let aad = aad(user_id, image_id);
    let mut out = Vec::with_capacity(HEADER + pt.len() + TAG * chunks);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(wrap_iv);
    out.extend_from_slice(&aes_encrypt(k_wrap, wrap_iv, dek, Some(&aad)));
    out.extend_from_slice(nonce_prefix);

    let mut enc =
        EncryptorBE32::from_aead(stream_cipher(dek), GenericArray::from_slice(nonce_prefix));
    let last_at = (chunks - 1) * CHUNK;
    for piece in pt[..last_at].chunks(CHUNK) {
        let ct = enc
            .encrypt_next(Payload {
                msg: piece,
                aad: &aad,
            })
            .expect("stream encrypt (counter capped above)");
        out.extend_from_slice(&ct);
    }
    let ct = enc
        .encrypt_last(Payload {
            msg: &pt[last_at..],
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
    let fail = CryptoError::DecryptFailed;
    if sealed.len() < MIN_SEALED || &sealed[..WRAP_IV_AT] != MAGIC {
        return Err(fail);
    }
    let aad = aad(user_id, image_id);
    let dek = Zeroizing::new(
        aes_decrypt(
            k_wrap,
            &sealed[WRAP_IV_AT..WRAPPED_AT],
            &sealed[WRAPPED_AT..PREFIX_AT],
            Some(&aad),
        )
        .map_err(|_| CryptoError::DecryptFailed)?,
    );

    let body = &sealed[HEADER..];
    let piece = CHUNK + TAG;
    let (before_last, last_len) = match body.len() % piece {
        0 => (body.len() / piece - 1, piece),
        rem => (body.len() / piece, rem),
    };
    if last_len < TAG || (last_len == TAG && before_last > 0) {
        return Err(fail);
    }
    if before_last as u64 >= MAX_CHUNKS {
        return Err(fail);
    }

    let mut dec = DecryptorBE32::from_aead(
        stream_cipher(&dek),
        GenericArray::from_slice(&sealed[PREFIX_AT..HEADER]),
    );
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() - TAG * (before_last + 1)));
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
    /// The vectors' plaintext rule: byte i = i % 251.
    fn plaintext(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }
    fn k_wrap() -> Zeroizing<[u8; 32]> {
        hkdf32_unsalted(&[0x11; 32], KEY_WRAP_INFO)
    }
    /// Seal `n` plaintext bytes under the vectors' fixed key material.
    fn seal_fixed(path: &str, n: usize, wrap_iv: [u8; 12]) -> Vec<u8> {
        let v = vectors();
        let id = image_id_for_path(UID, path).expect("valid path");
        let pt = plaintext(n);
        let (dek, prefix) = (hex_of(&v, "dek"), hex_of(&v, "nonce_prefix"));
        seal(&*k_wrap(), &dek, &wrap_iv, &prefix, UID, id, &pt).unwrap()
    }
    fn open_at(path: &str, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        open(
            &*k_wrap(),
            UID,
            image_id_for_path(UID, path).unwrap(),
            sealed,
        )
    }
    fn case_seal(c: &Value) -> Vec<u8> {
        let wrap_iv = if c.get("wrap_iv").is_some() {
            hex_of(c, "wrap_iv")
        } else {
            hex_of(&vectors(), "wrap_iv")
        };
        let n = c["len"].as_u64().unwrap() as usize;
        seal_fixed(c["path"].as_str().unwrap(), n, wrap_iv)
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

    /// `K_wrap` for MK = 0x11 x 32 matches the vectors, whose value came from node:crypto
    /// `hkdfSync("sha256", 0x11 x 32, 0x00 x 32, "braird-image-key-wrap-v1", 32)`.
    #[test]
    fn k_wrap_matches_node() {
        assert_eq!(
            hex::encode(*k_wrap()),
            vectors()["k_wrap"].as_str().unwrap()
        );
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
        assert_ne!(small[WRAP_IV_AT..PREFIX_AT], rewrap[WRAP_IV_AT..PREFIX_AT]);
        assert_eq!(small[PREFIX_AT..], rewrap[PREFIX_AT..]);
    }

    #[test]
    fn round_trips_at_the_chunk_edges() {
        for n in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 1] {
            let path = format!("{UID}/edge-{n}.jpg");
            let sealed = seal_fixed(&path, n, [7; 12]);
            let chunks = chunk_count(n).unwrap();
            assert_eq!(sealed.len(), HEADER + n + TAG * chunks, "n = {n}");
            assert_eq!(&sealed[..WRAP_IV_AT], MAGIC);
            assert_eq!(open_at(&path, &sealed).unwrap(), plaintext(n), "n = {n}");
        }
    }

    /// Every way to damage an object fails closed with `DecryptFailed`: never a panic, never
    /// partial plaintext. Base: three chunks (two full, one of 1 byte).
    #[test]
    fn every_tamper_fails_closed() {
        let path = format!("{UID}/note-tamper.jpg");
        let base = seal_fixed(&path, 2 * CHUNK + 1, [7; 12]);
        let piece = CHUNK + TAG;
        let (c0, c1, c2) = (HEADER, HEADER + piece, HEADER + 2 * piece);
        assert!(open_at(&path, &base).is_ok());

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
        for r in 1..TAG {
            let longer = [&base[..], &vec![0u8; r][..]].concat();
            damaged.push((format!("{r}-byte remainder"), longer));
        }
        damaged.push(("91 bytes".into(), base[..MIN_SEALED - 1].to_vec()));
        damaged.push(("header only".into(), base[..HEADER].to_vec()));
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
        let sealed = seal_fixed(&path, 37, [7; 12]);
        let other_uid = "00000000-0000-4000-8000-000000000000";
        let wrong = [
            open(&*k_wrap(), other_uid, "note-a", &sealed),
            open(&*k_wrap(), UID, "note-b", &sealed),
            open(&[0x22; 32], UID, "note-a", &sealed),
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
        let a = seal_fixed(&path, 100, [7; 12]);
        let id = image_id_for_path(UID, &path).unwrap();
        let b = seal(
            &*k_wrap(),
            &[0x33; 32],
            &[8; 12],
            &[9; 7],
            UID,
            id,
            &plaintext(100),
        )
        .unwrap();
        assert!(open_at(&path, &b).is_ok());
        let spliced = [&a[..HEADER], &b[HEADER..]].concat();
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
        let id = image_id_for_path(UID, &path).unwrap();
        let (dek, prefix, pt) = ([0x44; 32], [0x55; 7], plaintext(CHUNK));
        let canonical = seal(&*k_wrap(), &dek, &[1; 12], &prefix, UID, id, &pt).unwrap();
        assert!(open_at(&path, &canonical).is_ok());

        let a = aad(UID, id);
        let nonce_prefix = GenericArray::from_slice(&prefix);
        let mut enc = EncryptorBE32::from_aead(stream_cipher(&dek), nonce_prefix);
        let full = enc.encrypt_next(Payload { msg: &pt, aad: &a }).unwrap();
        let empty = enc.encrypt_last(Payload { msg: &[], aad: &a }).unwrap();
        let noncanonical = [&canonical[..HEADER], &full[..], &empty[..]].concat();
        let opened = open_at(&path, &noncanonical);
        assert!(matches!(opened, Err(CryptoError::DecryptFailed)));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn the_chunk_cap() {
        assert_eq!(chunk_count(0), Some(1));
        assert_eq!(chunk_count(CHUNK), Some(1));
        assert_eq!(chunk_count(CHUNK + 1), Some(2));
        let cap = u32::MAX as usize;
        assert_eq!(chunk_count(cap * CHUNK), Some(cap));
        assert_eq!(chunk_count(cap * CHUNK + 1), None);
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

        let upper_uid = UID.to_uppercase();
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
            format!("{upper_uid}/note-a.jpg"),
            format!("note-images/{UID}/note-a.jpg"),
            "00000000-0000-4000-8000-000000000000/note-a.jpg".to_string(),
            format!("{UID}/note.a.jpg"),
            format!("{UID}/note_a.jpg"),
            format!("{UID}/note-a.jpg?x"),
        ];
        for path in &bad {
            assert_eq!(image_id_for_path(UID, path), None, "{path:?}");
        }
        // Swapped arguments, and malformed user ids.
        let path = format!("{UID}/note-a.jpg");
        assert_eq!(image_id_for_path(&path, UID), None);
        let upper_path = format!("{upper_uid}/note-a.jpg");
        assert_eq!(image_id_for_path(&upper_uid, &upper_path), None);
        assert_eq!(image_id_for_path("not-a-uid", "not-a-uid/note-a.jpg"), None);
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
