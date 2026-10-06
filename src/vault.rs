//! [`Vault`] — the stateful FFI handle (Option B). Owns the 256-bit Master Key in
//! `Zeroizing` memory behind a `Mutex` (so `Arc<Vault>` is `Send + Sync` for Swift /
//! Kotlin callers on any thread). No method returns the raw MK across the FFI; the
//! only outputs are ciphertext, wrapped blobs, and content tags.

use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::primitives::fill_random;
#[cfg(not(target_arch = "wasm32"))]
use crate::primitives::hkdf32_unsalted;
use crate::{byte_encryption, content_tag, key_manager, note_encryption};
use crate::{CryptoError, WrappedBlob};
#[cfg(not(target_arch = "wasm32"))]
use aes_gcm::{
    aead::{AeadCore, OsRng},
    Aes256Gcm,
};

#[derive(uniffi::Object)]
pub struct Vault {
    mk: Mutex<Zeroizing<[u8; 32]>>,
}

fn new_vault(mk: Zeroizing<[u8; 32]>) -> Arc<Vault> {
    Arc::new(Vault { mk: Mutex::new(mk) })
}

/// Lock the MK mutex. `expect` is correct: a poisoned mutex means another thread
/// panicked mid-crypto, and continuing with possibly-inconsistent key state is worse
/// than aborting.
macro_rules! mk {
    ($self:ident) => {
        $self.mk.lock().expect("vault mutex poisoned")
    };
}

#[uniffi::export]
impl Vault {
    /// Generate a fresh random 256-bit Master Key in-core. The MK never leaves the
    /// handle; persist it with [`Vault::wrap_with_prf`].
    #[uniffi::constructor]
    pub fn generate() -> Arc<Vault> {
        let mut mk = Zeroizing::new([0u8; 32]);
        fill_random(mk.as_mut_slice());
        new_vault(mk)
    }

    /// Unlock by decrypting a stored prf-v1 blob with raw PRF bytes (the WebAuthn PRF
    /// output, fed to HKDF unchanged). The recovered MK stays inside the handle.
    #[uniffi::constructor]
    pub fn unlock(prf: Vec<u8>, blob: WrappedBlob) -> Result<Arc<Vault>, CryptoError> {
        Ok(new_vault(key_manager::unwrap_with_prf(&blob, &prf)?))
    }

    /// Unlock by trying each active prf-v1 blob with the asserted PRF and keeping the one
    /// that decrypts. Hosts pass ALL active prf-v1 blobs for the account: a blob is bound
    /// to exactly one credential's PRF, so a positional "first" pick fails whenever the
    /// account has more than one wrapper (linked devices / synced passkeys). Correctness is
    /// the trial decrypt — exactly one candidate's PRF derives the right AES key; the rest
    /// fail their GCM tag. Ordering the list by a known `credential_id` match is a valid
    /// host-side fast path, never a filter. A malformed candidate is skipped, not fatal;
    /// `DecryptFailed` iff none decrypt.
    ///
    /// Device-transfer create is this plus a PIN-wrap: `Vault::unlock_from_blobs(prf, blobs)` then
    /// [`Vault::pin_wrap`]. The single-blob [`Vault::unlock`] and the
    /// [`Vault::redeem_pin_transfer`] redeem path are unchanged.
    #[uniffi::constructor]
    pub fn unlock_from_blobs(
        prf: Vec<u8>,
        blobs: Vec<WrappedBlob>,
    ) -> Result<Arc<Vault>, CryptoError> {
        for blob in &blobs {
            if let Ok(mk) = key_manager::unwrap_with_prf(blob, &prf) {
                return Ok(new_vault(mk));
            }
        }
        Err(CryptoError::DecryptFailed)
    }

    /// Redeem a PIN-encrypted device-transfer blob on a new device (PBKDF2 @ 600k).
    #[uniffi::constructor]
    pub fn redeem_pin_transfer(
        transfer_blob: WrappedBlob,
        pin: String,
    ) -> Result<Arc<Vault>, CryptoError> {
        Ok(new_vault(key_manager::unwrap_with_pin(
            &transfer_blob,
            &pin,
        )?))
    }

    /// Wrap the owned MK with a PRF-derived key → a storable prf-v1 blob. Salt (32B)
    /// and IV (12B) are generated in-core with the CSPRNG — no nonce-reuse footgun.
    pub fn wrap_with_prf(&self, prf: Vec<u8>) -> WrappedBlob {
        let (salt, iv) = fresh_salt_iv();
        key_manager::wrap_with_prf(mk!(self).as_slice(), &prf, &salt, &iv)
    }

    /// Re-wrap the owned MK for a different credential/device. The Vault already holds
    /// the MK, so this is a fresh wrap under `new_prf` (multi-device add).
    pub fn rewrap(&self, new_prf: Vec<u8>) -> WrappedBlob {
        self.wrap_with_prf(new_prf)
    }

    /// PIN-wrap the owned MK for device transfer (PBKDF2-SHA256 @ 600k → AES-256-GCM).
    pub fn pin_wrap(&self, pin: String) -> WrappedBlob {
        let (salt, iv) = fresh_salt_iv();
        key_manager::wrap_with_pin(mk!(self).as_slice(), &pin, &salt, &iv)
    }

    /// enc:v2 when `note_id` is `Some` (AAD = UTF-8 noteId); enc:v1 when `None`. Fresh
    /// random 12-byte IV per call.
    pub fn encrypt_note(&self, note_id: Option<String>, plaintext: String) -> String {
        let mut iv = [0u8; 12];
        fill_random(&mut iv);
        note_encryption::encrypt_note(mk!(self).as_slice(), note_id.as_deref(), &plaintext, &iv)
    }

    /// Decrypt an enc:v1/enc:v2 payload produced by this core OR by the PWA.
    pub fn decrypt_note(
        &self,
        note_id: Option<String>,
        ciphertext: String,
    ) -> Result<String, CryptoError> {
        note_encryption::decrypt_note(mk!(self).as_slice(), note_id.as_deref(), &ciphertext)
    }

    /// 64-char lowercase hex content-dedup tag (HMAC-SHA256, 64-byte subkey).
    pub fn content_tag(&self, text: String, book_id: Option<String>) -> String {
        content_tag::content_tag(mk!(self).as_slice(), &text, book_id.as_deref())
    }

    /// Seal arbitrary bytes (e.g. an embedding vector) at rest: `[0x02][IV][ct]`,
    /// AAD = the caller's context string (the embedding pipeline passes `emb:{noteId}`,
    /// domain-separated from enc:v2's bare-noteId AAD). Fresh random IV per call.
    pub fn seal_bytes(&self, bytes: Vec<u8>, aad: String) -> Vec<u8> {
        let mut iv = [0u8; 12];
        fill_random(&mut iv);
        byte_encryption::seal_bytes(mk!(self).as_slice(), &bytes, &aad, &iv)
    }

    /// Open a blob produced by [`Vault::seal_bytes`].
    pub fn open_bytes(&self, sealed: Vec<u8>, aad: String) -> Result<Vec<u8>, CryptoError> {
        byte_encryption::open_bytes(mk!(self).as_slice(), &sealed, &aad)
    }
}

/// HKDF info for the book-url subkey (SUR-1112). Frozen wire constant: changing it orphans every
/// sealed `books.url`.
#[cfg(not(target_arch = "wasm32"))]
const BOOK_URL_INFO: &[u8] = b"braird-book-url-v1";

// Crate-internal field sealing (SUR-1112). NOT `#[uniffi::export]`ed: core seals at write and opens
// at read; a host never handles the sealed form. Native-only, like `sync`, its only caller.
#[cfg(not(target_arch = "wasm32"))]
impl Vault {
    /// Seal a book's share link: enc:v2 (AAD = the book id) under a SUBKEY of the MK, HKDF info
    /// [`BOOK_URL_INFO`]. A separate key, not an AAD prefix, keeps it apart from note and question
    /// text (enc:v2 under the MK, AAD = a bare record id): ids are free text, so no AAD prefix
    /// alone could stop a hostile server presenting a url ciphertext as a note `url:<id>`.
    /// A shared link can be a capability (an "anyone with the link" document), so the server and
    /// every backup hold only ciphertext; dedup runs on the device after opening.
    pub(crate) fn seal_book_url(&self, book_id: &str, url: &str) -> String {
        // A fresh 12-byte nonce per call, straight from the OS CSPRNG.
        let iv = Aes256Gcm::generate_nonce(&mut OsRng);
        note_encryption::encrypt_note(self.book_url_key().as_slice(), Some(book_id), url, &iv)
    }

    /// Open [`Vault::seal_book_url`]'s output, or `None`. Only a bound enc:v2 value under the url
    /// subkey opens: an enc:v1, a plaintext, a note ciphertext or another row's url never does.
    pub(crate) fn open_book_url(&self, book_id: &str, sealed: &str) -> Option<String> {
        if !note_encryption::is_encrypted_v2(sealed) {
            return None;
        }
        note_encryption::decrypt_note(self.book_url_key().as_slice(), Some(book_id), sealed).ok()
    }

    fn book_url_key(&self) -> Zeroizing<[u8; 32]> {
        hkdf32_unsalted(mk!(self).as_slice(), BOOK_URL_INFO)
    }
}

fn fresh_salt_iv() -> ([u8; 32], [u8; 12]) {
    let mut salt = [0u8; 32];
    let mut iv = [0u8; 12];
    fill_random(&mut salt);
    fill_random(&mut iv);
    (salt, iv)
}

// ── Test / parity seams ──────────────────────────────────────────────────────
// Built ONLY under `--features test-seams`, and NEVER `#[uniffi::export]`ed, so the
// with-raw-MK constructor, the fixed-salt/IV determinism overrides, and the raw-MK
// readback are all absent from the production cdylib + the generated Swift/Kotlin
// bindings (naming-reviewer / crypto-reviewer BLOCKER: a public fixed-IV path is a
// catastrophic GCM nonce-reuse footgun). The parity harness (`tests/parity.rs`)
// drives these to reproduce the frozen golden vectors byte-for-byte.
#[cfg(feature = "test-seams")]
impl Vault {
    /// Construct from a known MK (hex). Mirrors the JS vectors that fix `mk = 0x11*32`.
    pub fn __with_raw_mk_hex(mk_hex: &str) -> Result<Arc<Vault>, CryptoError> {
        let bytes =
            hex::decode(mk_hex).map_err(|e| CryptoError::BadInput(format!("mk hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(CryptoError::BadInput("mk must be 32 bytes".into()));
        }
        let mut mk = Zeroizing::new([0u8; 32]);
        mk.copy_from_slice(&bytes);
        Ok(new_vault(mk))
    }

    /// Read back the raw MK as hex — proves mk-unwrap without exporting the MK across
    /// the FFI (this accessor is not in the binding).
    pub fn __raw_mk_hex(&self) -> String {
        hex::encode(mk!(self).as_slice())
    }

    pub fn __wrap_with_prf_fixed(&self, prf: &[u8], salt: &[u8], iv: &[u8]) -> WrappedBlob {
        key_manager::wrap_with_prf(mk!(self).as_slice(), prf, salt, iv)
    }

    pub fn __pin_wrap_fixed(&self, pin: &str, salt: &[u8], iv: &[u8]) -> WrappedBlob {
        key_manager::wrap_with_pin(mk!(self).as_slice(), pin, salt, iv)
    }

    pub fn __encrypt_note_fixed(
        &self,
        note_id: Option<&str>,
        plaintext: &str,
        iv: &[u8],
    ) -> String {
        note_encryption::encrypt_note(mk!(self).as_slice(), note_id, plaintext, iv)
    }
}

#[cfg(test)]
mod zeroization {
    use zeroize::{Zeroize, Zeroizing};

    /// Criterion #7: the Master Key wrapper actually wipes its bytes. `Zeroizing<[u8;
    /// 32]>` zeroes on `Drop`; here we prove the wipe by reading the LIVE buffer through
    /// a raw pointer immediately after an explicit `zeroize()` (safe — same scope, not
    /// yet dropped). Rust addresses are stable: no moving/compacting GC can relocate the
    /// key behind our back and leave a copy un-wiped (the property the JVM `SecretKeySpec`
    /// arm failed in the SUR-658 spike). This is the same `Zeroizing<[u8; 32]>` the
    /// `Vault` holds its MK in.
    #[test]
    fn zeroizing_wipes_master_key_bytes() {
        let mut mk = Zeroizing::new([0x11u8; 32]);
        assert!(mk.iter().all(|&b| b == 0x11));
        let ptr = mk.as_ptr();
        mk.zeroize();
        let after = unsafe { std::slice::from_raw_parts(ptr, 32) };
        assert!(
            after.iter().all(|&b| b == 0),
            "MK bytes must be all-zero after zeroize"
        );
    }
}

#[cfg(test)]
mod book_url_seal {
    use super::{new_vault, Vault};
    use zeroize::Zeroizing;

    /// Known answer for the url subkey (MK = 0x11 × 32, the parity vectors' MK). A change to the
    /// salt, the info string or the length orphans every synced `books.url`; this pins all three.
    #[test]
    fn the_url_subkey_is_frozen() {
        let vault = new_vault(Zeroizing::new([0x11u8; 32]));
        // Cross-checked with Node: crypto.hkdfSync("sha256", 0x11×32, 0x00×32, "braird-book-url-v1", 32).
        assert_eq!(
            hex::encode(*vault.book_url_key()),
            "b20d1486c7f2027dca744a4749cb0c7e3045c8403507d0daa124088e5e22c759"
        );
    }

    /// SUR-1112 — a sealed link opens only under its own row and this vault, and nothing else
    /// opens as a link: not another row's link, not note text under the same id (the subkey
    /// separates them), not enc:v1, not plaintext, not another vault's ciphertext.
    #[test]
    fn only_the_rows_own_link_opens() {
        let vault = Vault::generate();
        let sealed = vault.seal_book_url("b1", "https://e.com/x");
        assert!(sealed.starts_with("enc:v2:") && !sealed.contains("e.com"));
        assert_eq!(
            vault.open_book_url("b1", &sealed).as_deref(),
            Some("https://e.com/x")
        );
        assert_eq!(vault.open_book_url("b2", &sealed), None, "another row");

        let note = vault.encrypt_note(Some("b1".into()), "https://e.com/x".into());
        assert_eq!(vault.open_book_url("b1", &note), None, "note text, same id");
        assert!(
            vault
                .decrypt_note(Some("b1".into()), sealed.clone())
                .is_err(),
            "and back"
        );
        let v1 = vault.encrypt_note(None, "https://e.com/x".into());
        assert_eq!(vault.open_book_url("b1", &v1), None, "enc:v1");
        assert_eq!(
            vault.open_book_url("b1", "https://e.com/x"),
            None,
            "plaintext"
        );
        assert_eq!(
            Vault::generate().open_book_url("b1", &sealed),
            None,
            "another key"
        );
    }
}
