//! enc:v1 / enc:v2 note-text sealing. Both formats are
//! `enc:vN:<base64(iv)>.<base64(ct)>` with the 16-byte GCM tag folded into the
//! ciphertext. v2 binds the noteId as AAD so ciphertext can't be transplanted
//! between records; v1 (legacy reads) has no AAD.

use crate::primitives::{aes_decrypt, aes_encrypt, b64decode, b64encode};
use crate::CryptoError;

const SENTINEL_V1: &str = "enc:v1:";
const SENTINEL_V2: &str = "enc:v2:";

/// Structural check for the AAD-bound format — the ONLY sentinel check in the crate, deliberately.
/// `enc:v1` is not accepted: it carries no AAD, so [`decrypt_note`] opens a v1 payload under ANY id — the id argument is ignored entirely on
/// that branch. Any caller asking "is this ciphertext bound to THIS row?" must gate on this.
///
/// The looser `is_encrypted` companion is GONE. It mirrored the PWA's `isEncrypted()`, accepted v1,
/// and by being the obvious thing to reach for it is what made the permissive read gate easy to
/// write — the hole SUR-1070 closed. Both paths that briefly seemed to need it (the read gate, then
/// the archive gate) turned out to need the strict check instead. Reintroduce a v1-aware helper only
/// with a caller that genuinely needs v1, and name it so the difference is unmissable.
pub fn is_encrypted_v2(value: &str) -> bool {
    value.starts_with(SENTINEL_V2)
}

/// Seal plaintext. `note_id = Some` → enc:v2 (AAD = UTF-8 noteId); `None` → enc:v1.
pub fn encrypt_note(mk: &[u8], note_id: Option<&str>, plaintext: &str, iv: &[u8]) -> String {
    let (aad, sentinel) = match note_id {
        Some(id) => (Some(id.as_bytes()), SENTINEL_V2),
        None => (None, SENTINEL_V1),
    };
    let ct = aes_encrypt(mk, iv, plaintext.as_bytes(), aad);
    format!("{sentinel}{}.{}", b64encode(iv), b64encode(&ct))
}

/// Open an enc:v1/enc:v2 payload. enc:v2 requires the matching noteId.
pub fn decrypt_note(mk: &[u8], note_id: Option<&str>, value: &str) -> Result<String, CryptoError> {
    let (is_v2, payload) = if let Some(p) = value.strip_prefix(SENTINEL_V2) {
        (true, p)
    } else if let Some(p) = value.strip_prefix(SENTINEL_V1) {
        (false, p)
    } else {
        return Err(CryptoError::BadInput("unrecognised sentinel".into()));
    };
    let (iv_b64, ct_b64) = payload
        .split_once('.')
        .ok_or_else(|| CryptoError::BadInput("missing '.' separator".into()))?;
    let iv = b64decode(iv_b64)?;
    let ct = b64decode(ct_b64)?;
    let aad: Option<&[u8]> = if is_v2 {
        Some(
            note_id
                .ok_or_else(|| CryptoError::BadInput("noteId required to decrypt enc:v2".into()))?
                .as_bytes(),
        )
    } else {
        None
    };
    let pt = aes_decrypt(mk, &iv, &ct, aad)?;
    String::from_utf8(pt).map_err(|e| CryptoError::BadInput(format!("utf8: {e}")))
}
