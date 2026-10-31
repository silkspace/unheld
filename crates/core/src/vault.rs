//! The vault: everything the endpoint remembers, encrypted at rest under a passphrase.
//! The file is salt, nonce, ciphertext and nothing else, so it carries no cleartext header and
//! is indistinguishable from random bytes. The format version lives inside the ciphertext.

use crate::config;
use crate::vocab::Refuse;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The symmetric vault key. Zeroised on drop, never printed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; config::vault::KEY_LEN]);

fn derive(passphrase: &str, salt: &[u8]) -> Result<VaultKey, Refuse> {
    let params = Params::new(
        config::vault::ARGON2_MEMORY_KIB,
        config::vault::ARGON2_ITERATIONS,
        config::vault::ARGON2_LANES,
        Some(config::vault::KEY_LEN),
    )
    .map_err(|_| Refuse::Protocol)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; config::vault::KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| Refuse::Protocol)?;
    Ok(VaultKey(key))
}

/// Encrypt `plain` under `passphrase` into the on-disk format: salt, nonce, ciphertext.
pub fn seal_to_file(path: &Path, passphrase: &str, plain: &[u8]) -> Result<(), Refuse> {
    let mut salt = [0u8; config::vault::SALT_LEN];
    let mut nonce = [0u8; config::vault::NONCE_LEN];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);
    let key = derive(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let ct = cipher
        .encrypt(XNonce::try_from(&nonce[..]).map_err(|_| Refuse::Protocol)?.as_ref(), plain)
        .map_err(|_| Refuse::Protocol)?;
    let mut out = Vec::with_capacity(salt.len() + nonce.len() + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &out).map_err(|_| Refuse::VaultIo)?;
    std::fs::rename(&tmp, path).map_err(|_| Refuse::VaultIo)?;
    Ok(())
}

/// Decrypt the on-disk format. A wrong passphrase, a damaged file and a file that was never a
/// vault are the same refusal, because the file carries nothing that would tell them apart.
pub fn open_from_file(path: &Path, passphrase: &str) -> Result<Vec<u8>, Refuse> {
    let bytes = std::fs::read(path).map_err(|_| Refuse::VaultIo)?;
    let salt_end = config::vault::SALT_LEN;
    let nonce_end = salt_end + config::vault::NONCE_LEN;
    let salt = bytes.get(..salt_end).ok_or(Refuse::VaultLocked)?;
    let nonce = bytes.get(salt_end..nonce_end).ok_or(Refuse::VaultLocked)?;
    let ct = bytes.get(nonce_end..).ok_or(Refuse::VaultLocked)?;
    let key = derive(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    cipher
        .decrypt(XNonce::try_from(nonce).map_err(|_| Refuse::VaultLocked)?.as_ref(), ct)
        .map_err(|_| Refuse::VaultLocked)
}
