#![forbid(unsafe_code)]
//! The adversary's objects.
//!
//! Everything downstream of `seal` lives in this crate's vocabulary: a `Blob` of one of the
//! fixed bucket sizes, and a `Carrier` that moves blobs and names no other type. The crate
//! graph keeps this crate ignorant of keys, sessions and plaintext (KERNEL.md, L2).

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Every constant the adversary's side of the system knows.
pub mod config {
    /// Fixed blob sizes in bytes. A payload is padded up to the smallest bucket that holds it
    /// and its length prefix (KERNEL.md, L4).
    pub const BUCKETS: [usize; 4] = [1024, 4096, 16384, 65536];
    /// Bytes of big-endian length prefix inside a blob.
    pub const LEN_PREFIX: usize = 4;
}

/// Why a blob could not be made or read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BlobError {
    #[error("payload exceeds the largest bucket")]
    TooLarge,
    #[error("length is not a bucket size")]
    NotABucket,
    #[error("blob is malformed")]
    Malformed,
}

/// A fixed-size ciphertext container. The only thing that ever leaves a device.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blob(Vec<u8>);

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blob({} bytes)", self.0.len())
    }
}

impl Blob {
    /// Wrap `inner` in a length prefix and zero-pad to the smallest bucket that fits.
    pub fn pad(inner: &[u8]) -> Result<Blob, BlobError> {
        let need = inner.len() + config::LEN_PREFIX;
        let bucket = *config::BUCKETS
            .iter()
            .find(|&&b| b >= need)
            .ok_or(BlobError::TooLarge)?;
        let mut v = Vec::with_capacity(bucket);
        v.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        v.extend_from_slice(inner);
        v.resize(bucket, 0);
        Ok(Blob(v))
    }

    /// Recover the payload from a blob.
    pub fn unpad(&self) -> Result<Vec<u8>, BlobError> {
        let prefix = self
            .0
            .get(..config::LEN_PREFIX)
            .ok_or(BlobError::Malformed)?;
        let len = u32::from_be_bytes(prefix.try_into().map_err(|_| BlobError::Malformed)?) as usize;
        let end = config::LEN_PREFIX + len;
        self.0
            .get(config::LEN_PREFIX..end)
            .map(|s| s.to_vec())
            .ok_or(BlobError::Malformed)
    }

    /// Accept bytes as a blob only if their length is a bucket.
    pub fn from_bytes(v: Vec<u8>) -> Result<Blob, BlobError> {
        if config::BUCKETS.contains(&v.len()) {
            Ok(Blob(v))
        } else {
            Err(BlobError::NotABucket)
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Text-safe form for carriers that move strings (mail, chat, clipboard).
    pub fn to_text(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.0)
    }

    pub fn from_text(s: &str) -> Result<Blob, BlobError> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.trim())
            .map_err(|_| BlobError::Malformed)?;
        Blob::from_bytes(bytes)
    }
}

/// Why a carrier failed. Never carries payload.
#[derive(Debug, thiserror::Error)]
pub enum CarrierError {
    #[error("carrier i/o failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Blob(#[from] BlobError),
    #[error("carrier has nothing to deliver")]
    Empty,
    /// An ordered carrier delivered a number that is not the next one (L12).
    #[error("carrier delivered out of order: expected {expected}, got {got}")]
    Disordered { expected: u64, got: u64 },
    /// The carrier would not move the blob, and says why in one fixed sentence.
    #[error("carrier refused: {0}")]
    Refused(&'static str),
}

/// Moves blobs. Mentions no other type (KERNEL.md, L2).
pub trait Carrier {
    fn put(&mut self, blob: &Blob) -> Result<(), CarrierError>;
    fn get(&mut self) -> Result<Blob, CarrierError>;
    /// Whether this carrier delivers blobs in a total order. Groups above the small bound need one (L19).
    fn ordered(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// L1 and L4 over every payload length that fits: pad then unpad is the identity and the
        /// blob is exactly a bucket.
        #[test]
        fn pad_unpad_identity(inner in proptest::collection::vec(any::<u8>(), 0..config::BUCKETS[config::BUCKETS.len() - 1] - config::LEN_PREFIX)) {
            let b = Blob::pad(&inner).unwrap();
            prop_assert!(config::BUCKETS.contains(&b.len()));
            prop_assert_eq!(b.unpad().unwrap(), inner);
            prop_assert_eq!(Blob::from_text(&b.to_text()).unwrap(), b);
        }

        /// L8: arbitrary bytes of bucket size never panic, and either unpad or refuse.
        #[test]
        fn arbitrary_bucket_never_panics(bytes in proptest::collection::vec(any::<u8>(), config::BUCKETS[0]..=config::BUCKETS[0])) {
            let b = Blob::from_bytes(bytes).unwrap();
            let _ = b.unpad();
        }

        /// L8: arbitrary text never panics in from_text.
        #[test]
        fn arbitrary_text_never_panics(s in ".*") {
            let _ = Blob::from_text(&s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_bucket() {
        for n in [0usize, 1, 100, 1019, 1020, 1021, 5000] {
            let inner = vec![7u8; n];
            let b = Blob::pad(&inner).unwrap();
            assert!(config::BUCKETS.contains(&b.len()));
            assert_eq!(b.unpad().unwrap(), inner);
            assert_eq!(Blob::from_text(&b.to_text()).unwrap(), b);
        }
    }

    #[test]
    fn too_large_is_refused_with_no_bytes() {
        let big = vec![0u8; config::BUCKETS[config::BUCKETS.len() - 1]];
        assert_eq!(Blob::pad(&big), Err(BlobError::TooLarge));
    }

    #[test]
    fn non_bucket_lengths_are_refused() {
        assert_eq!(Blob::from_bytes(vec![0u8; 1000]), Err(BlobError::NotABucket));
    }
}
