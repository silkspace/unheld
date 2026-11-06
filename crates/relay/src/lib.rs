#![forbid(unsafe_code)]
//! A store of queues that orders blobs and knows nothing else (docs/decisions/006-relay.md).
//!
//! A queue is a numbered sequence of blobs behind two bearer capabilities, one to append and one
//! to read, which the relay holds as hashes. The relay's acceptance order is the total order a
//! group needs (L19), its answers are blobs, numbers and refusals and nothing a client would act
//! on (L22), and this crate depends on `unheld-blob` and on nothing that can name a key (L2).

pub mod carrier;
pub mod server;
pub mod store;
pub mod tls;
pub mod wire;

/// Every constant the relay and its carrier know.
pub mod config {
    /// Bytes in a queue identifier and in each capability.
    pub const ID_LEN: usize = 32;
    /// Bytes in a capability hash and in a certificate pin (SHA-256).
    pub const HASH_LEN: usize = 32;
    /// Bytes in a frame's length prefix.
    pub const FRAME_PREFIX: usize = 4;
    /// Largest frame body: a put of the largest bucket.
    pub const MAX_BODY: usize = 1 + ID_LEN + ID_LEN + unheld_blob::config::BUCKETS[3];
    /// Limits a relay enforces by default.
    pub mod limits {
        /// Blobs one queue holds before puts are refused as full (L13).
        pub const DEPTH: u64 = 1024;
        /// Puts one queue accepts per minute before the next is refused as too fast (L13).
        pub const PUTS_PER_MINUTE: usize = 600;
        /// Queues one relay holds before creation is refused.
        pub const QUEUES: usize = 100_000;
        /// Seconds a queue lives untouched before the relay forgets it.
        pub const IDLE_SECS: u64 = 30 * 24 * 60 * 60;
        /// Seconds a connection may stay silent before the relay closes it.
        pub const SILENCE_SECS: u64 = 120;
    }
    /// When a reader moves to a fresh queue (docs/decisions/009-queue-rotation.md).
    pub mod rotate {
        /// Seconds a queue is read before its reader makes the next one.
        pub const SECS: u64 = 7 * 24 * 60 * 60;
        /// Blobs collected from a queue before its reader makes the next one.
        pub const BLOBS: u64 = 256;
    }
    /// Names on the relay's disk.
    pub mod files {
        pub const CERT: &str = "cert.der";
        pub const KEY: &str = "key.der";
        pub const QUEUES: &str = "queues";
        pub const WRITE_HASH: &str = "write";
        pub const READ_HASH: &str = "read";
        /// Digits in a blob file name, so names sort as numbers.
        pub const SEQ_DIGITS: usize = 20;
    }
    /// The queue address scheme: `unheld-relay://host:port/<queue>#<pin>`.
    pub const SCHEME: &str = "unheld-relay://";
}

/// Why the relay or its carrier could not go on. Never carries payload.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("relay i/o failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error("the relay's certificate could not be made")]
    Certificate,
    #[error("malformed frame")]
    Malformed,
    #[error("the relay refused: {0}")]
    Refused(&'static str),
    #[error("the relay answered out of order: expected {expected}, got {got}")]
    Disordered { expected: u64, got: u64 },
    #[error("queue address is malformed")]
    BadAddress,
}

/// Lower-case hexadecimal, the one text form used for identifiers, capabilities and pins.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Fresh random bytes for an identifier or a capability.
pub(crate) fn random<const N: usize>() -> [u8; N] {
    use rand::RngCore as _;
    let mut out = [0u8; N];
    rand::rng().fill_bytes(&mut out);
    out
}
