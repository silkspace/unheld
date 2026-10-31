//! Every constant the endpoint knows, read as `config::part::VALUE`.

/// Vault files and key derivation.
pub mod vault {
    pub const FILE_NAME: &str = "vault";
    /// Format version, carried inside the ciphertext so the file has no cleartext header.
    pub const FORMAT_VERSION: u32 = 1;
    pub const SALT_LEN: usize = 16;
    pub const NONCE_LEN: usize = 24;
    pub const KEY_LEN: usize = 32;
    /// Argon2id parameters: memory in KiB, iterations, lanes.
    pub const ARGON2_MEMORY_KIB: u32 = 65536;
    pub const ARGON2_ITERATIONS: u32 = 3;
    pub const ARGON2_LANES: u32 = 1;
    /// Environment variable that supplies the passphrase for scripted use.
    pub const PASSPHRASE_ENV: &str = "UNHELD_PASSPHRASE";
    /// Environment variable that overrides the profiles directory.
    pub const HOME_ENV: &str = "UNHELD_HOME";
    pub const HOME_DIR_NAME: &str = ".unheld";
}

/// Identity.
pub mod identity {
    /// Random bytes standing for an identity inside credentials, so introductions carry no name.
    pub const CREDENTIAL_ID_LEN: usize = 16;
}

/// Fingerprint display.
pub mod fp {
    /// Digits in the pairwise safety number.
    pub const DIGITS: usize = 60;
    /// Digits per spoken group.
    pub const GROUP: usize = 5;
    /// Domain separator for the pairwise hash.
    pub const DOMAIN: &[u8] = b"unheld fp v1";
}

/// Messaging Layer Security choices.
pub mod mls {
    use openmls::prelude::Ciphersuite;
    pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    /// Out-of-order tolerance and maximum forward distance for the sender ratchet (L13).
    pub const OUT_OF_ORDER_TOLERANCE: u32 = 32;
    pub const MAX_FORWARD_DISTANCE: u32 = 1000;
}

/// Framing of several MLS messages inside one blob.
pub mod frame {
    pub const COUNT_LEN: usize = 1;
    pub const LEN_LEN: usize = 4;
}
