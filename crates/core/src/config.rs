//! Every constant the endpoint knows, read as `config::part::VALUE`.

/// Vault files and key derivation.
pub mod vault {
    pub const FILE_NAME: &str = "vault";
    /// The duress marker: a small file encrypted under the duress passphrase.
    pub const DURESS_FILE_NAME: &str = "d";
    /// Random bytes inside the duress marker, so it decrypts to something checkable.
    pub const DURESS_MARKER_LEN: usize = 32;
    /// Format version, carried inside the ciphertext so the file has no cleartext header.
    pub const FORMAT_VERSION: u32 = 2;
    pub const SALT_LEN: usize = 16;
    pub const NONCE_LEN: usize = 24;
    pub const KEY_LEN: usize = 32;
    /// Argon2id parameters: memory in KiB, iterations, lanes.
    pub const ARGON2_MEMORY_KIB: u32 = 65536;
    pub const ARGON2_ITERATIONS: u32 = 3;
    pub const ARGON2_LANES: u32 = 1;
    /// Environment variable that supplies the passphrase for scripted use.
    pub const PASSPHRASE_ENV: &str = "UNHELD_PASSPHRASE";
    /// The controlling terminal, for a process whose standard streams carry a protocol.
    pub const TTY: &str = "/dev/tty";
    /// Environment variable that overrides the profiles directory.
    pub const HOME_ENV: &str = "UNHELD_HOME";
    pub const HOME_DIR_NAME: &str = ".unheld";
}

/// Identity.
pub mod identity {
    /// Random bytes standing for an identity inside credentials, so introductions carry no name.
    pub const CREDENTIAL_ID_LEN: usize = 16;
}

/// Devices of one identity (L15).
pub mod device {
    /// Ed25519 public key length, the one signature scheme in `mls::CIPHERSUITE`.
    pub const KEY_LEN: usize = 32;
    pub const SIGNATURE_LEN: usize = 64;
    /// Version byte of the device certificate carried in every credential.
    pub const CERT_VERSION: u8 = 1;
    /// Version byte of a certificate that also carries a continuity statement from a previous
    /// identity key (L14).
    pub const CERT_VERSION_ROTATED: u8 = 2;
    /// Domain separator for the continuity statement the old identity key signs over the new.
    pub const ROTATE_DOMAIN: &[u8] = b"unheld rotate v1";
    /// Domain separator for certificate signatures and the enrolment seal.
    pub const DOMAIN: &[u8] = b"unheld device v1";
    /// Domain separator for the digits a new device shows its witness.
    pub const FP_DOMAIN: &[u8] = b"unheld device fp v1";
    /// Enrolment time is rounded down to this many seconds before it enters a certificate.
    pub const ENROLLED_AT_STEP: u64 = 86_400;
    /// Local name of the device that created the identity.
    pub const FIRST_NAME: &str = "first";
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

/// Groups above two.
pub mod group {
    /// Members, counting yourself, above which the carrier must deliver in order (L19).
    pub const SMALL: usize = 8;
    /// Members, counting yourself, below which a roster is a pairwise session, not a group.
    pub const MIN_MEMBERS: usize = 3;
    /// Prefix of the local name a joiner gives a group it was welcomed into.
    pub const JOINED_NAME_PREFIX: &str = "g-";
    /// Prefix shown before the key hash of a member nobody here has verified (L18).
    pub const UNVERIFIED_PREFIX: &str = "?";
}

/// Recovery shares (L21).
pub mod recovery {
    /// Version byte of a share.
    pub const SHARE_VERSION: u8 = 1;
    /// Fewest shares that may be needed to rebuild; one share would be a copy of the key.
    pub const MIN_THRESHOLD: u8 = 2;
    /// Local name of the device a recovery creates.
    pub const DEVICE_NAME: &str = "recovered";
    /// Signed and checked after a rebuild, so a wrong share is a refusal and not a wrong key.
    pub const PROBE: &[u8] = b"unheld recovery probe v1";
}

/// Framing of several MLS messages inside one blob.
pub mod frame {
    pub const COUNT_LEN: usize = 1;
    pub const LEN_LEN: usize = 4;
}
