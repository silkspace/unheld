//! Every closed set, as an enum.

use serde::{Deserialize, Serialize};

/// Where a contact stands. Only `Verified` can be sent to (L3, L14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerState {
    /// An introduction was imported and nobody has compared the fingerprint.
    Pending,
    /// The pairwise fingerprint was compared and matched.
    Verified,
    /// The public key differs from the one that was verified.
    Changed,
}

/// Every way a verb refuses. Never carries plaintext or key material.
#[derive(Debug, thiserror::Error)]
pub enum Refuse {
    #[error("no identity in this vault")]
    NoIdentity,
    #[error("an identity already exists in this vault")]
    IdentityExists,
    #[error("unknown peer")]
    UnknownPeer,
    #[error("peer is not verified; run `verify` and compare the digits")]
    Unverified,
    #[error("peer's key has changed; run `verify` again")]
    Changed,
    #[error("fingerprint not confirmed")]
    NotConfirmed,
    #[error("peer has no unused introduction; ask for a fresh one")]
    NoIntro,
    #[error("introduction is malformed or its signature does not verify")]
    BadIntro,
    #[error("blob is malformed")]
    BadBlob,
    #[error("sender is not a verified peer")]
    UnknownSender,
    #[error("no session for this message")]
    UnknownSession,
    #[error("message was already opened, or arrived outside the tolerance window")]
    Replay,
    #[error("vault could not be opened: wrong passphrase or damaged file")]
    VaultLocked,
    #[error("no vault for this profile; create one with `id new <name>` or pass `--profile <name>`")]
    NoVault,
    #[error("vault i/o failed")]
    VaultIo,
    #[error("protocol error")]
    Protocol,
    #[error("payload exceeds the largest bucket")]
    TooLarge,
}
