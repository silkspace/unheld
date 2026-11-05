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

/// How a group member stands with you (L18). Only your own `verify` makes `Verified`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberTrust {
    /// You compared the fingerprint with this person.
    Verified,
    /// You have their introduction and have not compared it.
    Pending,
    /// Their key differs from the one you verified.
    Changed,
    /// You never met them; the group's admin put them in the roster.
    Vouched,
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
    #[error("carrier holds nothing to open")]
    NothingToOpen,
    #[error("carrier could not be read or written")]
    CarrierIo,
    #[error("carrier skipped from {0} to {1}: a blob between them was not delivered")]
    Gap(u64, u64),
    #[error("carrier refused: {0}")]
    CarrierRefused(&'static str),
    #[error("empty message")]
    EmptyMessage,
    #[error("duress passphrase must differ from the vault passphrase")]
    DuressSame,
    #[error("sender is not a verified peer")]
    UnknownSender,
    #[error("no session for this message")]
    UnknownSession,
    #[error("could not open: already opened, outside the tolerance window, or altered in transit")]
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
    #[error("a group of {0} needs an ordered carrier, and file, clipboard and pipes are not; the bound here is {1}")]
    NeedsOrder(usize, usize),
    #[error("a group needs at least {0} members counting you; two people is a session")]
    TooSmall(usize),
    #[error("unknown group")]
    UnknownGroup,
    #[error("a group with this name exists")]
    GroupExists,
    #[error("only the group's admin changes its roster")]
    NotAdmin,
    #[error("roster change refused: its sender has no right to change this roster")]
    NoRight,
    #[error("no such member in this group")]
    NotMember,
    #[error("enrolment request is malformed")]
    BadRequest,
    #[error("enrolment is malformed, not for this device, or its certificate does not verify")]
    BadEnrolment,
    #[error("this vault is not a device waiting to be enrolled")]
    NotPending,
    #[error("a device with this name or key is already enrolled")]
    DeviceExists,
    #[error("introduction is not from an enrolled device of this identity")]
    NotADevice,
    #[error("no such device")]
    UnknownDevice,
    #[error("a device cannot revoke itself; revoke it from another")]
    ThisDevice,
    #[error("vault was written by an older build and this one does not read it")]
    VaultOld,
    #[error("key change refused: no continuity statement from the key that was verified")]
    NoContinuity,
    #[error("share is malformed, from a different split, or altered")]
    BadShare,
    #[error("this split needs {0} shares to rebuild the identity")]
    NotEnoughShares(usize),
    #[error("at least {0} shares must be needed, and no more than there are")]
    BadThreshold(u8),
}
