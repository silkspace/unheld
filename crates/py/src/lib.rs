#![forbid(unsafe_code)]
//! `unheld`, the Python module: the core's verbs one to one, with the core's vocabulary.
//!
//! Python is the carrier here. A verb that seals returns `bytes` of one bucket size, a verb that
//! opens takes them back, and what the Python program does with the bytes in between is its own
//! transport. Keys never cross into Python: there is no verb that returns one, and a share from
//! `split` stays in Rust until the program asks for its text. Every verb that changes state
//! writes the vault before it returns, so a program that forgets to call `save` cannot roll a
//! ratchet back and open a message twice.

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::PathBuf;
use unheld_blob::Blob;
use unheld_core::vocab;

pyo3::create_exception!(
    unheld,
    Refused,
    PyException,
    "A verb refused. `reason` is the `Refuse` that says why; the message is one fixed sentence and never carries plaintext or key material."
);

/// Every way a verb refuses, mirroring the core's vocabulary. A refusal that carries numbers in
/// Rust puts them in the exception's message here.
#[pyclass(eq, eq_int, hash, frozen, module = "unheld")]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Refuse {
    NoIdentity,
    IdentityExists,
    UnknownPeer,
    Unverified,
    NoGrant,
    Changed,
    NotConfirmed,
    NoIntro,
    BadIntro,
    BadBlob,
    NothingToOpen,
    CarrierIo,
    Gap,
    CarrierRefused,
    EmptyMessage,
    DuressSame,
    UnknownSender,
    UnknownSession,
    Replay,
    VaultLocked,
    NoVault,
    VaultIo,
    Protocol,
    TooLarge,
    NeedsOrder,
    TooSmall,
    UnknownGroup,
    GroupExists,
    NotAdmin,
    NoRight,
    NotMember,
    BadRequest,
    BadEnrolment,
    NotPending,
    DeviceExists,
    NotADevice,
    UnknownDevice,
    ThisDevice,
    VaultOld,
    NoContinuity,
    BadShare,
    NotEnoughShares,
    BadThreshold,
}

fn reason(r: &vocab::Refuse) -> Refuse {
    use vocab::Refuse as R;
    match r {
        R::NoIdentity => Refuse::NoIdentity,
        R::IdentityExists => Refuse::IdentityExists,
        R::UnknownPeer => Refuse::UnknownPeer,
        R::Unverified => Refuse::Unverified,
        R::NoGrant => Refuse::NoGrant,
        R::Changed => Refuse::Changed,
        R::NotConfirmed => Refuse::NotConfirmed,
        R::NoIntro => Refuse::NoIntro,
        R::BadIntro => Refuse::BadIntro,
        R::BadBlob => Refuse::BadBlob,
        R::NothingToOpen => Refuse::NothingToOpen,
        R::CarrierIo => Refuse::CarrierIo,
        R::Gap(_, _) => Refuse::Gap,
        R::CarrierRefused(_) => Refuse::CarrierRefused,
        R::EmptyMessage => Refuse::EmptyMessage,
        R::DuressSame => Refuse::DuressSame,
        R::UnknownSender => Refuse::UnknownSender,
        R::UnknownSession => Refuse::UnknownSession,
        R::Replay => Refuse::Replay,
        R::VaultLocked => Refuse::VaultLocked,
        R::NoVault => Refuse::NoVault,
        R::VaultIo => Refuse::VaultIo,
        R::Protocol => Refuse::Protocol,
        R::TooLarge => Refuse::TooLarge,
        R::NeedsOrder(_, _) => Refuse::NeedsOrder,
        R::TooSmall(_) => Refuse::TooSmall,
        R::UnknownGroup => Refuse::UnknownGroup,
        R::GroupExists => Refuse::GroupExists,
        R::NotAdmin => Refuse::NotAdmin,
        R::NoRight => Refuse::NoRight,
        R::NotMember => Refuse::NotMember,
        R::BadRequest => Refuse::BadRequest,
        R::BadEnrolment => Refuse::BadEnrolment,
        R::NotPending => Refuse::NotPending,
        R::DeviceExists => Refuse::DeviceExists,
        R::NotADevice => Refuse::NotADevice,
        R::UnknownDevice => Refuse::UnknownDevice,
        R::ThisDevice => Refuse::ThisDevice,
        R::VaultOld => Refuse::VaultOld,
        R::NoContinuity => Refuse::NoContinuity,
        R::BadShare => Refuse::BadShare,
        R::NotEnoughShares(_) => Refuse::NotEnoughShares,
        R::BadThreshold(_) => Refuse::BadThreshold,
    }
}

/// The core's refusal as the Python exception, with `reason` set on the instance.
fn refused(py: Python<'_>, r: vocab::Refuse) -> PyErr {
    let err = Refused::new_err(r.to_string());
    if let Err(e) = err.value(py).setattr("reason", reason(&r)) {
        return e;
    }
    err
}

trait OrRefused<T> {
    fn or_refused(self, py: Python<'_>) -> PyResult<T>;
}

impl<T> OrRefused<T> for Result<T, vocab::Refuse> {
    fn or_refused(self, py: Python<'_>) -> PyResult<T> {
        self.map_err(|r| refused(py, r))
    }
}

fn blob(bytes: &[u8]) -> Result<Blob, vocab::Refuse> {
    Blob::from_bytes(bytes.to_vec()).map_err(|_| vocab::Refuse::BadBlob)
}

fn bytes<'py>(py: Python<'py>, b: &Blob) -> Bound<'py, PyBytes> {
    PyBytes::new(py, b.as_bytes())
}

/// Where a contact stands. Only `Verified` can be sent to (L3, L14).
#[pyclass(eq, eq_int, hash, frozen, module = "unheld")]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PeerState {
    Pending,
    Verified,
    Changed,
}

impl From<vocab::PeerState> for PeerState {
    fn from(s: vocab::PeerState) -> PeerState {
        match s {
            vocab::PeerState::Pending => PeerState::Pending,
            vocab::PeerState::Verified => PeerState::Verified,
            vocab::PeerState::Changed => PeerState::Changed,
        }
    }
}

/// How a group member stands with you (L18). Only your own `verify` makes `Verified`.
#[pyclass(eq, eq_int, hash, frozen, module = "unheld")]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum MemberTrust {
    Verified,
    Pending,
    Changed,
    Vouched,
}

impl From<vocab::MemberTrust> for MemberTrust {
    fn from(t: vocab::MemberTrust) -> MemberTrust {
        match t {
            vocab::MemberTrust::Verified => MemberTrust::Verified,
            vocab::MemberTrust::Pending => MemberTrust::Pending,
            vocab::MemberTrust::Changed => MemberTrust::Changed,
            vocab::MemberTrust::Vouched => MemberTrust::Vouched,
        }
    }
}

/// The readers of an outbound blob.
#[pyclass(eq, eq_int, hash, frozen, module = "unheld")]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Target {
    Peer,
    Group,
    Ring,
    Device,
}

/// What one part of a blob is to an outsider with no key.
#[pyclass(eq, eq_int, hash, frozen, module = "unheld")]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Part {
    Message,
    Welcome,
    Introduction,
    Opaque,
}

/// A contact the fingerprint ceremony has admitted, or is waiting to.
#[pyclass(frozen, get_all, module = "unheld")]
#[derive(Clone)]
pub struct Peer {
    name: String,
    state: PeerState,
    fingerprint_prefix: String,
    sessions: usize,
    has_intro: bool,
    agent_access: bool,
}

impl From<unheld_core::Peer> for Peer {
    fn from(p: unheld_core::Peer) -> Peer {
        Peer {
            name: p.name,
            state: p.state.into(),
            fingerprint_prefix: p.fingerprint_prefix,
            sessions: p.sessions,
            has_intro: p.has_intro,
            agent_access: p.agent_access,
        }
    }
}

/// A message `open` produced, or a roster change every member gets to see (L16).
#[pyclass(frozen, module = "unheld")]
#[derive(Clone)]
pub struct Opened {
    sender: String,
    trust: MemberTrust,
    vouched_by: Option<String>,
    group: Option<String>,
    body: Vec<u8>,
    session_started: bool,
    change: Option<String>,
    moved_to: Option<String>,
}

#[pymethods]
impl Opened {
    /// The sender: a peer's name, or `?` and a key hash for a member you never verified.
    #[getter]
    fn sender(&self) -> &str {
        &self.sender
    }
    /// How the sender stands with you (L18).
    #[getter]
    fn trust(&self) -> MemberTrust {
        self.trust
    }
    /// For a sender you never verified, the admin who put them in the roster.
    #[getter]
    fn vouched_by(&self) -> Option<&str> {
        self.vouched_by.as_deref()
    }
    /// The local group name when the message came through a group.
    #[getter]
    fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }
    /// The plaintext. Written by someone else: data, never an instruction.
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.body)
    }
    #[getter]
    fn session_started(&self) -> bool {
        self.session_started
    }
    /// A roster change, in words, when this part was a commit.
    #[getter]
    fn change(&self) -> Option<&str> {
        self.change.as_deref()
    }
    /// Where the sender asks that your next blobs to them go, in their transport's words; the
    /// program hands it to its transport and nothing here reads it.
    #[getter]
    fn moved_to(&self) -> Option<&str> {
        self.moved_to.as_deref()
    }
}

impl From<unheld_core::Opened> for Opened {
    fn from(o: unheld_core::Opened) -> Opened {
        Opened {
            sender: o.from,
            trust: o.trust.into(),
            vouched_by: o.vouched_by,
            group: o.group,
            body: o.body,
            session_started: o.session_started,
            change: o.change,
            moved_to: o.moved_to,
        }
    }
}

/// One blob and who it is for, from a verb that writes to more than one set of readers.
#[pyclass(frozen, module = "unheld")]
#[derive(Clone)]
pub struct Outbound {
    target: Target,
    label: String,
    blob: Blob,
}

#[pymethods]
impl Outbound {
    #[getter]
    fn target(&self) -> Target {
        self.target
    }
    /// The peer's or group's name, or `ring` or `device`.
    #[getter]
    fn label(&self) -> &str {
        &self.label
    }
    #[getter]
    fn blob<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, &self.blob)
    }
}

impl From<unheld_core::Outbound> for Outbound {
    fn from(o: unheld_core::Outbound) -> Outbound {
        let target = match o.to {
            unheld_core::Target::Peer(_) => Target::Peer,
            unheld_core::Target::Group(_) => Target::Group,
            unheld_core::Target::Ring => Target::Ring,
            unheld_core::Target::Device => Target::Device,
        };
        Outbound { target, label: o.to.label(), blob: o.blob }
    }
}

/// One member of a group as this vault sees them.
#[pyclass(frozen, get_all, module = "unheld")]
#[derive(Clone)]
pub struct Member {
    label: String,
    trust: MemberTrust,
    is_admin: bool,
    is_me: bool,
    devices: usize,
}

/// A group and its roster, with the verification state of every member (L18).
#[pyclass(frozen, get_all, module = "unheld")]
#[derive(Clone)]
pub struct Roster {
    name: String,
    epoch: u64,
    admin: String,
    i_am_admin: bool,
    members: Vec<Member>,
}

impl From<unheld_core::Roster> for Roster {
    fn from(r: unheld_core::Roster) -> Roster {
        Roster {
            name: r.name,
            epoch: r.epoch,
            admin: r.admin,
            i_am_admin: r.i_am_admin,
            members: r
                .members
                .into_iter()
                .map(|m| Member { label: m.label, trust: m.trust.into(), is_admin: m.is_admin, is_me: m.is_me, devices: m.devices })
                .collect(),
        }
    }
}

/// The two blobs an `add` produces: a commit for the members, a welcome for the newcomer.
#[pyclass(frozen, module = "unheld")]
pub struct Added {
    for_group: Blob,
    for_newcomer: Blob,
}

#[pymethods]
impl Added {
    #[getter]
    fn for_group<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, &self.for_group)
    }
    #[getter]
    fn for_newcomer<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, &self.for_newcomer)
    }
}

/// What a device shows about itself.
#[pyclass(frozen, get_all, module = "unheld")]
#[derive(Clone)]
pub struct Device {
    name: String,
    fingerprint_prefix: String,
    enrolled_at: u64,
    is_this: bool,
    revoked: bool,
}

impl From<unheld_core::Device> for Device {
    fn from(d: unheld_core::Device) -> Device {
        Device { name: d.name, fingerprint_prefix: d.fingerprint_prefix, enrolled_at: d.enrolled_at, is_this: d.is_this, revoked: d.revoked }
    }
}

/// What an outsider can read from one part of a blob without any key.
#[pyclass(frozen, get_all, module = "unheld")]
#[derive(Clone)]
pub struct OutsidePart {
    kind: Part,
    wire_format: Option<String>,
    group_id_prefix: Option<String>,
    epoch: Option<u64>,
    content_type: Option<String>,
    ciphersuite: Option<String>,
    recipients: Option<usize>,
}

/// Everything an outsider can read from a blob. Measured, not assumed (L7).
#[pyclass(frozen, get_all, module = "unheld")]
#[derive(Clone)]
pub struct Outside {
    bucket: usize,
    parts: Vec<OutsidePart>,
}

impl From<unheld_core::Outside> for Outside {
    fn from(o: unheld_core::Outside) -> Outside {
        use unheld_core::OutsidePart as P;
        let blank = OutsidePart {
            kind: Part::Opaque,
            wire_format: None,
            group_id_prefix: None,
            epoch: None,
            content_type: None,
            ciphersuite: None,
            recipients: None,
        };
        let parts = o
            .parts
            .into_iter()
            .map(|p| match p {
                P::Message { wire_format, group_id_prefix, epoch, content_type } => OutsidePart {
                    kind: Part::Message,
                    wire_format: Some(wire_format),
                    group_id_prefix: Some(group_id_prefix),
                    epoch: Some(epoch),
                    content_type: Some(content_type),
                    ..blank.clone()
                },
                P::Welcome { ciphersuite, recipients } => {
                    OutsidePart { kind: Part::Welcome, ciphersuite: Some(ciphersuite), recipients: Some(recipients), ..blank.clone() }
                }
                P::Introduction => OutsidePart { kind: Part::Introduction, ..blank.clone() },
                P::Opaque => blank.clone(),
            })
            .collect();
        Outside { bucket: o.bucket, parts }
    }
}

/// One of `n` shares of the identity key (L21). The bytes stay in Rust, zeroised when the
/// object is collected, until `to_text` is called for the person who will hold it.
#[pyclass(frozen, module = "unheld")]
pub struct Share {
    inner: unheld_core::Share,
}

#[pymethods]
impl Share {
    /// A share the person typed or pasted back. Malformed text is refused.
    #[staticmethod]
    fn from_text(py: Python<'_>, text: &str) -> PyResult<Share> {
        Ok(Share { inner: unheld_core::Share::from_text(text).or_refused(py)? })
    }
    /// Which share this is.
    #[getter]
    fn index(&self) -> u8 {
        self.inner.index()
    }
    /// How many shares rebuild the key.
    #[getter]
    fn threshold(&self) -> u8 {
        self.inner.threshold()
    }
    /// The share as text, to show once and never store. Python cannot zeroise a `str`.
    fn to_text(&self) -> String {
        self.inner.to_text().to_string()
    }
}

/// An unlocked vault. Every verb that changes state writes the vault before it returns.
#[pyclass(module = "unheld")]
pub struct Core {
    inner: unheld_core::Core,
}

#[pymethods]
impl Core {
    /// `gen`: a new identity in a new vault under `dir`, locked with `passphrase` (L20).
    #[staticmethod]
    fn create(py: Python<'_>, dir: PathBuf, passphrase: &str, name: &str) -> PyResult<Core> {
        Ok(Core { inner: unheld_core::Core::create(&dir, passphrase, name).or_refused(py)? })
    }

    /// Open the vault under `dir`. A wrong passphrase and a damaged file are the same refusal.
    #[staticmethod]
    fn unlock(py: Python<'_>, dir: PathBuf, passphrase: &str) -> PyResult<Core> {
        Ok(Core { inner: unheld_core::Core::unlock(&dir, passphrase).or_refused(py)? })
    }

    /// A vault for a device that has no identity yet, and the request text it hands to a
    /// device that has one (L15).
    #[staticmethod]
    fn create_device(py: Python<'_>, dir: PathBuf, passphrase: &str) -> PyResult<(Core, String)> {
        let (core, request) = unheld_core::Core::create_device(&dir, passphrase).or_refused(py)?;
        Ok((Core { inner: core }, request.to_text()))
    }

    /// `join`: a vault on a new device holding the identity the shares rebuild (L21).
    #[staticmethod]
    fn recover(py: Python<'_>, dir: PathBuf, passphrase: &str, name: &str, shares: Vec<PyRef<'_, Share>>) -> PyResult<Core> {
        let shares: Vec<unheld_core::Share> = shares.iter().map(|s| s.inner.clone()).collect();
        Ok(Core { inner: unheld_core::Core::recover(&dir, passphrase, name, &shares).or_refused(py)? })
    }

    /// Write the vault. Every verb below that changes state already does this.
    fn save(&mut self, py: Python<'_>) -> PyResult<()> {
        self.inner.save().or_refused(py)
    }

    /// This identity's name.
    #[getter]
    fn name(&self, py: Python<'_>) -> PyResult<String> {
        Ok(self.inner.name().or_refused(py)?.to_owned())
    }

    /// The short form of this identity's fingerprint.
    #[getter]
    fn fingerprint_prefix(&self, py: Python<'_>) -> PyResult<String> {
        self.inner.own_fingerprint_prefix().or_refused(py)
    }

    /// `intro`: this identity's signed public bundle, as text, to hand over out of band.
    fn intro(&mut self, py: Python<'_>) -> PyResult<String> {
        Ok(self.inner.intro().or_refused(py)?.to_text())
    }

    /// Stage a peer from their introduction. The peer is `Pending` until `verify` (L3).
    fn import_intro(&mut self, py: Python<'_>, name: &str, intro: &str) -> PyResult<Peer> {
        let intro = unheld_core::Intro::from_text(intro).or_refused(py)?;
        Ok(self.inner.import(name, &intro).or_refused(py)?.into())
    }

    /// The pairwise safety number, as groups of digits to read aloud.
    fn fingerprint(&self, py: Python<'_>, name: &str) -> PyResult<String> {
        Ok(self.inner.fingerprint(name).or_refused(py)?.spoken())
    }

    /// `verify`: the one constructor of a `Verified` peer. `confirmed` is the human's answer to
    /// whether every group of digits matched; anything but `True` is refused (L3).
    fn verify(&mut self, py: Python<'_>, name: &str, confirmed: bool) -> PyResult<Peer> {
        Ok(self.inner.verify(name, confirmed).or_refused(py)?.into())
    }

    fn peer(&self, py: Python<'_>, name: &str) -> PyResult<Peer> {
        Ok(self.inner.peer(name).or_refused(py)?.into())
    }

    /// Let an agent read and send with this peer through `unheld mcp`, or stop letting it. The
    /// person's decision, never a program's on its own (docs/decisions/007).
    fn grant_agent(&mut self, py: Python<'_>, name: &str, granted: bool) -> PyResult<Peer> {
        Ok(self.inner.grant_agent(name, granted).or_refused(py)?.into())
    }

    fn peers(&self) -> Vec<Peer> {
        self.inner.peers().into_iter().map(Peer::from).collect()
    }

    /// `seal`: `body` to `name`, padded to a bucket. Refused unless the peer is `Verified` (L3,
    /// L4, L14). `moved_to` rides inside the encryption and tells the peer where your next blobs
    /// from them should go, in your transport's words (L7).
    #[pyo3(signature = (name, body, moved_to=None))]
    fn seal<'py>(&mut self, py: Python<'py>, name: &str, body: &[u8], moved_to: Option<&str>) -> PyResult<Bound<'py, PyBytes>> {
        let blob = match moved_to {
            Some(to) => self.inner.seal_moved(name, body, to),
            None => self.inner.seal(name, body),
        };
        Ok(bytes(py, &blob.or_refused(py)?))
    }

    /// `open`: every message or roster change one blob holds. A replayed, reflected or altered
    /// blob is refused (L11, L12, L13).
    fn open(&mut self, py: Python<'_>, blob_bytes: &[u8]) -> PyResult<Vec<Opened>> {
        let b = blob(blob_bytes).or_refused(py)?;
        Ok(self.inner.open(&b).or_refused(py)?.into_iter().map(Opened::from).collect())
    }

    /// `forget`: end every session with a peer, or leave a group, deleting the keys (L10).
    fn forget(&mut self, py: Python<'_>, name: &str) -> PyResult<usize> {
        self.inner.forget(name).or_refused(py)
    }

    /// A duress passphrase: unlocking with it destroys the vault and answers as a wrong
    /// passphrase would (L10).
    fn set_duress(&self, py: Python<'_>, duress: &str) -> PyResult<()> {
        self.inner.set_duress(duress).or_refused(py)
    }

    /// `start`: a group of verified peers with you as admin; the welcome every newcomer opens.
    /// `ordered` is your statement that your carrier delivers in order, which is what lets a
    /// group above the small bound form (L16, L19).
    fn group_new<'py>(&mut self, py: Python<'py>, name: &str, peers: Vec<String>, ordered: bool) -> PyResult<Bound<'py, PyBytes>> {
        let peers: Vec<&str> = peers.iter().map(String::as_str).collect();
        Ok(bytes(py, &self.inner.group_new(name, &peers, ordered).or_refused(py)?))
    }

    /// `add`: admin only; a commit for the members and a welcome for the newcomer (L16, L17).
    fn group_add(&mut self, py: Python<'_>, group: &str, peer: &str, ordered: bool) -> PyResult<Added> {
        let a = self.inner.group_add(group, peer, ordered).or_refused(py)?;
        Ok(Added { for_group: a.for_group, for_newcomer: a.for_newcomer })
    }

    /// `remove`: admin only; the commit after which the member opens nothing (L16, L17).
    fn group_remove<'py>(&mut self, py: Python<'py>, group: &str, member: &str) -> PyResult<Bound<'py, PyBytes>> {
        Ok(bytes(py, &self.inner.group_remove(group, member).or_refused(py)?))
    }

    /// `seal` to every member of a group (L4, L8, L18).
    fn group_seal<'py>(&mut self, py: Python<'py>, group: &str, body: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        Ok(bytes(py, &self.inner.group_seal(group, body).or_refused(py)?))
    }

    fn roster(&self, py: Python<'_>, group: &str) -> PyResult<Roster> {
        Ok(self.inner.roster(group).or_refused(py)?.into())
    }

    fn groups(&self) -> Vec<Roster> {
        self.inner.groups().into_iter().map(Roster::from).collect()
    }

    fn group_rename(&mut self, py: Python<'_>, old: &str, new: &str) -> PyResult<()> {
        self.inner.group_rename(old, new).or_refused(py)
    }

    /// The enrolment request again, for a device still waiting (L15).
    fn request(&self, py: Python<'_>) -> PyResult<String> {
        Ok(self.inner.request().or_refused(py)?.to_text())
    }

    /// `enroll`: on a device that has the identity. `confirmed` is the human's answer to whether
    /// the new device shows exactly the digits this one shows; nothing happens without it (L15).
    fn enroll(&mut self, py: Python<'_>, device_name: &str, request: &str, confirmed: bool) -> PyResult<String> {
        let request = unheld_core::Request::from_text(request).or_refused(py)?;
        Ok(self.inner.enroll(device_name, &request, confirmed).or_refused(py)?.to_text())
    }

    /// The digits a request's key makes, for the two screens to compare (L15).
    #[staticmethod]
    fn request_fingerprint(py: Python<'_>, request: &str) -> PyResult<String> {
        let request = unheld_core::Request::from_text(request).or_refused(py)?;
        Ok(request.fingerprint().or_refused(py)?.spoken())
    }

    /// On the new device: open the enrolment, become the identity, and return what to hand back.
    fn join_device(&mut self, py: Python<'_>, enrolment: &str) -> PyResult<String> {
        let enrolment = unheld_core::Enrolment::from_text(enrolment).or_refused(py)?;
        Ok(self.inner.join_device(&enrolment).or_refused(py)?.to_text())
    }

    /// On the witness: bring the new device into every session and group, one blob per set of
    /// readers (L15, L16).
    fn connect_device(&mut self, py: Python<'_>, attach: &str) -> PyResult<Vec<Outbound>> {
        let attach = unheld_core::Attach::from_text(attach).or_refused(py)?;
        Ok(self.inner.connect_device(&attach).or_refused(py)?.into_iter().map(Outbound::from).collect())
    }

    /// `remove` for a device: one commit per session; a device cannot revoke itself (L15).
    fn revoke_device(&mut self, py: Python<'_>, device_name: &str) -> PyResult<Vec<Outbound>> {
        Ok(self.inner.revoke_device(device_name).or_refused(py)?.into_iter().map(Outbound::from).collect())
    }

    fn devices(&self, py: Python<'_>) -> PyResult<Vec<Device>> {
        Ok(self.inner.devices().or_refused(py)?.into_iter().map(Device::from).collect())
    }

    /// `rotate`: new keys with a continuity statement; every peer shows `Changed` until they
    /// verify again (L14).
    fn rotate(&mut self, py: Python<'_>) -> PyResult<Vec<Outbound>> {
        Ok(self.inner.rotate().or_refused(py)?.into_iter().map(Outbound::from).collect())
    }

    /// `split`: `n` shares of the identity key, any `k` of which rebuild it. The vault is byte
    /// for byte what it was (L21).
    fn split(&self, py: Python<'_>, k: u8, n: u8) -> PyResult<Vec<Share>> {
        Ok(self.inner.split(k, n).or_refused(py)?.into_iter().map(|inner| Share { inner }).collect())
    }
}

/// `wipe`: overwrite and remove the vault under `dir` (L10).
#[pyfunction]
fn wipe(py: Python<'_>, dir: PathBuf) -> PyResult<()> {
    unheld_core::wipe(&dir).or_refused(py)
}

/// Read a blob the way a carrier would: no vault, no key (L7).
#[pyfunction]
fn inspect(py: Python<'_>, blob_bytes: &[u8]) -> PyResult<Outside> {
    let b = blob(blob_bytes).or_refused(py)?;
    Ok(unheld_core::inspect(&b).into())
}

#[pymodule(name = "unheld")]
fn unheld(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Core>()?;
    m.add_class::<Refuse>()?;
    m.add_class::<PeerState>()?;
    m.add_class::<MemberTrust>()?;
    m.add_class::<Target>()?;
    m.add_class::<Part>()?;
    m.add_class::<Peer>()?;
    m.add_class::<Opened>()?;
    m.add_class::<Outbound>()?;
    m.add_class::<Member>()?;
    m.add_class::<Roster>()?;
    m.add_class::<Added>()?;
    m.add_class::<Device>()?;
    m.add_class::<OutsidePart>()?;
    m.add_class::<Outside>()?;
    m.add_class::<Share>()?;
    m.add_function(wrap_pyfunction!(wipe, m)?)?;
    m.add_function(wrap_pyfunction!(inspect, m)?)?;
    m.add("Refused", m.py().get_type::<Refused>())?;
    m.add("BUCKETS", unheld_blob::config::BUCKETS.to_vec())?;
    m.add("SMALL_GROUP", unheld_core::config::group::SMALL)?;
    Ok(())
}
