#![forbid(unsafe_code)]
//! The endpoint: identity, introduction, verification, sessions over Messaging Layer Security,
//! and the encrypted vault. Every verb is total and fails closed with a `Refuse` that carries
//! neither plaintext nor key material (KERNEL.md).

pub mod config;
mod device;
mod group;
mod recovery;
pub mod vault;
pub mod vocab;

pub use device::{Attach, Device, Enrolment, Request};
pub use group::{Member, Roster};
pub use recovery::Share;

use base64::Engine as _;
use openmls::prelude::*;
use device::{leaf_identity, DeviceRecord, PendingDevice};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Deserialize as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use unheld_blob::Blob;
use vocab::{MemberTrust, PeerState, Refuse};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// What the vault remembers, besides the MLS storage map.
#[derive(Serialize, Deserialize, Default)]
struct State {
    /// Format version, inside the ciphertext (see `vault`).
    #[serde(default)]
    version: u32,
    identity: Option<IdentityRecord>,
    peers: BTreeMap<String, PeerRecord>,
    /// Groups above two, by local name.
    #[serde(default)]
    groups: BTreeMap<String, GroupRecord>,
    /// A device waiting to be enrolled, before this vault has an identity.
    #[serde(default)]
    pending: Option<PendingDevice>,
    /// Sessions the enrolment announced, so their welcomes land under the right names.
    #[serde(default)]
    expected: Vec<(Vec<u8>, Expected)>,
    /// The OpenMLS storage, base64 key and value pairs.
    storage: Vec<(String, String)>,
}

/// What a session announced at enrolment is.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) enum Expected {
    Pair(String),
    Group { admin: Vec<u8>, name: String },
}

#[derive(Serialize, Deserialize, Clone)]
struct IdentityRecord {
    /// The local name. Never leaves the vault.
    name: String,
    /// The identity key, the one peers verify. Its private half is in the MLS storage.
    signature_public: Vec<u8>,
    /// This device's key, the one on every leaf this device holds (L15).
    device_public: Vec<u8>,
    device_name: String,
    /// This device's certificate: the content of every credential this device presents.
    cert: Vec<u8>,
    /// Every device of this identity, by local name, this one included.
    devices: BTreeMap<String, DeviceRecord>,
    /// The session among this identity's devices alone, once there are two.
    ring: Option<Vec<u8>>,
    /// Identity keys this was before each rotation, oldest first (L14).
    #[serde(default)]
    previous: Vec<Vec<u8>>,
    /// Sessions whose leaf still carries an old credential of ours, updated on next send.
    #[serde(default)]
    needs_update: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct PeerRecord {
    /// The peer's identity key as last seen; `Changed` until verified again after a rotation.
    signature_public: Vec<u8>,
    /// Identity keys this peer held before, so a device of theirs not yet updated is still them.
    #[serde(default)]
    previous: Vec<Vec<u8>>,
    state: PeerState,
    /// Their unused introduction (a serialised key package), consumed when a session starts.
    intro: Option<Vec<u8>>,
    /// Sessions with this peer, by group id.
    groups: Vec<Vec<u8>>,
    /// Whether the person has let an agent read and send with this peer (docs/decisions/007).
    #[serde(default)]
    agent: bool,
}

/// A group above two. The roster itself lives in the MLS group; this remembers the local name
/// and who may change the roster (docs/decisions/003-groups.md).
#[derive(Serialize, Deserialize, Clone)]
struct GroupRecord {
    group_id: Vec<u8>,
    /// Signature key of the one member whose commits may change the roster (L16).
    admin: Vec<u8>,
}

/// A contact the fingerprint ceremony has admitted. Constructed by `verify` alone (L3).
#[derive(Debug, Clone, Serialize)]
pub struct Peer {
    pub name: String,
    pub state: PeerState,
    pub fingerprint_prefix: String,
    pub sessions: usize,
    pub has_intro: bool,
    /// The person has let an agent read and send with this peer through `unheld mcp`.
    pub agent_access: bool,
}

/// A signed public bundle to hand over out of band.
#[derive(Debug, Clone)]
pub struct Intro(pub Vec<u8>);

impl Intro {
    pub fn to_text(&self) -> String {
        B64.encode(&self.0)
    }
    pub fn from_text(s: &str) -> Result<Intro, Refuse> {
        B64.decode(s.trim()).map(Intro).map_err(|_| Refuse::BadIntro)
    }
}

/// The pairwise safety number, as spoken digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint(pub String);

impl Fingerprint {
    pub fn spoken(&self) -> String {
        self.0
            .as_bytes()
            .chunks(config::fp::GROUP)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// A message that `open` produced, or a roster change every member gets to see (L16).
#[derive(Debug, Clone, Serialize)]
pub struct Opened {
    /// The sender: a peer's name, or `?` and a key hash for a member you never verified.
    pub from: String,
    /// How the sender stands with you (L18).
    pub trust: MemberTrust,
    /// For a sender you never verified, the admin who put them in the roster.
    pub vouched_by: Option<String>,
    /// The local group name when the message came through a group.
    pub group: Option<String>,
    pub body: Vec<u8>,
    pub session_started: bool,
    /// A roster change, in words, when this part was a commit.
    pub change: Option<String>,
    /// Where the sender asks that your next blobs to them be put, in the words of their carrier.
    /// The core carries it and never reads it; the client hands it to the carrier it names.
    pub moved_to: Option<String>,
}

impl Opened {
    fn pairwise(from: String, body: Vec<u8>, session_started: bool) -> Opened {
        Opened { from, trust: MemberTrust::Verified, vouched_by: None, group: None, body, session_started, change: None, moved_to: None }
    }
}

/// One blob and who it is for, when a verb writes to more than one set of readers.
#[derive(Debug, Clone)]
pub struct Outbound {
    pub to: Target,
    pub blob: Blob,
}

/// The readers of an outbound blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Target {
    /// A peer, on the pairwise session.
    Peer(String),
    /// Every member of a group.
    Group(String),
    /// This identity's other devices.
    Ring,
    /// The device just enrolled.
    Device,
}

impl Target {
    /// A short word for the carrier that will hold the blob.
    pub fn label(&self) -> String {
        match self {
            Target::Peer(n) | Target::Group(n) => n.clone(),
            Target::Ring => "ring".to_owned(),
            Target::Device => "device".to_owned(),
        }
    }
}

/// An unlocked vault with its MLS provider. Dropping it saves nothing; call `save`.
pub struct Core {
    provider: OpenMlsRustCrypto,
    state: State,
    path: PathBuf,
    passphrase: String,
}

fn vault_path(dir: &Path) -> PathBuf {
    dir.join(config::vault::FILE_NAME)
}

fn mls_err<E: std::fmt::Debug>(_e: E) -> Refuse {
    Refuse::Protocol
}

/// How every session is created: ratchet tree in the welcome, bounded out-of-order tolerance (L13).
pub(crate) fn group_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(config::mls::CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            config::mls::OUT_OF_ORDER_TOLERANCE,
            config::mls::MAX_FORWARD_DISTANCE,
        ))
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            config::mls::OUT_OF_ORDER_TOLERANCE,
            config::mls::MAX_FORWARD_DISTANCE,
        ))
        .build()
}

impl Core {
    /// A vault with nothing in it yet. Refuses if one exists.
    fn empty(dir: &Path, passphrase: &str) -> Result<Core, Refuse> {
        std::fs::create_dir_all(dir).map_err(|_| Refuse::VaultIo)?;
        let path = vault_path(dir);
        if path.exists() {
            return Err(Refuse::IdentityExists);
        }
        let state = State { version: config::vault::FORMAT_VERSION, ..State::default() };
        Ok(Core { provider: OpenMlsRustCrypto::default(), state, path, passphrase: passphrase.to_owned() })
    }

    /// `gen`: create a vault with a fresh identity on its first device. Refuses if one exists.
    pub fn create(dir: &Path, passphrase: &str, name: &str) -> Result<Core, Refuse> {
        let mut core = Core::empty(dir, passphrase)?;
        let identity = SignatureKeyPair::new(config::mls::CIPHERSUITE.signature_algorithm()).map_err(mls_err)?;
        identity.store(core.provider.storage()).map_err(mls_err)?;
        let device = SignatureKeyPair::new(config::mls::CIPHERSUITE.signature_algorithm()).map_err(mls_err)?;
        device.store(core.provider.storage()).map_err(mls_err)?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let cert = device::Cert::issue(&identity, device.public(), now)?;
        let mut devices = BTreeMap::new();
        devices.insert(
            config::device::FIRST_NAME.to_owned(),
            DeviceRecord { public: device.to_public_vec(), enrolled_at: cert.enrolled_at, revoked: false },
        );
        core.state.identity = Some(IdentityRecord {
            name: name.to_owned(),
            signature_public: identity.to_public_vec(),
            device_public: device.to_public_vec(),
            device_name: config::device::FIRST_NAME.to_owned(),
            cert: cert.encode(),
            devices,
            ring: None,
            previous: Vec::new(),
            needs_update: Vec::new(),
        });
        core.save()?;
        Ok(core)
    }

    /// `unlock`: open an existing vault.
    pub fn unlock(dir: &Path, passphrase: &str) -> Result<Core, Refuse> {
        let path = vault_path(dir);
        if !path.exists() {
            return Err(Refuse::NoVault);
        }
        let plain = match vault::open_from_file(&path, passphrase) {
            Ok(p) => p,
            Err(e) => {
                // A duress passphrase destroys the vault and answers exactly as a wrong one would.
                if duress_matches(dir, passphrase) {
                    wipe(dir)?;
                }
                return Err(e);
            }
        };
        let version: VersionOnly = serde_json::from_slice(&plain).map_err(|_| Refuse::VaultLocked)?;
        if version.version < config::vault::FORMAT_VERSION {
            return Err(Refuse::VaultOld);
        }
        let state: State = serde_json::from_slice(&plain).map_err(|_| Refuse::VaultLocked)?;
        if state.version > config::vault::FORMAT_VERSION {
            return Err(Refuse::VaultLocked);
        }
        let provider = OpenMlsRustCrypto::default();
        {
            let mut map = provider.storage().values.write().map_err(|_| Refuse::Protocol)?;
            for (k, v) in &state.storage {
                let k = B64.decode(k).map_err(|_| Refuse::VaultLocked)?;
                let v = B64.decode(v).map_err(|_| Refuse::VaultLocked)?;
                map.insert(k, v);
            }
        }
        Ok(Core { provider, state, path, passphrase: passphrase.to_owned() })
    }

    /// `lock`: write the vault. The only path by which state reaches disk.
    pub fn save(&mut self) -> Result<(), Refuse> {
        let map: HashMap<Vec<u8>, Vec<u8>> = {
            let guard = self.provider.storage().values.read().map_err(|_| Refuse::Protocol)?;
            guard.clone()
        };
        self.state.storage = map
            .iter()
            .map(|(k, v)| (B64.encode(k), B64.encode(v)))
            .collect();
        let plain = serde_json::to_vec(&self.state).map_err(|_| Refuse::Protocol)?;
        vault::seal_to_file(&self.path, &self.passphrase, &plain)
    }

    fn identity(&self) -> Result<&IdentityRecord, Refuse> {
        self.state.identity.as_ref().ok_or(Refuse::NoIdentity)
    }

    /// This device's key: what signs every leaf and every message this device sends.
    fn signer(&self) -> Result<SignatureKeyPair, Refuse> {
        let id = self.identity()?;
        SignatureKeyPair::read(self.provider.storage(), &id.device_public, config::mls::CIPHERSUITE.signature_algorithm())
            .ok_or(Refuse::NoIdentity)
    }

    /// The identity key: what signs device certificates and nothing else.
    fn identity_signer(&self) -> Result<SignatureKeyPair, Refuse> {
        let id = self.identity()?;
        SignatureKeyPair::read(self.provider.storage(), &id.signature_public, config::mls::CIPHERSUITE.signature_algorithm())
            .ok_or(Refuse::NoIdentity)
    }

    /// This device's credential: its certificate under the identity key, and its own key.
    fn credential_with_key(&self) -> Result<CredentialWithKey, Refuse> {
        let id = self.identity()?;
        Ok(CredentialWithKey {
            credential: BasicCredential::new(id.cert.clone()).into(),
            signature_key: id.device_public.clone().into(),
        })
    }

    /// A fresh key package, serialised.
    fn key_package_bytes(&self) -> Result<Vec<u8>, Refuse> {
        let signer = self.signer()?;
        let cwk = self.credential_with_key()?;
        let bundle = KeyPackage::builder().build(config::mls::CIPHERSUITE, &self.provider, &signer, cwk).map_err(mls_err)?;
        let out: MlsMessageOut = bundle.into();
        out.to_bytes().map_err(mls_err)
    }

    fn load_gid(&self, gid: &[u8]) -> Result<MlsGroup, Refuse> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(gid))
            .map_err(mls_err)?
            .ok_or(Refuse::UnknownSession)
    }

    /// The identity a group member belongs to, if their certificate holds.
    pub(crate) fn member_identity(&self, m: &openmls::prelude::Member) -> Option<Vec<u8>> {
        leaf_identity(&self.provider, &m.credential, &m.signature_key)
    }

    pub fn name(&self) -> Result<&str, Refuse> {
        Ok(&self.identity()?.name)
    }

    /// Short public fingerprint of this identity alone, for display. Not the pairwise number.
    pub fn own_fingerprint_prefix(&self) -> Result<String, Refuse> {
        Ok(prefix(&self.identity()?.signature_public))
    }

    /// `intro`: a fresh signed key package to hand over out of band.
    pub fn intro(&mut self) -> Result<Intro, Refuse> {
        let bytes = self.key_package_bytes()?;
        self.save()?;
        Ok(Intro(bytes))
    }

    /// Stage a peer from their introduction. The peer is `Pending` until `verify`. The identity
    /// staged is the one the introduction's device certificate names, and the certificate must
    /// hold, so a peer is a person and not one of their devices.
    pub fn import(&mut self, name: &str, intro: &Intro) -> Result<Peer, Refuse> {
        let kp = parse_key_package(&self.provider, &intro.0)?;
        let leaf = kp.leaf_node();
        let their_pub = leaf_identity(&self.provider, leaf.credential(), leaf.signature_key().as_slice()).ok_or(Refuse::BadIntro)?;
        let state = match self.state.peers.get(name) {
            Some(existing) if existing.signature_public != their_pub => PeerState::Changed,
            Some(existing) => existing.state,
            None => PeerState::Pending,
        };
        let previous = self.state.peers.get(name).map(|p| p.previous.clone()).unwrap_or_default();
        self.state.peers.insert(
            name.to_owned(),
            PeerRecord {
                signature_public: their_pub,
                previous,
                state,
                intro: Some(intro.0.clone()),
                agent: self.state.peers.get(name).map(|p| p.agent).unwrap_or(false),
                groups: self
                    .state
                    .peers
                    .get(name)
                    .map(|p| p.groups.clone())
                    .unwrap_or_default(),
            },
        );
        self.save()?;
        self.peer(name)
    }

    /// The pairwise safety number with `name`, identical on both sides.
    pub fn fingerprint(&self, name: &str) -> Result<Fingerprint, Refuse> {
        let mine = &self.identity()?.signature_public;
        let theirs = &self.state.peers.get(name).ok_or(Refuse::UnknownPeer)?.signature_public;
        Ok(pairwise(mine, theirs))
    }

    /// `verify`: the only way a peer becomes `Verified` (L3). `confirmed` is the human's answer.
    pub fn verify(&mut self, name: &str, confirmed: bool) -> Result<Peer, Refuse> {
        if !confirmed {
            return Err(Refuse::NotConfirmed);
        }
        let rec = self.state.peers.get_mut(name).ok_or(Refuse::UnknownPeer)?;
        rec.state = PeerState::Verified;
        self.save()?;
        self.peer(name)
    }

    pub fn peer(&self, name: &str) -> Result<Peer, Refuse> {
        let rec = self.state.peers.get(name).ok_or(Refuse::UnknownPeer)?;
        Ok(Peer {
            name: name.to_owned(),
            state: rec.state,
            fingerprint_prefix: prefix(&rec.signature_public),
            sessions: rec.groups.len(),
            has_intro: rec.intro.is_some(),
            agent_access: rec.agent,
        })
    }

    /// Let an agent read and send with this peer through `unheld mcp`, or stop letting it. The
    /// person's decision, made at the command line and nowhere else (docs/decisions/007).
    pub fn grant_agent(&mut self, name: &str, granted: bool) -> Result<Peer, Refuse> {
        let rec = self.state.peers.get_mut(name).ok_or(Refuse::UnknownPeer)?;
        rec.agent = granted;
        self.save()?;
        self.peer(name)
    }

    pub fn peers(&self) -> Vec<Peer> {
        self.state
            .peers
            .keys()
            .filter_map(|n| self.peer(n).ok())
            .collect()
    }

    /// `seal`: encrypt `body` to a verified peer, starting a session if none exists.
    pub fn seal(&mut self, name: &str, body: &[u8]) -> Result<Blob, Refuse> {
        self.seal_to(name, body, None)
    }

    /// `seal`, carrying beside the body where the peer should put their next blobs to you: your
    /// carrier's words for a new queue, which the core never reads (L7).
    pub fn seal_moved(&mut self, name: &str, body: &[u8], moved_to: &str) -> Result<Blob, Refuse> {
        self.seal_to(name, body, Some(moved_to))
    }

    fn seal_to(&mut self, name: &str, body: &[u8], moved_to: Option<&str>) -> Result<Blob, Refuse> {
        let rec = self.state.peers.get(name).ok_or(Refuse::UnknownPeer)?.clone();
        match rec.state {
            PeerState::Verified => {}
            PeerState::Changed => return Err(Refuse::Changed),
            PeerState::Pending => return Err(Refuse::Unverified),
        }
        let signer = self.signer()?;
        let mut parts: Vec<Vec<u8>> = Vec::new();

        let mut group = match rec.groups.last() {
            Some(gid) => MlsGroup::load(self.provider.storage(), &GroupId::from_slice(gid))
                .map_err(mls_err)?
                .ok_or(Refuse::UnknownSession)?,
            None => {
                let intro = rec.intro.as_ref().ok_or(Refuse::NoIntro)?;
                let kp = parse_key_package(&self.provider, intro)?;
                let cwk = self.credential_with_key()?;
                let mut group = MlsGroup::new(&self.provider, &signer, &group_config(), cwk).map_err(mls_err)?;
                let (_commit, welcome, _info) = group
                    .add_members(&self.provider, &signer, core::slice::from_ref(&kp))
                    .map_err(mls_err)?;
                group.merge_pending_commit(&self.provider).map_err(mls_err)?;
                parts.push(welcome.to_bytes().map_err(mls_err)?);
                let gid = group.group_id().as_slice().to_vec();
                let r = self.state.peers.get_mut(name).ok_or(Refuse::UnknownPeer)?;
                r.groups.push(gid);
                r.intro = None;
                group
            }
        };

        if let Some(update) = self.pending_update(&mut group)? {
            parts.push(update);
        }
        let msg = group
            .create_message(&self.provider, &signer, &pack_payload(body, moved_to)?)
            .map_err(mls_err)?;
        parts.push(msg.to_bytes().map_err(mls_err)?);
        let blob = Blob::pad(&frame(&parts)?).map_err(|_| Refuse::TooLarge)?;
        self.save()?;
        Ok(blob)
    }

    /// `open`: decrypt a blob. A welcome from an unverified sender is refused and its group deleted.
    pub fn open(&mut self, blob: &Blob) -> Result<Vec<Opened>, Refuse> {
        let inner = blob.unpad().map_err(|_| Refuse::BadBlob)?;
        let parts = unframe(&inner)?;
        let mut opened = Vec::new();
        for part in parts {
            let msg = MlsMessageIn::tls_deserialize_exact(&part).map_err(|_| Refuse::BadBlob)?;
            match msg.extract() {
                MlsMessageBodyIn::Welcome(welcome) => opened.push(self.join(welcome)?),
                MlsMessageBodyIn::PrivateMessage(pm) => opened.extend(self.receive(pm.into())?),
                MlsMessageBodyIn::PublicMessage(pm) => opened.extend(self.receive(pm.into())?),
                _ => return Err(Refuse::BadBlob),
            }
        }
        self.save()?;
        Ok(opened)
    }

    /// Join from a welcome. Its sender must be a peer you verified (L3, L16), or another device
    /// of your own identity bringing this one in; otherwise the group is deleted and nothing is
    /// kept. Two identities is a session with that peer; more is a group.
    fn join(&mut self, welcome: Welcome) -> Result<Opened, Refuse> {
        let staged = StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None)
            .map_err(|e| match e {
                WelcomeError::NoMatchingKeyPackage | WelcomeError::NoMatchingEncryptionKey => Refuse::Replay,
                _ => Refuse::Protocol,
            })?;
        let sender_leaf = staged.welcome_sender().map_err(mls_err)?;
        let sender_identity = leaf_identity(&self.provider, sender_leaf.credential(), sender_leaf.signature_key().as_slice());
        let mut group = staged.into_group(&self.provider).map_err(mls_err)?;
        let gid = group.group_id().as_slice().to_vec();
        let me = self.identity()?.signature_public.clone();
        // Everyone in the room, by identity; a leaf with no valid certificate belongs to nobody.
        let identities: Vec<Option<Vec<u8>>> = group.members().map(|m| self.member_identity(&m)).collect();
        if sender_identity.as_deref() == Some(me.as_slice()) {
            return self.join_as_device(group, gid, identities);
        }
        let Some(sender) = sender_identity.as_deref().and_then(|k| self.verified_peer(k)) else {
            group.delete(self.provider.storage()).map_err(mls_err)?;
            return Err(Refuse::UnknownSender);
        };
        let sender_key = sender_identity.unwrap_or_default();
        let mut distinct: Vec<Option<Vec<u8>>> = identities.clone();
        distinct.sort();
        distinct.dedup();
        let members = distinct.len();
        if members >= config::group::MIN_MEMBERS {
            let local = format!("{}{}", config::group::JOINED_NAME_PREFIX, prefix(&gid));
            self.state.groups.insert(local.clone(), GroupRecord { group_id: gid, admin: sender_key });
            let unverified = distinct.iter().filter(|k| self.member_label(k.as_deref().unwrap_or_default()).1 == MemberTrust::Vouched).count();
            return Ok(Opened {
                from: sender.clone(),
                trust: MemberTrust::Verified,
                vouched_by: None,
                group: Some(local),
                body: Vec::new(),
                session_started: true,
                change: Some(format!("{sender} welcomed you to a group of {members}; {unverified} of them you never verified")),
                moved_to: None,
            });
        }
        if let Some(r) = self.state.peers.get_mut(&sender) {
            r.groups.push(gid);
        }
        Ok(Opened::pairwise(sender, Vec::new(), true))
    }

    /// A welcome from another device of this identity: the ring, or a session that device is in
    /// and announced at enrolment. A session it did not announce is placed by its roster when
    /// that is unambiguous, and refused otherwise.
    fn join_as_device(&mut self, mut group: MlsGroup, gid: Vec<u8>, identities: Vec<Option<Vec<u8>>>) -> Result<Opened, Refuse> {
        let me = self.identity()?.signature_public.clone();
        let mut others: Vec<Vec<u8>> = identities.into_iter().flatten().filter(|k| k != &me).collect();
        others.sort();
        others.dedup();
        let device_name = self.identity()?.device_name.clone();
        let expected = self.expected(&gid);
        let (place, text) = match expected {
            Some(Expected::Pair(name)) if self.state.peers.contains_key(&name) => (Expected::Pair(name.clone()), format!("your session with {name} now reaches {device_name}")),
            Some(Expected::Group { admin, name }) => (Expected::Group { admin, name: name.clone() }, format!("the group {name} now reaches {device_name}")),
            _ if others.is_empty() => {
                if let Some(id) = self.state.identity.as_mut() {
                    id.ring = Some(gid);
                }
                return Ok(Opened { from: device_name.clone(), trust: MemberTrust::Verified, vouched_by: None, group: None, body: Vec::new(), session_started: true, change: Some(format!("{device_name} is now a device of this identity")), moved_to: None });
            }
            _ if others.len() == 1 => match self.verified_peer(&others[0]) {
                Some(name) => (Expected::Pair(name.clone()), format!("your session with {name} now reaches {device_name}")),
                None => {
                    group.delete(self.provider.storage()).map_err(mls_err)?;
                    return Err(Refuse::UnknownSender);
                }
            },
            _ => {
                group.delete(self.provider.storage()).map_err(mls_err)?;
                return Err(Refuse::UnknownSender);
            }
        };
        match place {
            Expected::Pair(name) => {
                if let Some(r) = self.state.peers.get_mut(&name) {
                    r.groups.push(gid);
                }
            }
            Expected::Group { admin, name } => {
                let local = if self.state.groups.contains_key(&name) || self.state.peers.contains_key(&name) {
                    format!("{}{}", config::group::JOINED_NAME_PREFIX, prefix(&gid))
                } else {
                    name
                };
                self.state.groups.insert(local, GroupRecord { group_id: gid, admin });
            }
        }
        Ok(Opened { from: device_name, trust: MemberTrust::Verified, vouched_by: None, group: None, body: Vec::new(), session_started: true, change: Some(text), moved_to: None })
    }

    /// Where a group id lives: a pairwise session with a peer, a named group, or the ring.
    fn locate(&self, gid: &[u8]) -> Option<Located> {
        if let Some((n, _)) = self.state.peers.iter().find(|(_, p)| p.groups.iter().any(|g| g == gid)) {
            return Some(Located::Pair(n.clone()));
        }
        if self.identity().ok().and_then(|i| i.ring.as_deref()) == Some(gid) {
            return Some(Located::Ring);
        }
        self.state
            .groups
            .iter()
            .find(|(_, g)| g.group_id == gid)
            .map(|(n, g)| Located::Group(n.clone(), g.clone()))
    }

    /// The name of a verified peer whose identity this is.
    fn verified_peer(&self, identity: &[u8]) -> Option<String> {
        self.state
            .peers
            .iter()
            .find(|(_, p)| p.signature_public == identity && p.state == PeerState::Verified)
            .map(|(n, _)| n.clone())
    }

    /// Process one message on a session, a group or the ring. A commit that changes a roster is
    /// merged only when its sender holds the right (L16): the admin may change anything, and any
    /// member may add or remove devices of their own identity, which changes no roster of people.
    /// Otherwise it is refused and nothing moves.
    fn receive(&mut self, pm: ProtocolMessage) -> Result<Option<Opened>, Refuse> {
        let gid = pm.group_id().as_slice().to_vec();
        let located = self.locate(&gid).ok_or(Refuse::UnknownSession)?;
        let mut group = self.load_gid(&gid)?;
        let processed = group
            .process_message(&self.provider, pm)
            .map_err(|e| match e {
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(_)) => Refuse::Replay,
                _ => Refuse::Protocol,
            })?;
        let sender = match processed.sender() {
            Sender::Member(idx) => group.member_at(*idx).ok_or(Refuse::UnknownSender)?,
            _ => return Err(Refuse::UnknownSender),
        };
        let sender_identity = self.member_identity(&sender).ok_or(Refuse::UnknownSender)?;
        let me = self.identity()?.signature_public.clone();
        let i_sent = self.is_me(&sender_identity);
        let (from, trust) = self.member_label(&sender_identity);
        let (group_name, admin) = match &located {
            Located::Pair(name) => {
                let known = self.state.peers.get(name).ok_or(Refuse::UnknownPeer)?;
                let is_peer = known.signature_public == sender_identity || known.previous.iter().any(|p| p == &sender_identity);
                if !(is_peer && known.state != PeerState::Pending) && !i_sent {
                    return Err(Refuse::UnknownSender);
                }
                (None, None)
            }
            Located::Ring => {
                if !i_sent {
                    return Err(Refuse::UnknownSender);
                }
                (None, Some(me.clone()))
            }
            Located::Group(gname, rec) => (Some(gname.clone()), Some(rec.admin.clone())),
        };
        let vouched_by = match (&located, trust) {
            (Located::Group(_, rec), MemberTrust::Vouched) => Some(self.member_label(&rec.admin).0),
            _ => None,
        };
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                if matches!(located, Located::Ring) {
                    self.receive_ring(&app.into_bytes())?;
                    return Ok(None);
                }
                let (body, moved_to) = unpack_payload(&app.into_bytes())?;
                Ok(Some(Opened { from, trust, vouched_by, group: group_name, body, session_started: false, change: None, moved_to }))
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                // A sender whose new leaf names another identity is rotating its key, and may do
                // so only with the old key's statement over the new one (L14).
                let rotation = commit
                    .update_path_leaf_node()
                    .and_then(|leaf| device::leaf_cert(&self.provider, leaf.credential(), leaf.signature_key().as_slice()))
                    .filter(|cert| cert.identity != sender_identity)
                    .map(|cert| match cert.continuity {
                        Some(c) if c.previous == sender_identity => Ok(cert.identity),
                        _ => Err(Refuse::NoContinuity),
                    })
                    .transpose()?;
                if let Some(new_key) = &rotation {
                    if i_sent && !self.is_me(new_key) {
                        return Err(Refuse::NoContinuity);
                    }
                }
                // Who comes and goes, by identity, before anything is merged.
                let added: Vec<Vec<u8>> = commit
                    .add_proposals()
                    .map(|a| {
                        let leaf = a.add_proposal().key_package().leaf_node();
                        leaf_identity(&self.provider, leaf.credential(), leaf.signature_key().as_slice()).unwrap_or_default()
                    })
                    .collect();
                let removed: Vec<Vec<u8>> = commit
                    .remove_proposals()
                    .filter_map(|r| group.member_at(r.remove_proposal().removed()))
                    .map(|m| self.member_identity(&m).unwrap_or_default())
                    .collect();
                let own_devices_only = added.iter().chain(&removed).all(|k| k == &sender_identity);
                let people_change = !own_devices_only;
                let is_admin = admin.as_deref() == Some(sender_identity.as_slice());
                if people_change && (!is_admin || matches!(located, Located::Pair(_))) {
                    return Err(Refuse::NoRight);
                }
                let me_removed = commit.self_removed();
                group.merge_staged_commit(&self.provider, *commit).map_err(mls_err)?;
                let rotated = match &rotation {
                    Some(new_key) if !i_sent => self.note_rotation(&located, &sender_identity, new_key),
                    _ => false,
                };
                let still_here = group.members().any(|m| self.member_identity(&m).map(|k| self.is_me(&k)).unwrap_or(false));
                let where_ = group_name.clone().map(|g| format!(" in {g}")).unwrap_or_default();
                let change = if rotated {
                    format!("{from} changed their key{where_}; verify again before sending to them")
                } else if me_removed && i_sent {
                    group.delete(self.provider.storage()).map_err(mls_err)?;
                    self.drop_session(&located);
                    format!("another device of yours revoked this one{where_}; those keys are deleted")
                } else if me_removed && !still_here {
                    group.delete(self.provider.storage()).map_err(mls_err)?;
                    self.drop_session(&located);
                    format!("{from} removed you{where_}; its keys are deleted")
                } else if me_removed {
                    group.delete(self.provider.storage()).map_err(mls_err)?;
                    self.drop_session(&located);
                    format!("{from} removed this device{where_}; your other devices stay")
                } else if own_devices_only && (!added.is_empty() || !removed.is_empty()) {
                    let mut parts = Vec::new();
                    if !added.is_empty() {
                        parts.push(format!("added {} device{}", added.len(), if added.len() == 1 { "" } else { "s" }));
                    }
                    if !removed.is_empty() {
                        parts.push(format!("removed {} device{}", removed.len(), if removed.len() == 1 { "" } else { "s" }));
                    }
                    format!("{from} {}{where_}", parts.join(" and "))
                } else if people_change {
                    let names = |ks: &[Vec<u8>]| ks.iter().map(|k| self.member_label(k).0).collect::<Vec<_>>().join(", ");
                    let mut parts = Vec::new();
                    if !added.is_empty() {
                        parts.push(format!("added {}", names(&added)));
                    }
                    if !removed.is_empty() {
                        parts.push(format!("removed {}", names(&removed)));
                    }
                    format!("{from} {}{where_}", parts.join(" and "))
                } else {
                    format!("{from} refreshed their keys{where_}")
                };
                if matches!(located, Located::Ring) {
                    return Ok(None);
                }
                Ok(Some(Opened { from, trust, vouched_by, group: group_name, body: Vec::new(), session_started: false, change: Some(change), moved_to: None }))
            }
            _ => Ok(None),
        }
    }

    /// A peer's leaf moved to a new identity with continuity from the old: the peer is `Changed`
    /// until verified again, and if they were a group's admin the right follows the key. True
    /// when a peer record changed.
    fn note_rotation(&mut self, located: &Located, old_key: &[u8], new_key: &[u8]) -> bool {
        if let Located::Group(gname, _) = located {
            if let Some(g) = self.state.groups.get_mut(gname) {
                if g.admin == old_key {
                    g.admin = new_key.to_vec();
                }
            }
        }
        let Some(p) = self.state.peers.values_mut().find(|p| p.signature_public == old_key) else { return false };
        p.previous.push(old_key.to_vec());
        p.signature_public = new_key.to_vec();
        p.state = PeerState::Changed;
        p.intro = None;
        true
    }

    /// Forget where a session lived once its keys are gone.
    fn drop_session(&mut self, located: &Located) {
        match located {
            Located::Pair(name) => {
                if let Some(r) = self.state.peers.get_mut(name) {
                    r.groups.retain(|_| false);
                }
            }
            Located::Group(gname, _) => {
                self.state.groups.remove(gname);
            }
            Located::Ring => {
                if let Some(i) = self.state.identity.as_mut() {
                    i.ring = None;
                }
            }
        }
    }
}

/// Where a group id lives.
enum Located {
    Pair(String),
    Group(String, GroupRecord),
    Ring,
}

/// Enough of a vault to read its format version before the rest is parsed.
#[derive(Deserialize)]
struct VersionOnly {
    #[serde(default)]
    version: u32,
}

/// What an outsider can read from one part of a blob without any key.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum OutsidePart {
    /// An MLS message: its session id prefix, epoch and content type are in the clear.
    Message { wire_format: String, group_id_prefix: String, epoch: u64, content_type: String },
    /// A welcome: the ciphersuite and the number of recipients are in the clear.
    Welcome { ciphersuite: String, recipients: usize },
    /// An introduction (a key package), which is public by design.
    Introduction,
    /// Bytes that parse as none of the above.
    Opaque,
}

/// Everything an outsider can read from a blob. Measured, not assumed (TRACE.md, L7).
#[derive(Debug, Clone, Serialize)]
pub struct Outside {
    pub bucket: usize,
    pub parts: Vec<OutsidePart>,
}

/// Read a blob the way a carrier would: no vault, no key.
pub fn inspect(blob: &Blob) -> Outside {
    let bucket = blob.len();
    let parts = match blob.unpad().ok().and_then(|inner| unframe(&inner).ok()) {
        None => vec![OutsidePart::Opaque],
        Some(parts) => parts
            .iter()
            .map(|p| match MlsMessageIn::tls_deserialize_exact(p) {
                Err(_) => OutsidePart::Opaque,
                Ok(m) => {
                    let wire_format = format!("{:?}", m.wire_format());
                    match m.extract() {
                        MlsMessageBodyIn::PrivateMessage(pm) => OutsidePart::Message {
                            wire_format,
                            group_id_prefix: prefix(pm.group_id().as_slice()),
                            epoch: pm.epoch().as_u64(),
                            content_type: format!("{:?}", pm.content_type()),
                        },
                        MlsMessageBodyIn::PublicMessage(pm) => OutsidePart::Message {
                            wire_format,
                            group_id_prefix: prefix(pm.group_id().as_slice()),
                            epoch: pm.epoch().as_u64(),
                            content_type: format!("{:?}", pm.content_type()),
                        },
                        MlsMessageBodyIn::Welcome(w) => OutsidePart::Welcome {
                            ciphersuite: format!("{:?}", w.ciphersuite()),
                            recipients: w.secrets().len(),
                        },
                        MlsMessageBodyIn::KeyPackage(_) => OutsidePart::Introduction,
                        _ => OutsidePart::Opaque,
                    }
                }
            })
            .collect(),
    };
    Outside { bucket, parts }
}

impl Core {
    /// `forget`: end every session with a peer and delete its keys. The peer and its
    /// verification stay; the next message starts a fresh session from a fresh introduction.
    pub fn forget(&mut self, name: &str) -> Result<usize, Refuse> {
        if let Some(g) = self.state.groups.get(name).cloned() {
            if let Some(mut group) = MlsGroup::load(self.provider.storage(), &GroupId::from_slice(&g.group_id)).map_err(mls_err)? {
                group.delete(self.provider.storage()).map_err(mls_err)?;
            }
            self.state.groups.remove(name);
            self.save()?;
            return Ok(1);
        }
        let rec = self.state.peers.get(name).ok_or(Refuse::UnknownPeer)?.clone();
        let mut ended = 0;
        for gid in &rec.groups {
            if let Some(mut g) = MlsGroup::load(self.provider.storage(), &GroupId::from_slice(gid)).map_err(mls_err)? {
                g.delete(self.provider.storage()).map_err(mls_err)?;
                ended += 1;
            }
        }
        if let Some(r) = self.state.peers.get_mut(name) {
            r.groups.clear();
        }
        self.save()?;
        Ok(ended)
    }

    /// Set a duress passphrase. Unlocking with it destroys the vault and answers as a wrong
    /// passphrase would, so the person demanding it learns nothing.
    pub fn set_duress(&self, duress: &str) -> Result<(), Refuse> {
        if duress == self.passphrase {
            return Err(Refuse::DuressSame);
        }
        let dir = self.path.parent().ok_or(Refuse::VaultIo)?;
        let mut marker = vec![0u8; config::vault::DURESS_MARKER_LEN];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut marker);
        vault::seal_to_file(&dir.join(config::vault::DURESS_FILE_NAME), duress, &marker)
    }
}

/// True when the duress marker exists and decrypts under this passphrase.
fn duress_matches(dir: &Path, passphrase: &str) -> bool {
    let p = dir.join(config::vault::DURESS_FILE_NAME);
    p.exists() && vault::open_from_file(&p, passphrase).is_ok()
}

/// `wipe`: overwrite and remove the vault and the duress marker. The vault key is derived from
/// the passphrase and never stored, so removing the ciphertext is what erasure means here.
pub fn wipe(dir: &Path) -> Result<(), Refuse> {
    for name in [config::vault::FILE_NAME, config::vault::DURESS_FILE_NAME] {
        let p = dir.join(name);
        if p.exists() {
            let len = std::fs::metadata(&p).map(|m| m.len() as usize).unwrap_or(0);
            let mut noise = vec![0u8; len];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut noise);
            let _ = std::fs::write(&p, &noise);
            std::fs::remove_file(&p).map_err(|_| Refuse::VaultIo)?;
        }
    }
    let _ = std::fs::remove_dir(dir);
    Ok(())
}

fn parse_key_package(provider: &OpenMlsRustCrypto, bytes: &[u8]) -> Result<KeyPackage, Refuse> {
    let msg = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| Refuse::BadIntro)?;
    match msg.extract() {
        MlsMessageBodyIn::KeyPackage(kp) => kp
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| Refuse::BadIntro),
        _ => Err(Refuse::BadIntro),
    }
}

/// Pairwise fingerprint over both public keys in canonical order, as decimal digits.
fn pairwise(a: &[u8], b: &[u8]) -> Fingerprint {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    digits_of(config::fp::DOMAIN, &[lo, hi])
}

/// Spoken digits over a domain and some keys, uniform by rejection sampling.
pub(crate) fn digits_of(domain: &[u8], keys: &[&[u8]]) -> Fingerprint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for k in keys {
        hasher.update(k);
    }
    let mut reader = hasher.finalize_xof();
    let mut digits = String::with_capacity(config::fp::DIGITS);
    let mut buf = [0u8; 1];
    while digits.len() < config::fp::DIGITS {
        reader.fill(&mut buf);
        if buf[0] < 250 {
            digits.push(char::from(b'0' + buf[0] % 10));
        }
    }
    Fingerprint(digits)
}

fn prefix(public: &[u8]) -> String {
    let hash = blake3::hash(public);
    let hex = hash.to_hex();
    hex.get(..config::fp::GROUP * 2).unwrap_or(&hex).to_owned() // slice-ok: display prefix of a hash
}

fn frame(parts: &[Vec<u8>]) -> Result<Vec<u8>, Refuse> {
    let count = u8::try_from(parts.len()).map_err(|_| Refuse::TooLarge)?;
    let mut out = vec![count];
    for p in parts {
        let len = u32::try_from(p.len()).map_err(|_| Refuse::TooLarge)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(p);
    }
    Ok(out)
}

/// The body and, when the sender has moved, their new address, as one framed plaintext.
pub(crate) fn pack_payload(body: &[u8], moved_to: Option<&str>) -> Result<Vec<u8>, Refuse> {
    let mut parts = vec![body.to_vec()];
    if let Some(to) = moved_to {
        parts.push(to.as_bytes().to_vec());
    }
    frame(&parts)
}

fn unpack_payload(bytes: &[u8]) -> Result<(Vec<u8>, Option<String>), Refuse> {
    let mut parts = unframe(bytes).map_err(|_| Refuse::Protocol)?.into_iter();
    let body = parts.next().ok_or(Refuse::Protocol)?;
    let moved_to = parts.next().map(|p| String::from_utf8(p).map_err(|_| Refuse::Protocol)).transpose()?;
    if parts.next().is_some() {
        return Err(Refuse::Protocol);
    }
    Ok((body, moved_to))
}

fn unframe(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Refuse> {
    let count = *bytes.first().ok_or(Refuse::BadBlob)? as usize;
    if count == 0 {
        return Err(Refuse::BadBlob);
    }
    let mut pos = config::frame::COUNT_LEN;
    let mut parts = Vec::with_capacity(count);
    for _ in 0..count {
        let len_bytes = bytes.get(pos..pos + config::frame::LEN_LEN).ok_or(Refuse::BadBlob)?;
        let len = u32::from_be_bytes(len_bytes.try_into().map_err(|_| Refuse::BadBlob)?) as usize;
        pos += config::frame::LEN_LEN;
        let part = bytes.get(pos..pos + len).ok_or(Refuse::BadBlob)?;
        parts.push(part.to_vec());
        pos += len;
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("unheld-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn two_parties_roundtrip_and_laws() {
        let a_dir = tmp("alice");
        let b_dir = tmp("bob");
        let mut alice = Core::create(&a_dir, "pw-a", "alice").unwrap();
        let mut bob = Core::create(&b_dir, "pw-b", "bob").unwrap();

        let ia = alice.intro().unwrap();
        let ib = bob.intro().unwrap();
        alice.import("bob", &ib).unwrap();
        bob.import("alice", &ia).unwrap();

        // L3: no send before verify.
        assert!(matches!(alice.seal("bob", b"hi"), Err(Refuse::Unverified)));
        // Pairwise fingerprint agrees on both sides.
        assert_eq!(alice.fingerprint("bob").unwrap(), bob.fingerprint("alice").unwrap());
        assert!(matches!(alice.verify("bob", false), Err(Refuse::NotConfirmed)));
        alice.verify("bob", true).unwrap();
        bob.verify("alice", true).unwrap();

        // L1 roundtrip, through a reopened vault on each side.
        let blob = alice.seal("bob", b"hello bob").unwrap();
        assert!(unheld_blob::config::BUCKETS.contains(&blob.len()));
        let mut bob = Core::unlock(&b_dir, "pw-b").unwrap();
        let got = bob.open(&blob).unwrap();
        assert_eq!(got.last().unwrap().body, b"hello bob");

        // Reply flows back on the same session.
        let reply = bob.seal("alice", b"hello alice").unwrap();
        let mut alice = Core::unlock(&a_dir, "pw-a").unwrap();
        let got = alice.open(&reply).unwrap();
        assert_eq!(got[0].body, b"hello alice");

        // L11: replay is refused.
        assert!(matches!(alice.open(&reply), Err(Refuse::Replay)));
        // L8: a tampered blob is refused with nothing partial.
        let mut bytes = blob.as_bytes().to_vec();
        if let Some(b) = bytes.get_mut(40) { *b ^= 1; }
        let tampered = Blob::from_bytes(bytes).unwrap();
        assert!(bob.open(&tampered).is_err());
        // Wrong passphrase is a locked vault.
        assert!(matches!(Core::unlock(&a_dir, "nope"), Err(Refuse::VaultLocked)));
        // The vault file has no cleartext header: its first bytes are the random salt.
        let v1 = std::fs::read(a_dir.join(config::vault::FILE_NAME)).unwrap();
        alice.save().unwrap();
        let v2 = std::fs::read(a_dir.join(config::vault::FILE_NAME)).unwrap();
        assert_ne!(&v1[..config::vault::SALT_LEN], &v2[..config::vault::SALT_LEN]);
        assert!(!v1.windows(6).any(|w| w == b"UNHELD" || w == b"alice\""));
    }

    #[test]
    fn changed_key_blocks_until_verified_again() {
        let a_dir = tmp("a14");
        let b_dir = tmp("b14");
        let b2_dir = tmp("b14-newphone");
        let mut alice = Core::create(&a_dir, "pw", "alice").unwrap();
        let mut bob = Core::create(&b_dir, "pw", "bob").unwrap();
        let mut bob_new = Core::create(&b2_dir, "pw", "bob").unwrap();
        alice.import("bob", &bob.intro().unwrap()).unwrap();
        alice.verify("bob", true).unwrap();
        assert_eq!(alice.peer("bob").unwrap().state, PeerState::Verified);
        // A new introduction under the same name with a different key demotes the peer (L14).
        let p = alice.import("bob", &bob_new.intro().unwrap()).unwrap();
        assert_eq!(p.state, PeerState::Changed);
        assert!(matches!(alice.seal("bob", b"hi"), Err(Refuse::Changed)));
        // Only a fresh comparison restores sending.
        alice.verify("bob", true).unwrap();
        assert!(alice.seal("bob", b"hi").is_ok());
    }

    /// L8: a blob that frames no message at all is refused, not opened as nothing.
    #[test]
    fn a_frame_with_no_parts_is_refused() {
        let dir = tmp("empty-frame");
        let mut core = Core::create(&dir, "pw", "alice").unwrap();
        let before = std::fs::read(dir.join(config::vault::FILE_NAME)).unwrap();
        let blob = Blob::pad(&[0]).unwrap();
        assert!(matches!(core.open(&blob), Err(Refuse::BadBlob)));
        // Nothing was opened, so nothing was written.
        assert_eq!(std::fs::read(dir.join(config::vault::FILE_NAME)).unwrap(), before);
    }

    #[test]
    fn introduction_carries_no_name() {
        let dir = tmp("nameless");
        let mut core = Core::create(&dir, "pw", "a-very-distinctive-name").unwrap();
        let intro = core.intro().unwrap();
        assert!(!intro.0.windows(23).any(|w| w == b"a-very-distinctive-name"));
    }

    #[test]
    fn what_an_outsider_can_read_is_exactly_this() {
        let a_dir = tmp("out-a");
        let b_dir = tmp("out-b");
        let mut alice = Core::create(&a_dir, "pw", "alice").unwrap();
        let mut bob = Core::create(&b_dir, "pw", "bob").unwrap();
        alice.import("bob", &bob.intro().unwrap()).unwrap();
        alice.verify("bob", true).unwrap();
        let first = alice.seal("bob", b"one").unwrap();
        let second = alice.seal("bob", b"two").unwrap();
        let o1 = inspect(&first);
        let o2 = inspect(&second);
        // The first blob shows a welcome for one recipient and an application message.
        assert!(matches!(o1.parts[0], OutsidePart::Welcome { recipients: 1, .. }));
        assert!(matches!(&o1.parts[1], OutsidePart::Message { content_type, .. } if content_type == "Application"));
        // Both blobs expose the same session id prefix: the linkage recorded in decision 002.
        let gid = |p: &OutsidePart| match p { OutsidePart::Message { group_id_prefix, .. } => group_id_prefix.clone(), _ => String::new() };
        assert_eq!(gid(&o1.parts[1]), gid(&o2.parts[0]));
        // Random bytes of bucket size read as opaque.
        let mut junk = vec![0u8; unheld_blob::config::BUCKETS[0]];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut junk);
        assert_eq!(inspect(&Blob::from_bytes(junk).unwrap()).parts, vec![OutsidePart::Opaque]);
    }

    #[test]
    fn forget_ends_sessions_and_wipe_erases() {
        let a_dir = tmp("f-a");
        let b_dir = tmp("f-b");
        let mut alice = Core::create(&a_dir, "pw", "alice").unwrap();
        let mut bob = Core::create(&b_dir, "pw", "bob").unwrap();
        alice.import("bob", &bob.intro().unwrap()).unwrap();
        alice.verify("bob", true).unwrap();
        bob.import("alice", &alice.intro().unwrap()).unwrap();
        bob.verify("alice", true).unwrap();
        let blob = alice.seal("bob", b"x").unwrap();
        bob.open(&blob).unwrap();
        assert_eq!(alice.peer("bob").unwrap().sessions, 1);
        // forget: the session is gone, the peer and its verification remain.
        assert_eq!(alice.forget("bob").unwrap(), 1);
        let p = alice.peer("bob").unwrap();
        assert_eq!((p.sessions, p.state), (0, PeerState::Verified));
        // Bob's next message to the old session cannot be opened by alice (L10).
        let late = bob.seal("alice", b"late").unwrap();
        assert!(matches!(alice.open(&late), Err(Refuse::UnknownSession)));
        // wipe: nothing is left on disk.
        wipe(&a_dir).unwrap();
        assert!(!a_dir.join(config::vault::FILE_NAME).exists());
        assert!(matches!(Core::unlock(&a_dir, "pw"), Err(Refuse::NoVault)));
    }

    #[test]
    fn duress_passphrase_wipes_and_looks_like_a_wrong_one() {
        let dir = tmp("duress");
        let core = Core::create(&dir, "pw", "alice").unwrap();
        assert!(matches!(core.set_duress("pw"), Err(Refuse::DuressSame)));
        core.set_duress("help").unwrap();
        // A wrong passphrase refuses and leaves the vault.
        assert!(matches!(Core::unlock(&dir, "nope"), Err(Refuse::VaultLocked)));
        assert!(dir.join(config::vault::FILE_NAME).exists());
        // The duress passphrase refuses with the same words and the vault is gone.
        assert!(matches!(Core::unlock(&dir, "help"), Err(Refuse::VaultLocked)));
        assert!(!dir.join(config::vault::FILE_NAME).exists());
        assert!(!dir.join(config::vault::DURESS_FILE_NAME).exists());
    }

    #[test]
    fn welcome_from_unverified_sender_is_refused() {
        let a_dir = tmp("mallory");
        let b_dir = tmp("victim");
        let mut mallory = Core::create(&a_dir, "pw", "mallory").unwrap();
        let mut victim = Core::create(&b_dir, "pw", "victim").unwrap();
        let iv = victim.intro().unwrap();
        mallory.import("victim", &iv).unwrap();
        mallory.verify("victim", true).unwrap();
        let blob = mallory.seal("victim", b"trust me").unwrap();
        // Victim never verified mallory: the session is refused and not kept.
        assert!(matches!(victim.open(&blob), Err(Refuse::UnknownSender)));
        assert!(victim.peers().is_empty());
    }
}
