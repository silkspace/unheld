#![forbid(unsafe_code)]
//! The endpoint: identity, introduction, verification, sessions over Messaging Layer Security,
//! and the encrypted vault. Every verb is total and fails closed with a `Refuse` that carries
//! neither plaintext nor key material (KERNEL.md).

pub mod config;
pub mod vault;
pub mod vocab;

use base64::Engine as _;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Deserialize as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use unheld_blob::Blob;
use vocab::{PeerState, Refuse};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// What the vault remembers, besides the MLS storage map.
#[derive(Serialize, Deserialize, Default)]
struct State {
    /// Format version, inside the ciphertext (see `vault`).
    #[serde(default)]
    version: u32,
    identity: Option<IdentityRecord>,
    peers: BTreeMap<String, PeerRecord>,
    /// The OpenMLS storage, base64 key and value pairs.
    storage: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize, Clone)]
struct IdentityRecord {
    /// The local name. Never leaves the vault.
    name: String,
    /// Random bytes that stand for this identity inside credentials, so an introduction
    /// carries no name.
    credential_id: Vec<u8>,
    signature_public: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct PeerRecord {
    signature_public: Vec<u8>,
    state: PeerState,
    /// Their unused introduction (a serialised key package), consumed when a session starts.
    intro: Option<Vec<u8>>,
    /// Sessions with this peer, by group id.
    groups: Vec<Vec<u8>>,
}

/// A contact the fingerprint ceremony has admitted. Constructed by `verify` alone (L3).
#[derive(Debug, Clone, Serialize)]
pub struct Peer {
    pub name: String,
    pub state: PeerState,
    pub fingerprint_prefix: String,
    pub sessions: usize,
    pub has_intro: bool,
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

/// A message that `open` produced.
#[derive(Debug, Clone, Serialize)]
pub struct Opened {
    pub from: String,
    pub body: Vec<u8>,
    pub session_started: bool,
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

impl Core {
    /// `gen`: create a vault with a fresh identity. Refuses if one exists.
    pub fn create(dir: &Path, passphrase: &str, name: &str) -> Result<Core, Refuse> {
        std::fs::create_dir_all(dir).map_err(|_| Refuse::VaultIo)?;
        let path = vault_path(dir);
        if path.exists() {
            return Err(Refuse::IdentityExists);
        }
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(config::mls::CIPHERSUITE.signature_algorithm())
            .map_err(mls_err)?;
        signer.store(provider.storage()).map_err(mls_err)?;
        let mut credential_id = vec![0u8; config::identity::CREDENTIAL_ID_LEN];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut credential_id);
        let state = State {
            version: config::vault::FORMAT_VERSION,
            identity: Some(IdentityRecord {
                name: name.to_owned(),
                credential_id,
                signature_public: signer.to_public_vec(),
            }),
            ..State::default()
        };
        let mut core = Core { provider, state, path, passphrase: passphrase.to_owned() };
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

    fn signer(&self) -> Result<SignatureKeyPair, Refuse> {
        let id = self.identity()?;
        SignatureKeyPair::read(
            self.provider.storage(),
            &id.signature_public,
            config::mls::CIPHERSUITE.signature_algorithm(),
        )
        .ok_or(Refuse::NoIdentity)
    }

    fn credential_with_key(&self) -> Result<CredentialWithKey, Refuse> {
        let id = self.identity()?;
        Ok(CredentialWithKey {
            credential: BasicCredential::new(id.credential_id.clone()).into(),
            signature_key: id.signature_public.clone().into(),
        })
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
        let signer = self.signer()?;
        let cwk = self.credential_with_key()?;
        let bundle = KeyPackage::builder()
            .build(config::mls::CIPHERSUITE, &self.provider, &signer, cwk)
            .map_err(mls_err)?;
        let out: MlsMessageOut = bundle.into();
        let bytes = out.to_bytes().map_err(mls_err)?;
        self.save()?;
        Ok(Intro(bytes))
    }

    /// Stage a peer from their introduction. The peer is `Pending` until `verify`.
    pub fn import(&mut self, name: &str, intro: &Intro) -> Result<Peer, Refuse> {
        let kp = parse_key_package(&self.provider, &intro.0)?;
        let their_pub = kp.leaf_node().signature_key().as_slice().to_vec();
        let state = match self.state.peers.get(name) {
            Some(existing) if existing.signature_public != their_pub => PeerState::Changed,
            Some(existing) => existing.state,
            None => PeerState::Pending,
        };
        self.state.peers.insert(
            name.to_owned(),
            PeerRecord {
                signature_public: their_pub,
                state,
                intro: Some(intro.0.clone()),
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
        })
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
                let cfg = MlsGroupCreateConfig::builder()
                    .ciphersuite(config::mls::CIPHERSUITE)
                    .use_ratchet_tree_extension(true)
                    .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                        config::mls::OUT_OF_ORDER_TOLERANCE,
                        config::mls::MAX_FORWARD_DISTANCE,
                    ))
                    .build();
                let cwk = self.credential_with_key()?;
                let mut group = MlsGroup::new(&self.provider, &signer, &cfg, cwk).map_err(mls_err)?;
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

        let msg = group
            .create_message(&self.provider, &signer, body)
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
                MlsMessageBodyIn::Welcome(welcome) => {
                    let name = self.join(welcome)?;
                    opened.push(Opened { from: name, body: Vec::new(), session_started: true });
                }
                MlsMessageBodyIn::PrivateMessage(pm) => {
                    let (name, body) = self.receive(pm.into())?;
                    if let Some(body) = body {
                        opened.push(Opened { from: name, body, session_started: false });
                    }
                }
                MlsMessageBodyIn::PublicMessage(pm) => {
                    let (name, body) = self.receive(pm.into())?;
                    if let Some(body) = body {
                        opened.push(Opened { from: name, body, session_started: false });
                    }
                }
                _ => return Err(Refuse::BadBlob),
            }
        }
        self.save()?;
        Ok(opened)
    }

    fn join(&mut self, welcome: Welcome) -> Result<String, Refuse> {
        let cfg = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                config::mls::OUT_OF_ORDER_TOLERANCE,
                config::mls::MAX_FORWARD_DISTANCE,
            ))
            .build();
        let staged = StagedWelcome::new_from_welcome(&self.provider, &cfg, welcome, None)
            .map_err(|e| match e {
                WelcomeError::NoMatchingKeyPackage | WelcomeError::NoMatchingEncryptionKey => Refuse::Replay,
                _ => Refuse::Protocol,
            })?;
        let mut group = staged.into_group(&self.provider).map_err(mls_err)?;
        let own = group.own_leaf_index();
        let other = group
            .members()
            .find(|m| m.index != own)
            .ok_or(Refuse::Protocol)?;
        let found = self
            .state
            .peers
            .iter()
            .find(|(_, p)| p.signature_public == other.signature_key && p.state == PeerState::Verified)
            .map(|(n, _)| n.clone());
        match found {
            Some(name) => {
                let gid = group.group_id().as_slice().to_vec();
                if let Some(r) = self.state.peers.get_mut(&name) {
                    r.groups.push(gid);
                }
                Ok(name)
            }
            None => {
                group.delete(self.provider.storage()).map_err(mls_err)?;
                Err(Refuse::UnknownSender)
            }
        }
    }

    fn receive(&mut self, pm: ProtocolMessage) -> Result<(String, Option<Vec<u8>>), Refuse> {
        let gid = pm.group_id().clone();
        let mut group = MlsGroup::load(self.provider.storage(), &gid)
            .map_err(mls_err)?
            .ok_or(Refuse::UnknownSession)?;
        let processed = group
            .process_message(&self.provider, pm)
            .map_err(|e| match e {
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(_)) => Refuse::Replay,
                _ => Refuse::Protocol,
            })?;
        let sender_key = match processed.sender() {
            Sender::Member(idx) => group
                .member_at(*idx)
                .map(|m| m.signature_key)
                .ok_or(Refuse::UnknownSender)?,
            _ => return Err(Refuse::UnknownSender),
        };
        let name = self
            .state
            .peers
            .iter()
            .find(|(_, p)| p.signature_public == sender_key && p.state == PeerState::Verified)
            .map(|(n, _)| n.clone())
            .ok_or(Refuse::UnknownSender)?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok((name, Some(app.into_bytes()))),
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                group.merge_staged_commit(&self.provider, *commit).map_err(mls_err)?;
                Ok((name, None))
            }
            _ => Ok((name, None)),
        }
    }
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
    let mut hasher = blake3::Hasher::new();
    hasher.update(config::fp::DOMAIN);
    hasher.update(lo);
    hasher.update(hi);
    let mut reader = hasher.finalize_xof();
    let mut digits = String::with_capacity(config::fp::DIGITS);
    let mut buf = [0u8; 1];
    while digits.len() < config::fp::DIGITS {
        reader.fill(&mut buf);
        // Rejection sampling keeps the digits uniform.
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

fn unframe(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Refuse> {
    let count = *bytes.first().ok_or(Refuse::BadBlob)? as usize;
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
