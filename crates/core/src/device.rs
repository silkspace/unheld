//! Devices of one identity (L15). An identity is one signing key that peers verify; a device is a
//! second signing key that sits on every leaf the device holds, bound to the identity by a
//! certificate the identity key signed. A device is enrolled only after a device already enrolled
//! displayed the newcomer's fingerprint and its holder said yes, and only that device can turn the
//! yes into a certificate. The identity's devices also share a session of their own, the ring,
//! through which nothing a peer could read ever travels.

use crate::vocab::{PeerState, Refuse};
use crate::{config, frame, mls_err, parse_key_package, prefix, unframe, Core, Expected, Fingerprint, Outbound, Target, B64};
use base64::Engine as _;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer as _;
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as _, Serialize as _};
use unheld_blob::Blob;

/// `Device`: the identity key's statement that a device key belongs to it. This is the content of
/// every MLS credential this identity's devices present, so it is public by design and carries
/// no name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    pub identity: Vec<u8>,
    pub device: Vec<u8>,
    /// Day of enrolment as seconds since the epoch, rounded to `config::device::ENROLLED_AT_STEP`.
    pub enrolled_at: u64,
    pub signature: Vec<u8>,
}

impl Cert {
    fn signed_part(identity: &[u8], device: &[u8], enrolled_at: u64) -> Vec<u8> {
        let mut m = Vec::with_capacity(config::device::DOMAIN.len() + identity.len() + device.len() + 8);
        m.extend_from_slice(config::device::DOMAIN);
        m.extend_from_slice(identity);
        m.extend_from_slice(device);
        m.extend_from_slice(&enrolled_at.to_be_bytes());
        m
    }

    /// Sign a device into an identity. Only the holder of the identity key can.
    pub(crate) fn issue(identity: &SignatureKeyPair, device: &[u8], now: u64) -> Result<Cert, Refuse> {
        let enrolled_at = now - now % config::device::ENROLLED_AT_STEP;
        let identity_pk = identity.to_public_vec();
        let signature = identity
            .sign(&Self::signed_part(&identity_pk, device, enrolled_at))
            .map_err(mls_err)?;
        Ok(Cert { identity: identity_pk, device: device.to_vec(), enrolled_at, signature })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = vec![config::device::CERT_VERSION];
        out.extend_from_slice(&self.identity);
        out.extend_from_slice(&self.device);
        out.extend_from_slice(&self.enrolled_at.to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse a certificate and check its signature under the identity key it names, and that the
    /// device key it names is `leaf_key`, the key that signed the leaf carrying it.
    pub(crate) fn verify(provider: &impl OpenMlsProvider, bytes: &[u8], leaf_key: &[u8]) -> Option<Cert> {
        let pk = config::device::KEY_LEN;
        let (version, rest) = bytes.split_first()?;
        if *version != config::device::CERT_VERSION {
            return None;
        }
        let identity = rest.get(..pk)?.to_vec();
        let device = rest.get(pk..2 * pk)?.to_vec();
        let at = rest.get(2 * pk..2 * pk + 8)?;
        let enrolled_at = u64::from_be_bytes(at.try_into().ok()?);
        let signature = rest.get(2 * pk + 8..)?.to_vec();
        if device != leaf_key || signature.len() != config::device::SIGNATURE_LEN {
            return None;
        }
        provider
            .crypto()
            .verify_signature(
                config::mls::CIPHERSUITE.signature_algorithm(),
                &Self::signed_part(&identity, &device, enrolled_at),
                &identity,
                &signature,
            )
            .ok()?;
        Some(Cert { identity, device, enrolled_at, signature })
    }
}

/// The identity a leaf belongs to, if its certificate holds. A leaf with no valid certificate
/// belongs to nobody and is treated as a stranger.
pub(crate) fn leaf_identity(provider: &impl OpenMlsProvider, credential: &Credential, leaf_key: &[u8]) -> Option<Vec<u8>> {
    leaf_cert(provider, credential, leaf_key).map(|c| c.identity)
}

/// The certificate a leaf carries, if it holds.
pub(crate) fn leaf_cert(provider: &impl OpenMlsProvider, credential: &Credential, leaf_key: &[u8]) -> Option<Cert> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    Cert::verify(provider, basic.identity(), leaf_key)
}

/// A device of this identity, as the vault remembers it.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct DeviceRecord {
    pub public: Vec<u8>,
    pub enrolled_at: u64,
    pub revoked: bool,
}

/// A device before enrolment: its own signing key and the key the enrolment bundle is sealed to.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct PendingDevice {
    pub device_public: Vec<u8>,
    pub kem_private: Vec<u8>,
    pub kem_public: Vec<u8>,
}

/// What a device shows about itself, for the `devices` listing.
#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub name: String,
    pub fingerprint_prefix: String,
    pub enrolled_at: u64,
    pub is_this: bool,
    pub revoked: bool,
}

/// What a new device hands to an existing one: its device key and an encryption key.
#[derive(Debug, Clone)]
pub struct Request(pub Vec<u8>);

impl Request {
    pub fn to_text(&self) -> String {
        B64.encode(&self.0)
    }
    pub fn from_text(s: &str) -> Result<Request, Refuse> {
        B64.decode(s.trim()).map(Request).map_err(|_| Refuse::BadRequest)
    }
    fn parts(&self) -> Result<(Vec<u8>, Vec<u8>), Refuse> {
        let pk = config::device::KEY_LEN;
        let device = self.0.get(..pk).ok_or(Refuse::BadRequest)?.to_vec();
        let kem = self.0.get(pk..).ok_or(Refuse::BadRequest)?.to_vec();
        if kem.is_empty() {
            return Err(Refuse::BadRequest);
        }
        Ok((device, kem))
    }
    /// The digits the new device shows and the witness compares (L15).
    pub fn fingerprint(&self) -> Result<Fingerprint, Refuse> {
        Ok(device_fingerprint(&self.parts()?.0))
    }
}

/// The digits of one device key alone, shown on the new device and on the witness.
pub(crate) fn device_fingerprint(device: &[u8]) -> Fingerprint {
    crate::digits_of(config::device::FP_DOMAIN, &[device])
}

/// What an existing device hands back after the yes: the identity, sealed to the newcomer alone.
#[derive(Debug, Clone)]
pub struct Enrolment(pub Vec<u8>);

impl Enrolment {
    pub fn to_text(&self) -> String {
        B64.encode(&self.0)
    }
    pub fn from_text(s: &str) -> Result<Enrolment, Refuse> {
        B64.decode(s.trim()).map(Enrolment).map_err(|_| Refuse::BadEnrolment)
    }
}

/// The plaintext of an enrolment bundle. The identity's private key travels here and nowhere
/// else, sealed to a key that exists on the new device alone.
#[derive(Serialize, Deserialize)]
struct Bundle {
    name: String,
    /// The identity key pair in its serde form, the same bytes the vault's key store holds.
    identity_keypair: Vec<u8>,
    identity_public: Vec<u8>,
    device_name: String,
    cert: Vec<u8>,
    devices: Vec<(String, DeviceRecord)>,
    peers: Vec<(String, Vec<u8>, PeerState)>,
    /// Every session the new device will be welcomed into, and what it is.
    groups: Vec<(Vec<u8>, Expected)>,
    /// How many introductions the newcomer must hand back: one per session plus the ring.
    key_packages_needed: usize,
}

/// What the enrolled device hands back: one introduction per session it will be brought into.
#[derive(Debug, Clone)]
pub struct Attach(pub Vec<u8>);

impl Attach {
    pub fn to_text(&self) -> String {
        B64.encode(&self.0)
    }
    pub fn from_text(s: &str) -> Result<Attach, Refuse> {
        B64.decode(s.trim()).map(Attach).map_err(|_| Refuse::BadIntro)
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Core {
    /// Issue this identity's certificate for a device key.
    pub(crate) fn issue_cert(&self, device: &[u8]) -> Result<Cert, Refuse> {
        Cert::issue(&self.identity_signer()?, device, now())
    }

    /// A vault for a device that has no identity yet. Returns the request it hands to a device
    /// that has one. The vault holds the device key and the key the enrolment is sealed to.
    pub fn create_device(dir: &std::path::Path, passphrase: &str) -> Result<(Core, Request), Refuse> {
        let mut core = Core::empty(dir, passphrase)?;
        let device = SignatureKeyPair::new(config::mls::CIPHERSUITE.signature_algorithm()).map_err(mls_err)?;
        device.store(core.provider.storage()).map_err(mls_err)?;
        let ikm = core.provider.rand().random_vec(config::device::KEY_LEN).map_err(mls_err)?;
        let kem = core.provider.crypto().derive_hpke_keypair(config::mls::CIPHERSUITE.hpke_config(), &ikm).map_err(mls_err)?;
        let pending = PendingDevice {
            device_public: device.to_public_vec(),
            kem_private: kem.private[..].to_vec(),
            kem_public: kem.public.clone(),
        };
        let mut req = pending.device_public.clone();
        req.extend_from_slice(&pending.kem_public);
        core.state.pending = Some(pending);
        core.save()?;
        Ok((core, Request(req)))
    }

    /// The request again, for a device that is still waiting.
    pub fn request(&self) -> Result<Request, Refuse> {
        let p = self.state.pending.as_ref().ok_or(Refuse::NotPending)?;
        let mut req = p.device_public.clone();
        req.extend_from_slice(&p.kem_public);
        Ok(Request(req))
    }

    /// `enroll`: the witness's side. `confirmed` is the human's answer after comparing the digits
    /// on both screens; nothing happens without it (L15). The identity is sealed to the newcomer.
    pub fn enroll(&mut self, device_name: &str, request: &Request, confirmed: bool) -> Result<Enrolment, Refuse> {
        if !confirmed {
            return Err(Refuse::NotConfirmed);
        }
        let (device_pk, kem_pk) = request.parts()?;
        let id = self.identity()?.clone();
        if id.devices.contains_key(device_name) {
            return Err(Refuse::DeviceExists);
        }
        if id.devices.values().any(|d| d.public == device_pk) {
            return Err(Refuse::DeviceExists);
        }
        let cert = self.issue_cert(&device_pk)?;
        let identity = self.identity_signer()?;
        let sessions = self.state.peers.values().map(|p| p.groups.len()).sum::<usize>() + self.state.groups.len();
        let mut devices: Vec<(String, DeviceRecord)> = id.devices.iter().map(|(n, d)| (n.clone(), d.clone())).collect();
        let record = DeviceRecord { public: device_pk.clone(), enrolled_at: cert.enrolled_at, revoked: false };
        devices.push((device_name.to_owned(), record.clone()));
        let bundle = Bundle {
            name: id.name.clone(),
            identity_keypair: serde_json::to_vec(&identity).map_err(|_| Refuse::Protocol)?,
            identity_public: identity.to_public_vec(),
            device_name: device_name.to_owned(),
            cert: cert.encode(),
            devices,
            peers: self.state.peers.iter().map(|(n, p)| (n.clone(), p.signature_public.clone(), p.state)).collect(),
            groups: self
                .state
                .peers
                .iter()
                .flat_map(|(n, p)| p.groups.iter().map(move |g| (g.clone(), Expected::Pair(n.clone()))))
                .chain(self.state.groups.iter().map(|(n, g)| (g.group_id.clone(), Expected::Group { admin: g.admin.clone(), name: n.clone() })))
                .collect(),
            key_packages_needed: sessions + 1,
        };
        let plain = serde_json::to_vec(&bundle).map_err(|_| Refuse::Protocol)?;
        let ct = self
            .provider
            .crypto()
            .hpke_seal(config::mls::CIPHERSUITE.hpke_config(), &kem_pk, config::device::DOMAIN, &device_pk, &plain)
            .map_err(mls_err)?;
        let bytes = ct.tls_serialize_detached().map_err(mls_err)?;
        if let Some(id) = self.state.identity.as_mut() {
            id.devices.insert(device_name.to_owned(), record);
        }
        self.save()?;
        Ok(Enrolment(bytes))
    }

    /// The newcomer's side: open the enrolment, become the identity, and hand back the
    /// introductions the witness needs to bring this device into every session.
    pub fn join_device(&mut self, enrolment: &Enrolment) -> Result<Attach, Refuse> {
        let pending = self.state.pending.clone().ok_or(Refuse::NotPending)?;
        let ct = HpkeCiphertext::tls_deserialize_exact(&enrolment.0).map_err(|_| Refuse::BadEnrolment)?;
        let plain = self
            .provider
            .crypto()
            .hpke_open(config::mls::CIPHERSUITE.hpke_config(), &ct, &pending.kem_private, config::device::DOMAIN, &pending.device_public)
            .map_err(|_| Refuse::BadEnrolment)?;
        let bundle: Bundle = serde_json::from_slice(&plain).map_err(|_| Refuse::BadEnrolment)?;
        let cert = Cert::verify(&self.provider, &bundle.cert, &pending.device_public).ok_or(Refuse::BadEnrolment)?;
        if cert.identity != bundle.identity_public {
            return Err(Refuse::BadEnrolment);
        }
        let identity: SignatureKeyPair = serde_json::from_slice(&bundle.identity_keypair).map_err(|_| Refuse::BadEnrolment)?;
        if identity.to_public_vec() != cert.identity || identity.to_public_vec() != bundle.identity_public || identity.signature_scheme() != config::mls::CIPHERSUITE.signature_algorithm() {
            return Err(Refuse::BadEnrolment);
        }
        identity.store(self.provider.storage()).map_err(mls_err)?;
        self.state.identity = Some(crate::IdentityRecord {
            name: bundle.name,
            signature_public: bundle.identity_public,
            device_public: pending.device_public.clone(),
            device_name: bundle.device_name,
            cert: bundle.cert,
            devices: bundle.devices.into_iter().collect(),
            ring: None,
        });
        for (name, key, state) in bundle.peers {
            self.state.peers.insert(name, crate::PeerRecord { signature_public: key, state, intro: None, groups: Vec::new() });
        }
        self.state.expected = bundle.groups;
        self.state.pending = None;
        let mut parts = Vec::with_capacity(bundle.key_packages_needed);
        for _ in 0..bundle.key_packages_needed {
            parts.push(self.key_package_bytes()?);
        }
        self.save()?;
        Ok(Attach(frame(&parts)?))
    }

    /// The witness's last step: bring the enrolled device into the ring and every session and
    /// group. One commit per session goes to its readers; every welcome goes to the new device.
    pub fn connect_device(&mut self, attach: &Attach) -> Result<Vec<Outbound>, Refuse> {
        let kps = unframe(&attach.0)?
            .iter()
            .map(|p| parse_key_package(&self.provider, p))
            .collect::<Result<Vec<_>, _>>()?;
        let id = self.identity()?.clone();
        let mut kps = kps.into_iter();
        let next = |kps: &mut dyn Iterator<Item = KeyPackage>| -> Result<KeyPackage, Refuse> {
            let kp = kps.next().ok_or(Refuse::BadIntro)?;
            let leaf_key = kp.leaf_node().signature_key().as_slice().to_vec();
            let cert = leaf_cert(&self.provider, kp.leaf_node().credential(), &leaf_key).ok_or(Refuse::BadIntro)?;
            let known = id.devices.values().any(|d| d.public == cert.device && !d.revoked);
            if cert.identity != id.signature_public || !known || cert.device == id.device_public {
                return Err(Refuse::NotADevice);
            }
            Ok(kp)
        };
        let signer = self.signer()?;
        let mut out = Vec::new();
        let mut welcomes = Vec::new();

        // The ring first: created now if this is the identity's second device.
        let ring_kp = next(&mut kps)?;
        match id.ring.clone() {
            None => {
                let cwk = self.credential_with_key()?;
                let mut ring = MlsGroup::new(&self.provider, &signer, &crate::group_config(), cwk).map_err(mls_err)?;
                let (_c, welcome, _i) = ring.add_members(&self.provider, &signer, &[ring_kp]).map_err(mls_err)?;
                ring.merge_pending_commit(&self.provider).map_err(mls_err)?;
                welcomes.push(welcome.to_bytes().map_err(mls_err)?);
                if let Some(i) = self.state.identity.as_mut() {
                    i.ring = Some(ring.group_id().as_slice().to_vec());
                }
            }
            Some(gid) => {
                let mut ring = self.load_gid(&gid)?;
                let (commit, welcome, _i) = ring.add_members(&self.provider, &signer, &[ring_kp]).map_err(mls_err)?;
                ring.merge_pending_commit(&self.provider).map_err(mls_err)?;
                welcomes.push(welcome.to_bytes().map_err(mls_err)?);
                out.push(Outbound { to: Target::Ring, blob: Self::one_part_blob(&commit)? });
            }
        }
        // Then every pairwise session and every group.
        let sessions: Vec<(Target, Vec<u8>)> = self
            .state
            .peers
            .iter()
            .flat_map(|(n, p)| p.groups.iter().map(move |g| (Target::Peer(n.clone()), g.clone())))
            .chain(self.state.groups.iter().map(|(n, g)| (Target::Group(n.clone()), g.group_id.clone())))
            .collect();
        for (to, gid) in sessions {
            let kp = next(&mut kps)?;
            let mut group = self.load_gid(&gid)?;
            let (commit, welcome, _i) = group.add_members(&self.provider, &signer, &[kp]).map_err(mls_err)?;
            group.merge_pending_commit(&self.provider).map_err(mls_err)?;
            welcomes.push(welcome.to_bytes().map_err(mls_err)?);
            out.push(Outbound { to, blob: Self::one_part_blob(&commit)? });
        }
        out.push(Outbound { to: Target::Device, blob: Blob::pad(&frame(&welcomes)?).map_err(|_| Refuse::TooLarge)? });
        self.save()?;
        Ok(out)
    }

    /// `revoke`: drop a device from the ring and every session. The commits go to the readers of
    /// each; the revoked device opens nothing sealed afterwards. The device you are on cannot
    /// revoke itself.
    pub fn revoke_device(&mut self, device_name: &str) -> Result<Vec<Outbound>, Refuse> {
        let id = self.identity()?.clone();
        let rec = id.devices.get(device_name).ok_or(Refuse::UnknownDevice)?.clone();
        if rec.public == id.device_public {
            return Err(Refuse::ThisDevice);
        }
        if rec.revoked {
            return Err(Refuse::UnknownDevice);
        }
        let signer = self.signer()?;
        let mut out = Vec::new();
        let sessions: Vec<(Target, Vec<u8>)> = id
            .ring
            .iter()
            .map(|g| (Target::Ring, g.clone()))
            .chain(self.state.peers.iter().flat_map(|(n, p)| p.groups.iter().map(move |g| (Target::Peer(n.clone()), g.clone()))))
            .chain(self.state.groups.iter().map(|(n, g)| (Target::Group(n.clone()), g.group_id.clone())))
            .collect();
        for (to, gid) in sessions {
            let mut group = self.load_gid(&gid)?;
            let Some(index) = group.members().find(|m| m.signature_key == rec.public).map(|m| m.index) else { continue };
            let (commit, _w, _i) = group.remove_members(&self.provider, &signer, &[index]).map_err(mls_err)?;
            group.merge_pending_commit(&self.provider).map_err(mls_err)?;
            out.push(Outbound { to, blob: Self::one_part_blob(&commit)? });
        }
        if let Some(d) = self.state.identity.as_mut().and_then(|i| i.devices.get_mut(device_name)) {
            d.revoked = true;
        }
        self.save()?;
        Ok(out)
    }

    /// Every device of this identity.
    pub fn devices(&self) -> Result<Vec<Device>, Refuse> {
        let id = self.identity()?;
        Ok(id
            .devices
            .iter()
            .map(|(n, d)| Device {
                name: n.clone(),
                fingerprint_prefix: prefix(&d.public),
                enrolled_at: d.enrolled_at,
                is_this: d.public == id.device_public,
                revoked: d.revoked,
            })
            .collect())
    }

    /// What the enrolment said a session id would be, consumed on first use.
    pub(crate) fn expected(&mut self, gid: &[u8]) -> Option<Expected> {
        let pos = self.state.expected.iter().position(|(g, _)| g == gid)?;
        Some(self.state.expected.remove(pos).1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vocab::MemberTrust;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("unheld-device-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn pair(a: &mut Core, a_name: &str, b: &mut Core, b_name: &str) {
        a.import(b_name, &b.intro().unwrap()).unwrap();
        a.verify(b_name, true).unwrap();
        b.import(a_name, &a.intro().unwrap()).unwrap();
        b.verify(a_name, true).unwrap();
    }

    fn blob_for<'a>(outs: &'a [Outbound], to: &Target) -> &'a Blob {
        &outs.iter().find(|o| &o.to == to).unwrap().blob
    }

    #[test]
    fn a_second_device_needs_a_witness_and_then_reaches_every_session() {
        let mut alice = Core::create(&tmp("alice"), "pw", "alice").unwrap();
        let mut bob = Core::create(&tmp("bob"), "pw", "bob").unwrap();
        let mut carol = Core::create(&tmp("carol"), "pw", "carol").unwrap();
        pair(&mut alice, "alice", &mut bob, "bob");
        pair(&mut alice, "alice", &mut carol, "carol");
        pair(&mut bob, "bob", &mut carol, "carol");
        // A session with Bob and a group of three exist before the phone does.
        bob.open(&alice.seal("bob", b"one").unwrap()).unwrap();
        alice.import("bob", &bob.intro().unwrap()).unwrap();
        let welcome = alice.group_new("team", &["bob", "carol"], false).unwrap();
        bob.open(&welcome).unwrap();
        carol.open(&welcome).unwrap();

        // The phone asks; the digits it shows are the digits the witness sees (L15).
        let (mut phone, request) = Core::create_device(&tmp("alice-phone"), "pw", ).unwrap();
        assert!(matches!(phone.name(), Err(Refuse::NoIdentity)));
        assert_eq!(phone.request().unwrap().fingerprint().unwrap(), request.fingerprint().unwrap());
        assert_eq!(request.fingerprint().unwrap().0.len(), config::fp::DIGITS);
        // No yes, no device.
        assert!(matches!(alice.enroll("phone", &request, false), Err(Refuse::NotConfirmed)));
        assert_eq!(alice.devices().unwrap().len(), 1);
        let enrolment = alice.enroll("phone", &request, true).unwrap();
        assert_eq!(alice.devices().unwrap().len(), 2);
        assert!(matches!(alice.enroll("phone", &request, true), Err(Refuse::DeviceExists)));
        // The enrolment opens on the phone alone.
        let (mut other, _) = Core::create_device(&tmp("stranger-phone"), "pw").unwrap();
        assert!(matches!(other.join_device(&enrolment), Err(Refuse::BadEnrolment)));
        assert!(matches!(other.name(), Err(Refuse::NoIdentity)));
        let attach = phone.join_device(&enrolment).unwrap();
        assert_eq!(phone.name().unwrap(), "alice");
        assert_eq!(phone.own_fingerprint_prefix().unwrap(), alice.own_fingerprint_prefix().unwrap());
        assert_eq!(phone.peer("bob").unwrap().state, PeerState::Verified);
        assert!(phone.devices().unwrap().iter().any(|d| d.is_this && d.name == "phone"));

        // The witness brings the phone into the ring, the session and the group.
        let outs = alice.connect_device(&attach).unwrap();
        let targets: Vec<Target> = outs.iter().map(|o| o.to.clone()).collect();
        assert_eq!(targets, vec![Target::Peer("bob".into()), Target::Group("team".into()), Target::Device]);
        let seen = bob.open(blob_for(&outs, &Target::Peer("bob".into()))).unwrap();
        assert_eq!(seen[0].change.as_deref(), Some("alice added 1 device"));
        let seen = carol.open(blob_for(&outs, &Target::Group("team".into()))).unwrap();
        assert!(seen[0].change.as_deref().unwrap().starts_with("alice added 1 device in "));
        bob.open(blob_for(&outs, &Target::Group("team".into()))).unwrap();
        let joined = phone.open(blob_for(&outs, &Target::Device)).unwrap();
        assert_eq!(joined.len(), 3);
        assert!(joined.iter().all(|o| o.session_started));
        assert_eq!(phone.peer("bob").unwrap().sessions, 1);
        assert_eq!(phone.groups().len(), 1);
        assert_eq!(phone.roster("team").unwrap().admin, "alice");

        // Both devices read what Bob sends, and what either sends reads as Alice.
        let hi = bob.seal("alice", b"hi both").unwrap();
        assert_eq!(alice.open(&hi).unwrap()[0].body, b"hi both");
        assert_eq!(phone.open(&hi).unwrap()[0].body, b"hi both");
        let from_phone = phone.seal("bob", b"from the phone").unwrap();
        let got = bob.open(&from_phone).unwrap();
        assert_eq!((got[0].from.as_str(), &got[0].body[..]), ("alice", &b"from the phone"[..]));
        assert_eq!(alice.open(&from_phone).unwrap()[0].body, b"from the phone");
        let team_msg = phone.group_seal("team", b"team, from the phone").unwrap();
        let got = carol.open(&team_msg).unwrap();
        assert_eq!((got[0].from.as_str(), got[0].trust), ("alice", MemberTrust::Verified));
        bob.open(&team_msg).unwrap();
        alice.open(&team_msg).unwrap();
        // Bob's roster shows one Alice with two devices, not two Alices.
        let bob_team = bob.groups().into_iter().next().unwrap();
        let a = bob_team.members.iter().find(|m| m.label == "alice").unwrap();
        assert_eq!((a.devices, a.is_admin, bob_team.members.len()), (2, true, 3));

        // Revocation from the other device: every session drops the phone, and the phone knows.
        assert!(matches!(alice.revoke_device("first"), Err(Refuse::ThisDevice)));
        let outs = alice.revoke_device("phone").unwrap();
        let targets: Vec<Target> = outs.iter().map(|o| o.to.clone()).collect();
        assert_eq!(targets, vec![Target::Ring, Target::Peer("bob".into()), Target::Group("team".into())]);
        let seen = bob.open(blob_for(&outs, &Target::Peer("bob".into()))).unwrap();
        assert_eq!(seen[0].change.as_deref(), Some("alice removed 1 device"));
        carol.open(blob_for(&outs, &Target::Group("team".into()))).unwrap();
        bob.open(blob_for(&outs, &Target::Group("team".into()))).unwrap();
        assert!(phone.open(blob_for(&outs, &Target::Ring)).unwrap().is_empty());
        let seen = phone.open(blob_for(&outs, &Target::Peer("bob".into()))).unwrap();
        assert!(seen[0].change.as_deref().unwrap().starts_with("another device of yours revoked this one"));
        assert_eq!(phone.peer("bob").unwrap().sessions, 0);
        let later = bob.seal("alice", b"after").unwrap();
        assert_eq!(alice.open(&later).unwrap()[0].body, b"after");
        assert!(matches!(phone.open(&later), Err(Refuse::UnknownSession)));
        assert!(alice.devices().unwrap().iter().any(|d| d.name == "phone" && d.revoked));
    }

    #[test]
    fn a_person_added_to_a_pairwise_session_is_refused_as_before() {
        let mut alice = Core::create(&tmp("p-alice"), "pw", "alice").unwrap();
        let mut bob = Core::create(&tmp("p-bob"), "pw", "bob").unwrap();
        let mut carol = Core::create(&tmp("p-carol"), "pw", "carol").unwrap();
        pair(&mut alice, "alice", &mut bob, "bob");
        pair(&mut bob, "bob", &mut carol, "carol");
        bob.open(&alice.seal("bob", b"one").unwrap()).unwrap();
        // Bob's client is altered to add Carol to the pairwise session as if she were a device.
        let gid = bob.state.peers.get("alice").unwrap().groups[0].clone();
        let mut group = bob.load_gid(&gid).unwrap();
        let kp = parse_key_package(&bob.provider, bob.state.peers.get("carol").unwrap().intro.as_ref().unwrap()).unwrap();
        let signer = bob.signer().unwrap();
        let (commit, _w, _i) = group.add_members(&bob.provider, &signer, &[kp]).unwrap();
        group.merge_pending_commit(&bob.provider).unwrap();
        let blob = Core::one_part_blob(&commit).unwrap();
        // Carol's leaf carries Carol's certificate, not Bob's, so this is a person and refused (L16).
        assert!(matches!(alice.open(&blob), Err(Refuse::NoRight)));
        let _ = carol;
    }

    #[test]
    fn an_older_vault_is_refused_in_words() {
        let dir = tmp("old");
        std::fs::create_dir_all(&dir).unwrap();
        let old = serde_json::json!({ "version": 1, "identity": null, "peers": {}, "storage": [] });
        crate::vault::seal_to_file(&dir.join(config::vault::FILE_NAME), "pw", old.to_string().as_bytes()).unwrap();
        assert!(matches!(Core::unlock(&dir, "pw"), Err(Refuse::VaultOld)));
    }
}
