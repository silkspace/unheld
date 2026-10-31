//! Recovery shares (L21). `split` cuts the identity key into `n` Shamir shares of which any `k`
//! rebuild it, by an interactive ceremony and nothing else: no share is ever written by `lock`,
//! and a share is zeroised when it drops. `recover` is the inverse, on a device with no vault,
//! and gives back the identity alone: peers who verified it still trust it, but their names,
//! the sessions and the device list are gone with the old vault.

use crate::device::{Cert, DeviceRecord};
use crate::vocab::Refuse;
use crate::{config, mls_err, Core, IdentityRecord, B64};
use base64::Engine as _;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer as _;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::Path;
use vsss_rs::{DefaultShare, Gf256, IdentifierGf256, ReadableShareSet, Share as _};
use zeroize::{Zeroize, Zeroizing};

type ByteShare = DefaultShare<IdentifierGf256, IdentifierGf256>;

/// One of `n` shares. A secret: exists only during the ceremony, zeroised on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Share {
    bytes: Vec<u8>,
}

impl Share {
    /// Version, index, threshold, then one field element per byte of the secret.
    fn new(index: u8, threshold: u8, values: Vec<u8>) -> Share {
        let mut bytes = vec![config::recovery::SHARE_VERSION, index, threshold];
        bytes.extend_from_slice(&values);
        Share { bytes }
    }
    pub fn to_text(&self) -> Zeroizing<String> {
        Zeroizing::new(B64.encode(&self.bytes))
    }
    pub fn from_text(s: &str) -> Result<Share, Refuse> {
        let bytes = B64.decode(s.trim()).map_err(|_| Refuse::BadShare)?;
        let share = Share { bytes };
        share.parts()?;
        Ok(share)
    }
    /// Which share this is, of how many needed.
    pub fn index(&self) -> u8 {
        self.bytes.get(1).copied().unwrap_or(0)
    }
    pub fn threshold(&self) -> u8 {
        self.bytes.get(2).copied().unwrap_or(0)
    }
    fn parts(&self) -> Result<(u8, u8, &[u8]), Refuse> {
        let (version, rest) = self.bytes.split_first().ok_or(Refuse::BadShare)?;
        if *version != config::recovery::SHARE_VERSION {
            return Err(Refuse::BadShare);
        }
        let index = *rest.first().ok_or(Refuse::BadShare)?;
        let threshold = *rest.get(1).ok_or(Refuse::BadShare)?;
        let values = rest.get(2..).ok_or(Refuse::BadShare)?;
        if index == 0 || threshold < config::recovery::MIN_THRESHOLD || values.is_empty() {
            return Err(Refuse::BadShare);
        }
        Ok((index, threshold, values))
    }
}

/// The operating system's random source, through the interface the sharing crate asks for.
struct Entropy;

impl rand_core::TryRng for Entropy {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(rand::RngCore::next_u32(&mut rand::rng()))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(rand::RngCore::next_u64(&mut rand::rng()))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        rand::RngCore::fill_bytes(&mut rand::rng(), dst);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Entropy {}

/// Shamir over each byte of the secret, with the same identifiers across bytes.
fn split_bytes(secret: &[u8], k: u8, n: u8) -> Result<Vec<Share>, Refuse> {
    if k < config::recovery::MIN_THRESHOLD || n < k {
        return Err(Refuse::BadThreshold(config::recovery::MIN_THRESHOLD));
    }
    let ids: Vec<IdentifierGf256> = (1..=n).map(|i| IdentifierGf256(Gf256(i))).collect();
    let mut columns: Vec<Vec<u8>> = vec![Vec::with_capacity(secret.len()); n as usize];
    for &b in secret {
        let shares = vsss_rs::shamir::split_secret_with_ids::<ByteShare>(
            k as usize,
            n as usize,
            &IdentifierGf256(Gf256(b)),
            Entropy,
            ids.iter().copied(),
        )
        .map_err(|_| Refuse::Protocol)?;
        for s in shares {
            let i = u8::from(s.identifier().0) as usize;
            columns.get_mut(i - 1).ok_or(Refuse::Protocol)?.push(u8::from(s.value().0));
        }
    }
    Ok(columns.into_iter().enumerate().map(|(i, v)| Share::new(i as u8 + 1, k, v)).collect())
}

fn join_bytes(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>, Refuse> {
    let first = shares.first().ok_or(Refuse::NotEnoughShares(0))?.parts()?;
    let threshold = first.1 as usize;
    let len = first.2.len();
    let mut seen = Vec::new();
    let mut parsed = Vec::new();
    for s in shares {
        let (index, t, values) = s.parts()?;
        if t as usize != threshold || values.len() != len || seen.contains(&index) {
            return Err(Refuse::BadShare);
        }
        seen.push(index);
        parsed.push((index, values));
    }
    if parsed.len() < threshold {
        return Err(Refuse::NotEnoughShares(threshold));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    for pos in 0..len {
        let column: Vec<ByteShare> = parsed
            .iter()
            .take(threshold)
            .map(|(index, values)| ByteShare::with_identifier_and_value(IdentifierGf256(Gf256(*index)), IdentifierGf256(Gf256(values[pos]))))
            .collect();
        let v = column.combine().map_err(|_| Refuse::BadShare)?;
        out.push(u8::from(v.0));
    }
    Ok(out)
}

impl Core {
    /// `split`: `n` shares of the identity key, any `k` of which rebuild it. Nothing is written;
    /// the vault is byte for byte what it was.
    pub fn split(&self, k: u8, n: u8) -> Result<Vec<Share>, Refuse> {
        let identity = self.identity_signer()?;
        let secret = Zeroizing::new(serde_json::to_vec(&identity).map_err(|_| Refuse::Protocol)?);
        split_bytes(&secret, k, n)
    }

    /// `join`: a vault on a new device holding the identity the shares rebuild, under `name`,
    /// with a fresh device key and no peers. Refuses with fewer than `k` shares, and when the
    /// rebuilt key does not sign, which is what a wrong or altered share produces.
    pub fn recover(dir: &Path, passphrase: &str, name: &str, shares: &[Share]) -> Result<Core, Refuse> {
        let secret = join_bytes(shares)?;
        let identity: SignatureKeyPair = serde_json::from_slice(&secret).map_err(|_| Refuse::BadShare)?;
        if identity.signature_scheme() != config::mls::CIPHERSUITE.signature_algorithm() {
            return Err(Refuse::BadShare);
        }
        let mut core = Core::empty(dir, passphrase)?;
        let probe = identity.sign(config::recovery::PROBE).map_err(|_| Refuse::BadShare)?;
        core.provider
            .crypto()
            .verify_signature(identity.signature_scheme(), config::recovery::PROBE, identity.public(), &probe)
            .map_err(|_| Refuse::BadShare)?;
        identity.store(core.provider.storage()).map_err(mls_err)?;
        let device = SignatureKeyPair::new(config::mls::CIPHERSUITE.signature_algorithm()).map_err(mls_err)?;
        device.store(core.provider.storage()).map_err(mls_err)?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let cert = Cert::issue(&identity, device.public(), now)?;
        let mut devices = BTreeMap::new();
        devices.insert(
            config::recovery::DEVICE_NAME.to_owned(),
            DeviceRecord { public: device.to_public_vec(), enrolled_at: cert.enrolled_at, revoked: false },
        );
        core.state.identity = Some(IdentityRecord {
            name: name.to_owned(),
            signature_public: identity.to_public_vec(),
            device_public: device.to_public_vec(),
            device_name: config::recovery::DEVICE_NAME.to_owned(),
            cert: cert.encode(),
            devices,
            ring: None,
            previous: Vec::new(),
            needs_update: Vec::new(),
        });
        core.save()?;
        Ok(core)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vocab::PeerState;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("unheld-recover-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn shares_rebuild_the_identity_and_the_vault_never_holds_one() {
        let a_dir = tmp("alice");
        let mut alice = Core::create(&a_dir, "pw", "alice").unwrap();
        let mut bob = Core::create(&tmp("bob"), "pw", "bob").unwrap();
        bob.import("alice", &alice.intro().unwrap()).unwrap();
        bob.verify("alice", true).unwrap();
        let fp = bob.fingerprint("alice").unwrap();

        // L21: the ceremony produces shares and the vault is byte for byte what it was.
        let before = std::fs::read(a_dir.join(config::vault::FILE_NAME)).unwrap();
        assert!(matches!(alice.split(1, 3), Err(Refuse::BadThreshold(_))));
        assert!(matches!(alice.split(4, 3), Err(Refuse::BadThreshold(_))));
        let shares = alice.split(2, 3).unwrap();
        assert_eq!(std::fs::read(a_dir.join(config::vault::FILE_NAME)).unwrap(), before);
        assert_eq!(shares.len(), 3);
        for s in &shares {
            assert!(!before.windows(16).any(|w| s.to_text().as_bytes().windows(16).any(|v| v == w)));
        }
        let texts: Vec<Zeroizing<String>> = shares.iter().map(Share::to_text).collect();

        // One share is nothing; two of three, in any order, are the identity.
        let one = [Share::from_text(&texts[2]).unwrap()];
        assert!(matches!(Core::recover(&tmp("one"), "pw", "alice", &one), Err(Refuse::NotEnoughShares(2))));
        let two = [Share::from_text(&texts[2]).unwrap(), Share::from_text(&texts[0]).unwrap()];
        let mut again = Core::recover(&tmp("again"), "pw", "alice again", &two).unwrap();
        assert_eq!(again.own_fingerprint_prefix().unwrap(), alice.own_fingerprint_prefix().unwrap());
        assert!(again.peers().is_empty());
        assert_eq!(again.devices().unwrap().len(), 1);

        // Bob's trust survives: the recovered device's introduction is the same identity.
        let p = bob.import("alice", &again.intro().unwrap()).unwrap();
        assert_eq!(p.state, PeerState::Verified);
        assert_eq!(bob.fingerprint("alice").unwrap(), fp);
        again.import("bob", &bob.intro().unwrap()).unwrap();
        again.verify("bob", true).unwrap();
        let hello = again.seal("bob", b"back").unwrap();
        assert_eq!(bob.open(&hello).unwrap().last().unwrap().body, b"back");

        // An altered share rebuilds a key that does not sign, and is refused with nothing kept.
        let mut altered = Share::from_text(&texts[1]).unwrap();
        if let Some(b) = altered.bytes.get_mut(20) { *b ^= 1; }
        let bad = [Share::from_text(&texts[0]).unwrap(), altered];
        let bad_dir = tmp("bad");
        assert!(matches!(Core::recover(&bad_dir, "pw", "alice", &bad), Err(Refuse::BadShare)));
        assert!(!bad_dir.join(config::vault::FILE_NAME).exists());
    }
}
