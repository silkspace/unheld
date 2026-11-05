//! The relay's transport identity: a self-signed Ed25519 certificate that clients pin by hash, so
//! the web public key infrastructure is not a party. Signing and TLS are graviola through rustls.

use crate::config::{files, HASH_LEN};
use crate::{hex, unhex, RelayError};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use std::sync::Arc;
use subtle::ConstantTimeEq as _;

/// The hash of the relay's certificate, which is the whole of what a client trusts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pin(pub [u8; HASH_LEN]);

impl Pin {
    pub fn of(cert: &[u8]) -> Pin {
        Pin(Sha256::digest(cert).into())
    }

    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    pub fn parse(s: &str) -> Result<Pin, RelayError> {
        unhex::<HASH_LEN>(s).map(Pin).ok_or(RelayError::BadAddress)
    }
}

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls_graviola::default_provider())
}

/// A certificate and the key behind it.
pub struct Identity {
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

/// graviola's Ed25519 key in the shape rcgen signs with.
struct Ed25519Key {
    key: graviola::signing::eddsa::Ed25519SigningKey,
    public: [u8; 32],
}

impl rcgen::PublicKeyData for Ed25519Key {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

impl rcgen::SigningKey for Ed25519Key {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.key.sign(msg).to_vec())
    }
}

impl Identity {
    /// A fresh key and a self-signed certificate naming `host`.
    pub fn generate(host: &str) -> Result<Identity, RelayError> {
        let key = graviola::signing::eddsa::Ed25519SigningKey::generate().map_err(|_| RelayError::Certificate)?;
        let signer = Ed25519Key { public: key.public_key().as_bytes(), key };
        let mut params = rcgen::CertificateParams::new(vec![host.to_string()]).map_err(|_| RelayError::Certificate)?;
        params.serial_number = Some(rcgen::SerialNumber::from(crate::random::<16>().to_vec()));
        let cert = params.self_signed(&signer).map_err(|_| RelayError::Certificate)?;
        let mut buf = [0u8; 128];
        let pkcs8 = signer.key.to_pkcs8_der(&mut buf).map_err(|_| RelayError::Certificate)?;
        Ok(Identity { cert: cert.der().clone(), key: PrivatePkcs8KeyDer::from(pkcs8.to_vec()) })
    }

    pub fn save(&self, dir: &Path) -> Result<(), RelayError> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join(files::CERT), self.cert.as_ref())?;
        let key_path = dir.join(files::KEY);
        std::fs::write(&key_path, self.key.secret_pkcs8_der())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn load(dir: &Path) -> Result<Identity, RelayError> {
        let cert = CertificateDer::from(std::fs::read(dir.join(files::CERT))?);
        let key = PrivatePkcs8KeyDer::from(std::fs::read(dir.join(files::KEY))?);
        Ok(Identity { cert, key })
    }

    pub fn pin(&self) -> Pin {
        Pin::of(self.cert.as_ref())
    }

    pub fn server_config(&self) -> Result<Arc<ServerConfig>, RelayError> {
        let config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], PrivateKeyDer::Pkcs8(self.key.clone_key()))?;
        Ok(Arc::new(config))
    }
}

/// Accepts exactly the certificate whose hash is the pin, whatever its names and dates say.
#[derive(Debug)]
struct Pinned {
    pin: Pin,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if bool::from(Pin::of(end_entity.as_ref()).0.ct_eq(&self.pin.0)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// A client configuration that trusts one certificate, by hash.
pub fn client_config(pin: Pin) -> Result<Arc<ClientConfig>, RelayError> {
    let provider = provider();
    let algorithms = provider.signature_verification_algorithms;
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned { pin, algorithms }))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_survives_disk_and_its_pin_is_its_certificate() {
        let dir = std::env::temp_dir().join(format!("unheld-relay-id-{}", std::process::id()));
        let id = Identity::generate("127.0.0.1").unwrap();
        id.save(&dir).unwrap();
        let back = Identity::load(&dir).unwrap();
        assert_eq!(id.pin(), back.pin());
        assert_eq!(Pin::parse(&id.pin().to_hex()).unwrap(), id.pin());
        assert!(Pin::parse("zz").is_err());
        back.server_config().unwrap();
        client_config(id.pin()).unwrap();
    }
}
