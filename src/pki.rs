//! Application instance certificate and trust lists.
//!
//! The directory layout is the one used by async-opcua (and most OPC UA stacks):
//!
//! ```text
//! pki/
//!   own/cert.der          gateway certificate (shown to clients and to the PLC)
//!   private/private.pem   gateway private key
//!   trusted/              certificates of trusted clients and upstream servers
//!   rejected/             unknown certificates, waiting for an administrator
//! ```

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use opcua::crypto::{CertificateStore, KeySize, PrivateKey, SecurityPolicy, X509Data, X509};
use serde::Serialize;

use crate::config::GatewayConfig;

/// Validity of a newly generated gateway certificate. PLC trust lists are
/// tedious to update, so this errs on the long side.
const CERTIFICATE_DAYS: u32 = 5 * 365;
const KEY_SIZE: u32 = 2048;

#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub thumbprint: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

impl CertificateInfo {
    pub fn from_x509(cert: &X509) -> Self {
        Self {
            subject: cert.subject_name(),
            thumbprint: cert.thumbprint().as_hex_string(),
            not_before: cert.not_before().ok().map(|t| t.to_rfc3339()),
            not_after: cert.not_after().ok().map(|t| t.to_rfc3339()),
        }
    }
}

pub struct Pki {
    store: CertificateStore,
}

impl Pki {
    pub fn open(pki_dir: &Path) -> anyhow::Result<Self> {
        let store = CertificateStore::new(pki_dir);
        store
            .ensure_pki_path()
            .map_err(|e| anyhow!(e))
            .with_context(|| format!("creating PKI directory {}", pki_dir.display()))?;
        Ok(Self { store })
    }

    /// Makes sure the gateway has an application instance certificate, generating
    /// a self-signed one when none exists. Returns the certificate and whether it
    /// was newly created.
    pub fn ensure_own_certificate(&self, gateway: &GatewayConfig) -> anyhow::Result<(X509, bool)> {
        if let (Ok(cert), Ok(_)) = (self.store.read_own_cert(), self.store.read_own_pkey()) {
            return Ok((cert, false));
        }
        let args = certificate_request(gateway);
        let (cert, _key) = self
            .store
            .create_and_store_application_instance_cert(&args, false)
            .map_err(|e| anyhow!("generating gateway certificate: {e}"))?;
        Ok((cert, true))
    }

    pub fn own_certificate(&self) -> anyhow::Result<X509> {
        self.store.read_own_cert().map_err(|e| anyhow!(e))
    }

    pub fn trusted(&self) -> Vec<CertificateInfo> {
        list_dir(&self.store.trusted_certs_dir())
    }

    pub fn rejected(&self) -> Vec<CertificateInfo> {
        list_dir(&self.store.rejected_certs_dir())
    }

    pub fn own_certificate_der(&self) -> anyhow::Result<Vec<u8>> {
        let path = self.store.own_certificate_path();
        std::fs::read(&path).with_context(|| format!("reading {}", path.display()))
    }

    /// Adds a certificate to the trust list (and removes it from rejected).
    pub fn trust(&self, cert: &X509) -> anyhow::Result<CertificateInfo> {
        let name = CertificateStore::cert_file_name(cert);
        let der = cert
            .to_der()
            .map_err(|e| anyhow!("encoding certificate: {e}"))?;
        write_file(&self.store.trusted_certs_dir().join(&name), &der)?;
        if let Some(path) = find(
            &self.store.rejected_certs_dir(),
            &cert.thumbprint().as_hex_string(),
        ) {
            let _ = std::fs::remove_file(path);
        }
        Ok(CertificateInfo::from_x509(cert))
    }

    /// Moves a rejected certificate to the trust list.
    pub fn trust_rejected(&self, thumbprint: &str) -> anyhow::Result<CertificateInfo> {
        let path = find(&self.store.rejected_certs_dir(), thumbprint)
            .ok_or_else(|| anyhow!("no rejected certificate {thumbprint}"))?;
        let cert = CertificateStore::read_cert(&path).map_err(|e| anyhow!(e))?;
        self.trust(&cert)
    }

    /// Moves a trusted certificate back to rejected, so it can be trusted again later.
    pub fn untrust(&self, thumbprint: &str) -> anyhow::Result<CertificateInfo> {
        let path = find(&self.store.trusted_certs_dir(), thumbprint)
            .ok_or_else(|| anyhow!("no trusted certificate {thumbprint}"))?;
        let cert = CertificateStore::read_cert(&path).map_err(|e| anyhow!(e))?;
        let target = self
            .store
            .rejected_certs_dir()
            .join(CertificateStore::cert_file_name(&cert));
        std::fs::rename(&path, &target)
            .with_context(|| format!("moving {} to rejected", path.display()))?;
        Ok(CertificateInfo::from_x509(&cert))
    }

    pub fn delete_rejected(&self, thumbprint: &str) -> anyhow::Result<CertificateInfo> {
        let path = find(&self.store.rejected_certs_dir(), thumbprint)
            .ok_or_else(|| anyhow!("no rejected certificate {thumbprint}"))?;
        let cert = CertificateStore::read_cert(&path).map_err(|e| anyhow!(e))?;
        std::fs::remove_file(&path)?;
        Ok(CertificateInfo::from_x509(&cert))
    }

    /// Replaces the gateway certificate with a new self-signed one. The old
    /// pair is kept as `.bak`. Every PLC must then trust the new certificate.
    pub fn regenerate_own(&self, gateway: &GatewayConfig) -> anyhow::Result<X509> {
        self.backup_own()?;
        let (cert, _key) = self
            .store
            .create_and_store_application_instance_cert(&certificate_request(gateway), true)
            .map_err(|e| anyhow!("generating gateway certificate: {e}"))?;
        Ok(cert)
    }

    /// Installs a certificate (DER or PEM) and its private key (PEM), e.g. one
    /// issued by a plant CA. Refuses a key that does not belong to the certificate.
    pub fn import_own(&self, cert: &[u8], key_pem: &[u8]) -> anyhow::Result<X509> {
        let cert = X509::from_der(cert)
            .or_else(|_| X509::from_pem(cert))
            .map_err(|_| anyhow!("the certificate is neither DER nor PEM"))?;
        let key = PrivateKey::from_pem(key_pem)
            .map_err(|_| anyhow!("the private key is not a PEM encoded RSA key"))?;
        let policy = SecurityPolicy::Basic256Sha256;
        let probe = b"opcua-audit-gateway key check";
        let mut signature = vec![0u8; key.size()];
        policy
            .asymmetric_sign(&key, probe, &mut signature)
            .map_err(|e| anyhow!("private key unusable: {e}"))?;
        let public = cert
            .public_key()
            .map_err(|e| anyhow!("certificate has no usable public key: {e}"))?;
        if policy
            .asymmetric_verify_signature(&public, probe, &signature)
            .is_err()
        {
            bail!("the private key does not belong to the certificate");
        }
        self.backup_own()?;
        let der = cert
            .to_der()
            .map_err(|e| anyhow!("encoding certificate: {e}"))?;
        write_file(&self.store.own_certificate_path(), &der)?;
        write_file(&self.store.own_private_key_path(), key_pem)?;
        Ok(cert)
    }

    fn backup_own(&self) -> anyhow::Result<()> {
        for path in [
            self.store.own_certificate_path(),
            self.store.own_private_key_path(),
        ] {
            if path.exists() {
                let mut bak = path.clone().into_os_string();
                bak.push(".bak");
                std::fs::copy(&path, PathBuf::from(bak))?;
            }
        }
        Ok(())
    }
}

fn write_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

/// The file in `dir` holding the certificate with this thumbprint.
fn find(dir: &Path, thumbprint: &str) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .find(|p| {
            CertificateStore::read_cert(p)
                .map(|c| {
                    c.thumbprint()
                        .as_hex_string()
                        .eq_ignore_ascii_case(thumbprint)
                })
                .unwrap_or(false)
        })
}

fn certificate_request(gateway: &GatewayConfig) -> X509Data {
    let application_uri = gateway.application_uri();
    let extra =
        (!gateway.certificate_hostnames.is_empty()).then(|| gateway.certificate_hostnames.clone());
    X509Data {
        key_size: KEY_SIZE,
        common_name: gateway.application_name.clone(),
        organization: gateway.application_name.clone(),
        organizational_unit: "opcua-audit-gateway".into(),
        country: String::new(),
        state: String::new(),
        alt_host_names: X509Data::alt_host_names(&application_uri, extra, true, true, true),
        certificate_duration_days: CERTIFICATE_DAYS,
    }
}

fn list_dir(dir: &Path) -> Vec<CertificateInfo> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut certs: Vec<_> = entries
        .flatten()
        .filter(|e| e.path().is_file())
        .filter_map(|e| CertificateStore::read_cert(&e.path()).ok())
        .map(|c| CertificateInfo::from_x509(&c))
        .collect();
    certs.sort_by(|a, b| a.subject.cmp(&b.subject));
    certs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_certificate_once() {
        let dir = tempfile::tempdir().unwrap();
        let gateway = GatewayConfig {
            application_uri: Some("urn:test:opcua-audit-gateway".into()),
            certificate_hostnames: vec!["gateway.test".into()],
            ..GatewayConfig::default()
        };
        let pki = Pki::open(dir.path()).unwrap();

        let (first, created) = pki.ensure_own_certificate(&gateway).unwrap();
        assert!(created);
        first
            .is_application_uri_valid("urn:test:opcua-audit-gateway")
            .unwrap();
        first.is_hostname_valid("gateway.test").unwrap();

        let (second, created) = pki.ensure_own_certificate(&gateway).unwrap();
        assert!(!created);
        assert_eq!(
            first.thumbprint().as_hex_string(),
            second.thumbprint().as_hex_string()
        );
        assert!(pki.trusted().is_empty());
    }

    #[test]
    fn trust_untrust_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::open(dir.path()).unwrap();
        let (cert, _) = X509::cert_and_pkey(&X509Data::sample_cert()).unwrap();
        let thumb = cert.thumbprint().as_hex_string();

        // A client shows up: the store puts its certificate in rejected.
        std::fs::write(
            pki.store.rejected_certs_dir().join("client.der"),
            cert.to_der().unwrap(),
        )
        .unwrap();
        assert_eq!(pki.rejected().len(), 1);

        pki.trust_rejected(&thumb).unwrap();
        assert_eq!(pki.trusted().len(), 1);
        assert!(pki.rejected().is_empty());

        pki.untrust(&thumb).unwrap();
        assert!(pki.trusted().is_empty());
        assert_eq!(pki.rejected().len(), 1);

        pki.delete_rejected(&thumb).unwrap();
        assert!(pki.rejected().is_empty());
        assert!(pki.trust_rejected(&thumb).is_err());
    }

    #[test]
    fn import_checks_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::open(&dir.path().join("pki")).unwrap();
        let make = |name: &str| {
            let cert = dir.path().join(format!("{name}.der"));
            let key = dir.path().join(format!("{name}.pem"));
            CertificateStore::create_certificate_and_key(
                &X509Data::sample_cert(),
                true,
                &cert,
                &key,
            )
            .unwrap();
            (std::fs::read(cert).unwrap(), std::fs::read(key).unwrap())
        };
        let (cert, key) = make("a");
        let (_, other_key) = make("b");
        let err = pki.import_own(&cert, &other_key).unwrap_err();
        assert!(err.to_string().contains("does not belong"));
        let imported = pki.import_own(&cert, &key).unwrap();
        assert_eq!(
            pki.own_certificate().unwrap().thumbprint().as_hex_string(),
            imported.thumbprint().as_hex_string()
        );
    }
}
