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

use std::path::Path;

use anyhow::{anyhow, Context};
use opcua::crypto::{CertificateStore, X509Data, X509};
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
}
