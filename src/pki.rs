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
/// Most certificates kept in `rejected/`: every unknown client adds one.
const MAX_REJECTED: usize = 200;

/// Whether a certificate's common name is safe as the file name async-opcua
/// derives from it (it only removes `/`; on Windows `\` and `:` would
/// leave the PKI directory).
pub fn safe_file_name(cert: &X509) -> bool {
    let name = cert.common_name().unwrap_or_default();
    !name.chars().any(|c| {
        c.is_control()
            || (cfg!(windows) && matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    })
}

/// Deletes the oldest files of `rejected/` beyond [`MAX_REJECTED`].
pub fn cap_rejected(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<_> = entries
        .flatten()
        .filter_map(|e| {
            let modified = e.metadata().ok()?.modified().ok()?;
            e.path().is_file().then(|| (modified, e.path()))
        })
        .collect();
    if files.len() <= MAX_REJECTED {
        return;
    }
    files.sort();
    for (_, path) in &files[..files.len() - MAX_REJECTED] {
        let _ = std::fs::remove_file(path);
    }
}

/// Makes the private key readable by the service only.
/// Generates a self-signed certificate with a new key and stores both as the
/// store's own. The key is created with mode 0600 in a 0700 directory (never
/// readable by others, whatever the umask) and written before the
/// certificate, each file replaced in one step.
pub(crate) fn create_own(store: &CertificateStore, args: &X509Data) -> anyhow::Result<X509> {
    use base64::Engine;
    let (cert, key) = X509::cert_and_pkey(args).map_err(|e| anyhow!("{e}"))?;
    let der = key.to_der().map_err(|e| anyhow!("encoding the key: {e}"))?;
    let body = base64::engine::general_purpose::STANDARD.encode(der.as_bytes());
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    let key_path = store.own_private_key_path();
    if let Some(dir) = key_path.parent() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir)?;
    }
    crate::fsutil::write_atomic(&key_path, pem.as_bytes(), Some(0o600))?;
    let cert_der = cert
        .to_der()
        .map_err(|e| anyhow!("encoding certificate: {e}"))?;
    crate::fsutil::write_atomic(&store.own_certificate_path(), &cert_der, Some(0o644))?;
    Ok(cert)
}

/// Fails unless `key` is the private key of `cert` (a signature made with
/// it verifies with the certificate's public key).
pub(crate) fn check_key_pair(cert: &X509, key: &PrivateKey) -> anyhow::Result<()> {
    let policy = SecurityPolicy::Basic256Sha256;
    let probe = b"opcua-audit-gateway key check";
    let mut signature = vec![0u8; key.size()];
    policy
        .asymmetric_sign(key, probe, &mut signature)
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
    Ok(())
}

pub(crate) fn protect_private_key(store: &CertificateStore) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key = store.own_private_key_path();
        if let Some(dir) = key.parent() {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        if key.exists() {
            let _ = std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600));
        }
    }
    #[cfg(not(unix))]
    let _ = store;
}

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
        // async-opcua writes the key with the default mode; also fixes keys
        // written by earlier versions.
        let result =
            if let (Ok(cert), Ok(key)) = (self.store.read_own_cert(), self.store.read_own_pkey()) {
                // Certificate and key are two files: an import or regenerate
                // interrupted between them leaves a pair that does not match.
                match check_key_pair(&cert, &key) {
                    Ok(()) => (cert, false),
                    Err(e) => {
                        let restored = self.restore_backup().with_context(|| {
                            format!(
                                "gateway certificate: {e:#}, and no backup pair matches; \
                                 import certificate and key again, or regenerate"
                            )
                        })?;
                        tracing::warn!(
                            "gateway certificate: {e:#} (an interrupted import?); restored \
                             the last backup pair [{}]",
                            restored.thumbprint().as_hex_string()
                        );
                        (restored, false)
                    }
                }
            } else {
                let cert = create_own(&self.store, &certificate_request(gateway))
                    .context("generating gateway certificate")?;
                (cert, true)
            };
        protect_private_key(&self.store);
        Ok(result)
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

    /// Number of rejected certificates, without parsing them.
    pub fn rejected_count(&self) -> usize {
        std::fs::read_dir(self.store.rejected_certs_dir())
            .map(|d| d.flatten().filter(|e| e.path().is_file()).count())
            .unwrap_or(0)
    }

    pub fn own_certificate_der(&self) -> anyhow::Result<Vec<u8>> {
        let path = self.store.own_certificate_path();
        std::fs::read(&path).with_context(|| format!("reading {}", path.display()))
    }

    /// Adds a certificate to the trust list (and removes it from rejected).
    pub fn trust(&self, cert: &X509) -> anyhow::Result<CertificateInfo> {
        if !safe_file_name(cert) {
            bail!("the certificate's common name cannot be used as a file name");
        }
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
        let cert = create_own(&self.store, &certificate_request(gateway))
            .context("generating gateway certificate")?;
        protect_private_key(&self.store);
        Ok(cert)
    }

    /// Installs a certificate (DER or PEM) and its private key (PEM), e.g. one
    /// issued by a plant CA. Refuses a key that does not belong to the certificate.
    pub fn import_own(
        &self,
        cert: &[u8],
        key_pem: &[u8],
        gateway: &GatewayConfig,
    ) -> anyhow::Result<X509> {
        let cert = X509::from_der(cert)
            .or_else(|_| X509::from_pem(cert))
            .map_err(|_| anyhow!("the certificate is neither DER nor PEM"))?;
        let key = PrivateKey::from_pem(key_pem)
            .map_err(|_| anyhow!("the private key is not a PEM encoded RSA key"))?;
        check_key_pair(&cert, &key)?;
        // Clients reject a certificate that is not valid now or names
        // another application.
        cert.is_time_valid(&chrono::Utc::now())
            .map_err(|_| anyhow!("the certificate is expired or not yet valid"))?;
        cert.is_application_uri_valid(&gateway.application_uri())
            .map_err(|_| {
                anyhow!(
                    "the certificate's subjectAltName must contain the application URI {}",
                    gateway.application_uri()
                )
            })?;
        self.backup_own()?;
        let der = cert
            .to_der()
            .map_err(|e| anyhow!("encoding certificate: {e}"))?;
        // Key first: each file is replaced in one step, and a key the old
        // certificate does not match is only a moment's state.
        crate::fsutil::write_atomic(&self.store.own_private_key_path(), key_pem, Some(0o600))?;
        crate::fsutil::write_atomic(&self.store.own_certificate_path(), &der, Some(0o644))?;
        protect_private_key(&self.store);
        Ok(cert)
    }

    /// Keeps the current pair as `<file>.<timestamp>.bak`.
    /// Puts back the newest backup pair (`.<stamp>.bak`, taken before every
    /// import and regenerate) whose key belongs to its certificate.
    fn restore_backup(&self) -> anyhow::Result<X509> {
        let cert_path = self.store.own_certificate_path();
        let key_path = self.store.own_private_key_path();
        let name = |p: &Path| {
            p.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        let (cert_name, key_name) = (name(&cert_path), name(&key_path));
        let dir = cert_path.parent().unwrap_or(Path::new("."));
        let mut stamps: Vec<String> = std::fs::read_dir(dir)?
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.strip_prefix(&format!("{cert_name}."))?
                    .strip_suffix(".bak")
                    .map(String::from)
            })
            .collect();
        stamps.sort();
        for stamp in stamps.iter().rev() {
            let cert_bak = dir.join(format!("{cert_name}.{stamp}.bak"));
            let key_bak = key_path.with_file_name(format!("{key_name}.{stamp}.bak"));
            let (Ok(cert_der), Ok(key_pem)) = (std::fs::read(&cert_bak), std::fs::read(&key_bak))
            else {
                continue;
            };
            let (Ok(cert), Ok(key)) = (X509::from_der(&cert_der), PrivateKey::from_pem(&key_pem))
            else {
                continue;
            };
            if check_key_pair(&cert, &key).is_ok() {
                crate::fsutil::write_atomic(&key_path, &key_pem, Some(0o600))?;
                crate::fsutil::write_atomic(&cert_path, &cert_der, Some(0o644))?;
                return Ok(cert);
            }
        }
        bail!("no matching backup")
    }

    fn backup_own(&self) -> anyhow::Result<()> {
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
        for path in [
            self.store.own_certificate_path(),
            self.store.own_private_key_path(),
        ] {
            if path.exists() {
                let mut bak = path.clone().into_os_string();
                bak.push(format!(".{stamp}.bak"));
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
    fn new_keys_are_never_readable_by_others() {
        // Audit finding S11: created 0600 (in a 0700 directory), not
        // chmod-ed afterwards; and the pair belongs together.
        let dir = tempfile::tempdir().unwrap();
        let store = CertificateStore::new(dir.path());
        let cert = create_own(&store, &certificate_request(&GatewayConfig::default())).unwrap();
        let key = store.read_own_pkey().unwrap();
        check_key_pair(&cert, &key).unwrap();
        assert_eq!(
            store.read_own_cert().unwrap().thumbprint(),
            cert.thumbprint()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            let key_path = store.own_private_key_path();
            assert_eq!(mode(&key_path), 0o600);
            assert_eq!(mode(key_path.parent().unwrap()), 0o700);
        }
    }

    #[test]
    fn interrupted_replacement_restores_the_backup() {
        // Audit finding N14: a new key without its certificate (a crash
        // between the two files) brings back the last matching pair.
        let dir = tempfile::tempdir().unwrap();
        let gateway = GatewayConfig {
            application_uri: Some("urn:test:opcua-audit-gateway".into()),
            ..GatewayConfig::default()
        };
        let pki = Pki::open(dir.path()).unwrap();
        let (first, _) = pki.ensure_own_certificate(&gateway).unwrap();
        let first_key = std::fs::read(pki.store.own_private_key_path()).unwrap();
        // A second pair, then only the first's certificate back: mismatch.
        let second = pki.regenerate_own(&gateway).unwrap();
        let cert_path = pki.store.own_certificate_path();
        std::fs::write(&cert_path, first.to_der().unwrap()).unwrap();
        let (restored, created) = pki.ensure_own_certificate(&gateway).unwrap();
        assert!(!created);
        // The backup taken before regenerate holds the first pair.
        assert_eq!(restored.thumbprint(), first.thumbprint());
        assert_ne!(restored.thumbprint(), second.thumbprint());
        assert_eq!(
            std::fs::read(pki.store.own_private_key_path()).unwrap(),
            first_key
        );

        // Without any matching backup it refuses to start.
        for e in std::fs::read_dir(cert_path.parent().unwrap())
            .unwrap()
            .flatten()
        {
            if e.file_name().to_string_lossy().ends_with(".bak") {
                std::fs::remove_file(e.path()).unwrap();
            }
        }
        let key_dir = pki.store.own_private_key_path();
        for e in std::fs::read_dir(key_dir.parent().unwrap())
            .unwrap()
            .flatten()
        {
            if e.file_name().to_string_lossy().ends_with(".bak") {
                std::fs::remove_file(e.path()).unwrap();
            }
        }
        std::fs::write(&cert_path, second.to_der().unwrap()).unwrap();
        assert!(pki.ensure_own_certificate(&gateway).is_err());
    }

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
        let gateway = GatewayConfig {
            application_uri: Some("urn:OPCUADemo".into()),
            ..GatewayConfig::default()
        };
        let err = pki.import_own(&cert, &other_key, &gateway).unwrap_err();
        assert!(err.to_string().contains("does not belong"));
        // A certificate for another application is refused.
        let other_app = GatewayConfig {
            application_uri: Some("urn:someone-else".into()),
            ..GatewayConfig::default()
        };
        let err = pki.import_own(&cert, &key, &other_app).unwrap_err();
        assert!(err.to_string().contains("application URI"), "{err}");
        let imported = pki.import_own(&cert, &key, &gateway).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(pki.store.own_private_key_path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the key is private");
        }
        assert_eq!(
            pki.own_certificate().unwrap().thumbprint().as_hex_string(),
            imported.thumbprint().as_hex_string()
        );
    }
}
