//! HTTPS for the web UI (rustls with the `ring` provider, which cross-compiles
//! to every target the gateway ships for).

use std::sync::Arc;

use anyhow::{anyhow, Context};
use opcua::crypto::{CertificateStore, X509Data, X509};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::Config;

/// Where the web UI's own certificate lives: separate from the gateway's
/// OPC UA certificate, so renewing one never touches the other (PLCs trust
/// the OPC UA one; browsers and assistants trust this one).
pub fn web_store(config: &Config) -> CertificateStore {
    CertificateStore::new(&config.gateway.data_dir.join("web-pki"))
}

fn web_certificate_request(config: &Config) -> X509Data {
    let hosts = &config.gateway.certificate_hostnames;
    X509Data {
        key_size: 2048,
        common_name: format!("{} (web UI)", config.gateway.application_name),
        organization: config.gateway.application_name.clone(),
        organizational_unit: "opcua-audit-gateway web UI".into(),
        country: String::new(),
        state: String::new(),
        alt_host_names: X509Data::alt_host_names(
            "urn:opcua-audit-gateway:web",
            (!hosts.is_empty()).then(|| hosts.clone()),
            true,
            true,
            true,
        ),
        // Browsers accept at most 398 days for public certificates; a
        // self-signed one the user trusts is not held to that, but a year
        // keeps it in line.
        certificate_duration_days: 397,
    }
}

/// The web UI's self-signed certificate, generated when there is none or
/// when certificate and key do not belong together (e.g. after a crash
/// halfway through writing them). Returns it and whether it was created.
pub fn ensure_web_certificate(config: &Config) -> anyhow::Result<(X509, bool)> {
    let store = web_store(config);
    let existing = match (store.read_own_cert(), store.read_own_pkey()) {
        (Ok(cert), Ok(key)) => match crate::pki::check_key_pair(&cert, &key) {
            Ok(()) => Some(cert),
            Err(e) => {
                tracing::warn!("web UI certificate: {e:#}; generating a new one");
                None
            }
        },
        _ => None,
    };
    let result = if let Some(cert) = existing {
        (cert, false)
    } else {
        let cert = crate::pki::create_own(&store, &web_certificate_request(config))
            .context("generating the web UI certificate")?;
        (cert, true)
    };
    crate::pki::protect_private_key(&store);
    Ok(result)
}

/// A new web UI certificate (e.g. with other host names). Used from the next
/// start of the gateway.
pub fn regenerate_web_certificate(config: &Config) -> anyhow::Result<X509> {
    let store = web_store(config);
    let cert = crate::pki::create_own(&store, &web_certificate_request(config))
        .context("generating the web UI certificate")?;
    crate::pki::protect_private_key(&store);
    Ok(cert)
}

/// The TLS configuration: the configured PEM files, or else the web UI's own
/// self-signed certificate (browsers ask to accept it once, or import it as
/// trusted: Settings, Web UI). Also returns the certificate it presents
/// (DER), which is what the Settings page offers for download.
pub fn server_config(config: &Config) -> anyhow::Result<(ServerConfig, Vec<u8>)> {
    let (chain, key) = match (&config.web.tls_certificate, &config.web.tls_private_key) {
        (Some(cert), Some(key)) => {
            let chain = CertificateDer::pem_file_iter(cert)
                .with_context(|| format!("reading {}", cert.display()))?
                .collect::<Result<Vec<_>, _>>()
                .with_context(|| format!("parsing {}", cert.display()))?;
            if chain.is_empty() {
                anyhow::bail!("{} contains no certificate", cert.display());
            }
            let key = PrivateKeyDer::from_pem_file(key)
                .with_context(|| format!("reading private key {}", key.display()))?;
            (chain, key)
        }
        _ => {
            ensure_web_certificate(config)?;
            let store = web_store(config);
            let cert_path = store.own_certificate_path();
            let key_path = store.own_private_key_path();
            let der = std::fs::read(&cert_path)
                .with_context(|| format!("reading {}", cert_path.display()))?;
            let key = PrivateKeyDer::from_pem_file(&key_path)
                .with_context(|| format!("reading {}", key_path.display()))?;
            (vec![CertificateDer::from(der)], key)
        }
    };
    let leaf = chain[0].to_vec();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("TLS setup: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| anyhow!("TLS certificate or key unusable: {e}"))?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((server, leaf))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::routing::get;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::config::EXAMPLE_CONFIG;

    #[tokio::test]
    async fn serves_https_with_its_own_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, EXAMPLE_CONFIG).unwrap();
        let mut config = Config::load(&path).unwrap();
        config.web.tls = true;
        let pki = crate::pki::Pki::open(&config.gateway.pki_dir).unwrap();
        let (opcua_cert, _) = pki.ensure_own_certificate(&config.gateway).unwrap();
        let (cert, created) = ensure_web_certificate(&config).unwrap();
        assert!(created);
        // Separate from the OPC UA certificate, and kept across starts.
        assert_ne!(cert.thumbprint(), opcua_cert.thumbprint());
        let (again, created) = ensure_web_certificate(&config).unwrap();
        assert!(!created);
        assert_eq!(again.thumbprint(), cert.thumbprint());

        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(
            server_config(&config).unwrap().0,
        ));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/api/health", get(|| async { "ok" }));
        tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .unwrap()
                .serve(app.into_make_service())
                .await
                .unwrap()
        });

        // A client that trusts exactly the gateway certificate.
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(cert.to_der().unwrap()))
            .unwrap();
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .expect("TLS handshake with the gateway certificate");
        stream
            .write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.ok();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("ok"));
    }

    #[test]
    fn mismatched_key_pair_is_replaced() {
        // Audit finding S10: a key that does not belong to the certificate
        // (a crash halfway) gives a new pair instead of a failing start.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, EXAMPLE_CONFIG).unwrap();
        let config = Config::load(&path).unwrap();
        let (first, _) = ensure_web_certificate(&config).unwrap();
        let other = tempfile::tempdir().unwrap();
        let other = CertificateStore::new(other.path());
        other
            .create_and_store_application_instance_cert(&web_certificate_request(&config), true)
            .unwrap();
        std::fs::copy(
            other.own_private_key_path(),
            web_store(&config).own_private_key_path(),
        )
        .unwrap();
        let (second, created) = ensure_web_certificate(&config).unwrap();
        assert!(created);
        assert_ne!(first.thumbprint(), second.thumbprint());
        server_config(&config).unwrap();
    }

    #[test]
    fn half_configured_tls_is_rejected() {
        let mut config: Config = toml::from_str(EXAMPLE_CONFIG).unwrap();
        config.web.tls_certificate = Some("cert.pem".into());
        assert!(config.validate().is_err());
    }
}
