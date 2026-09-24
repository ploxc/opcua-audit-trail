//! HTTPS for the web UI (rustls with the `ring` provider, which cross-compiles
//! to every target the gateway ships for).

use std::sync::Arc;

use anyhow::{anyhow, Context};
use opcua::crypto::CertificateStore;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::Config;

/// The TLS configuration: the configured PEM files, or else the gateway's own
/// OPC UA certificate and key (self-signed; browsers ask to accept it once, or
/// import `pki/own/cert.der` as trusted).
pub fn server_config(config: &Config) -> anyhow::Result<ServerConfig> {
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
            let store = CertificateStore::new(&config.gateway.pki_dir);
            let cert_path = store.own_certificate_path();
            let key_path = store.own_private_key_path();
            let der = std::fs::read(&cert_path)
                .with_context(|| format!("reading {}", cert_path.display()))?;
            let key = PrivateKeyDer::from_pem_file(&key_path)
                .with_context(|| format!("reading {}", key_path.display()))?;
            (vec![CertificateDer::from(der)], key)
        }
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("TLS setup: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| anyhow!("TLS certificate or key unusable: {e}"))?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(server)
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
    async fn serves_https_with_the_gateway_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, EXAMPLE_CONFIG).unwrap();
        let mut config = Config::load(&path).unwrap();
        config.web.tls = true;
        let pki = crate::pki::Pki::open(&config.gateway.pki_dir).unwrap();
        let (cert, _) = pki.ensure_own_certificate(&config.gateway).unwrap();

        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(
            server_config(&config).unwrap(),
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
    fn half_configured_tls_is_rejected() {
        let mut config: Config = toml::from_str(EXAMPLE_CONFIG).unwrap();
        config.web.tls_certificate = Some("cert.pem".into());
        assert!(config.validate().is_err());
    }
}
