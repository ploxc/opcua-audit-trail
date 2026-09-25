//! TLS for the exporter (QuestDB over HTTPS).

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// A client configuration trusting `ca_file` (PEM), or the public roots.
pub fn client_config(ca_file: Option<&Path>) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    match ca_file {
        Some(path) => {
            for cert in CertificateDer::pem_file_iter(path)
                .with_context(|| format!("reading {}", path.display()))?
            {
                roots
                    .add(cert.with_context(|| format!("reading {}", path.display()))?)
                    .with_context(|| format!("using a certificate from {}", path.display()))?;
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Connects to `host:port` and completes a TLS handshake for `host`.
pub async fn connect(
    config: Arc<rustls::ClientConfig>,
    host: &str,
    port: u16,
) -> anyhow::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connecting to {host}:{port}"))?;
    let name = ServerName::try_from(
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
    )
    .with_context(|| format!("invalid host name {host}"))?;
    TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .with_context(|| format!("TLS handshake with {host}:{port}"))
}

#[cfg(test)]
pub mod tests {
    use std::path::PathBuf;

    use base64::Engine;

    use super::*;
    use crate::config::Config;

    /// A TLS server configuration for `localhost` (the web UI's own
    /// self-signed certificate) and a PEM file that trusts it.
    pub fn localhost_server(dir: &Path) -> (Arc<rustls::ServerConfig>, PathBuf) {
        let path = dir.join("config.toml");
        std::fs::write(&path, crate::config::EXAMPLE_CONFIG).unwrap();
        let mut config = Config::load(&path).unwrap();
        config.gateway.certificate_hostnames = vec!["localhost".into()];
        let (cert, _) = crate::web::tls::ensure_web_certificate(&config).unwrap();
        let base64 = base64::engine::general_purpose::STANDARD.encode(cert.to_der().unwrap());
        let lines: Vec<&str> = base64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let ca_file = dir.join("ca.pem");
        std::fs::write(
            &ca_file,
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                lines.join("\n")
            ),
        )
        .unwrap();
        let server = crate::web::tls::server_config(&config).unwrap();
        (Arc::new(server), ca_file)
    }

    #[tokio::test]
    async fn verifies_the_server_against_the_ca_file() {
        let dir = tempfile::tempdir().unwrap();
        let (server, ca_file) = localhost_server(dir.path());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server);
            while let Ok((tcp, _)) = listener.accept().await {
                let _ = acceptor.accept(tcp).await;
            }
        });
        let trusted = client_config(Some(&ca_file)).unwrap();
        connect(trusted, "localhost", port).await.unwrap();
        // The public roots do not include a self-signed certificate.
        let public = client_config(None).unwrap();
        assert!(connect(public, "localhost", port).await.is_err());
        // A trusted certificate for another name is refused too.
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let other = ServerName::try_from("other.test").unwrap();
        assert!(TlsConnector::from(client_config(Some(&ca_file)).unwrap())
            .connect(other, tcp)
            .await
            .is_err());
    }
}
