//! TLS for the exporters (QuestDB over HTTPS, syslog over TLS).

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

/// Splits `host:port` (also `[v6]:port`).
pub fn host_port(address: &str) -> anyhow::Result<(String, u16)> {
    let (host, port) = address
        .rsplit_once(':')
        .with_context(|| format!("{address} has no port"))?;
    Ok((
        host.to_string(),
        port.parse()
            .with_context(|| format!("invalid port in {address}"))?,
    ))
}
