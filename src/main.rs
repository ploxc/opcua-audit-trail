mod audit;
mod config;
mod discovery;
mod pki;
mod relay;
mod web;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};

use crate::audit::{AuditEntry, AuditEvent, AuditReader};
use crate::config::Config;
use crate::pki::Pki;

#[derive(Parser)]
#[command(
    version,
    about = "Transparent OPC UA gateway with an audit trail of every write"
)]
struct Cli {
    /// Path to the configuration file.
    #[arg(
        short,
        long,
        global = true,
        env = "OPCUA_GATEWAY_CONFIG",
        default_value = "config.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write an example config (if missing) and create the gateway certificate.
    Init,
    /// Run the gateway.
    Run,
    /// Show the endpoints (security policies, modes, login methods) of a server.
    Discover {
        /// Endpoint URL, e.g. opc.tcp://192.168.0.10:4840
        endpoint_url: String,
    },
    /// Check the integrity of the audit trail's hash chain.
    Verify,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // The client library logs its own errors for failures we already report.
                "info,opcua_client=off,opcua_core=warn,opcua_crypto=warn,opcua_types=warn".into()
            }),
        )
        .init();

    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async {
        match cli.command {
            Command::Init => init(&cli.config),
            Command::Run => run(&cli.config).await,
            Command::Discover { endpoint_url } => discover(&cli.config, &endpoint_url).await,
            Command::Verify => verify(&cli.config).await,
        }
    });
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn init(path: &Path) -> anyhow::Result<ExitCode> {
    if path.exists() {
        println!("config {} already exists, keeping it", path.display());
    } else {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, config::EXAMPLE_CONFIG)
            .with_context(|| format!("writing {}", path.display()))?;
        println!("wrote example config to {}", path.display());
    }
    let config = Config::load(path)?;
    let pki = Pki::open(&config.gateway.pki_dir)?;
    let (cert, created) = pki.ensure_own_certificate(&config.gateway)?;
    println!(
        "{} gateway certificate {} (thumbprint {})",
        if created { "created" } else { "found" },
        cert.subject_name(),
        cert.thumbprint().as_hex_string()
    );
    Ok(ExitCode::SUCCESS)
}

async fn run(path: &Path) -> anyhow::Result<ExitCode> {
    let config = Arc::new(Config::load(path)?);

    let pki = Pki::open(&config.gateway.pki_dir)?;
    let (cert, created) = pki.ensure_own_certificate(&config.gateway)?;
    tracing::info!(
        thumbprint = %cert.thumbprint().as_hex_string(),
        "{} gateway certificate {}",
        if created { "created" } else { "using" },
        cert.subject_name()
    );

    let db = config.audit_database();
    let audit = audit::start(&db, &config.audit)?;
    audit
        .record_committed(AuditEntry::new(AuditEvent::GatewayStarted {
            version: env!("CARGO_PKG_VERSION").into(),
        }))
        .await
        .context("writing the first audit record")?;
    tracing::info!("audit trail at {}", db.display());
    tokio::spawn(audit::run_retention(
        audit.clone(),
        config.audit.retention_days,
    ));

    let client = Arc::new(discovery::discovery_client(&config)?);
    let statuses = discovery::initial_statuses(&config);
    let mut relays = Vec::new();
    for target in &config.targets {
        tokio::spawn(discovery::monitor_target(
            client.clone(),
            target.clone(),
            statuses.clone(),
            audit.clone(),
        ));
        let relay = Arc::new(relay::RelayTarget::new(
            target.clone(),
            Arc::new(relay::GatewayIdentity::load(&config, target)?),
            statuses.clone(),
            client.clone(),
            audit.clone(),
            config.audit.fail_mode,
        ));
        tokio::spawn(relay::serve(relay.clone()));
        relays.push(relay);
    }

    let state = web::AppState {
        config: config.clone(),
        statuses,
        audit: audit.clone(),
        reader: AuditReader::new(&db),
        client,
        pki: Arc::new(pki),
        relays,
    };
    let listener = tokio::net::TcpListener::bind(config.web.listen)
        .await
        .with_context(|| format!("binding web UI to {}", config.web.listen))?;
    tracing::info!("web UI on http://{}", config.web.listen);
    axum::serve(listener, web::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("shutting down");
    if let Err(e) = audit
        .record_committed(AuditEntry::new(AuditEvent::GatewayStopped))
        .await
    {
        tracing::error!("could not record shutdown: {e}");
    }
    audit.flush().await;
    Ok(ExitCode::SUCCESS)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn discover(path: &Path, endpoint_url: &str) -> anyhow::Result<ExitCode> {
    // Discovery needs no certificate, so it also works before `init`.
    let config = if path.exists() {
        Config::load(path)?
    } else {
        let mut config = Config::default();
        config.gateway.pki_dir = std::env::temp_dir().join("opcua-audit-gateway-pki");
        config
    };
    let client = discovery::discovery_client(&config)?;
    let endpoints = discovery::discover(&client, endpoint_url).await?;
    if let Some(first) = endpoints.first() {
        println!(
            "server: {} ({})",
            first.server_application_name, first.server_application_uri
        );
        if let Some(cert) = &first.server_certificate {
            println!("certificate: {} [{}]", cert.subject, cert.thumbprint);
        }
    }
    println!(
        "\n{:<24} {:<16} {:>5}  user tokens",
        "security policy", "mode", "level"
    );
    for e in &endpoints {
        let tokens: Vec<_> = e
            .user_tokens
            .iter()
            .map(|t| t.token_type.as_str())
            .collect();
        println!(
            "{:<24} {:<16} {:>5}  {}",
            e.security_policy,
            e.security_mode,
            e.security_level,
            tokens.join(", ")
        );
    }
    Ok(ExitCode::SUCCESS)
}

async fn verify(path: &Path) -> anyhow::Result<ExitCode> {
    let config = Config::load(path)?;
    let report = AuditReader::new(&config.audit_database()).verify().await?;
    println!(
        "{} records (seq {}..{}), head {}",
        report.records,
        report.first_seq.unwrap_or(0),
        report.last_seq.unwrap_or(0),
        report.head_hash
    );
    if report.ok() {
        println!("audit trail intact");
        Ok(ExitCode::SUCCESS)
    } else {
        println!("AUDIT TRAIL BROKEN: {}", report.error.unwrap_or_default());
        Ok(ExitCode::from(2))
    }
}
