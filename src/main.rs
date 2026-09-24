mod audit;
mod config;
mod discovery;
mod export;
mod pki;
mod relay;
mod targets;
#[cfg(test)]
mod testutil;
mod users;
mod web;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};

use crate::audit::{AuditEntry, AuditEvent, AuditReader};
use crate::config::Config;
use crate::pki::Pki;
use crate::users::{Role, UserStore};

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
    /// Manage web UI users.
    #[command(subcommand)]
    User(UserCommand),
}

#[derive(Subcommand)]
enum UserCommand {
    /// Add a user (asks for the password).
    Add {
        username: String,
        /// admin, operator or auditor
        #[arg(long, default_value = "auditor")]
        role: String,
    },
    /// Set a new password (asks for it).
    Passwd { username: String },
    /// Change a user's role.
    Role { username: String, role: String },
    /// Delete a user.
    Delete { username: String },
    /// List users.
    List,
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
            Command::Run => run(&cli.config, shutdown_signal()).await,
            Command::Discover { endpoint_url } => discover(&cli.config, &endpoint_url).await,
            Command::Verify => verify(&cli.config).await,
            Command::User(cmd) => user_command(&cli.config, cmd),
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

fn user_store(config: &Config) -> anyhow::Result<UserStore> {
    UserStore::open(&config.gateway.data_dir.join("gateway.db"))
}

fn read_new_password() -> anyhow::Result<String> {
    let first = rpassword::prompt_password("password: ")?;
    let second = rpassword::prompt_password("repeat password: ")?;
    if first != second {
        anyhow::bail!("the passwords do not match");
    }
    Ok(first)
}

fn user_command(path: &Path, cmd: UserCommand) -> anyhow::Result<ExitCode> {
    let config = Config::load(path)?;
    let users = user_store(&config)?;
    match cmd {
        UserCommand::Add { username, role } => {
            let role = Role::parse(&role)?;
            users.create(&username, &read_new_password()?, role)?;
            println!("added {username} ({})", role.as_str());
        }
        UserCommand::Passwd { username } => {
            users.set_password(&username, &read_new_password()?)?;
            println!("password of {username} changed");
        }
        UserCommand::Role { username, role } => {
            users.set_role(&username, Role::parse(&role)?)?;
            println!("role of {username} changed");
        }
        UserCommand::Delete { username } => {
            users.delete(&username)?;
            println!("deleted {username}");
        }
        UserCommand::List => {
            for u in users.list()? {
                println!(
                    "{:<24} {:<9} since {}",
                    u.username,
                    u.role.as_str(),
                    u.created_at
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Runs the gateway until `shutdown` completes.
async fn run(
    path: &Path,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<ExitCode> {
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

    let users = Arc::new(user_store(&config)?);
    if users.count()? == 0 {
        let password = users::random_password();
        users.create("admin", &password, Role::Admin)?;
        tracing::warn!(
            "created web UI user 'admin' with password '{password}'. \
             Log in and change it (or: opcua-audit-gateway user passwd admin)"
        );
        let _ = audit
            .record(AuditEntry::new(AuditEvent::ConfigChanged {
                by: "gateway".into(),
                summary: "created initial user 'admin'".into(),
            }))
            .await;
    }

    let client = Arc::new(discovery::discovery_client(&config)?);
    let statuses = discovery::initial_statuses(&Config::default());
    let targets = Arc::new(targets::TargetManager::new(
        path.to_path_buf(),
        config.as_ref().clone(),
        statuses.clone(),
        client.clone(),
        audit.clone(),
    ));
    targets.start_all().await;

    let exports = export::start(
        &config.export,
        AuditReader::new(&db),
        &config.gateway.data_dir.join("export-state.json"),
    )?;

    let state = web::AppState {
        config: config.clone(),
        targets: targets.clone(),
        statuses,
        audit: audit.clone(),
        reader: AuditReader::new(&db),
        client,
        pki: Arc::new(pki),
        users,
        sessions: Default::default(),
        browser: Default::default(),
        exports,
    };
    tokio::spawn(state.browser.clone().reap_idle(state.clone()));
    let router = web::router(state);
    if config.web.tls {
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(
            web::tls::server_config(&config)?,
        ));
        let listener = std::net::TcpListener::bind(config.web.listen)
            .with_context(|| format!("binding web UI to {}", config.web.listen))?;
        listener.set_nonblocking(true)?;
        let handle = axum_server::Handle::new();
        let stopper = handle.clone();
        tokio::spawn(async move {
            shutdown.await;
            stopper.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
        });
        tracing::info!("web UI on https://{}", config.web.listen);
        axum_server::from_tcp_rustls(listener, tls)?
            .handle(handle)
            .serve(router.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(config.web.listen)
            .await
            .with_context(|| format!("binding web UI to {}", config.web.listen))?;
        tracing::info!("web UI on http://{}", config.web.listen);
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown)
            .await?;
    }

    tracing::info!("shutting down");
    targets.stop_all().await;
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
