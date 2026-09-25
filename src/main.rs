mod audit;
mod config;
mod discovery;
mod export;
mod fsutil;
mod pki;
mod relay;
#[cfg(windows)]
mod service;
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
    /// Write logs to daily files in this directory (kept 14 days) instead of
    /// the console.
    #[arg(long, global = true, env = "OPCUA_GATEWAY_LOG_DIR")]
    log_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write an example config (if missing) and create the gateway certificate.
    Init,
    /// Run the gateway.
    Run {
        /// If the config file does not exist yet, create it as a copy of this
        /// file first (used by the container image).
        #[arg(long)]
        create_config_from: Option<PathBuf>,
    },
    /// Show the endpoints (security policies, modes, login methods) of a server.
    Discover {
        /// Endpoint URL, e.g. opc.tcp://192.168.0.10:4840
        endpoint_url: String,
    },
    /// Check the integrity of the audit trail's hash chain.
    ///
    /// The chain alone cannot show that its newest records were cut off or
    /// that it was rebuilt. Records known from elsewhere catch that: the last
    /// exported records are checked automatically, and `--expect` adds heads
    /// noted down earlier (printed by every run).
    Verify {
        /// A record that must still be in the trail, as SEQ:HASH.
        #[arg(long = "expect", value_name = "SEQ:HASH")]
        expect: Vec<String>,
    },
    /// Manage web UI users.
    #[command(subcommand)]
    User(UserCommand),
    /// Install or remove the Windows service.
    #[cfg(windows)]
    #[command(subcommand)]
    Service(ServiceCommand),
}

#[cfg(windows)]
#[derive(Subcommand)]
enum ServiceCommand {
    /// Register an auto-start service for this config (run as administrator).
    Install,
    /// Stop and remove the service.
    Uninstall,
    /// Entry point used by the service manager.
    Run,
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

fn init_logging(log_dir: Option<&Path>) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // The client library logs its own errors for failures we already report.
        "info,opcua_client=off,opcua_core=warn,opcua_crypto=warn,opcua_types=warn".into()
    });
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    let Some(dir) = log_dir else {
        builder.init();
        return None;
    };
    let _ = std::fs::create_dir_all(dir);
    let appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("gateway")
        .filename_suffix("log")
        .max_log_files(14)
        .build(dir);
    match appender {
        Ok(appender) => {
            let (writer, guard) = tracing_appender::non_blocking(appender);
            builder.with_ansi(false).with_writer(writer).init();
            Some(guard)
        }
        Err(e) => {
            builder.init();
            tracing::error!("cannot log to {}: {e}", dir.display());
            None
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let _log_guard = init_logging(cli.log_dir.as_deref());

    #[cfg(windows)]
    if let Command::Service(cmd) = &cli.command {
        let result = match cmd {
            ServiceCommand::Run => service::dispatch(cli.config.clone()),
            ServiceCommand::Install => std::path::absolute(&cli.config)
                .map_err(anyhow::Error::from)
                .and_then(|config| {
                    let log_dir = cli
                        .log_dir
                        .clone()
                        .unwrap_or_else(|| config.parent().unwrap_or(Path::new(".")).join("logs"));
                    let loaded = Config::load(&config)?;
                    let mut dirs = vec![
                        config.parent().unwrap_or(Path::new(".")).to_path_buf(),
                        loaded.gateway.data_dir.clone(),
                        loaded.gateway.pki_dir.clone(),
                        log_dir.clone(),
                    ];
                    // A directory inside another one is covered by it.
                    dirs.sort();
                    dirs.dedup();
                    let nested: Vec<_> = dirs
                        .iter()
                        .filter(|d| dirs.iter().any(|p| p != *d && d.starts_with(p)))
                        .cloned()
                        .collect();
                    dirs.retain(|d| !nested.contains(d));
                    service::install(&config, &log_dir, &dirs)?;
                    println!(
                        "installed service {} (config {}, logs in {}); only the service and \
                         administrators can access {}. Start it with: sc start {}",
                        service::NAME,
                        config.display(),
                        log_dir.display(),
                        dirs.iter()
                            .map(|d| d.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                        service::NAME
                    );
                    Ok(())
                }),
            ServiceCommand::Uninstall => service::uninstall().map(|()| println!("service removed")),
        };
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        };
    }

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
            Command::Run { create_config_from } => {
                if let Some(template) = create_config_from.filter(|_| !cli.config.exists()) {
                    if let Some(dir) = cli.config.parent().filter(|d| !d.as_os_str().is_empty()) {
                        std::fs::create_dir_all(dir).ok();
                    }
                    if let Err(e) = std::fs::copy(&template, &cli.config) {
                        eprintln!(
                            "error: cannot create {} from {}: {e}",
                            cli.config.display(),
                            template.display()
                        );
                        return Ok(ExitCode::FAILURE);
                    }
                    println!(
                        "created {} from {}",
                        cli.config.display(),
                        template.display()
                    );
                }
                run(&cli.config, shutdown_signal()).await
            }
            Command::Discover { endpoint_url } => discover(&cli.config, &endpoint_url).await,
            Command::Verify { expect } => verify(&cli.config, &expect).await,
            Command::User(cmd) => user_command(&cli.config, cmd),
            #[cfg(windows)]
            Command::Service(_) => unreachable!("handled above"),
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

/// The first admin password: `OPCUA_GATEWAY_ADMIN_PASSWORD` when set, else a
/// random one printed once to stdout (`docker compose logs gateway`), never
/// to a log file. Either way it must be changed at the first login.
fn create_initial_admin(users: &UserStore) -> anyhow::Result<()> {
    let from_env = std::env::var(ADMIN_PASSWORD_ENV)
        .ok()
        .filter(|p| !p.is_empty());
    match from_env {
        Some(password) => {
            users
                .create_initial_admin(&password)
                .context(ADMIN_PASSWORD_ENV)?;
            tracing::warn!(
                "created web UI user 'admin' with the password from {ADMIN_PASSWORD_ENV}; \
                 it must be changed at the first login"
            );
        }
        None => {
            let password = users::random_password();
            users.create_initial_admin(&password)?;
            println!(
                "\n  Web UI first login: admin / {password}\n  \
                 (shown once; it must be changed at the first login. Lost it? \
                 opcua-audit-gateway user passwd admin)\n"
            );
            tracing::warn!(
                "created web UI user 'admin'; its first password is printed on the console \
                 (stdout) only, and must be changed at the first login"
            );
        }
    }
    Ok(())
}

/// Environment variable with the first admin password (min. 8 characters).
const ADMIN_PASSWORD_ENV: &str = "OPCUA_GATEWAY_ADMIN_PASSWORD";

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
    let db = config.gateway.data_dir.join("gateway.db");
    let db = std::path::absolute(&db).unwrap_or(db);
    let existing: Vec<String> = users.list()?.into_iter().map(|u| u.username).collect();
    // Checked before asking for a password, not after.
    let must_exist = |username: &str| -> anyhow::Result<()> {
        if existing.iter().any(|u| u == username) {
            return Ok(());
        }
        if existing.is_empty() {
            anyhow::bail!(
                "there are no users yet in {} (is this the config the gateway runs with?)",
                db.display()
            );
        }
        anyhow::bail!(
            "no user '{username}' in {}; the users are: {}. Add one with: user add {username}",
            db.display(),
            existing.join(", ")
        )
    };
    match cmd {
        UserCommand::Add { username, role } => {
            let role = Role::parse(&role)?;
            if existing.contains(&username) {
                anyhow::bail!("user '{username}' already exists; change the password with: user passwd {username}");
            }
            users.create(&username, &read_new_password()?, role)?;
            println!("added {username} ({})", role.as_str());
        }
        // Without any users yet (the gateway never ran with this data
        // directory), `passwd admin` creates the admin with that password.
        UserCommand::Passwd { username } if username == "admin" && existing.is_empty() => {
            users.create_with("admin", &read_new_password()?, Role::Admin, false)?;
            println!("created admin in {} with this password", db.display());
        }
        UserCommand::Passwd { username } => {
            must_exist(&username)?;
            users.set_password(&username, &read_new_password()?)?;
            println!("password of {username} changed; their web sessions have ended");
        }
        UserCommand::Role { username, role } => {
            must_exist(&username)?;
            users.set_role(&username, Role::parse(&role)?)?;
            println!("role of {username} changed");
        }
        UserCommand::Delete { username } => {
            must_exist(&username)?;
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
    tokio::spawn(audit::run_retention(audit.clone()));

    let users = Arc::new(user_store(&config)?);
    if users.count()? == 0 {
        create_initial_admin(&users)?;
        let _ = audit
            .record(AuditEntry::new(AuditEvent::ConfigChanged {
                by: "gateway".into(),
                summary: "created initial user 'admin'".into(),
            }))
            .await;
    }

    // Corrections made while loading are made for real: the file is written
    // back, and each one is a record, like a change in the web UI.
    if !config.load_fixes.is_empty() {
        targets::write_targets(path, &config.targets)
            .with_context(|| format!("writing the corrected {}", path.display()))?;
        for summary in &config.load_fixes {
            let _ = audit
                .record(AuditEntry::new(AuditEvent::ConfigChanged {
                    by: "gateway".into(),
                    summary: summary.clone(),
                }))
                .await;
        }
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

    let exports = export::Exports::start(
        &config.export,
        AuditReader::new(&db),
        audit.clone(),
        &config.gateway.data_dir.join("export-state.json"),
    )?;

    // HTTPS setup failing stops the web UI only: the relay keeps auditing.
    let tls = if config.web.tls {
        match web::tls::server_config(&config) {
            Ok(tls) => Some(tls),
            Err(e) => {
                tracing::error!(
                    "web UI not started: HTTPS setup failed: {e:#}; the relay keeps running"
                );
                let _ = audit
                    .record(AuditEntry::new(AuditEvent::ConfigChanged {
                        by: "gateway".into(),
                        summary: format!("web UI not started: HTTPS setup failed: {e:#}"),
                    }))
                    .await;
                None
            }
        }
    } else {
        None
    };
    let state = web::AppState {
        web_certificate: tls.as_ref().map(|(_, der)| Arc::new(der.clone())),
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
    if config.web.tls && tls.is_none() {
        shutdown.await;
    } else if let Some((server, _)) = tls {
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server));
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
            .serve(router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(config.web.listen)
            .await
            .with_context(|| format!("binding web UI to {}", config.web.listen))?;
        tracing::info!("web UI on http://{}", config.web.listen);
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
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

async fn verify(path: &Path, expect: &[String]) -> anyhow::Result<ExitCode> {
    let config = Config::load(path)?;
    let mut anchors = export::anchors_from(&config.gateway.data_dir.join("export-state.json"));
    for e in expect {
        let (seq, hash) = e
            .split_once(':')
            .with_context(|| format!("--expect {e}: use SEQ:HASH"))?;
        anchors.push(audit::store::Anchor {
            seq: seq
                .parse()
                .with_context(|| format!("--expect {e}: invalid sequence number"))?,
            hash: hash.to_string(),
            source: format!("--expect {e}"),
        });
    }
    let db = config.audit_database();
    if !db.exists() {
        if anchors.is_empty() {
            println!("no audit trail yet at {}", db.display());
            return Ok(ExitCode::SUCCESS);
        }
        println!(
            "AUDIT TRAIL MISSING: {} does not exist, but {} had records",
            db.display(),
            anchors[0].source
        );
        return Ok(ExitCode::from(2));
    }
    let report = AuditReader::new(&db).verify_against(anchors).await?;
    println!(
        "{} records (seq {}..{}), head {}",
        report.records,
        report.first_seq.unwrap_or(0),
        report.last_seq.unwrap_or(0),
        report.head_hash
    );
    println!(
        "note the head to check later: opcua-audit-gateway verify --expect {}:{}",
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
