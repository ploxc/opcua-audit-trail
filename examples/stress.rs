//! Stress scenarios for the gateway: start one and let it run.
//!
//! ```sh
//! cargo run --release --example stress -- writes    --url opc.tcp://127.0.0.1:4841/
//! cargo run --release --example stress -- subscribe --items 500
//! cargo run --release --example stress -- sessions  --clients 20
//! cargo run --release --example stress -- reconnect
//! cargo run --release --example stress -- large     --kb 1024
//! cargo run --release --example stress -- soak      --duration 3600
//! cargo run --release --example stress -- all
//! ```
//!
//! Scenarios:
//! - `writes`: every client writes `Line1.Setpoint` as fast as it can (or at
//!   `--rate` per second). Throughput and latency of writes.
//! - `subscribe`: every client monitors `--items` items (the server clock and
//!   `Line1.*`, repeated) at `--interval` ms. Notifications per second: the
//!   everyday read traffic of an HMI or SCADA, which the gateway only passes on.
//! - `large`: writes strings of `--kb` KiB to `Line1.Recipe`. Servers limit
//!   the string length (async-opcua: 64 KiB by default) and refuse longer
//!   ones; the gateway still records every attempt.
//! - `sessions`: connect, read, disconnect, over and over, at `--connect-rate`
//!   sessions per second in total. Session setup cost (with `--secure`: the
//!   asymmetric crypto) and sessions left behind on the PLC.
//! - `reconnect`: connect, write a few times, then drop the connection without
//!   closing the session, over and over (also at `--connect-rate`). The
//!   abandoned sessions stay on the PLC until they time out
//!   (`--session-timeout`); a PLC has a session limit (the demo PLC: 20).
//! - `soak`: `writes` at 5 per second per client, for a long `--duration`.
//! - `all`: every scenario above except `soak`, one after the other.
//!
//! The gateway accepts at most 5 new connections per second from one address
//! (bursts of 10) and 10 at the same time; every session here takes two
//! (GetEndpoints, then the session). Raise `--connect-rate` or `--clients`
//! above that to see it refuse.
//!
//! Common options:
//! - `--direct opc.tcp://plc:4840/` runs the scenario against the PLC itself
//!   first, so the report shows what the gateway adds.
//! - `--user operator --password operator` logs in (default: anonymous);
//!   `--secure` uses Basic256Sha256 SignAndEncrypt. The client certificate is
//!   in `./stress-client-pki`; a strict PLC must trust it for `--direct`.
//! - `--namespace http://microsoft.com/Opc/OpcPlc/` for OPC PLC with
//!   `docker/opc-plc/nodes.json` (default: the demo PLC's `urn:demo-plc:line`).
//! - `--api http://127.0.0.1:8080 --api-user admin --api-password …` counts
//!   the gateway's `write` records afterwards and compares them with the
//!   writes that got an answer. The user needs at least the auditor role.
//!
//! Afterwards, check the chain with `opcua-audit-gateway verify` (or
//! Verify in the web UI).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use bytes::Bytes;
use clap::{Args, Parser, Subcommand};
use http_body_util::{BodyExt, Full};
use opcua::client::{ClientBuilder, DataChangeCallback, IdentityToken, Password, Session};
use opcua::crypto::SecurityPolicy;
use opcua::types::{
    AttributeId, DataValue, MessageSecurityMode, MonitoredItemCreateRequest, MonitoringMode,
    MonitoringParameters, NodeId, NumericRange, ReadValueId, StatusCode, TimestampsToReturn,
    VariableId, WriteValue,
};
use parking_lot::Mutex;
use tokio::task::JoinHandle;

#[derive(Parser)]
#[command(about = "Stress scenarios for the OPC UA audit gateway")]
struct Cli {
    #[command(subcommand)]
    scenario: Scenario,
    #[command(flatten)]
    common: Common,
}

#[derive(Subcommand, Clone, Copy)]
enum Scenario {
    /// Writes as fast as possible (or --rate per client per second).
    Writes {
        #[arg(long, default_value_t = 0.0)]
        rate: f64,
    },
    /// Monitored items: notifications per second.
    Subscribe {
        #[arg(long, default_value_t = 200)]
        items: usize,
        #[arg(long, default_value_t = 100)]
        interval: u64,
    },
    /// Connect, read, disconnect, over and over.
    Sessions,
    /// Connect, write, drop the connection without closing the session.
    Reconnect,
    /// Large string writes.
    Large {
        #[arg(long, default_value_t = 32)]
        kb: usize,
    },
    /// Writes at a steady rate for a long time.
    Soak {
        #[arg(long, default_value_t = 5.0)]
        rate: f64,
    },
    /// Every scenario except soak, one after the other.
    All,
}

#[derive(Args, Clone)]
struct Common {
    /// The gateway's endpoint.
    #[arg(long, global = true, default_value = "opc.tcp://127.0.0.1:4841/")]
    url: String,
    /// The PLC's own endpoint: run the scenario there first, for comparison.
    #[arg(long, global = true)]
    direct: Option<String>,
    #[arg(long, global = true)]
    user: Option<String>,
    #[arg(long, global = true)]
    password: Option<String>,
    /// Basic256Sha256 SignAndEncrypt instead of None.
    #[arg(long, global = true)]
    secure: bool,
    /// Namespace of the `Line1.*` nodes.
    #[arg(long, global = true, default_value = "urn:demo-plc:line")]
    namespace: String,
    /// Concurrent clients.
    #[arg(long, global = true, default_value_t = 4)]
    clients: usize,
    /// New sessions per second in total (sessions, reconnect).
    #[arg(long, global = true, default_value_t = 2.0)]
    connect_rate: f64,
    /// Session timeout the clients ask for, in ms: how long an abandoned
    /// session stays on the server.
    #[arg(long, global = true, default_value_t = 10_000)]
    session_timeout: u32,
    /// Seconds per scenario (soak: default one hour).
    #[arg(long, global = true)]
    duration: Option<u64>,
    /// The gateway's web UI, to count the audit records afterwards.
    #[arg(long, global = true)]
    api: Option<String>,
    #[arg(long, global = true, default_value = "admin")]
    api_user: String,
    #[arg(long, global = true)]
    api_password: Option<String>,
}

// ---------- results ----------

/// What a scenario counted. Latencies are in microseconds.
#[derive(Default)]
struct Stats {
    good: AtomicU64,
    bad: AtomicU64,
    errors: AtomicU64,
    notifications: AtomicU64,
    latencies: Mutex<Vec<u64>>,
    first_error: Mutex<Option<String>>,
    bad_codes: Mutex<std::collections::BTreeMap<String, u64>>,
}

impl Stats {
    fn timed(&self, started: Instant) {
        self.latencies
            .lock()
            .push(started.elapsed().as_micros() as u64);
    }

    fn status(&self, code: StatusCode) {
        if code.is_good() {
            self.good.fetch_add(1, Ordering::Relaxed);
        } else {
            self.bad.fetch_add(1, Ordering::Relaxed);
            *self.bad_codes.lock().entry(format!("{code}")).or_default() += 1;
        }
    }

    /// A failed request: a refusal by the server (a ServiceFault) counts as a
    /// bad status, a broken connection or timeout as an error.
    fn failed(&self, e: opcua::types::Error) {
        let code = e.status();
        let transport = [
            StatusCode::BadConnectionClosed,
            StatusCode::BadNotConnected,
            StatusCode::BadTimeout,
            StatusCode::BadCommunicationError,
            StatusCode::BadSecureChannelClosed,
            StatusCode::BadServerNotConnected,
        ];
        if transport.contains(&code) {
            self.error(e);
        } else {
            self.status(code);
        }
    }

    fn error(&self, e: impl std::fmt::Display) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        self.first_error.lock().get_or_insert_with(|| e.to_string());
    }

    /// Requests that got an answer from the server (good or bad status).
    fn answered(&self) -> u64 {
        self.good.load(Ordering::Relaxed) + self.bad.load(Ordering::Relaxed)
    }

    fn report(&self, label: &str, what: &str, elapsed: Duration) {
        let secs = elapsed.as_secs_f64().max(0.001);
        let good = self.good.load(Ordering::Relaxed);
        let bad = self.bad.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);
        let notifications = self.notifications.load(Ordering::Relaxed);
        println!("  {label}");
        // Monitored items are created once: a rate says nothing there.
        let rate = if what == "monitored items" {
            String::new()
        } else {
            format!(" = {:.0}/s", (good + bad) as f64 / secs)
        };
        println!("    {what}: {good} good, {bad} bad status, {errors} errors in {secs:.1} s{rate}");
        if notifications > 0 {
            println!(
                "    notifications: {notifications} = {:.0}/s",
                notifications as f64 / secs
            );
        }
        let mut l = std::mem::take(&mut *self.latencies.lock());
        if !l.is_empty() {
            l.sort_unstable();
            let p = |q: f64| l[((l.len() - 1) as f64 * q) as usize] as f64 / 1000.0;
            println!(
                "    latency ms: p50 {:.2}  p95 {:.2}  p99 {:.2}  max {:.2}",
                p(0.50),
                p(0.95),
                p(0.99),
                p(1.0)
            );
        }
        for (code, n) in self.bad_codes.lock().iter() {
            println!("    bad: {code} x{n}");
        }
        if let Some(e) = self.first_error.lock().as_ref() {
            println!("    first error: {e}");
            if e.contains("BadCertificateUntrusted") || e.contains("BadSecurityChecksFailed") {
                println!(
                    "    hint: the server does not trust ./stress-client-pki/own/cert.der yet: \
                     trust the \"Stress client\" certificate (gateway: Certificates in the \
                     web UI, or move it from pki/rejected to pki/trusted)"
                );
            }
        }
    }
}

// ---------- OPC UA ----------

struct Conn {
    session: Arc<Session>,
    event_loop: JoinHandle<StatusCode>,
    ns: u16,
}

impl Conn {
    fn node(&self, name: &str) -> NodeId {
        NodeId::new(self.ns, format!("Line1.{name}"))
    }

    fn write_value(&self, name: &str, value: DataValue) -> WriteValue {
        WriteValue {
            node_id: self.node(name),
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
            value,
        }
    }

    async fn close(self) {
        let _ = self.session.disconnect().await;
        self.event_loop.abort();
    }

    /// Drops the TCP connection without closing the session, like a client
    /// that crashes or loses the network.
    fn drop_hard(self) {
        self.event_loop.abort();
    }
}

async fn connect(c: &Common, url: &str) -> anyhow::Result<Conn> {
    let identity = match (&c.user, &c.password) {
        (Some(u), Some(p)) => IdentityToken::UserName(u.clone(), Password::new(p.clone())),
        _ => IdentityToken::Anonymous,
    };
    let (policy, mode) = if c.secure {
        (
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
        )
    } else {
        (SecurityPolicy::None, MessageSecurityMode::None)
    };
    let mut client = ClientBuilder::new()
        .application_name("Stress client")
        .application_uri("urn:stress-client")
        .pki_dir("./stress-client-pki")
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .session_timeout(c.session_timeout)
        .client()
        .map_err(|e| anyhow::anyhow!("client configuration: {e:?}"))?;
    let (session, event_loop) = client
        .connect_to_matching_endpoint((url, policy.to_uri(), mode), identity)
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e}"))?;
    let mut event_loop = event_loop.spawn();
    tokio::select! {
        connected = session.wait_for_connection() => {
            if !connected {
                event_loop.abort();
                bail!("no session");
            }
        }
        // The event loop ends when the connection fails: its status says why
        // (e.g. BadSecurityChecksFailed for an untrusted certificate).
        ended = &mut event_loop => {
            bail!("connection failed: {}", ended.map(|s| s.to_string()).unwrap_or_default());
        }
        _ = tokio::time::sleep(Duration::from_secs(10)) => {
            event_loop.abort();
            bail!("no session within 10 s");
        }
    }
    let ns = match session.get_namespace_index(&c.namespace).await {
        Ok(ns) => ns,
        Err(e) => {
            event_loop.abort();
            bail!(
                "namespace {} not found ({e}); pick one with --namespace",
                c.namespace
            );
        }
    };
    Ok(Conn {
        session,
        event_loop,
        ns,
    })
}

// ---------- scenarios ----------

/// Spreads new sessions over time: at most `rate` per second over all clients.
struct Pacer {
    next: tokio::sync::Mutex<Instant>,
    period: Duration,
}

impl Pacer {
    fn new(rate: f64) -> Arc<Self> {
        Arc::new(Pacer {
            next: tokio::sync::Mutex::new(Instant::now()),
            period: Duration::from_secs_f64(1.0 / rate.max(0.01)),
        })
    }

    async fn wait(&self) {
        let mut next = self.next.lock().await;
        let now = Instant::now();
        if *next > now {
            tokio::time::sleep(*next - now).await;
        }
        *next = (*next).max(now) + self.period;
    }
}

/// Runs `worker` in `--clients` tasks until the deadline and prints progress
/// every 10 seconds.
async fn run_workers<F, Fut>(clients: usize, duration: Duration, stats: &Arc<Stats>, worker: F)
where
    F: Fn(usize, Instant) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let deadline = Instant::now() + duration;
    let tasks: Vec<_> = (0..clients)
        .map(|i| tokio::spawn(worker(i, deadline)))
        .collect();
    let done = Arc::new(AtomicBool::new(false));
    let progress = {
        let stats = stats.clone();
        let done = done.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let mut last = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                if done.load(Ordering::Relaxed) {
                    break;
                }
                let now = stats.answered() + stats.notifications.load(Ordering::Relaxed);
                eprintln!(
                    "    ... {:>4.0} s: {:.0}/s, {} errors",
                    started.elapsed().as_secs_f64(),
                    (now - last) as f64 / 10.0,
                    stats.errors.load(Ordering::Relaxed)
                );
                last = now;
            }
        })
    };
    for t in tasks {
        let _ = t.await;
    }
    done.store(true, Ordering::Relaxed);
    progress.abort();
}

/// Sleeps so that a loop runs at `rate` per second (0: no pause).
async fn pace(rate: f64, started: Instant) {
    if rate > 0.0 {
        let period = Duration::from_secs_f64(1.0 / rate);
        tokio::time::sleep(period.saturating_sub(started.elapsed())).await;
    }
}

async fn writes(c: Arc<Common>, url: String, rate: f64, duration: Duration) -> Arc<Stats> {
    let stats = Arc::new(Stats::default());
    run_workers(c.clients, duration, &stats, |i, deadline| {
        let (c, url, stats) = (c.clone(), url.clone(), stats.clone());
        async move {
            let conn = match connect(&c, &url).await {
                Ok(conn) => conn,
                Err(e) => return stats.error(e),
            };
            let mut n = 0u64;
            while Instant::now() < deadline {
                let started = Instant::now();
                n += 1;
                let value = 50.0 + i as f64 + (n % 100) as f64 / 10.0;
                let w = conn.write_value("Setpoint", DataValue::value_only(value));
                match conn.session.write(&[w]).await {
                    Ok(r) => {
                        stats.timed(started);
                        r.into_iter().for_each(|s| stats.status(s));
                    }
                    Err(e) => stats.failed(e),
                }
                pace(rate, started).await;
            }
            conn.close().await;
        }
    })
    .await;
    stats
}

async fn subscribe(
    c: Arc<Common>,
    url: String,
    items: usize,
    interval: u64,
    duration: Duration,
) -> Arc<Stats> {
    let stats = Arc::new(Stats::default());
    run_workers(c.clients, duration, &stats, |_, deadline| {
        let (c, url, stats) = (c.clone(), url.clone(), stats.clone());
        async move {
            let conn = match connect(&c, &url).await {
                Ok(conn) => conn,
                Err(e) => return stats.error(e),
            };
            let counter = stats.clone();
            let subscription = conn
                .session
                .create_subscription(
                    Duration::from_millis(interval),
                    60,
                    10,
                    0,
                    0,
                    true,
                    DataChangeCallback::new(move |_, _| {
                        counter.notifications.fetch_add(1, Ordering::Relaxed);
                    }),
                )
                .await;
            let subscription = match subscription {
                Ok(id) => id,
                Err(e) => {
                    stats.error(format!("create subscription: {e}"));
                    return conn.close().await;
                }
            };
            let nodes = [
                NodeId::from(VariableId::Server_ServerStatus_CurrentTime),
                conn.node("Setpoint"),
                conn.node("Running"),
                conn.node("Recipe"),
            ];
            let requests: Vec<_> = (0..items)
                .map(|i| {
                    MonitoredItemCreateRequest::new(
                        ReadValueId::from(nodes[i % nodes.len()].clone()),
                        MonitoringMode::Reporting,
                        MonitoringParameters {
                            sampling_interval: interval as f64,
                            queue_size: 1,
                            discard_oldest: true,
                            ..Default::default()
                        },
                    )
                })
                .collect();
            let started = Instant::now();
            match conn
                .session
                .create_monitored_items(subscription, TimestampsToReturn::Both, requests)
                .await
            {
                Ok(created) => {
                    stats.timed(started);
                    created
                        .iter()
                        .for_each(|m| stats.status(m.result.status_code));
                }
                Err(e) => stats.error(format!("create monitored items: {e}")),
            }
            tokio::time::sleep(deadline.saturating_duration_since(Instant::now())).await;
            conn.close().await;
        }
    })
    .await;
    stats
}

async fn sessions(c: Arc<Common>, url: String, duration: Duration) -> Arc<Stats> {
    let stats = Arc::new(Stats::default());
    let pacer = Pacer::new(c.connect_rate);
    run_workers(c.clients, duration, &stats, |_, deadline| {
        let (c, url, stats, pacer) = (c.clone(), url.clone(), stats.clone(), pacer.clone());
        async move {
            while Instant::now() < deadline {
                pacer.wait().await;
                let started = Instant::now();
                let conn = match connect(&c, &url).await {
                    Ok(conn) => conn,
                    Err(e) => {
                        stats.error(e);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                };
                let read =
                    ReadValueId::from(NodeId::from(VariableId::Server_ServerStatus_CurrentTime));
                match conn
                    .session
                    .read(&[read], TimestampsToReturn::Neither, 0.0)
                    .await
                {
                    Ok(r) => {
                        stats.timed(started);
                        r.iter()
                            .for_each(|d| stats.status(d.status.unwrap_or(StatusCode::Good)));
                    }
                    Err(e) => stats.error(e),
                }
                conn.close().await;
            }
        }
    })
    .await;
    stats
}

async fn reconnect(c: Arc<Common>, url: String, duration: Duration) -> Arc<Stats> {
    let stats = Arc::new(Stats::default());
    let pacer = Pacer::new(c.connect_rate);
    run_workers(c.clients, duration, &stats, |i, deadline| {
        let (c, url, stats, pacer) = (c.clone(), url.clone(), stats.clone(), pacer.clone());
        async move {
            while Instant::now() < deadline {
                pacer.wait().await;
                let conn = match connect(&c, &url).await {
                    Ok(conn) => conn,
                    Err(e) => {
                        stats.error(e);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                };
                for n in 0..5 {
                    let started = Instant::now();
                    let value = 40.0 + i as f64 + f64::from(n);
                    let w = conn.write_value("Setpoint", DataValue::value_only(value));
                    match conn.session.write(&[w]).await {
                        Ok(r) => {
                            stats.timed(started);
                            r.into_iter().for_each(|s| stats.status(s));
                        }
                        Err(e) => stats.failed(e),
                    }
                }
                conn.drop_hard();
            }
        }
    })
    .await;
    stats
}

async fn large(c: Arc<Common>, url: String, kb: usize, duration: Duration) -> Arc<Stats> {
    let stats = Arc::new(Stats::default());
    run_workers(c.clients, duration, &stats, |i, deadline| {
        let (c, url, stats) = (c.clone(), url.clone(), stats.clone());
        async move {
            let conn = match connect(&c, &url).await {
                Ok(conn) => conn,
                Err(e) => return stats.error(e),
            };
            let mut n = 0usize;
            while Instant::now() < deadline {
                n += 1;
                let fill = char::from(b'A' + ((i + n) % 26) as u8);
                let text: String = std::iter::repeat_n(fill, kb * 1024).collect();
                let started = Instant::now();
                let w = conn.write_value("Recipe", DataValue::value_only(text));
                match conn.session.write(&[w]).await {
                    Ok(r) => {
                        stats.timed(started);
                        r.into_iter().for_each(|s| stats.status(s));
                    }
                    Err(e) => stats.failed(e),
                }
            }
            conn.close().await;
        }
    })
    .await;
    stats
}

// ---------- the gateway's audit trail ----------

/// A logged-in client for the gateway's web API.
struct Api {
    base: String,
    cookie: String,
    http: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<Bytes>,
    >,
}

impl Api {
    async fn login(base: &str, user: &str, password: &str) -> anyhow::Result<Self> {
        let http =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        let mut api = Api {
            base: base.trim_end_matches('/').to_string(),
            cookie: String::new(),
            http,
        };
        let body = serde_json::json!({ "username": user, "password": password });
        let (status, headers, _) = api.send("POST", "/api/login", Some(body)).await?;
        if !status.is_success() {
            bail!("web login as {user}: {status}");
        }
        api.cookie = headers
            .get(hyper::header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .context("no session cookie")?
            .to_string();
        Ok(api)
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> anyhow::Result<(hyper::StatusCode, hyper::HeaderMap, serde_json::Value)> {
        let mut request = hyper::Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base))
            .header("x-requested-with", "opcua-audit-gateway")
            .header("content-type", "application/json");
        if !self.cookie.is_empty() {
            request = request.header("cookie", &self.cookie);
        }
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let response = self
            .http
            .request(request.body(Full::new(Bytes::from(body)))?)
            .await
            .with_context(|| format!("{method} {path}"))?;
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await?.to_bytes();
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        Ok((parts.status, parts.headers, value))
    }

    /// The newest sequence number in the trail.
    async fn head(&self) -> anyhow::Result<i64> {
        let (status, _, v) = self.send("GET", "/api/audit?limit=1", None).await?;
        if !status.is_success() {
            bail!("reading the audit trail: {status} {v}");
        }
        Ok(v[0]["seq"].as_i64().unwrap_or(0))
    }

    /// `write` records after `seq`.
    async fn writes_after(&self, seq: i64) -> anyhow::Result<u64> {
        let mut count = 0;
        let mut before: Option<i64> = None;
        loop {
            let mut path = format!("/api/audit?kind=write&after_seq={seq}&limit=1000");
            if let Some(b) = before {
                path.push_str(&format!("&before_seq={b}"));
            }
            let (status, _, v) = self.send("GET", &path, None).await?;
            if !status.is_success() {
                bail!("reading the audit trail: {status} {v}");
            }
            let page = v.as_array().cloned().unwrap_or_default();
            count += page.len() as u64;
            if page.len() < 1000 {
                return Ok(count);
            }
            before = page.last().and_then(|r| r["seq"].as_i64());
        }
    }
}

// ---------- main ----------

impl Scenario {
    fn name(self) -> &'static str {
        match self {
            Scenario::Writes { .. } => "writes",
            Scenario::Subscribe { .. } => "subscribe",
            Scenario::Sessions => "sessions",
            Scenario::Reconnect => "reconnect",
            Scenario::Large { .. } => "large",
            Scenario::Soak { .. } => "soak",
            Scenario::All => "all",
        }
    }

    /// What one counted unit is.
    fn unit(self) -> &'static str {
        match self {
            Scenario::Subscribe { .. } => "monitored items",
            Scenario::Sessions => "sessions",
            _ => "writes",
        }
    }

    fn writes(self) -> bool {
        matches!(
            self,
            Scenario::Writes { .. }
                | Scenario::Reconnect
                | Scenario::Large { .. }
                | Scenario::Soak { .. }
        )
    }

    async fn run(self, c: Arc<Common>, url: String, duration: Duration) -> Arc<Stats> {
        match self {
            Scenario::Writes { rate } | Scenario::Soak { rate } => {
                writes(c, url, rate, duration).await
            }
            Scenario::Subscribe { items, interval } => {
                subscribe(c, url, items, interval, duration).await
            }
            Scenario::Sessions => sessions(c, url, duration).await,
            Scenario::Reconnect => reconnect(c, url, duration).await,
            Scenario::Large { kb } => large(c, url, kb, duration).await,
            Scenario::All => unreachable!(),
        }
    }
}

async fn run_one(c: &Arc<Common>, api: Option<&Api>, scenario: Scenario) -> anyhow::Result<()> {
    let default = if matches!(scenario, Scenario::Soak { .. }) {
        3600
    } else {
        30
    };
    let duration = Duration::from_secs(c.duration.unwrap_or(default));
    println!(
        "\n== {} ({} clients, {} s{})",
        scenario.name(),
        c.clients,
        duration.as_secs(),
        if c.secure { ", SignAndEncrypt" } else { "" }
    );
    if let Some(direct) = &c.direct {
        let started = Instant::now();
        let stats = scenario.run(c.clone(), direct.clone(), duration).await;
        stats.report(
            &format!("direct   {direct}"),
            scenario.unit(),
            started.elapsed(),
        );
        if matches!(scenario, Scenario::Reconnect) {
            let wait = Duration::from_millis(u64::from(c.session_timeout)) + Duration::from_secs(5);
            eprintln!(
                "    waiting {} s for the PLC to drop the abandoned sessions",
                wait.as_secs()
            );
            tokio::time::sleep(wait).await;
        }
    }
    let head = match api {
        Some(api) if scenario.writes() => Some(api.head().await?),
        _ => None,
    };
    let started = Instant::now();
    let stats = scenario.run(c.clone(), c.url.clone(), duration).await;
    stats.report(
        &format!("gateway  {}", c.url),
        scenario.unit(),
        started.elapsed(),
    );
    if let (Some(api), Some(head)) = (api, head) {
        // The records are written in batches: give the last one a moment.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let recorded = api.writes_after(head).await?;
        let answered = stats.answered();
        let verdict = if recorded >= answered {
            "ok"
        } else {
            "MISSING RECORDS"
        };
        println!("    audit: {recorded} write records for {answered} answered writes: {verdict}");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let c = Arc::new(cli.common);
    let api = match &c.api {
        Some(base) => {
            let password = c
                .api_password
                .clone()
                .context("--api needs --api-password")?;
            Some(Api::login(base, &c.api_user, &password).await?)
        }
        None => None,
    };
    // Create the client certificate once, before clients race to do it.
    let _ = ClientBuilder::new()
        .application_name("Stress client")
        .application_uri("urn:stress-client")
        .pki_dir("./stress-client-pki")
        .create_sample_keypair(true)
        .client();

    let scenarios = match cli.scenario {
        Scenario::All => vec![
            Scenario::Writes { rate: 0.0 },
            Scenario::Subscribe {
                items: 200,
                interval: 100,
            },
            Scenario::Large { kb: 32 },
            Scenario::Sessions,
            Scenario::Reconnect,
        ],
        one => vec![one],
    };
    for scenario in scenarios {
        run_one(&c, api.as_ref(), scenario).await?;
    }
    println!("\nCheck the hash chain: opcua-audit-gateway verify (or Verify in the web UI).");
    Ok(())
}
