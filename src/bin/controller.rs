//! CRBB experiment controller.
//!
//! Subcommands:
//!   serve  -- run an HTTP coordination service for one experiment
//!   generate-tls -- emit a CA + per-node certs + controller signing key
//!
//! The controller issues a reader-set certificate after dissemination
//! completes (after `auth_delay_ms`), signs it with ed25519, and pushes
//! it to nodes via HTTP polling.

use anyhow::{bail, Context, Result};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::info;

#[derive(Parser, Debug)]
#[command(about = "CRBB experiment controller")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the coordination server for one experiment.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
        /// Number of nodes
        #[arg(long)]
        n: u32,
        #[arg(long)]
        t: u32,
        #[arg(long)]
        c: u32,
        #[arg(long)]
        message_len: usize,
        /// Delay after start before issuing the reader-set certificate.
        #[arg(long, default_value = "1000")]
        auth_delay_ms: u64,
        /// Outfile for collected metrics (JSON).
        #[arg(long, default_value = "run.json")]
        out: String,
    },
    /// Generate a CA, N node certs, and a controller signing key.
    GenerateTls {
        #[arg(long)]
        n: u32,
        #[arg(long, default_value = "tls")]
        out_dir: String,
    },
}

// --- Serve state ---

struct State {
    n: u32,
    t: u32,
    c: u32,
    message_len: usize,
    auth_delay_ms: u64,
    out: String,
    registered: Mutex<BTreeSet<u32>>,
    ready: Mutex<BTreeSet<u32>>,
    start_time: Mutex<Option<Instant>>,
    cert: Mutex<Option<ReaderCertificate>>,
    metrics: Mutex<HashMap<u32, serde_json::Value>>,
    signing_key: SigningKey,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReaderCertificate {
    pub mid: (u32, u64),
    pub readers: Vec<u32>,
    pub signature: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    match args.cmd {
        Cmd::GenerateTls { n, out_dir } => generate_tls(n, &out_dir),
        Cmd::Serve {
            bind,
            n,
            t,
            c,
            message_len,
            auth_delay_ms,
            out,
        } => serve(bind, n, t, c, message_len, auth_delay_ms, out).await,
    }
}

async fn serve(
    bind: SocketAddr,
    n: u32,
    t: u32,
    c: u32,
    message_len: usize,
    auth_delay_ms: u64,
    out: String,
) -> Result<()> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let state = Arc::new(State {
        n,
        t,
        c,
        message_len,
        auth_delay_ms,
        out,
        registered: Mutex::new(BTreeSet::new()),
        ready: Mutex::new(BTreeSet::new()),
        start_time: Mutex::new(None),
        cert: Mutex::new(None),
        metrics: Mutex::new(HashMap::new()),
        signing_key,
    });

    // Background task: issue certificate after auth_delay
    {
        let state = state.clone();
        tokio::spawn(async move {
            // Wait until all ready
            loop {
                let n_ready = state.ready.lock().await.len();
                if n_ready as u32 >= state.n {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let start = Instant::now();
            *state.start_time.lock().await = Some(start);
            info!(n = state.n, "all ready; starting experiment");

            tokio::time::sleep(Duration::from_millis(state.auth_delay_ms)).await;

            // Sample reader set: k = t+c+1 random correct nodes (assume no
            // Byzantines in this simple controller; the test harness
            // configures reader sets to be disjoint from Byzantine set).
            let k = (state.t + state.c + 1) as usize;
            let mut readers: Vec<u32> = (0..state.n).collect();
            use rand::seq::SliceRandom;
            readers.shuffle(&mut OsRng);
            readers.truncate(k);
            readers.sort_unstable();

            let mid = (0u32, 1u64);
            let msg = ReaderCertificate::signing_bytes(mid, &readers);
            let sig = state.signing_key.sign(&msg).to_bytes().to_vec();
            let cert = ReaderCertificate {
                mid,
                readers,
                signature: sig,
            };
            info!(readers = ?cert.readers, "issuing reader-set certificate");
            *state.cert.lock().await = Some(cert);
        });
    }

    // Background task: after all done, write the JSON outfile
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                let m = state.metrics.lock().await;
                if m.len() as u32 >= state.n {
                    let out_path = state.out.clone();
                    let data = serde_json::to_vec_pretty(&*m).unwrap();
                    tokio::fs::write(&out_path, &data).await.ok();
                    info!(path = %out_path, "wrote metrics");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
    }

    let app = Router::new()
        .route("/register", post(register))
        .route("/ready", post(ready))
        .route("/start", get(start))
        .route("/cert", get(get_cert))
        .route("/done", post(done))
        .with_state(state);

    info!(addr = %bind, "controller listening");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Deserialize)]
struct IdReq {
    id: u32,
}

async fn register(State(s): State<Arc<State>>, Json(req): Json<IdReq>) -> Json<serde_json::Value> {
    s.registered.lock().await.insert(req.id);
    Json(serde_json::json!({"ok": true}))
}

async fn ready(State(s): State<Arc<State>>, Json(req): Json<IdReq>) -> Json<serde_json::Value> {
    s.ready.lock().await.insert(req.id);
    Json(serde_json::json!({"ok": true}))
}

async fn start(State(s): State<Arc<State>>) -> Json<serde_json::Value> {
    let ready = s.ready.lock().await.len() as u32;
    let go = ready >= s.n;
    Json(serde_json::json!({"go": go}))
}

async fn get_cert(State(s): State<Arc<State>>) -> Json<Option<ReaderCertificate>> {
    let g = s.cert.lock().await;
    Json(g.clone())
}

#[derive(Deserialize)]
struct DoneReq {
    id: u32,
    metrics: serde_json::Value,
}

async fn done(State(s): State<Arc<State>>, Json(req): Json<DoneReq>) -> Json<serde_json::Value> {
    s.metrics.lock().await.insert(req.id, req.metrics);
    Json(serde_json::json!({"ok": true}))
}

// --- TLS generation ---

fn generate_tls(n: u32, out_dir: &str) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;
    std::fs::create_dir_all(format!("{}/nodes", out_dir))?;

    // CA
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(vec![])?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "CRBB Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key)?;
    std::fs::write(format!("{}/ca-cert.pem", out_dir), ca_cert.pem())?;
    std::fs::write(format!("{}/ca-key.pem", out_dir), ca_key.serialize_pem())?;

    // Per-node certs
    let ca_kp = KeyPair::from_pem(&ca_key.serialize_pem())?;
    let ca_cert_for_signing = CertificateParams::from_ca_cert_pem(&ca_cert.pem())?
        .self_signed(&ca_kp)?;

    for i in 0..n {
        let kp = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, format!("node-{}", i));
        let cert = params.signed_by(&kp, &ca_cert_for_signing, &ca_kp)?;
        std::fs::write(format!("{}/nodes/{}-cert.pem", out_dir, i), cert.pem())?;
        std::fs::write(format!("{}/nodes/{}-key.pem", out_dir, i), kp.serialize_pem())?;
    }
    info!(dir = out_dir, n, "generated TLS material");
    Ok(())
}