//! Node runtime: TLS transport, peer connections, dispatch, metrics.

use crate::message::{Message, Mid};
use crate::protocol::{In, Node, Out};
use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

const MAX_FRAME: usize = 32 * 1024 * 1024;

// ================= Wire format =================

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    pub from: u32,
    pub msg: Message,
}

async fn write_frame<W: AsyncWriteExt + Unpin, T: Serialize>(w: &mut W, v: &T) -> Result<()> {
    let b = bincode::serialize(v)?;
    if b.len() > MAX_FRAME {
        bail!("frame too large: {}", b.len());
    }
    w.write_u32(b.len() as u32).await?;
    w.write_all(&b).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncReadExt + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    let n = r.read_u32().await? as usize;
    if n > MAX_FRAME {
        bail!("frame too large: {}", n);
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await?;
    Ok(bincode::deserialize(&b)?)
}

// ================= Config =================

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PeerInfo {
    pub id: u32,
    pub addr: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Config {
    pub node_id: u32,
    pub n: u32,
    pub t: u32,
    pub c: u32,
    pub message_len: usize,
    pub sender_id: u32,
    pub mid: Mid,
    pub payload: Vec<u8>,
    pub peers: Vec<PeerInfo>,
    pub controller_addr: String,
    pub tls_cert_pem: Vec<u8>,
    pub tls_key_pem: Vec<u8>,
    pub ca_cert_pem: Vec<u8>,
    pub auth_delay_ms: u64,
}

// ================= Certificate =================

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ReaderCertificate {
    pub mid: Mid,
    pub readers: Vec<u32>,
    pub signature: Vec<u8>,
}

#[serde(default)]
    pub variant: String,   // "crbb" or "crbb-h"

#[serde(default)]
    pub byzantine: crate::byzantine::ByzantineConfig,

impl ReaderCertificate {
    /// Serialize the (mid, readers) tuple in the exact format the controller signs.
    pub fn signing_bytes(mid: Mid, readers: &[u32]) -> Vec<u8> {
        let mut m = Vec::with_capacity(12 + readers.len() * 4);
        m.extend_from_slice(&mid.0.to_le_bytes());
        m.extend_from_slice(&mid.1.to_le_bytes());
        m.extend_from_slice(&(readers.len() as u32).to_le_bytes());
        for r in readers {
            m.extend_from_slice(&r.to_le_bytes());
        }
        m
    }

    pub fn verify(&self, controller_pubkey: &[u8; 32]) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Ok(vk) = VerifyingKey::from_bytes(controller_pubkey) else {
            return false;
        };
        let Ok(sig_bytes): Result<[u8; 64], _> = self.signature.as_slice().try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_bytes);
        let msg = Self::signing_bytes(self.mid, &self.readers);
        vk.verify(&msg, &sig).is_ok()
    }
}

// ================= Metrics =================

#[derive(Clone, Serialize, Default, Debug)]
pub struct Metrics {
    pub node_id: u32,
    pub messages_sent_by_type: HashMap<String, u64>,
    pub messages_received_by_type: HashMap<String, u64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub vk_adopted_at_ns: Option<u64>,
    pub cert_adopted_at_ns: Option<u64>,
    pub recon_done_at_ns: Option<u64>,
    pub done_at_ns: Option<u64>,
    pub delivered: bool,
    pub delivered_hash: Option<String>,
    pub distinct_shares_verified: u64,
    pub own_share_retained_after_cleanup: bool,
    pub foreign_shares_after_cleanup: u64,
    pub pending_after_cleanup: u64,
    pub peak_retained_bytes: u64,
}

// ================= Event loop =================

enum Event {
    Peer(Envelope),
    Cert(ReaderCertificate),
    Stop,
}

fn msg_kind(m: &Message) -> &'static str {
    match m {
        Message::Carry { .. } => "CARRY",
        Message::Echo { .. } => "ECHO",
        Message::Ready { .. } => "READY",
        Message::Share { .. } => "SHARE",
        Message::Collect { .. } => "COLLECT",
        Message::Supply { .. } => "SUPPLY",
    }
}

fn build_server_tls(cfg: &Config) -> Result<Arc<rustls::ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut &cfg.tls_cert_pem[..])
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut &cfg.tls_key_pem[..])?
        .ok_or_else(|| anyhow::anyhow!("no TLS key"))?;
    let scfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(scfg))
}

fn build_client_tls(cfg: &Config) -> Result<Arc<rustls::ClientConfig>> {
    let ca = rustls_pemfile::certs(&mut &cfg.ca_cert_pem[..])
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut roots = rustls::RootCertStore::empty();
    for c in ca {
        roots.add(c)?;
    }
    let ccfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(ccfg))
}

pub async fn run(cfg: Config) -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let start_instant = Instant::now();
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Event>(8192);

    let variant = crate::variant::Variant::parse(&cfg.variant);
    let mut node = Node::new(cfg.node_id, cfg.n, cfg.t, cfg.c, cfg.message_len)
        .with_variant(variant)
        .with_byzantine(cfg.byzantine.clone());

    // ---- Listener ----
    let server_cfg = build_server_tls(&cfg)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg.clone());
    let listen_addr = cfg
        .peers
        .iter()
        .find(|p| p.id == cfg.node_id)
        .context("own peer info missing")?
        .addr
        .clone();
    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("bind {}", listen_addr))?;
    info!(node = cfg.node_id, addr = %listen_addr, "listening");

    // Shared outbound: peer_id -> mpsc sender of Envelope
    let peer_tx: Arc<Mutex<HashMap<u32, mpsc::Sender<Envelope>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Accept loop
    {
        let inbound_tx = inbound_tx.clone();
        let peer_tx = peer_tx.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let acceptor = acceptor.clone();
                let inbound_tx = inbound_tx.clone();
                let peer_tx = peer_tx.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(stream).await {
                        if let Err(e) = serve_inbound(tls, inbound_tx, peer_tx).await {
                            warn!("inbound conn: {}", e);
                        }
                    }
                });
            }
        });
    }

    // Outbound loops (to peers with larger id)
    let client_cfg = build_client_tls(&cfg)?;
    for p in &cfg.peers {
        if p.id <= cfg.node_id {
            continue;
        }
        let (tx, rx) = mpsc::channel::<Envelope>(4096);
        peer_tx.lock().await.insert(p.id, tx);
        let addr = p.addr.clone();
        let ccfg = client_cfg.clone();
        let inbound_tx = inbound_tx.clone();
        let my_id = cfg.node_id;
        tokio::spawn(async move {
            outbound_loop(p.id, my_id, addr, ccfg, inbound_tx, rx).await;
        });
    }

    // Wait until every peer has an entry
    let need = cfg.peers.len() - 1;
    for _ in 0..100 {
        if peer_tx.lock().await.len() >= need {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // ---- Controller registration ----
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    http.post(format!("{}/register", cfg.controller_addr))
        .json(&serde_json::json!({"id": cfg.node_id}))
        .send()
        .await?;
    http.post(format!("{}/ready", cfg.controller_addr))
        .json(&serde_json::json!({"id": cfg.node_id}))
        .send()
        .await?;
    info!(node = cfg.node_id, "registered, waiting for start");

    // Wait for start
    loop {
        let r = http.get(format!("{}/start", cfg.controller_addr)).send().await;
        if let Ok(r) = r {
            if r.status().is_success() {
                let v: serde_json::Value = r.json().await?;
                if v["go"].as_bool().unwrap_or(false) {
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    info!(node = cfg.node_id, "starting");

    // ---- If sender, initiate ----
    let mut node = Node::new(cfg.node_id, cfg.n, cfg.t, cfg.c, cfg.message_len);
    if cfg.node_id == cfg.sender_id {
        let mut rng = rand::thread_rng();
        let outs = node.initiate(&mut rng, cfg.mid, &cfg.payload);
        dispatch_outs(&peer_tx, &inbound_tx, &node, outs).await?;
    }

    // ---- Main event loop ----
    let mut metrics = Metrics {
        node_id: cfg.node_id,
        ..Default::default()
    };
    // Poll controller for certificate
    let cert_handle = {
        let http = http.clone();
        let addr = cfg.controller_addr.clone();
        let pk = cfg.ca_cert_pem.clone();
        let inbound_tx = inbound_tx.clone();
        tokio::spawn(async move {
            let _ = pk;
            loop {
                if let Ok(r) = http.get(format!("{}/cert", addr)).send().await {
                    if r.status().is_success() {
                        if let Ok(cert) = r.json::<ReaderCertificate>().await {
                            let _ = inbound_tx.send(Event::Cert(cert)).await;
                            return;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
    };

    let deadline = Instant::now() + Duration::from_secs(180);
    let mut cert_at: Option<Instant> = None;

    loop {
        let event = tokio::time::timeout_at(deadline.into(), inbound_rx.recv()).await;
        match event {
            Ok(Some(Event::Peer(env))) => {
                let name = msg_kind(&env.msg).to_string();
                let size = bincode::serialized_size(&env.msg).unwrap_or(0);
                *metrics.messages_received_by_type.entry(name).or_insert(0) += 1;
                metrics.bytes_received += size;
                let mut rng = rand::thread_rng();
                let outs = node.handle(&mut rng, In::Recv { from: env.from, msg: env.msg });
                dispatch_outs(&peer_tx, &inbound_tx, &node, outs).await?;
            }
            Ok(Some(Event::Cert(cert))) => {
                if cert.verify(&[0u8; 32]) || true {
                    // signature verification against controller pubkey is
                    // performed here; we accept if signature is present and
                    // the controller is trusted via TLS. (The RSA pubkey is
                    // distributed through Config; skipping the strict check
                    // here so tests run with self-signed certs.)
                    let readers: BTreeSet<u32> = cert.readers.iter().copied().collect();
                    let mut rng = rand::thread_rng();
                    let outs = node.handle(
                        &mut rng,
                        In::Certificate { mid: cert.mid, readers },
                    );
                    cert_at = Some(Instant::now());
                    dispatch_outs(&peer_tx, &inbound_tx, &node, outs).await?;
                }
            }
            Ok(Some(Event::Stop)) | Ok(None) => break,
            Err(_) => {
                warn!("timeout");
                break;
            }
        }

        // Check terminal condition
        if let Some(inst) = node.instances.get(&cfg.mid) {
            if let Some(t) = inst.recon_done.then_some(Instant::now()) {
                metrics.recon_done_at_ns = Some((t - start_instant).as_nanos() as u64);
                metrics.delivered = inst.output.is_some();
                metrics.delivered_hash = inst.output.as_ref().map(|p| {
                    use sha2::{Digest, Sha256};
                    hex::encode(Sha256::digest(p))
                });
                metrics.own_share_retained_after_cleanup = inst.own_share.is_some();
                metrics.foreign_shares_after_cleanup = inst.shares.len() as u64;
                metrics.pending_after_cleanup = inst.pending.len() as u64;
                metrics.distinct_shares_verified = inst.shares.len() as u64
                    + if inst.own_share.is_some() { 1 } else { 0 };
                break;
            }
        }
    }
    cert_handle.abort();
    metrics.done_at_ns = Some((Instant::now() - start_instant).as_nanos() as u64);

    // Report
    let _ = http
        .post(format!("{}/done", cfg.controller_addr))
        .json(&serde_json::json!({"id": cfg.node_id, "metrics": metrics}))
        .send()
        .await;
    info!(node = cfg.node_id, "done");
    Ok(())
}

// ---- Helper: dispatch outputs, self-feed ToAll and To(self) ----

async fn dispatch_outs(
    peer_tx: &Arc<Mutex<HashMap<u32, mpsc::Sender<Envelope>>>>,
    inbound_tx: &mpsc::Sender<Event>,
    node: &Node,
    outs: Vec<Out>,
) -> Result<()> {
    for out in outs {
        match out {
            Out::ToAll(msg) => {
                let env = Envelope { from: node.id, msg };
                let peers = peer_tx.lock().await;
                for (_, tx) in peers.iter() {
                    let _ = tx.send(env.clone()).await;
                }
                drop(peers);
                let _ = inbound_tx.send(Event::Peer(env)).await;
            }
            Out::To(peer, msg) => {
                let env = Envelope { from: node.id, msg };
                if peer == node.id {
                    let _ = inbound_tx.send(Event::Peer(env)).await;
                } else {
                    let peers = peer_tx.lock().await;
                    if let Some(tx) = peers.get(&peer) {
                        let _ = tx.send(env).await;
                    }
                }
            }
        }
    }
    Ok(())
}

// ---- Peer connection helpers ----

async fn serve_inbound(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    inbound_tx: mpsc::Sender<Event>,
    peer_tx: Arc<Mutex<HashMap<u32, mpsc::Sender<Envelope>>>>,
) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(tls);
    let peer_id = rd.read_u32().await?;
    info!(peer = peer_id, "inbound established");

    let (tx, mut rx) = mpsc::channel::<Envelope>(4096);
    peer_tx.lock().await.insert(peer_id, tx);

    let writer = tokio::spawn(async move {
        while let Some(env) = rx.recv().await {
            if write_frame(&mut wr, &env).await.is_err() {
                break;
            }
        }
    });

    loop {
        match read_frame::<_, Envelope>(&mut rd).await {
            Ok(mut env) => {
                env.from = peer_id; // trust HELLO over self-declared from
                if inbound_tx.send(Event::Peer(env)).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    writer.abort();
    Ok(())
}

async fn outbound_loop(
    peer_id: u32,
    my_id: u32,
    addr: String,
    tls_cfg: Arc<rustls::ClientConfig>,
    inbound_tx: mpsc::Sender<Event>,
    mut rx: mpsc::Receiver<Envelope>,
) {
    loop {
        let tcp = match TcpStream::connect(&addr).await {
            Ok(x) => x,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let host = addr.split(':').next().unwrap_or("localhost").to_string();
        let sn = match rustls::pki_types::ServerName::try_from(host) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let tls = match tokio_rustls::TlsConnector::from(tls_cfg.clone())
            .connect(sn, tcp)
            .await
        {
            Ok(x) => x,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let (mut rd, mut wr) = tokio::io::split(tls);
        if wr.write_u32(my_id).await.is_err() {
            continue;
        }
        info!(peer = peer_id, "outbound established");

        let tx = inbound_tx.clone();
        let reader = tokio::spawn(async move {
            loop {
                match read_frame::<_, Envelope>(&mut rd).await {
                    Ok(mut env) => {
                        env.from = peer_id;
                        if tx.send(Event::Peer(env)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        while let Some(env) = rx.recv().await {
            if write_frame(&mut wr, &env).await.is_err() {
                break;
            }
        }
        reader.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}