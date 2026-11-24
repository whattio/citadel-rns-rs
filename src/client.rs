//! Reusable Multi-Peer Reticulum Client Engine (`CitadelRnsClient`) — Clean-Room MIT Rust
//!
//! Powers zero-port in-process clients like `citadel-ghost-browser` (`citadel://` and `ironpass://`)
//! without opening any local HTTP socket on the operator workstation.
//!
//! Features:
//! - Simultaneous encrypted X25519 + Ed25519 Reticulum Links to multiple 0-port Ghost Linux servers
//! - Optional cryptographic destination hash pinning (`allow_hashes`) to reject rogue announces
//! - Per-link synchronized `WINDOW_SIZE = 10` `WindowAck` flow control (zero desync)
//! - Automatic in-memory `gzip` decompression while preserving compressed `v0.5.0` wire speed
//! - Live peer discovery & wire/logical telemetry counters

use crate::chtp::{
    decode_packet, encode_json_chunks, encode_packet, req_id_from_str, PacketKind, RequestMeta,
    ResponseMeta, MAX_CHUNK, WINDOW_SIZE,
};
use crate::fast_tcp::{FastTcpClient, FastTcpServer};
use anyhow::{anyhow, Result};
use flate2::read::GzDecoder;
use reticulum::destination::link::LinkEvent;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::{Transport, TransportConfig};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{oneshot, Mutex, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct PeerSummary {
    pub hash: String,
    pub alias: String,
    pub active: bool,
    pub requests: u64,
    pub wire_bytes: u64,
    pub logical_bytes: u64,
    pub chunks_rx: u64,
    pub last_seen_ts: u64,
}

#[derive(Debug, Clone)]
pub struct RnsHttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub wire_bytes: usize,
    pub chunks_rx: u32,
    pub was_gzip: bool,
    pub dest_hash: String,
}

struct PeerRecord {
    address_hash: AddressHash,
    hash_hex: String,
    alias: String,
    active: bool,
    requests: u64,
    wire_bytes: u64,
    logical_bytes: u64,
    chunks_rx: u64,
    last_seen_ts: u64,
}

struct PendingFetch {
    head_chunks: BTreeMap<u32, Vec<u8>>,
    meta: Option<ResponseMeta>,
    body_chunks: BTreeMap<u32, Vec<u8>>,
    wire_bytes: usize,
    chunks_rx: u32,
    dest_hash: String,
    done_tx: Option<oneshot::Sender<Result<RnsHttpResponse>>>,
}

pub struct CitadelRnsClient {
    transport: Arc<Transport>,
    peers: Arc<RwLock<HashMap<String, PeerRecord>>>,
    pending: Arc<Mutex<HashMap<[u8; 12], PendingFetch>>>,
    allow_hashes: Arc<HashSet<String>>,
    identity_name: String,
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sanitize_alias(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(40)
        .collect();
    cleaned.to_lowercase()
}

impl CitadelRnsClient {
    pub async fn start(
        identity_name: &str,
        rns_listen: Option<String>,
        rns_peers: Vec<String>,
        allow_hashes: Vec<String>,
    ) -> Arc<Self> {
        let id = PrivateIdentity::new_from_name(identity_name);
        let transport = Arc::new(Transport::new(TransportConfig::new("citadel-ghost-client", &id)));

        if let Some(ref listen_addr) = rns_listen {
            transport.iface_manager().lock().await.spawn(
                FastTcpServer::new(listen_addr, transport.iface_manager()),
                FastTcpServer::spawn,
            );
            info!(rns_listen = %listen_addr, "Citadel Ghost Client listening for 0-port outbound Debian/Linux Vaults");
        }

        for peer in &rns_peers {
            if !peer.trim().is_empty() {
                transport
                    .iface_manager()
                    .lock()
                    .await
                    .spawn(FastTcpClient::new(peer.trim()), FastTcpClient::spawn);
                info!(rns_peer = %peer, "Citadel Ghost Client dialing Reticulum peer");
            }
        }

        let allow_set: HashSet<String> = allow_hashes
            .into_iter()
            .map(|h| h.trim().trim_matches('<').trim_matches('>').to_lowercase())
            .filter(|h| !h.is_empty())
            .collect();

        let client = Arc::new(Self {
            transport: Arc::clone(&transport),
            peers: Arc::new(RwLock::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            allow_hashes: Arc::new(allow_set),
            identity_name: identity_name.to_string(),
        });

        // Task 1: Discover Vault announces, enforce optional hash allowlist, and establish X25519+Ed25519 Links
        {
            let t = Arc::clone(&client.transport);
            let peers = Arc::clone(&client.peers);
            let allow = Arc::clone(&client.allow_hashes);
            tokio::spawn(async move {
                let mut announces = t.recv_announces().await;
                while let Ok(announce) = announces.recv().await {
                    let desc = announce.destination.lock().await.desc;
                    let hash_hex = format!("{}", desc.address_hash)
                        .trim_matches('/')
                        .to_lowercase();

                    if !allow.is_empty() && !allow.contains(&hash_hex) {
                        warn!(dest_hash = %hash_hex, "REJECTED unpinned Reticulum announce (not in --allow-hash)");
                        continue;
                    }

                    let app_alias = String::from_utf8(announce.app_data.as_slice().to_vec())
                        .ok()
                        .map(|s| sanitize_alias(&s))
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| format!("node-{}", &hash_hex[..hash_hex.len().min(8)]));

                    let should_link = {
                        let mut map = peers.write().await;
                        match map.get_mut(&hash_hex) {
                            Some(rec) => {
                                rec.last_seen_ts = now_ts();
                                if !app_alias.starts_with("node-") {
                                    rec.alias = app_alias.clone();
                                }
                                !rec.active
                            }
                            None => {
                                map.insert(
                                    hash_hex.clone(),
                                    PeerRecord {
                                        address_hash: desc.address_hash,
                                        hash_hex: hash_hex.clone(),
                                        alias: app_alias.clone(),
                                        active: false,
                                        requests: 0,
                                        wire_bytes: 0,
                                        logical_bytes: 0,
                                        chunks_rx: 0,
                                        last_seen_ts: now_ts(),
                                    },
                                );
                                true
                            }
                        }
                    };

                    if should_link {
                        info!(dest_hash = %hash_hex, alias = %app_alias, "Establishing encrypted X25519+Ed25519 Reticulum Link...");
                        let _link = t.link(desc).await;
                        let mut map = peers.write().await;
                        if let Some(rec) = map.get_mut(&hash_hex) {
                            rec.active = true;
                            rec.last_seen_ts = now_ts();
                        }
                    }
                }
            });
        }

        // Task 2: Demux incoming encrypted CHT2 responses + per-link synchronized WindowAck
        {
            let t = Arc::clone(&client.transport);
            let peers = Arc::clone(&client.peers);
            let pending = Arc::clone(&client.pending);
            tokio::spawn(async move {
                let mut out_events = t.out_link_events();
                let mut rx_windows: HashMap<String, u32> = HashMap::new();

                loop {
                    let ev = match out_events.recv().await {
                        Ok(ev) => ev,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Ghost client out_link_events lagged by {n} — continuing");
                            continue;
                        }
                        Err(_) => break,
                    };

                    let link_key = format!("{}", ev.id);
                    match ev.event {
                        LinkEvent::Activated => {
                            rx_windows.insert(link_key, 0);
                            info!(link_id = %ev.id, "Encrypted Reticulum Link ACTIVATED (in-process)");
                        }
                        LinkEvent::Closed => {
                            rx_windows.remove(&link_key);
                            warn!(link_id = %ev.id, "Reticulum Link closed — will auto-reconnect on next announce");
                            let mut map = peers.write().await;
                            for rec in map.values_mut() {
                                // Mark stale links inactive so next 2s announce immediately re-links
                                if now_ts().saturating_sub(rec.last_seen_ts) >= 2 {
                                    rec.active = false;
                                }
                            }
                        }
                        LinkEvent::Data(payload) => {
                            let pkt = match decode_packet(payload.as_slice()) {
                                Ok(p) => p,
                                Err(e) => {
                                    warn!("Bad CHT2 packet: {e}");
                                    continue;
                                }
                            };

                            match pkt.kind {
                                PacketKind::RespHead => {
                                    let mut map = pending.lock().await;
                                    if let Some(entry) = map.get_mut(&pkt.req_id) {
                                        entry.head_chunks.insert(pkt.seq, pkt.payload);
                                        let mut joined = Vec::new();
                                        for (_, part) in &entry.head_chunks {
                                            joined.extend_from_slice(part);
                                        }
                                        if let Ok(meta) = serde_json::from_slice::<ResponseMeta>(&joined) {
                                            entry.meta = Some(meta);
                                        }
                                    }
                                }
                                PacketKind::RespChunk => {
                                    let dest_hex_opt = {
                                        let mut map = pending.lock().await;
                                        if let Some(entry) = map.get_mut(&pkt.req_id) {
                                            entry.wire_bytes += pkt.payload.len();
                                            entry.chunks_rx += 1;
                                            entry.body_chunks.insert(pkt.seq, pkt.payload);
                                            Some(entry.dest_hash.clone())
                                        } else {
                                            None
                                        }
                                    };

                                    let wc = rx_windows.entry(link_key).or_insert(0);
                                    *wc += 1;
                                    if *wc >= WINDOW_SIZE {
                                        *wc = 0;
                                        if let Some(dest_hex) = dest_hex_opt {
                                            let addr_opt = peers.read().await.get(&dest_hex).map(|r| r.address_hash);
                                            if let Some(dest_addr) = addr_opt {
                                                let ack = encode_packet(
                                                    PacketKind::WindowAck,
                                                    pkt.req_id,
                                                    pkt.seq,
                                                    &[],
                                                );
                                                let t_ack = Arc::clone(&t);
                                                tokio::spawn(async move {
                                                    t_ack.send_to_out_links(&dest_addr, &ack).await;
                                                });
                                            }
                                        }
                                    }
                                }
                                PacketKind::RespEnd => {
                                    let finished = pending.lock().await.remove(&pkt.req_id);
                                    if let Some(mut entry) = finished {
                                        // Offload gzip decompression & response assembly to a spawned task
                                        // so the 16-slot Reticulum out_link_events receiver NEVER lags!
                                        let peers_bg = Arc::clone(&peers);
                                        tokio::spawn(async move {
                                            let meta = entry.meta.unwrap_or(ResponseMeta {
                                                status: 200,
                                                headers: vec![("content-type".into(), "application/octet-stream".into())],
                                            });

                                            let mut raw_body = Vec::with_capacity(entry.wire_bytes);
                                            for (_, chunk) in entry.body_chunks {
                                                raw_body.extend_from_slice(&chunk);
                                            }

                                            let was_gzip = meta.headers.iter().any(|(k, v)| {
                                                k.eq_ignore_ascii_case("content-encoding")
                                                    && v.to_lowercase().contains("gzip")
                                            });

                                            let (final_body, final_headers) = if was_gzip && !raw_body.is_empty() {
                                                let mut dec = GzDecoder::new(&raw_body[..]);
                                                let mut out = Vec::with_capacity(raw_body.len() * 3);
                                                if dec.read_to_end(&mut out).is_ok() {
                                                    let cleaned: Vec<(String, String)> = meta
                                                        .headers
                                                        .into_iter()
                                                        .filter(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"))
                                                        .collect();
                                                    (out, cleaned)
                                                } else {
                                                    warn!(dest_hash = %entry.dest_hash, wire_bytes = entry.wire_bytes, "Gzip decode failed on CHT2 response");
                                                    (raw_body, meta.headers)
                                                }
                                            } else {
                                                (raw_body, meta.headers)
                                            };

                                            let logical_len = final_body.len() as u64;
                                            let wire_len = entry.wire_bytes as u64;
                                            let chunks = entry.chunks_rx as u64;
                                            {
                                                let mut pmap = peers_bg.write().await;
                                                if let Some(rec) = pmap.get_mut(&entry.dest_hash) {
                                                    rec.requests += 1;
                                                    rec.wire_bytes += wire_len;
                                                    rec.logical_bytes += logical_len;
                                                    rec.chunks_rx += chunks;
                                                    rec.last_seen_ts = now_ts();
                                                }
                                            }

                                            if let Some(tx) = entry.done_tx.take() {
                                                let _ = tx.send(Ok(RnsHttpResponse {
                                                    status: meta.status,
                                                    headers: final_headers,
                                                    body: final_body,
                                                    wire_bytes: entry.wire_bytes,
                                                    chunks_rx: entry.chunks_rx,
                                                    was_gzip,
                                                    dest_hash: entry.dest_hash,
                                                }));
                                            }
                                        });
                                    }
                                }
                                _ => {}
                            }
                        }
                        LinkEvent::Proof(_) | LinkEvent::RemoteIdentified(_) => {}
                    }
                }
            });
        }

        client
    }

    pub fn identity_name(&self) -> &str {
        &self.identity_name
    }

    pub async fn list_peers(&self) -> Vec<PeerSummary> {
        let map = self.peers.read().await;
        let mut list: Vec<PeerSummary> = map
            .values()
            .map(|r| PeerSummary {
                hash: r.hash_hex.clone(),
                alias: r.alias.clone(),
                active: r.active,
                requests: r.requests,
                wire_bytes: r.wire_bytes,
                logical_bytes: r.logical_bytes,
                chunks_rx: r.chunks_rx,
                last_seen_ts: r.last_seen_ts,
            })
            .collect();
        list.sort_by(|a, b| a.alias.cmp(&b.alias));
        list
    }

    pub async fn resolve_peer(&self, target: &str) -> Option<(AddressHash, String)> {
        let needle = target.trim().to_lowercase();
        let map = self.peers.read().await;
        // 1. Exact 128-bit hash match
        if let Some(rec) = map.get(&needle) {
            return Some((rec.address_hash, rec.hash_hex.clone()));
        }
        // 2. Prefix hash match or alias match
        for rec in map.values() {
            if rec.alias == needle
                || rec.hash_hex.starts_with(&needle)
                || rec.alias.contains(&needle)
            {
                return Some((rec.address_hash, rec.hash_hex.clone()));
            }
        }
        // 3. Single connected peer convenience alias ("default" / "peer")
        if (needle == "default" || needle == "peer") && map.len() == 1 {
            if let Some(rec) = map.values().next() {
                return Some((rec.address_hash, rec.hash_hex.clone()));
            }
        }
        None
    }

    pub async fn request(
        &self,
        target: &str,
        method: &str,
        path_and_query: &str,
        mut headers: HashMap<String, String>,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<RnsHttpResponse> {
        let (dest, dest_hex) = self
            .resolve_peer(target)
            .await
            .ok_or_else(|| anyhow!("No active Reticulum Vault matching '{target}'"))?;

        // Always request gzip on the encrypted wire; we decompress in RAM for WebView
        headers
            .entry("accept-encoding".into())
            .or_insert_with(|| "gzip".into());

        let req_id_str = Uuid::new_v4().simple().to_string()[..12].to_string();
        let req_id = req_id_from_str(&req_id_str);

        let meta = RequestMeta {
            method: method.to_string(),
            path: if path_and_query.is_empty() {
                "/".to_string()
            } else {
                path_and_query.to_string()
            },
            headers,
        };

        let head_pkts = encode_json_chunks(PacketKind::ReqHead, req_id, &meta)?;
        let (done_tx, done_rx) = oneshot::channel();

        self.pending.lock().await.insert(
            req_id,
            PendingFetch {
                head_chunks: BTreeMap::new(),
                meta: None,
                body_chunks: BTreeMap::new(),
                wire_bytes: 0,
                chunks_rx: 0,
                dest_hash: dest_hex.clone(),
                done_tx: Some(done_tx),
            },
        );

        for pkt in head_pkts {
            self.transport.send_to_out_links(&dest, &pkt).await;
        }
        let mut seq: u32 = 0;
        for slice in body.chunks(MAX_CHUNK) {
            let pkt = encode_packet(PacketKind::ReqChunk, req_id, seq, slice);
            self.transport.send_to_out_links(&dest, &pkt).await;
            seq += 1;
        }
        let end_pkt = encode_packet(PacketKind::ReqEnd, req_id, seq, &[]);
        self.transport.send_to_out_links(&dest, &end_pkt).await;

        match tokio::time::timeout(timeout, done_rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => {
                self.pending.lock().await.remove(&req_id);
                Err(anyhow!("Reticulum request channel closed"))
            }
            Err(_) => {
                self.pending.lock().await.remove(&req_id);
                Err(anyhow!(
                    "Reticulum request timed out after {}s ({target}{path_and_query})",
                    timeout.as_secs()
                ))
            }
        }
    }
}
