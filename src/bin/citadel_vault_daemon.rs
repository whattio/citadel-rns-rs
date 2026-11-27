//! Citadel Zero-Port HTTP-over-Reticulum Vault Daemon (Clean-Room MIT Rust v0.5.0)
//!
//! Features:
//! - True 0-port outbound Ghost mode (`--rns-peer`) for `nftables [CITADEL-DROP]` hosts
//! - Global serialized `SendGate` with synchronized `WINDOW_SIZE = 10` `WindowAck` flow control
//!   (zero desync across parallel browser asset loads & MJPEG/JPEG camera feeds)
//! - Automatic fast gzip compression over `CHT2` (400B chunks) for JS/CSS/HTML/JSON/SVG/WASM
//! - Zero-buffer streaming preserved for SSE (`text/event-stream`) LLM tokens & live JPEG frames
//! - HTTP caching headers (`ETag`, `Cache-Control`, `If-None-Match`, immutable `/assets/*`)

use anyhow::Result;
use citadel_rns_rs::chtp::{
    decode_packet, encode_json_chunks, encode_packet, req_id_to_string, PacketKind, RequestMeta,
    ResponseMeta, MAX_CHUNK, WINDOW_SIZE,
};
use clap::Parser;
use flate2::{write::GzEncoder, Compression};
use citadel_rns_rs::fast_tcp::{FastTcpClient, FastTcpServer};
use citadel_rns_rs::security::{
    load_effective_allowlist, verify_request_signature, IfacKey, HDR_VERIFIED_CLIENT,
};
use reticulum::destination::link::LinkEvent;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::{TimerConfig, Transport, TransportConfig};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "citadel-vault-daemon")]
#[command(about = "Zero-port Reticulum HTTP Vault Daemon with Lossless Flow Control (MIT Rust)")]
struct Args {
    /// Deterministic identity name seed for 512-bit Curve25519 keyset (X25519 + Ed25519)
    #[arg(long, default_value = "citadel-vault-node")]
    identity_name: String,

    /// Localhost-only upstream service (0 external web ports)
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    upstream: String,

    /// Reticulum TCP outbound peer address(es) for 0-port Ghost mode (repeatable: local + WAN relay)
    #[arg(long = "rns-peer")]
    rns_peers: Vec<String>,

    /// Optional Reticulum TCP bind address (only used if --rns-peer is not set)
    #[arg(long, default_value = "0.0.0.0:14245")]
    rns_bind: String,

    /// Lock 1 (IFAC): Path to shared dark-network key file (chmod 600)
    #[arg(long = "ifac-key-file", env = "CITADEL_IFAC_KEY_FILE")]
    ifac_key_file: Option<PathBuf>,

    /// Lock 1 (IFAC): Inline shared network passphrase (prefer --ifac-key-file)
    #[arg(long = "ifac-key", env = "CITADEL_IFAC_KEY")]
    ifac_key: Option<String>,

    /// Lock 2 (Ed25519 Mutual Auth): Authorized 32-hex Client IDs or 64-hex pubkeys (repeatable/comma-separated)
    #[arg(long = "allow-client", env = "CITADEL_ALLOW_CLIENTS", value_delimiter = ',')]
    allow_clients: Vec<String>,

    /// Lock 2 (Ed25519 Mutual Auth): Hot-reloaded file of authorized Client IDs (one per line, # comments allowed)
    #[arg(long = "allow-clients-file", env = "CITADEL_ALLOW_CLIENTS_FILE")]
    allow_clients_file: Option<PathBuf>,
}

#[derive(Clone)]
struct AuthPolicy {
    enforced: bool,
    static_clients: Vec<String>,
    clients_file: Option<PathBuf>,
    dest_hash_hex: String,
}

#[derive(Default)]
struct InboundRequest {
    head_chunks: BTreeMap<u32, Vec<u8>>,
    body_chunks: BTreeMap<u32, Vec<u8>>,
}

const MAX_RAM_CACHE_BYTES: usize = 48 * 1024 * 1024; // 48 MB pre-compressed static asset RAM cache
const MAX_SINGLE_RAM_ASSET: usize = 12 * 1024 * 1024; // 12 MB max single RAM-cached asset
const RAM_CACHE_TTL: Duration = Duration::from_secs(600);
const MAX_CONSECUTIVE_ACK_TIMEOUTS: u32 = 6; // Abort dead/abandoned streams in ~1.5s instead of 3 min

#[derive(Clone)]
struct CachedStatic {
    status: u16,
    headers: Vec<(String, String)>,
    wire_bytes: Arc<Vec<u8>>,
    orig_len: usize,
    inserted_at: Instant,
}

#[derive(Default)]
struct StaticRamCache {
    entries: HashMap<String, CachedStatic>,
    total_bytes: usize,
}

impl StaticRamCache {
    fn get(&mut self, key: &str) -> Option<CachedStatic> {
        if let Some(entry) = self.entries.get(key) {
            if entry.inserted_at.elapsed() <= RAM_CACHE_TTL {
                return Some(entry.clone());
            }
        }
        if let Some(expired) = self.entries.remove(key) {
            self.total_bytes = self.total_bytes.saturating_sub(expired.wire_bytes.len());
        }
        None
    }

    fn insert(&mut self, key: String, val: CachedStatic) {
        let new_len = val.wire_bytes.len();
        if new_len == 0 || new_len > MAX_SINGLE_RAM_ASSET {
            return;
        }
        if let Some(old) = self.entries.remove(&key) {
            self.total_bytes = self.total_bytes.saturating_sub(old.wire_bytes.len());
        }
        while self.total_bytes + new_len > MAX_RAM_CACHE_BYTES {
            let oldest_key = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.inserted_at)
                .map(|(k, _)| k.clone());
            match oldest_key {
                Some(k) => {
                    if let Some(evicted) = self.entries.remove(&k) {
                        self.total_bytes = self.total_bytes.saturating_sub(evicted.wire_bytes.len());
                    }
                }
                None => break,
            }
        }
        self.total_bytes += new_len;
        self.entries.insert(key, val);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChunkSendStatus {
    Ok,
    AckTimeout,
    NoActiveLinks,
}

struct SendGate {
    /// Serializes all outbound RNS packets and tracks global in-flight chunk count
    /// in lockstep with the Airlock's global rx_window.
    window: Mutex<u32>,
    ack_notify: Notify,
    active_links: AtomicUsize,
}

impl SendGate {
    fn new() -> Self {
        Self {
            window: Mutex::new(0),
            ack_notify: Notify::new(),
            active_links: AtomicUsize::new(0),
        }
    }

    fn on_ack(&self) {
        self.ack_notify.notify_waiters();
    }

    async fn on_link_activated(&self) {
        self.active_links.fetch_add(1, Ordering::Relaxed);
        *self.window.lock().await = 0;
        self.ack_notify.notify_waiters();
    }

    async fn on_link_closed(&self) {
        let _ = self.active_links.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(1))
        });
        *self.window.lock().await = 0;
        self.ack_notify.notify_waiters();
    }

    fn has_active_links(&self) -> bool {
        self.active_links.load(Ordering::Relaxed) > 0
    }

    async fn send_control(
        &self,
        transport: &Transport,
        dest_hash: &reticulum::hash::AddressHash,
        pkt: &[u8],
    ) {
        let _wc = self.window.lock().await;
        transport.send_to_in_links(dest_hash, pkt).await;
    }

    async fn send_chunk(
        &self,
        transport: &Transport,
        dest_hash: &reticulum::hash::AddressHash,
        pkt: &[u8],
    ) -> ChunkSendStatus {
        if !self.has_active_links() {
            return ChunkSendStatus::NoActiveLinks;
        }
        let mut wc = self.window.lock().await;
        *wc += 1;
        if *wc >= WINDOW_SIZE {
            let notified = self.ack_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            transport.send_to_in_links(dest_hash, pkt).await;
            let res = tokio::time::timeout(Duration::from_millis(250), notified).await;
            *wc = 0;
            if !self.has_active_links() {
                return ChunkSendStatus::NoActiveLinks;
            }
            if res.is_err() {
                return ChunkSendStatus::AckTimeout;
            }
        } else {
            transport.send_to_in_links(dest_hash, pkt).await;
        }
        ChunkSendStatus::Ok
    }
}

fn is_static_immutable_path(path: &str) -> bool {
    let clean = path.split('?').next().unwrap_or(path);
    let low = clean.to_lowercase();
    if low == "/"
        || low.ends_with(".html")
        || low.starts_with("/api/")
        || low.contains("/api/")
        || low.starts_with("/dpp/")
        || low.starts_with("/cam/")
    {
        return false;
    }
    if low.starts_with("/assets/")
        || low.starts_with("/_next/static/")
        || low.starts_with("/models/")
        || low.starts_with("/icons/")
        || low.starts_with("/images/")
        || low.starts_with("/fonts/")
    {
        return true;
    }
    matches!(
        low.rsplit('.').next().unwrap_or(""),
        "js" | "mjs"
            | "css"
            | "glb"
            | "gltf"
            | "obj"
            | "stl"
            | "wasm"
            | "woff2"
            | "woff"
            | "ttf"
            | "png"
            | "jpg"
            | "jpeg"
            | "webp"
            | "svg"
            | "ico"
            | "mp3"
            | "wav"
    )
}

fn is_compressible(ct: &str, path: &str) -> bool {
    let ct_l = ct.to_lowercase();
    if ct_l.contains("text/event-stream") || ct_l.contains("multipart/") {
        return false;
    }
    if ct_l.contains("text/")
        || ct_l.contains("javascript")
        || ct_l.contains("json")
        || ct_l.contains("svg")
        || ct_l.contains("wasm")
        || ct_l.contains("gltf-binary")
        || ct_l.contains("xml")
        || ct_l.contains("model/")
    {
        return true;
    }
    let clean = path.split('?').next().unwrap_or(path).to_lowercase();
    matches!(
        clean.rsplit('.').next().unwrap_or(""),
        "obj" | "gltf" | "glb" | "stl" | "ply" | "mtl" | "js" | "mjs" | "css" | "json" | "svg" | "wasm" | "xml" | "txt"
    )
}

async fn stream_buffered_response(
    req_id: [u8; 12],
    rid_str: &str,
    status: u16,
    headers: Vec<(String, String)>,
    wire_bytes: &[u8],
    transport: &Transport,
    dest_hash: &reticulum::hash::AddressHash,
    gate: &SendGate,
) -> (u32, bool) {
    let rmeta = ResponseMeta { status, headers };
    if let Ok(head_pkts) = encode_json_chunks(PacketKind::RespHead, req_id, &rmeta) {
        for pkt in head_pkts {
            gate.send_control(transport, dest_hash, &pkt).await;
        }
    }
    let mut seq: u32 = 0;
    let mut consecutive_timeouts: u32 = 0;
    for slice in wire_bytes.chunks(MAX_CHUNK) {
        let pkt = encode_packet(PacketKind::RespChunk, req_id, seq, slice);
        match gate.send_chunk(transport, dest_hash, &pkt).await {
            ChunkSendStatus::Ok => consecutive_timeouts = 0,
            ChunkSendStatus::AckTimeout => {
                consecutive_timeouts += 1;
                if consecutive_timeouts >= MAX_CONSECUTIVE_ACK_TIMEOUTS {
                    warn!(req_id = %rid_str, chunks_sent = seq, "Receiver unresponsive (6 WindowAck timeouts) — aborting dead stream");
                    return (seq, true);
                }
            }
            ChunkSendStatus::NoActiveLinks => {
                warn!(req_id = %rid_str, chunks_sent = seq, "All links closed mid-transfer — aborting stream");
                return (seq, true);
            }
        }
        seq = seq.wrapping_add(1);
    }
    let end_pkt = encode_packet(PacketKind::RespEnd, req_id, seq, &[]);
    gate.send_control(transport, dest_hash, &end_pkt).await;
    (seq, false)
}

async fn send_static_response(
    req_id: [u8; 12],
    status: u16,
    content_type: &str,
    body_bytes: &[u8],
    transport: &Transport,
    dest_hash: &reticulum::hash::AddressHash,
    gate: &SendGate,
) {
    let rmeta = ResponseMeta {
        status,
        headers: vec![("content-type".into(), content_type.into())],
    };
    if let Ok(head_pkts) = encode_json_chunks(PacketKind::RespHead, req_id, &rmeta) {
        for pkt in head_pkts {
            gate.send_control(transport, dest_hash, &pkt).await;
        }
    }
    let mut seq: u32 = 0;
    for slice in body_bytes.chunks(MAX_CHUNK) {
        let pkt = encode_packet(PacketKind::RespChunk, req_id, seq, slice);
        gate.send_chunk(transport, dest_hash, &pkt).await;
        seq = seq.wrapping_add(1);
    }
    let end_pkt = encode_packet(PacketKind::RespEnd, req_id, seq, &[]);
    gate.send_control(transport, dest_hash, &end_pkt).await;
}

async fn dispatch_request(
    req_id: [u8; 12],
    req: InboundRequest,
    client: reqwest::Client,
    upstream: String,
    transport: Arc<Transport>,
    dest_hash: reticulum::hash::AddressHash,
    gate: Arc<SendGate>,
    auth_policy: Arc<AuthPolicy>,
    ram_cache: Arc<Mutex<StaticRamCache>>,
) {
    let mut head_bytes = Vec::new();
    for (_, part) in req.head_chunks {
        head_bytes.extend_from_slice(&part);
    }
    let meta: RequestMeta = match serde_json::from_slice(&head_bytes) {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to parse CHT2 RequestMeta: {e}");
            return;
        }
    };

    let mut body_bytes = Vec::new();
    for (_, part) in req.body_chunks {
        body_bytes.extend_from_slice(&part);
    }

    let rid_str = req_id_to_string(&req_id);

    // Lock 2: Verify Ed25519 Client Identity Signature (enforced when --allow-client or --allow-clients-file is set)
    let verified_client = verify_request_signature(
        &auth_policy.dest_hash_hex,
        &meta.method,
        &meta.path,
        &body_bytes,
        &meta.headers,
    );

    if auth_policy.enforced {
        let allow_set = load_effective_allowlist(
            &auth_policy.static_clients,
            auth_policy.clients_file.as_deref(),
        );
        let auth_ok = match &verified_client {
            Ok(vc) => allow_set.contains(&vc.client_id) || allow_set.contains(&vc.pubkey_hex),
            Err(_) => false,
        };
        if !auth_ok {
            let (presented_id, reason) = match &verified_client {
                Ok(vc) => (
                    vc.client_id.clone(),
                    format!("Client Ed25519 ID '{}' is not in this vault's allowlist", vc.client_id),
                ),
                Err(e) => ("unauthenticated".to_string(), e.to_string()),
            };
            warn!(
                req_id = %rid_str,
                path = %meta.path,
                client_id = %presented_id,
                reason = %reason,
                "[CITADEL-AUTH-DROP] Blocked unauthorized Reticulum client (403)"
            );
            let wants_html = meta
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("accept"))
                .map(|(_, v)| v.contains("text/html"))
                .unwrap_or(false)
                && !meta.path.starts_with("/api/");
            if wants_html {
                let html = format!(
                    "<!DOCTYPE html><html><body style='background:#050907;color:#f3faf6;font-family:ui-monospace,monospace;padding:36px;max-width:720px;margin:0 auto;'>\
                     <h2 style='color:#f87171;'>🔒 CITADEL VAULT // 403 UNAUTHORIZED IDENTITY</h2>\
                     <p style='color:#94a3b8;line-height:1.6;'>This private Citadel Ghost Vault enforces <strong>Mutual Ed25519 Client Authentication</strong>.</p>\
                     <div style='background:#0b140f;border:1px solid rgba(248,113,113,0.4);border-radius:10px;padding:16px;margin:18px 0;'>\
                       <div style='font-size:11px;color:#94a3b8;'>YOUR DEVICE ED25519 CLIENT ID:</div>\
                       <div style='font-size:16px;color:#7dd3fc;font-weight:800;margin-top:6px;word-break:break-all;'>{presented_id}</div>\
                       <div style='font-size:11px;color:#fca5a5;margin-top:8px;'>Reason: {reason}</div>\
                     </div>\
                     <p style='color:#8ea99a;font-size:12px;'>Ask the vault owner to add your Device ID to <code>allowed_clients.txt</code> (hot-reloaded immediately — zero restart needed).</p>\
                     <p><a style='color:#84cc16;' href='bifrost://home/'>← Return to bifrost://home/</a></p></body></html>"
                );
                send_static_response(req_id, 403, "text/html; charset=utf-8", html.as_bytes(), &transport, &dest_hash, &gate).await;
            } else {
                let json = serde_json::json!({
                    "ok": false,
                    "error": "unauthorized_ed25519_client",
                    "client_id": presented_id,
                    "reason": reason,
                })
                .to_string();
                send_static_response(req_id, 403, "application/json; charset=utf-8", json.as_bytes(), &transport, &dest_hash, &gate).await;
            }
            return;
        }
    }

    let is_get_req = meta.method.eq_ignore_ascii_case("GET");
    let is_head_req = meta.method.eq_ignore_ascii_case("HEAD");
    let is_static_asset = is_static_immutable_path(&meta.path);
    let client_accepts_gzip = meta
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
        .map(|(_, v)| v.to_lowercase().contains("gzip"))
        .unwrap_or(false);

    // Fast path: 0.01 ms in-RAM pre-compressed static asset cache (Vite bundles, 3D room twins, icons)
    let ram_key = if is_get_req && is_static_asset {
        Some(format!("{}|gz={}", meta.path, client_accepts_gzip))
    } else {
        None
    };
    if let Some(ref key) = ram_key {
        let hit = { ram_cache.lock().await.get(key) };
        if let Some(cached) = hit {
            let (chunks, aborted) = stream_buffered_response(
                req_id,
                &rid_str,
                cached.status,
                cached.headers,
                &cached.wire_bytes,
                &transport,
                &dest_hash,
                &gate,
            )
            .await;
            if !aborted {
                info!(
                    req_id = %rid_str,
                    path = %meta.path,
                    orig_bytes = cached.orig_len,
                    wire_bytes = cached.wire_bytes.len(),
                    chunks = chunks,
                    "Streamed RAM-cached encrypted RNS response"
                );
            }
            return;
        }
    }

    info!(
        req_id = %rid_str,
        method = %meta.method,
        path = %meta.path,
        client_id = verified_client.as_ref().map(|v| v.client_id.as_str()).unwrap_or("anon"),
        body_len = body_bytes.len(),
        "RNS -> localhost HTTP"
    );

    let url = format!("{}{}", upstream.trim_end_matches('/'), meta.path);
    let method = meta
        .method
        .parse::<reqwest::Method>()
        .unwrap_or(reqwest::Method::GET);

    let mut rb = client.request(method, &url);
    if let Ok(vc) = &verified_client {
        rb = rb.header(HDR_VERIFIED_CLIENT, vc.client_id.as_str());
    }
    for (k, v) in &meta.headers {
        let kl = k.to_lowercase();
        if matches!(
            kl.as_str(),
            "content-type"
                | "accept"
                | "accept-encoding"
                | "cookie"
                | "authorization"
                | "if-none-match"
                | "if-modified-since"
        ) {
            rb = rb.header(k.as_str(), v.as_str());
        }
    }
    if !body_bytes.is_empty() {
        rb = rb.body(body_bytes);
    }

    match rb.send().await {
        Ok(mut resp) => {
            let status = resp.status().as_u16();
            let mut resp_headers = Vec::new();
            let mut content_type = String::new();
            let mut has_content_encoding = false;
            let mut has_cache_control = false;

            for (k, v) in resp.headers() {
                let kl = k.as_str().to_lowercase();
                if matches!(
                    kl.as_str(),
                    "content-type"
                        | "content-encoding"
                        | "cache-control"
                        | "etag"
                        | "last-modified"
                        | "vary"
                        | "set-cookie"
                        | "location"
                ) {
                    if let Ok(vs) = v.to_str() {
                        if kl == "content-type" {
                            content_type = vs.to_string();
                        } else if kl == "content-encoding" {
                            has_content_encoding = true;
                        } else if kl == "cache-control" {
                            has_cache_control = true;
                        }
                        resp_headers.push((kl, vs.to_string()));
                    }
                }
            }

            // Immutable cache header for Vite content-hashed static bundles (/assets/*)
            if status == 200 && !has_cache_control && meta.path.starts_with("/assets/") {
                resp_headers.push((
                    "cache-control".into(),
                    "public, max-age=31536000, immutable".into(),
                ));
            }

            let should_gzip = status == 200
                && !is_head_req
                && client_accepts_gzip
                && !has_content_encoding
                && is_compressible(&content_type, &meta.path);

            let should_buffer_static = status == 200 && is_get_req && is_static_asset && !should_gzip;

            if should_gzip {
                let raw_body = match resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(req_id = %rid_str, "Failed reading upstream body for gzip: {e}");
                        return;
                    }
                };
                let orig_len = raw_body.len();
                let comp_level = if is_static_asset {
                    Compression::default()
                } else {
                    Compression::fast()
                };
                let (wire_bytes, was_compressed): (Vec<u8>, bool) = if orig_len >= 512 {
                    let raw_vec = raw_body.to_vec();
                    let gz_res = if orig_len >= 64 * 1024 {
                        tokio::task::spawn_blocking(move || {
                            let mut enc = GzEncoder::new(Vec::with_capacity(orig_len / 3), comp_level);
                            if enc.write_all(&raw_vec).is_ok() {
                                match enc.finish() {
                                    Ok(gz) if gz.len() < orig_len => (gz, true),
                                    _ => (raw_vec, false),
                                }
                            } else {
                                (raw_vec, false)
                            }
                        })
                        .await
                        .unwrap_or_else(|_| (raw_body.to_vec(), false))
                    } else {
                        let mut enc = GzEncoder::new(Vec::with_capacity(orig_len / 3), comp_level);
                        if enc.write_all(&raw_vec).is_ok() {
                            match enc.finish() {
                                Ok(gz) if gz.len() < orig_len => (gz, true),
                                _ => (raw_vec, false),
                            }
                        } else {
                            (raw_vec, false)
                        }
                    };
                    gz_res
                } else {
                    (raw_body.to_vec(), false)
                };
                if was_compressed {
                    resp_headers.push(("content-encoding".into(), "gzip".into()));
                }

                let wire_arc = Arc::new(wire_bytes);
                if let Some(ref key) = ram_key {
                    if wire_arc.len() <= MAX_SINGLE_RAM_ASSET {
                        ram_cache.lock().await.insert(
                            key.clone(),
                            CachedStatic {
                                status,
                                headers: resp_headers.clone(),
                                wire_bytes: Arc::clone(&wire_arc),
                                orig_len,
                                inserted_at: Instant::now(),
                            },
                        );
                    }
                }

                let (chunks, aborted) = stream_buffered_response(
                    req_id,
                    &rid_str,
                    status,
                    resp_headers,
                    &wire_arc,
                    &transport,
                    &dest_hash,
                    &gate,
                )
                .await;
                if !aborted {
                    info!(
                        req_id = %rid_str,
                        status = status,
                        orig_bytes = orig_len,
                        wire_bytes = wire_arc.len(),
                        chunks = chunks,
                        "Streamed compressed encrypted RNS response"
                    );
                }
            } else if should_buffer_static {
                let raw_body = match resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(req_id = %rid_str, "Failed reading static upstream body: {e}");
                        return;
                    }
                };
                let orig_len = raw_body.len();
                let wire_arc = Arc::new(raw_body.to_vec());
                if let Some(ref key) = ram_key {
                    if wire_arc.len() <= MAX_SINGLE_RAM_ASSET {
                        ram_cache.lock().await.insert(
                            key.clone(),
                            CachedStatic {
                                status,
                                headers: resp_headers.clone(),
                                wire_bytes: Arc::clone(&wire_arc),
                                orig_len,
                                inserted_at: Instant::now(),
                            },
                        );
                    }
                }
                let (chunks, aborted) = stream_buffered_response(
                    req_id,
                    &rid_str,
                    status,
                    resp_headers,
                    &wire_arc,
                    &transport,
                    &dest_hash,
                    &gate,
                )
                .await;
                if !aborted {
                    info!(req_id = %rid_str, status = status, chunks = chunks, bytes = orig_len, "Streamed static encrypted RNS response");
                }
            } else {
                let rmeta = ResponseMeta {
                    status,
                    headers: resp_headers,
                };
                if let Ok(head_pkts) = encode_json_chunks(PacketKind::RespHead, req_id, &rmeta) {
                    for pkt in head_pkts {
                        gate.send_control(&transport, &dest_hash, &pkt).await;
                    }
                }

                let mut seq: u32 = 0;
                let mut total_bytes: usize = 0;
                let mut consecutive_timeouts: u32 = 0;
                let mut aborted = false;
                if !is_head_req {
                    'stream: while let Ok(Some(chunk)) = resp.chunk().await {
                        for slice in chunk.chunks(MAX_CHUNK) {
                            let pkt = encode_packet(PacketKind::RespChunk, req_id, seq, slice);
                            match gate.send_chunk(&transport, &dest_hash, &pkt).await {
                                ChunkSendStatus::Ok => consecutive_timeouts = 0,
                                ChunkSendStatus::AckTimeout => {
                                    consecutive_timeouts += 1;
                                    if consecutive_timeouts >= MAX_CONSECUTIVE_ACK_TIMEOUTS {
                                        warn!(req_id = %rid_str, chunks_sent = seq, "Receiver unresponsive (6 WindowAck timeouts) — aborting live stream");
                                        aborted = true;
                                        break 'stream;
                                    }
                                }
                                ChunkSendStatus::NoActiveLinks => {
                                    warn!(req_id = %rid_str, chunks_sent = seq, "All links closed mid-stream — aborting");
                                    aborted = true;
                                    break 'stream;
                                }
                            }
                            seq = seq.wrapping_add(1);
                            total_bytes += slice.len();
                        }
                    }
                }

                if !aborted {
                    let end_pkt = encode_packet(PacketKind::RespEnd, req_id, seq, &[]);
                    gate.send_control(&transport, &dest_hash, &end_pkt).await;
                    info!(req_id = %rid_str, status = status, chunks = seq, bytes = total_bytes, "Streamed lossless encrypted RNS response");
                }
            }
        }
        Err(e) => {
            let rmeta = ResponseMeta {
                status: 502,
                headers: vec![("content-type".into(), "text/plain".into())],
            };
            if let Ok(head_pkts) = encode_json_chunks(PacketKind::RespHead, req_id, &rmeta) {
                for pkt in head_pkts {
                    gate.send_control(&transport, &dest_hash, &pkt).await;
                }
            }
            let msg = format!("Upstream error: {e}");
            let mut seq: u32 = 0;
            for slice in msg.as_bytes().chunks(MAX_CHUNK) {
                let pkt = encode_packet(PacketKind::RespChunk, req_id, seq, slice);
                gate.send_chunk(&transport, &dest_hash, &pkt).await;
                seq += 1;
            }
            let end_pkt = encode_packet(PacketKind::RespEnd, req_id, seq, &[]);
            gate.send_control(&transport, &dest_hash, &end_pkt).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let ifac: Option<Arc<IfacKey>> =
        IfacKey::resolve(args.ifac_key.as_deref(), args.ifac_key_file.as_deref())?.map(Arc::new);

    let id = PrivateIdentity::new_from_name(&args.identity_name);
    let mut timers = TimerConfig::default();
    timers.in_link_stale = Duration::from_secs(45);
    timers.in_link_close = Duration::from_secs(15);
    timers.out_link_stale = Duration::from_secs(45);
    timers.out_link_close = Duration::from_secs(15);
    let mut transport = Transport::new(
        TransportConfig::new("citadel-vault", &id)
            .set_reroute_eager(true)
            .set_timer_config(timers),
    );

    let dest = transport
        .add_destination(id, DestinationName::new("citadel", "http_vault"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;
    let dest_hash_hex = format!("{dest_hash}").trim_matches('/').to_ascii_lowercase();

    let auth_enforced = !args.allow_clients.is_empty() || args.allow_clients_file.is_some();
    let auth_policy = Arc::new(AuthPolicy {
        enforced: auth_enforced,
        static_clients: args.allow_clients.clone(),
        clients_file: args.allow_clients_file.clone(),
        dest_hash_hex,
    });

    if !args.rns_peers.is_empty() {
        for peer in &args.rns_peers {
            transport.iface_manager().lock().await.spawn(
                FastTcpClient::new_with_ifac(peer, ifac.clone()),
                FastTcpClient::spawn,
            );
        }
        info!(
            dest_hash = %dest_hash,
            mode = "0-port-outbound",
            peers = ?args.rns_peers,
            upstream = %args.upstream,
            ifac = ifac.as_ref().map(|k| k.fingerprint()).unwrap_or("off"),
            client_allowlist = auth_enforced,
            "Citadel Zero-Port Lossless Vault Daemon v0.6.0 LIVE (Clean-Room MIT Rust)"
        );
    } else {
        transport.iface_manager().lock().await.spawn(
            FastTcpServer::new_with_ifac(&args.rns_bind, transport.iface_manager(), ifac.clone()),
            FastTcpServer::spawn,
        );
        info!(
            dest_hash = %dest_hash,
            mode = "tcp-server",
            bind = %args.rns_bind,
            upstream = %args.upstream,
            ifac = ifac.as_ref().map(|k| k.fingerprint()).unwrap_or("off"),
            client_allowlist = auth_enforced,
            "Citadel Zero-Port Lossless Vault Daemon v0.6.0 LIVE (Clean-Room MIT Rust)"
        );
    }

    let transport = Arc::new(transport);
    let gate = Arc::new(SendGate::new());
    let ram_cache = Arc::new(Mutex::new(StaticRamCache::default()));
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()?;
    let inflight: Arc<Mutex<HashMap<[u8; 12], InboundRequest>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Periodic Reticulum destination announce (includes identity alias in app_data for Ghost Browser discovery)
    {
        let t_ann = Arc::clone(&transport);
        let d_ann = Arc::clone(&dest);
        let alias_bytes = args.identity_name.clone().into_bytes();
        tokio::spawn(async move {
            loop {
                t_ann.send_announce(&d_ann, Some(&alias_bytes)).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }

    let mut in_events = transport.in_link_events();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down Citadel Zero-Port Vault Daemon");
                break;
            }
            ev = in_events.recv() => {
                let link_ev = match ev {
                    Ok(v) => v,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Vault in_link_events lagged by {n} — continuing");
                        continue;
                    }
                    Err(_) => break,
                };
                match link_ev.event {
                    LinkEvent::Activated => {
                        gate.on_link_activated().await;
                        info!(link_id = %link_ev.id, "Encrypted X25519+Ed25519 Reticulum link ACTIVATED");
                    }
                    LinkEvent::Closed => {
                        gate.on_link_closed().await;
                        info!(link_id = %link_ev.id, "Reticulum link closed");
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
                            PacketKind::WindowAck => {
                                gate.on_ack();
                            }
                            PacketKind::ReqHead => {
                                let mut map = inflight.lock().await;
                                map.entry(pkt.req_id).or_default().head_chunks.insert(pkt.seq, pkt.payload);
                            }
                            PacketKind::ReqChunk => {
                                let mut map = inflight.lock().await;
                                map.entry(pkt.req_id).or_default().body_chunks.insert(pkt.seq, pkt.payload);
                            }
                            PacketKind::ReqEnd => {
                                let req = inflight.lock().await.remove(&pkt.req_id).unwrap_or_default();
                                tokio::spawn(dispatch_request(
                                    pkt.req_id,
                                    req,
                                    http_client.clone(),
                                    args.upstream.clone(),
                                    Arc::clone(&transport),
                                    dest_hash,
                                    Arc::clone(&gate),
                                    Arc::clone(&auth_policy),
                                    Arc::clone(&ram_cache),
                                ));
                            }
                            _ => {}
                        }
                    }
                    LinkEvent::Proof(_) | LinkEvent::RemoteIdentified(_) => {}
                }
            }
        }
    }

    Ok(())
}
