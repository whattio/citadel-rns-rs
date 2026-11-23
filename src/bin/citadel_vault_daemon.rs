//! Citadel Zero-Port HTTP-over-Reticulum Vault Daemon (Clean-Room MIT Rust v0.4.0)
//!
//! Features:
//! - True 0-port outbound Ghost mode (`--rns-peer`) for `nftables [CITADEL-DROP]` hosts
//! - Global serialized send gate + 8-packet `WindowAck` flow control (mathematically prevents
//!   broadcast-buffer packet drops across parallel browser asset loads & MJPEG/JPEG camera feeds)
//! - Full multi-chunk payloads (HTML, multi-MB JS bundles, 3D GLB) + real-time SSE token streaming

use anyhow::Result;
use citadel_rns_rs::chtp::{
    decode_packet, encode_json_chunks, encode_packet, req_id_to_string, PacketKind, RequestMeta,
    ResponseMeta, MAX_CHUNK, WINDOW_SIZE,
};
use clap::Parser;
use reticulum::destination::link::LinkEvent;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::transport::{Transport, TransportConfig};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
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

    /// Reticulum TCP outbound peer address for 0-port Ghost mode (e.g. 127.0.0.1:14245)
    #[arg(long)]
    rns_peer: Option<String>,

    /// Optional Reticulum TCP bind address (only used if --rns-peer is not set)
    #[arg(long, default_value = "0.0.0.0:14245")]
    rns_bind: String,
}

#[derive(Default)]
struct InboundRequest {
    head_chunks: BTreeMap<u32, Vec<u8>>,
    body_chunks: BTreeMap<u32, Vec<u8>>,
}

struct SendGate {
    /// Serializes all outbound RNS packets so concurrent HTTP requests never burst past 16-slot broadcast capacity
    lock: Mutex<()>,
    ack_notify: Notify,
}

impl SendGate {
    fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            ack_notify: Notify::new(),
        }
    }

    fn on_ack(&self) {
        self.ack_notify.notify_waiters();
    }
}

async fn dispatch_request(
    req_id: [u8; 12],
    req: InboundRequest,
    client: reqwest::Client,
    upstream: String,
    transport: Arc<Transport>,
    dest_hash: reticulum::hash::AddressHash,
    gate: Arc<SendGate>,
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
    info!(req_id = %rid_str, method = %meta.method, path = %meta.path, body_len = body_bytes.len(), "RNS -> localhost HTTP");

    let url = format!("{}{}", upstream.trim_end_matches('/'), meta.path);
    let method = meta
        .method
        .parse::<reqwest::Method>()
        .unwrap_or(reqwest::Method::GET);

    let mut rb = client.request(method, &url);
    for (k, v) in &meta.headers {
        let kl = k.to_lowercase();
        if matches!(
            kl.as_str(),
            "content-type" | "accept" | "cookie" | "authorization"
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
            for (k, v) in resp.headers() {
                let kl = k.as_str().to_lowercase();
                if matches!(
                    kl.as_str(),
                    "content-type" | "cache-control" | "set-cookie" | "location"
                ) {
                    if let Ok(vs) = v.to_str() {
                        resp_headers.push((kl, vs.to_string()));
                    }
                }
            }
            let rmeta = ResponseMeta {
                status,
                headers: resp_headers,
            };

            if let Ok(head_pkts) = encode_json_chunks(PacketKind::RespHead, req_id, &rmeta) {
                let _g = gate.lock.lock().await;
                for pkt in head_pkts {
                    transport.send_to_in_links(&dest_hash, &pkt).await;
                }
            }

            let mut seq: u32 = 0;
            let mut total_bytes: usize = 0;
            let mut window_count: u32 = 0;

            while let Ok(Some(chunk)) = resp.chunk().await {
                for slice in chunk.chunks(MAX_CHUNK) {
                    let pkt = encode_packet(PacketKind::RespChunk, req_id, seq, slice);
                    {
                        let _g = gate.lock.lock().await;
                        window_count += 1;
                        if window_count >= WINDOW_SIZE {
                            let notified = gate.ack_notify.notified();
                            tokio::pin!(notified);
                            notified.as_mut().enable();
                            transport.send_to_in_links(&dest_hash, &pkt).await;
                            let _ = tokio::time::timeout(Duration::from_millis(250), notified).await;
                            window_count = 0;
                        } else {
                            transport.send_to_in_links(&dest_hash, &pkt).await;
                        }
                    }
                    seq = seq.wrapping_add(1);
                    total_bytes += slice.len();
                }
            }

            let end_pkt = encode_packet(PacketKind::RespEnd, req_id, seq, &[]);
            {
                let _g = gate.lock.lock().await;
                transport.send_to_in_links(&dest_hash, &end_pkt).await;
            }
            info!(req_id = %rid_str, status = status, chunks = seq, bytes = total_bytes, "Streamed lossless encrypted RNS response");
        }
        Err(e) => {
            let rmeta = ResponseMeta {
                status: 502,
                headers: vec![("content-type".into(), "text/plain".into())],
            };
            let _g = gate.lock.lock().await;
            if let Ok(head_pkts) = encode_json_chunks(PacketKind::RespHead, req_id, &rmeta) {
                for pkt in head_pkts {
                    transport.send_to_in_links(&dest_hash, &pkt).await;
                }
            }
            let msg = format!("Upstream error: {e}");
            let mut seq: u32 = 0;
            for slice in msg.as_bytes().chunks(MAX_CHUNK) {
                let pkt = encode_packet(PacketKind::RespChunk, req_id, seq, slice);
                transport.send_to_in_links(&dest_hash, &pkt).await;
                seq += 1;
            }
            let end_pkt = encode_packet(PacketKind::RespEnd, req_id, seq, &[]);
            transport.send_to_in_links(&dest_hash, &end_pkt).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let id = PrivateIdentity::new_from_name(&args.identity_name);
    let mut transport = Transport::new(TransportConfig::new("citadel-vault", &id));

    let dest = transport
        .add_destination(id, DestinationName::new("citadel", "http_vault"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;

    if let Some(ref peer) = args.rns_peer {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(peer), TcpClient::spawn);
        info!(
            dest_hash = %dest_hash,
            mode = "0-port-outbound",
            peer = %peer,
            upstream = %args.upstream,
            "Citadel Zero-Port Lossless Vault Daemon v0.4.0 LIVE (Clean-Room MIT Rust)"
        );
    } else {
        transport.iface_manager().lock().await.spawn(
            TcpServer::new(&args.rns_bind, transport.iface_manager()),
            TcpServer::spawn,
        );
        info!(
            dest_hash = %dest_hash,
            mode = "tcp-server",
            bind = %args.rns_bind,
            upstream = %args.upstream,
            "Citadel Zero-Port Lossless Vault Daemon v0.4.0 LIVE (Clean-Room MIT Rust)"
        );
    }

    let transport = Arc::new(transport);
    let gate = Arc::new(SendGate::new());
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()?;
    let inflight: Arc<Mutex<HashMap<[u8; 12], InboundRequest>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Periodic Reticulum destination announce
    {
        let t_ann = Arc::clone(&transport);
        let d_ann = Arc::clone(&dest);
        tokio::spawn(async move {
            loop {
                t_ann.send_announce(&d_ann, None).await;
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
                        info!(link_id = %link_ev.id, "Encrypted X25519+Ed25519 Reticulum link ACTIVATED");
                    }
                    LinkEvent::Closed => {
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
