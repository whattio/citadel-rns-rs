//! Citadel Reticulum Streaming Airlock Proxy (Clean-Room MIT Rust)
//!
//! Translates standard browser HTTP/SSE requests into chunked, end-to-end encrypted
//! X25519 + Ed25519 Reticulum Link packets (`CHT2`) via MIT-licensed `Reticulum-rs`.
//! Supports full SPA bundles, 3D GLB assets, and real-time streaming LLM SSE tokens.

use anyhow::Result;
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Uri},
    response::IntoResponse,
    Router,
};
use citadel_rns_rs::chtp::{
    decode_packet, encode_json_chunks, encode_packet, req_id_from_str, PacketKind, RequestMeta,
    ResponseMeta, MAX_CHUNK, WINDOW_SIZE,
};
use clap::Parser;
use futures_util::stream;
use reticulum::destination::link::LinkEvent;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::transport::{Transport, TransportConfig};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "citadel-airlock-proxy")]
#[command(about = "Streaming Airlock HTTP-to-Reticulum Proxy (Clean-Room MIT Rust)")]
struct Args {
    /// Reticulum TCP listen address for 0-port outbound Ghost nodes (e.g. 0.0.0.0:14245)
    #[arg(long)]
    rns_listen: Option<String>,

    /// Optional Reticulum TCP peer endpoint (used if --rns-listen is not set)
    #[arg(long, default_value = "127.0.0.1:14245")]
    rns_peer: String,

    /// Deterministic Airlock client identity name
    #[arg(long, default_value = "citadel-airlock-node")]
    identity_name: String,

    /// Local HTTP Airlock bind address (e.g. 127.0.0.1:7443)
    #[arg(long, default_value = "127.0.0.1:7443")]
    bind: SocketAddr,
}

struct PendingResponse {
    head_chunks: BTreeMap<u32, Vec<u8>>,
    head_tx: Option<oneshot::Sender<ResponseMeta>>,
    body_tx: mpsc::UnboundedSender<Vec<u8>>,
}

type PendingMap = Arc<Mutex<HashMap<[u8; 12], PendingResponse>>>;

#[derive(Clone)]
struct AirlockState {
    transport: Arc<Transport>,
    target_hash: Arc<RwLock<Option<AddressHash>>>,
    pending: PendingMap,
}

async fn handle_airlock_request(
    State(state): State<Arc<AirlockState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let dest = match *state.target_hash.read().await {
        Some(h) => h,
        None => {
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from(
                    "Citadel Airlock: waiting for Reticulum Vault link activation\n",
                ))
                .unwrap();
        }
    };

    let req_id_str = Uuid::new_v4().simple().to_string()[..12].to_string();
    let req_id = req_id_from_str(&req_id_str);

    let mut fwd_headers = HashMap::new();
    for key in ["content-type", "accept", "cookie", "authorization"] {
        if let Some(val) = headers.get(key).and_then(|v| v.to_str().ok()) {
            fwd_headers.insert(key.to_string(), val.to_string());
        }
    }

    let meta = RequestMeta {
        method: method.as_str().to_string(),
        path: uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .to_string(),
        headers: fwd_headers,
    };

    let head_pkts = match encode_json_chunks(PacketKind::ReqHead, req_id, &meta) {
        Ok(p) => p,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("CHT2 encode error: {e}")))
                .unwrap();
        }
    };

    let (head_tx, head_rx) = oneshot::channel();
    let (body_tx, body_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    state.pending.lock().await.insert(
        req_id,
        PendingResponse {
            head_chunks: BTreeMap::new(),
            head_tx: Some(head_tx),
            body_tx,
        },
    );

    // Send chunked request head + body + end
    for pkt in head_pkts {
        state.transport.send_to_out_links(&dest, &pkt).await;
    }
    let mut seq: u32 = 0;
    for slice in body.chunks(MAX_CHUNK) {
        let pkt = encode_packet(PacketKind::ReqChunk, req_id, seq, slice);
        state.transport.send_to_out_links(&dest, &pkt).await;
        seq += 1;
    }
    let end_pkt = encode_packet(PacketKind::ReqEnd, req_id, seq, &[]);
    state.transport.send_to_out_links(&dest, &end_pkt).await;

    info!(req_id = %req_id_str, method = %meta.method, path = %meta.path, "Dispatched streaming RNS request");

    match tokio::time::timeout(Duration::from_secs(30), head_rx).await {
        Ok(Ok(resp_meta)) => {
            let st = StatusCode::from_u16(resp_meta.status).unwrap_or(StatusCode::OK);
            let mut builder = Response::builder()
                .status(st)
                .header("x-citadel-transport", "reticulum-rs-mit-stream");
            for (k, v) in resp_meta.headers {
                if let (Ok(hk), Ok(hv)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(&v),
                ) {
                    builder = builder.header(hk, hv);
                }
            }

            let body_stream = stream::unfold(body_rx, |mut rx| async move {
                rx.recv()
                    .await
                    .map(|chunk| (Ok::<Bytes, std::io::Error>(Bytes::from(chunk)), rx))
            });
            builder.body(Body::from_stream(body_stream)).unwrap()
        }
        _ => {
            state.pending.lock().await.remove(&req_id);
            Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(Body::from(
                    "Citadel Airlock: Reticulum vault response timed out\n",
                ))
                .unwrap()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let id = PrivateIdentity::new_from_name(&args.identity_name);
    let transport = Arc::new(Transport::new(TransportConfig::new("citadel-airlock", &id)));

    if let Some(ref listen_addr) = args.rns_listen {
        transport.iface_manager().lock().await.spawn(
            TcpServer::new(listen_addr, transport.iface_manager()),
            TcpServer::spawn,
        );
        info!(rns_listen = %listen_addr, "Airlock listening for 0-port outbound Ghost Vaults");
    } else {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(&args.rns_peer), TcpClient::spawn);
        info!(rns_peer = %args.rns_peer, "Airlock dialing Reticulum Vault peer");
    }

    let target_hash: Arc<RwLock<Option<AddressHash>>> = Arc::new(RwLock::new(None));
    let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

    // Discover Vault announce & establish encrypted X25519+Ed25519 Link
    {
        let t = Arc::clone(&transport);
        let th = Arc::clone(&target_hash);
        tokio::spawn(async move {
            let mut announces = t.recv_announces().await;
            while let Ok(announce) = announces.recv().await {
                let desc = announce.destination.lock().await.desc;
                if th.read().await.is_none() {
                    info!(dest_hash = %desc.address_hash, "Discovered Citadel Vault announce — establishing encrypted Reticulum Link...");
                    let _link = t.link(desc).await;
                    *th.write().await = Some(desc.address_hash);
                }
            }
        });
    }

    // Demux incoming streaming CHT2 response packets + emit lossless WindowAck
    {
        let t = Arc::clone(&transport);
        let th = Arc::clone(&target_hash);
        let p = Arc::clone(&pending);
        tokio::spawn(async move {
            let mut out_events = t.out_link_events();
            let mut rx_window: u32 = 0;
            loop {
                let ev = match out_events.recv().await {
                    Ok(ev) => ev,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Airlock out_link_events lagged by {n} packets — continuing");
                        continue;
                    }
                    Err(_) => break,
                };
                match ev.event {
                    LinkEvent::Activated => {
                        info!(link_id = %ev.id, "Encrypted Reticulum Streaming Airlock Link ACTIVATED!");
                    }
                    LinkEvent::Closed => {
                        warn!(link_id = %ev.id, "Reticulum Airlock Link closed — clearing target for auto-reconnect");
                        *th.write().await = None;
                    }
                    LinkEvent::Data(payload) => {
                        let pkt = match decode_packet(payload.as_slice()) {
                            Ok(pkt) => pkt,
                            Err(e) => {
                                warn!("Bad CHT2 response packet: {e}");
                                continue;
                            }
                        };
                        let mut map = p.lock().await;
                        match pkt.kind {
                            PacketKind::RespHead => {
                                if let Some(entry) = map.get_mut(&pkt.req_id) {
                                    entry.head_chunks.insert(pkt.seq, pkt.payload);
                                    let mut joined = Vec::new();
                                    for (_, part) in &entry.head_chunks {
                                        joined.extend_from_slice(part);
                                    }
                                    if let Ok(meta) = serde_json::from_slice::<ResponseMeta>(&joined)
                                    {
                                        if let Some(tx) = entry.head_tx.take() {
                                            let _ = tx.send(meta);
                                        }
                                    }
                                }
                            }
                            PacketKind::RespChunk => {
                                if let Some(entry) = map.get(&pkt.req_id) {
                                    let _ = entry.body_tx.send(pkt.payload);
                                }
                                rx_window += 1;
                                if rx_window >= WINDOW_SIZE {
                                    rx_window = 0;
                                    if let Some(dest) = *th.read().await {
                                        let ack = encode_packet(
                                            PacketKind::WindowAck,
                                            pkt.req_id,
                                            pkt.seq,
                                            &[],
                                        );
                                        let t_ack = Arc::clone(&t);
                                        tokio::spawn(async move {
                                            t_ack.send_to_out_links(&dest, &ack).await;
                                        });
                                    }
                                }
                            }
                            PacketKind::RespEnd => {
                                map.remove(&pkt.req_id);
                                rx_window = 0;
                                if let Some(dest) = *th.read().await {
                                    let ack = encode_packet(
                                        PacketKind::WindowAck,
                                        pkt.req_id,
                                        pkt.seq,
                                        &[],
                                    );
                                    let t_ack = Arc::clone(&t);
                                    tokio::spawn(async move {
                                        t_ack.send_to_out_links(&dest, &ack).await;
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

    let state = Arc::new(AirlockState {
        transport,
        target_hash,
        pending,
    });

    let app = Router::new()
        .fallback(handle_airlock_request)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    info!(bind = %args.bind, peer = %args.rns_peer, "Citadel Streaming Airlock Proxy LIVE (Clean-Room MIT Rust)");
    axum::serve(listener, app).await?;
    Ok(())
}
