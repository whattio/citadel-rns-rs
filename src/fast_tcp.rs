//! High-throughput Reticulum HDLC-over-TCP interfaces (`FastTcpClient` / `FastTcpServer`).
//!
//! 100% wire-compatible with Reticulum's standard HDLC-over-TCP framing (`0x7E` / `0x7D` / `0x20`),
//! while fixing two major throughput bottlenecks in upstream `Reticulum-rs`:
//! 1. Sets `TCP_NODELAY` (`stream.set_nodelay(true)`) so small `WindowAck` packets never trigger
//!    Linux's 40 ms TCP Nagle + Delayed-ACK stall.
//! 2. Uses an O(1)-per-byte streaming HDLC decoder instead of shifting a 1.5 KB buffer per byte.

use reticulum::buffer::{InputBuffer, OutputBuffer};
use reticulum::iface::hdlc::Hdlc;
use reticulum::iface::{Interface, InterfaceContext, InterfaceManager, RxMessage};
use reticulum::packet::Packet;
use reticulum::serde::Serialize;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

const HDLC_FLAG: u8 = 0x7e;
const HDLC_ESC: u8 = 0x7d;
const HDLC_MASK: u8 = 0x20;
const MAX_FRAME_LEN: usize = 4096;

pub struct FastTcpClient {
    addr: String,
    stream: Option<TcpStream>,
}

impl FastTcpClient {
    pub fn new<T: Into<String>>(addr: T) -> Self {
        Self {
            addr: addr.into(),
            stream: None,
        }
    }

    pub fn new_from_stream<T: Into<String>>(addr: T, stream: TcpStream) -> Self {
        Self {
            addr: addr.into(),
            stream: Some(stream),
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let addr = { context.inner.lock().unwrap().addr.clone() };
        let iface_address = context.channel.address;
        let mut initial_stream = { context.inner.lock().unwrap().stream.take() };

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        let mut keep_reconnecting = true;
        'outer: loop {
            if !keep_reconnecting || context.cancel.is_cancelled() {
                break;
            }

            let stream_res = match initial_stream.take() {
                Some(s) => {
                    keep_reconnecting = false;
                    Ok(s)
                }
                None => {
                    let mut tx = tx_channel.lock().await;
                    tokio::select! {
                        biased;
                        _ = context.cancel.cancelled() => break,
                        Some(_) = tx.recv() => continue,
                        res = TcpStream::connect(addr.clone()) => res,
                    }
                }
            };

            let stream = match stream_res {
                Ok(s) => s,
                Err(_) => {
                    info!(addr = %addr, "fast_tcp: couldn't connect, retrying in 5s");
                    let retry_at = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                    loop {
                        let mut tx = tx_channel.lock().await;
                        tokio::select! {
                            biased;
                            _ = context.cancel.cancelled() => break 'outer,
                            Some(_) = tx.recv() => {}
                            _ = tokio::time::sleep_until(retry_at) => break,
                        }
                    }
                    continue;
                }
            };

            let _ = stream.set_nodelay(true);
            info!(addr = %addr, "fast_tcp: connected (TCP_NODELAY + O(1) HDLC)");

            let cancel = context.cancel.clone();
            let stop = cancel.child_token();
            let (mut read_stream, mut write_stream) = stream.into_split();

            let rx_task = {
                let stop = stop.clone();
                let rx_channel = rx_channel.clone();
                tokio::spawn(async move {
                    let mut tcp_buf = [0u8; 16384];
                    let mut frame_buf = Vec::with_capacity(1024);
                    let mut in_frame = false;
                    let mut escape = false;

                    loop {
                        tokio::select! {
                            _ = stop.cancelled() => break,
                            res = read_stream.read(&mut tcp_buf) => {
                                match res {
                                    Ok(0) => {
                                        warn!("fast_tcp: connection closed");
                                        stop.cancel();
                                        break;
                                    }
                                    Ok(n) => {
                                        for &b in &tcp_buf[..n] {
                                            if b == HDLC_FLAG {
                                                if in_frame && !frame_buf.is_empty() {
                                                    if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&frame_buf)) {
                                                        let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                                                    }
                                                    frame_buf.clear();
                                                    escape = false;
                                                } else {
                                                    in_frame = true;
                                                    escape = false;
                                                    frame_buf.clear();
                                                }
                                            } else if in_frame {
                                                if escape {
                                                    escape = false;
                                                    if frame_buf.len() < MAX_FRAME_LEN {
                                                        frame_buf.push(b ^ HDLC_MASK);
                                                    }
                                                } else if b == HDLC_ESC {
                                                    escape = true;
                                                } else if frame_buf.len() < MAX_FRAME_LEN {
                                                    frame_buf.push(b);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("fast_tcp: read error: {e}");
                                        stop.cancel();
                                        break;
                                    }
                                }
                            }
                        }
                    }
                })
            };

            let tx_task = {
                let stop = stop.clone();
                let tx_channel = tx_channel.clone();
                tokio::spawn(async move {
                    const BUF_SZ: usize = core::mem::size_of::<Packet>() * 2;
                    let mut tx_buf = [0u8; BUF_SZ];
                    let mut hdlc_buf = [0u8; BUF_SZ];

                    loop {
                        if stop.is_cancelled() {
                            break;
                        }
                        let mut tx = tx_channel.lock().await;
                        tokio::select! {
                            _ = stop.cancelled() => break,
                            Some(message) = tx.recv() => {
                                let mut out = OutputBuffer::new(&mut tx_buf);
                                if message.packet.serialize(&mut out).is_ok() {
                                    let mut hdlc_out = OutputBuffer::new(&mut hdlc_buf);
                                    if Hdlc::encode(out.as_slice(), &mut hdlc_out).is_ok() {
                                        if write_stream.write_all(hdlc_out.as_slice()).await.is_err() {
                                            stop.cancel();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                })
            };

            let _ = tokio::join!(tx_task, rx_task);
            info!(addr = %addr, "fast_tcp: disconnected");
        }

        iface_stop.cancel();
    }
}

impl Interface for FastTcpClient {
    fn mtu() -> usize {
        2048
    }
}

pub struct FastTcpServer {
    addr: String,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
}

impl FastTcpServer {
    pub fn new<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let addr = { context.inner.lock().unwrap().addr.clone() };
        let iface_manager = { context.inner.lock().unwrap().iface_manager.clone() };
        let (_, mut tx_channel) = context.channel.split();
        let cancel = context.cancel.clone();

        let drain_task = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        res = tx_channel.recv() => {
                            if res.is_none() { break; }
                        }
                    }
                }
            })
        };

        loop {
            if cancel.is_cancelled() {
                break;
            }
            let listener = match TcpListener::bind(addr.clone()).await {
                Ok(l) => l,
                Err(e) => {
                    warn!(addr = %addr, "fast_tcp_server: bind failed ({e}), retrying in 5s");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };
            info!(addr = %addr, "fast_tcp_server: listening (TCP_NODELAY + O(1) HDLC)");

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    res = listener.accept() => {
                        if let Ok((stream, peer)) = res {
                            let _ = stream.set_nodelay(true);
                            info!(peer = %peer, addr = %addr, "fast_tcp_server: accepted peer");
                            let mut mgr = iface_manager.lock().await;
                            mgr.spawn(
                                FastTcpClient::new_from_stream(peer.to_string(), stream),
                                FastTcpClient::spawn,
                            );
                        }
                    }
                }
            }
        }

        let _ = drain_task.await;
    }
}

impl Interface for FastTcpServer {
    fn mtu() -> usize {
        2048
    }
}
