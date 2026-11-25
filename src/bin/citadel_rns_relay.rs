//! Citadel Stateless Reticulum Transport Relay (`citadel-rns-relay`) — Clean-Room MIT Rust
//!
//! Turns any Debian/Ubuntu Linux server (from a compact micro-server to a cloud VPS) into a
//! blind, zero-plaintext Reticulum Transport Node (`retransmit=true`) that routes already-encrypted
//! X25519+Ed25519 links and announces between 0-port Ghost Servers, BIFROST Ghost Browsers,
//! peer-to-peer Ghost Apps, and other relays across NAT, Starlink CGNAT, and internet boundaries.
//!
//! Security Properties:
//! - Holds ZERO vault keys, ZERO user keys, ZERO message history, ZERO HTTP server
//! - Cannot decrypt, inspect, or forge any relayed packet (end-to-end encrypted by endpoints)
//! - Repeatable `--peer` enables self-healing multi-site mesh peering

use anyhow::Result;
use citadel_rns_rs::fast_tcp::{FastTcpClient, FastTcpServer};
use clap::Parser;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::{Transport, TransportConfig};
use std::sync::Arc;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "citadel-rns-relay")]
#[command(about = "Stateless Blind Reticulum Transport Relay Node (Clean-Room MIT Rust)")]
struct Args {
    /// Deterministic Transport Identity name (e.g. citadel-relay-eu, citadel-relay-us)
    #[arg(long, env = "CITADEL_RELAY_NAME", default_value = "citadel-relay-node")]
    identity_name: String,

    /// TCP listen address for inbound FastTcp Reticulum peers (0 plaintext, 0 HTTP)
    #[arg(long, env = "CITADEL_RELAY_LISTEN", default_value = "0.0.0.0:14290")]
    listen: String,

    /// Optional outbound peer Transport Relay(s) for multi-site mesh peering (repeatable or comma-separated)
    #[arg(long = "peer", env = "CITADEL_RELAY_PEERS", value_delimiter = ',')]
    peers: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let id = PrivateIdentity::new_from_name(&args.identity_name);
    let transport_hash = hex_hash(id.address_hash().as_slice());

    let cfg = TransportConfig::new(&args.identity_name, &id).set_retransmit(true);
    let transport = Arc::new(Transport::new(cfg));

    transport.iface_manager().lock().await.spawn(
        FastTcpServer::new(&args.listen, transport.iface_manager()),
        FastTcpServer::spawn,
    );

    for peer in &args.peers {
        let p = peer.trim();
        if !p.is_empty() {
            transport
                .iface_manager()
                .lock()
                .await
                .spawn(FastTcpClient::new(p), FastTcpClient::spawn);
            info!(peer = %p, "Connecting outbound to peer Reticulum Transport Relay");
        }
    }

    info!(
        identity = %args.identity_name,
        transport_id = %transport_hash,
        listen = %args.listen,
        peer_relays = args.peers.len(),
        "Citadel Blind Reticulum Transport Relay LIVE (retransmit=true, 0 plaintext, 0 keys)"
    );

    // Log relayed announces (metadata-minimal: destination hash only, zero payload inspection)
    let mut rx = transport.recv_announces().await;
    tokio::spawn(async move {
        while let Ok(ev) = rx.recv().await {
            let dest = ev.destination.lock().await;
            let h = hex_hash(dest.desc.address_hash.as_slice());
            info!(dest_hash = %h, "Relayed encrypted Reticulum announce");
        }
    });

    tokio::signal::ctrl_c().await?;
    info!("Citadel Reticulum Transport Relay shutting down cleanly");
    Ok(())
}

fn hex_hash(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
