//! Citadel Stateless Reticulum Transport Relay (`citadel-rns-relay`) — Clean-Room MIT Rust
//!
//! Turns any Linux server (Raspberry Pi 4B, Ventuno Q, or VPS) into a blind, zero-plaintext
//! Reticulum Transport Node that routes already-encrypted X25519+Ed25519 links and announces
//! between 0-port Citadel Vaults, BIFROST Ghost Browsers, Huginn RNS nodes, and peer relays
//! across NAT/Starlink/internet boundaries (e.g. Dubai <-> Vellinge <-> Bjärred <-> Los Angeles).
//!
//! Security Properties:
//! - Holds ZERO vault keys, ZERO user keys, ZERO message history, ZERO HTTP server
//! - Cannot decrypt, inspect, or forge any relayed packet (end-to-end encrypted by endpoints)
//! - Lock 1 (**IFAC Dark-Network Masking**): `--ifac-key-file` / `CITADEL_IFAC_KEY_FILE` silently
//!   drops all unauthenticated TCP scanners and rogue Reticulum clients before packet parsing
//! - Repeatable `--peer` enables self-healing multi-city mesh peering

use anyhow::Result;
use citadel_rns_rs::fast_tcp::{FastTcpClient, FastTcpServer};
use citadel_rns_rs::security::IfacKey;
use clap::Parser;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::{Transport, TransportConfig};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "citadel-rns-relay")]
#[command(about = "Stateless Blind Reticulum Transport Relay Node with IFAC Dark-Network Masking (MIT Rust)")]
struct Args {
    /// Deterministic Transport Identity name (e.g. citadel-relay-dubai, citadel-relay-bjarred)
    #[arg(long, env = "CITADEL_RELAY_NAME", default_value = "citadel-relay-dubai")]
    identity_name: String,

    /// TCP listen address for inbound FastTcp Reticulum peers (0 plaintext, 0 HTTP)
    #[arg(long, env = "CITADEL_RELAY_LISTEN", default_value = "0.0.0.0:14290")]
    listen: String,

    /// Optional outbound peer Transport Relay(s) for multi-city mesh peering (repeatable)
    #[arg(long = "peer", env = "CITADEL_RELAY_PEERS", value_delimiter = ',')]
    peers: Vec<String>,

    /// Lock 1 (IFAC): Path to shared network key file (chmod 600) for dark-network frame masking
    #[arg(long = "ifac-key-file", env = "CITADEL_IFAC_KEY_FILE")]
    ifac_key_file: Option<PathBuf>,

    /// Lock 1 (IFAC): Inline shared network passphrase (prefer --ifac-key-file to avoid ps aux exposure)
    #[arg(long = "ifac-key", env = "CITADEL_IFAC_KEY")]
    ifac_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let ifac: Option<Arc<IfacKey>> =
        IfacKey::resolve(args.ifac_key.as_deref(), args.ifac_key_file.as_deref())?.map(Arc::new);

    let id = PrivateIdentity::new_from_name(&args.identity_name);
    let transport_hash = hex_hash(id.address_hash().as_slice());

    let cfg = TransportConfig::new(&args.identity_name, &id).set_retransmit(true);
    let transport = Arc::new(Transport::new(cfg));

    transport.iface_manager().lock().await.spawn(
        FastTcpServer::new_with_ifac(&args.listen, transport.iface_manager(), ifac.clone()),
        FastTcpServer::spawn,
    );

    for peer in &args.peers {
        let p = peer.trim();
        if !p.is_empty() {
            transport.iface_manager().lock().await.spawn(
                FastTcpClient::new_with_ifac(p, ifac.clone()),
                FastTcpClient::spawn,
            );
            info!(peer = %p, "Connecting outbound to peer Reticulum Transport Relay");
        }
    }

    info!(
        identity = %args.identity_name,
        transport_id = %transport_hash,
        listen = %args.listen,
        peer_relays = args.peers.len(),
        ifac = ifac.as_ref().map(|k| k.fingerprint()).unwrap_or("off"),
        "Citadel Blind Reticulum Transport Relay LIVE (retransmit=true, 0 plaintext, 0 keys)"
    );

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
