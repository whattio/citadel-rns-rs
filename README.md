# `citadel-rns-rs` — Application-Layer HTTP/DPP Tunnel Built on `Reticulum-rs` (Experimental Preview)

[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE)
[![Live Architecture](https://img.shields.io/badge/Architecture-citadel.ironpass.tech-84cc16.svg)](https://citadel.ironpass.tech/)
[![Protocol](https://img.shields.io/badge/Protocol-Reticulum%20(Public%20Domain%202016)-38bdf8.svg)](https://reticulum.network/)

> **Scope & Status (Experimental Developer Preview):** `citadel-rns-rs` is an **application-layer HTTP/SSE/DPP tunneling daemon and client library (`CHT2`)** built on top of the MIT-licensed Rust [`Reticulum-rs`](https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs) crate. It is **not** a full Reticulum protocol implementation and does not replace Mark Qvist's authoritative Python Reference Implementation ([markqvist/Reticulum](https://github.com/markqvist/Reticulum)). Ongoing engineering work includes formal wire-level interoperability testing against the official Python `RNS` reference node and evaluating community-recognized **Quad4 `Reticulum-Go`** as an optional transport backend. Designed strictly for **EU ESPR / CIRPASS-2 Digital Product Passports, critical-infrastructure resilience, and defensive sovereign privacy** (non-weaponized).

> **Live Architecture & Interactive Non-IP Simulator:** [https://citadel.ironpass.tech/](https://citadel.ironpass.tech/)

---

## Architecture Overview

`citadel-rns-rs` enables any Debian/Ubuntu Linux server to run with **0 open inbound web ports** (`nftables` `policy drop`), dialing outbound over an end-to-end encrypted, non-IP Reticulum link to an authorized Airlock proxy or operator workstation:

```text
[Standard Browser / HTTP Client]
        │  Local HTTP / SSE
        ▼
[citadel-airlock-proxy]   (Optional Airlock Appliance or Operator Workstation)
        │
        ═══[ 🔒 Encrypted X25519 + Ed25519 Reticulum Link (CHT2 Streaming) ]═══
        │  Runs over untrusted Fiber / Starlink / 5G / LAN pipes
        ▼
[citadel-vault-daemon]    (0-Port Ghost Linux Server · nftables DROP inbound)
        │  127.0.0.1 loopback only
        ▼
[Local Application / Vault / AI Enclave]
```

## Why Clean-Room MIT Rust?
- **Zero Commercial / Defense Licensing Risk:** Built strictly on the 100% Public Domain Reticulum Wire Protocol using MIT-licensed Rust (`Reticulum-rs`) — never bundling post-April-2025 restricted upstream Python `RNS` packages.
- **Standardized Cryptographic Primitives:**
  - **512-bit Curve25519 identity keysets** (`X25519` ECDH ephemeral key exchange + `Ed25519` signatures)
  - **128-bit cryptographic destination hashes** (zero IPv4/IPv6 addressing, zero DNS)
  - **Streaming `CHT2` Chunked Wire Framing (`v0.5.0`):** 400-byte chunks fitting inside Reticulum's 431-byte encrypted Link MDU, synchronized global `SendGate` (`WINDOW_SIZE = 10`), fast `gzip` compression for JS/CSS/HTML/JSON/SVG/WASM, zero-buffer SSE streaming for AI tokens, HTTP caching (`ETag` / `Cache-Control`), and **`FastTcp`** (`TCP_NODELAY` + O(1) streaming HDLC decoder — delivering **>15 MB/s** encrypted wire / **>50 MB/s** effective HTTP throughput)
- **True 0-Port Outbound Ghost Mode:** The protected Linux host opens zero inbound ports and dials outbound to the Airlock (`--rns-peer`), remaining invisible to LAN/WAN port scans.

## Binaries
| Binary | Role |
|---|---|
| `citadel-vault-daemon` | Runs on the 0-port Ghost Linux host, dialing outbound to a relay or Airlock and forwarding authenticated Reticulum traffic strictly to a localhost loopback service (`127.0.0.1:<port>`). |
| `citadel-airlock-proxy` | Runs on an optional Airlock appliance or operator workstation, bridging standard HTTP/SSE clients into 0-port Ghost servers over encrypted Reticulum. |
| `citadel-rns-relay` | Stateless **Blind Reticulum Transport Node** (`retransmit=true`). Routes already-encrypted `X25519+Ed25519` links and announces across NAT, Starlink CGNAT, and multi-site meshes with **zero keys, zero history, and zero plaintext visibility**. |

## Quick Start (Linux `aarch64` / `armv7l` / `x86_64` / macOS)
```bash
# 1. Build all three release binaries
cargo build --release

# 2. Option A — Direct LAN (Airlock or BIFROST listens locally)
RUST_LOG=info ./target/release/citadel-airlock-proxy \
  --identity-name my-airlock \
  --rns-listen 0.0.0.0:14245 \
  --bind 127.0.0.1:7443

RUST_LOG=info ./target/release/citadel-vault-daemon \
  --identity-name my-ghost-vault \
  --upstream http://127.0.0.1:8080 \
  --rns-peer <AIRLOCK_HOST>:14245

# 3. Option B — Multi-Site / Internet Mesh via Blind Transport Relay
# On ONE reachable Linux server (compact micro-server on fiber OR small VPS):
RUST_LOG=info ./target/release/citadel-rns-relay \
  --identity-name citadel-relay-eu \
  --listen 0.0.0.0:14290

# On any 0-port Ghost Server (dials outbound, 0 open ports):
RUST_LOG=info ./target/release/citadel-vault-daemon \
  --identity-name my-ghost-vault \
  --upstream http://127.0.0.1:8080 \
  --rns-peer <RELAY_HOST>:14290

# On any BIFROST Ghost Browser or Airlock workstation (dials outbound, 0 open ports):
bifrost-ghost-browser --no-listen --rns-peer <RELAY_HOST>:14290
```

### Multi-Site Relay Peering (Self-Healing Mesh)
Run `citadel-rns-relay` at multiple sites (for example, office fiber + partner site + backup VPS) and pass repeatable `--peer` flags (or `CITADEL_RELAY_PEERS=host1:14290,host2:14290`):
```bash
citadel-rns-relay \
  --identity-name citadel-relay-site-b \
  --listen 0.0.0.0:14290 \
  --peer <SITE_A_RELAY>:14290
```
Only **one** relay in a mesh needs a forwarded TCP port on its internet router — every other relay, Ghost Server, and BIFROST client can sit behind closed NAT/CGNAT firewalls and dial outbound to it.

---

## Crossing NAT & Starlink: Why a Blind Reticulum Relay ≠ Cloudflare Tunnel

A common first question from engineers and CISOs is: *"If Reticulum is peer-to-peer, why do we need a Transport Relay across the internet — isn't that just like a Cloudflare Tunnel?"*

### 1. The Physics of Closed Firewalls (NAT / Starlink CGNAT)
- **Over Sub-GHz LoRa radio or a local LAN:** Reticulum is **100% direct peer-to-peer** — zero relays, zero routers, zero ports.
- **Over the global internet:** Home and corporate routers drop unsolicited inbound packets, and Starlink / 5G use CGNAT (no dedicated public IPv4). When **both** endpoints are 0-port and refuse all inbound traffic, no protocol can pierce two closed firewalls without **at least one reachable Transport Node** that both sides dial outbound to.

### 2. Blind Reticulum Transport Relay vs. Corporate Zero-Trust Tunnels

| Property | **Corporate Tunnel (e.g., Cloudflare Tunnel)** | **Blind Reticulum Transport Relay (`citadel-rns-relay`)** |
| :--- | :--- | :--- |
| **Can the relay decrypt your traffic?** | **Yes.** Terminates TLS at vendor edge servers, decrypts into plaintext in vendor RAM, inspects HTTP/URLs/headers, and re-encrypts. | **No — mathematically impossible.** Payloads are end-to-end encrypted (`X25519 + Ed25519`) *before* leaving the endpoint. The relay sees only opaque ciphertext. |
| **Who owns & controls the relay?** | Single third-party cloud vendor (account, DNS, billing, ToS, jurisdiction). | **You** (any Debian/Ubuntu micro-server on fiber, partner hardware, or a disposable VPS). Swap relays anytime without changing any `bifrost://<hash>` address. |
| **DNS & HTTP metadata exposure** | Logs domain names, URL paths, source IPs, and TLS SNI. | **0 DNS, 0 hostnames, 0 HTTP headers** exposed on the wire. |
| **When the internet goes down** | **100% offline.** | The exact same cryptographic addresses route seamlessly over **LAN, Wi-Fi, Starlink, 5G, or Sub-GHz LoRa**. |
| **Vault / Server attack surface** | 0 open ports, but vendor holds TLS termination. | **0 open ports AND you hold 100% of the cryptographic keys.** |

### Persistent User-Level `systemd` Service (Zero Root Required)
```ini
# ~/.config/systemd/user/citadel-rns-relay.service
[Unit]
Description=Citadel Blind Reticulum Transport Relay
After=network-online.target

[Service]
Type=simple
Environment=RUST_LOG=info
Environment=CITADEL_RELAY_NAME=citadel-relay-node
Environment=CITADEL_RELAY_LISTEN=0.0.0.0:14290
# Optional comma-separated peer relays:
# Environment=CITADEL_RELAY_PEERS=relay-2.example:14290
ExecStart=%h/bin/citadel-rns-relay
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
```
Enable with `loginctl enable-linger "$USER" && systemctl --user enable --now citadel-rns-relay.service`. If the relay host runs `nftables` default-drop, allow **only** TCP `14290` inbound while keeping every other port dropped.

## Part of Citadel // IronPass
`citadel-rns-rs` is the open-source MIT transport core powering **[Citadel // IronPass](https://citadel.ironpass.tech/)**:
- **Citadel** — Sovereign Zero-IP Linux compute & peer-to-peer Reticulum network fabric (scaling from compact micro-servers & Edge AI appliances to multi-GPU clusters).
- **IronPass** — Physical & cryptographic hardware identity layer (NXP NTAG 424 DNA NFC silicon, Ed25519 hardware root-of-trust, and physically air-gapped Offline Digital Product Passport vaults).

## Attribution & Credits
- **Reticulum Network Stack & Protocol:** Full credit to Danish engineer and cryptographer **Mark Qvist**, inventor of [Reticulum](https://reticulum.network/) and maintainer of the authoritative Python Reference Implementation ([markqvist/Reticulum](https://github.com/markqvist/Reticulum)), who dedicated the Reticulum Protocol to the public domain in 2016.
- **Rust Underlying Crate:** Built as an application-layer tunnel on top of [`BeechatNetworkSystemsLtd/Reticulum-rs`](https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs) (MIT License), with formal Python `RNS` wire-interop verification and optional **Quad4 `Reticulum-Go`** transport support on the roadmap.

## License
Released under the [MIT License](LICENSE).
