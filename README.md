# `citadel-rns-rs` — Clean-Room MIT Rust Reticulum Transport Stack

[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE)
[![Live Architecture](https://img.shields.io/badge/Architecture-citadel.ironpass.tech-84cc16.svg)](https://citadel.ironpass.tech/)
[![Protocol](https://img.shields.io/badge/Wire%20Protocol-Reticulum%20(Public%20Domain)-38bdf8.svg)](https://reticulum.network/)

Clean-room, **MIT-licensed Rust** implementation of Citadel's zero-port Reticulum transport daemons built on the **100% Public Domain Reticulum Wire Protocol** via [`Reticulum-rs`](https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs).

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
  - **Streaming `CHT2` Chunked Wire Framing** (340-byte chunks fitting inside Reticulum's encrypted Link MTU, supporting full web applications, 3D GLB assets, and real-time Server-Sent Events / streaming LLM tokens)
- **True 0-Port Outbound Ghost Mode:** The protected Linux host opens zero inbound ports and dials outbound to the Airlock (`--rns-peer`), remaining invisible to LAN/WAN port scans.

## Binaries
| Binary | Role |
|---|---|
| `citadel-vault-daemon` | Runs on the 0-port Ghost Linux host, dialing outbound to the Airlock and forwarding authenticated Reticulum traffic strictly to a localhost loopback service (`127.0.0.1:<port>`). |
| `citadel-airlock-proxy` | Runs on an optional Airlock appliance or operator workstation, bridging standard HTTP/SSE browsers into 0-port Ghost servers over encrypted Reticulum. |

## Quick Start (Linux `aarch64` / `armv7l` / `x86_64` / macOS)
```bash
# 1. Build release binaries
cargo build --release

# 2. Start Airlock Proxy (listens for 0-port outbound Ghost nodes)
RUST_LOG=info ./target/release/citadel-airlock-proxy \
  --identity-name my-airlock \
  --rns-listen 0.0.0.0:14245 \
  --bind 127.0.0.1:7443

# 3. Start Vault Daemon on your 0-port Ghost Linux server (0 inbound ports required)
RUST_LOG=info ./target/release/citadel-vault-daemon \
  --identity-name my-ghost-vault \
  --upstream http://127.0.0.1:8080 \
  --rns-peer <AIRLOCK_HOST>:14245
```

## Part of Citadel // IronPass
`citadel-rns-rs` is the open-source MIT transport core powering **[Citadel // IronPass](https://citadel.ironpass.tech/)**:
- **Citadel** — Sovereign Zero-IP Linux compute & peer-to-peer Reticulum network fabric (scaling from compact micro-servers & Edge AI appliances to multi-GPU clusters).
- **IronPass** — Physical & cryptographic hardware identity layer (NXP NTAG 424 DNA NFC silicon, Ed25519 hardware root-of-trust, and physically air-gapped Offline Digital Product Passport vaults).

## Attribution & Credits
- **Reticulum Network Stack & Wire Protocol:** Full credit to Danish engineer and cryptographer **Mark Qvist**, inventor of [Reticulum](https://reticulum.network/), for pioneering non-IP cryptographic networking and releasing the Reticulum wire-protocol specification into the public domain.
- **Rust Wire Implementation:** Built on [`BeechatNetworkSystemsLtd/Reticulum-rs`](https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs) (MIT License).

## License
Released under the [MIT License](LICENSE).
