//! Citadel Zero-Trust Cryptographic Locks (`security.rs`) — Clean-Room MIT Rust
//!
//! Implements two defense-in-depth cryptographic layers:
//! 1. **Lock 1 — IFAC (Interface Access Code) Dark-Network Masking:**
//!    Authenticates and XOR-masks every HDLC-over-TCP frame with a pre-shared network key
//!    (`HMAC-SHA256` 8-byte tag + per-packet SHA-256 keystream mask). Unauthorized scanners
//!    and unkeyed Reticulum peers are silently dropped before reaching `Packet::deserialize`.
//! 2. **Lock 2 — Mutual Ed25519 Client Identity Authentication:**
//!    Every operator browser/client holds a persistent Ed25519 keypair (`chmod 600`) and signs
//!    every `CHT2` request (`dest_hash`, `method`, `path`, `timestamp`, `sha256(body)`).
//!    Private `citadel-vault-daemon` instances verify the signature against an allowlist of
//!    authorized 32-hex Client IDs (or 64-hex public keys), rejecting unknown peers with `403`.

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub const IFAC_TAG_LEN: usize = 8;
pub const AUTH_MAX_SKEW_SECS: i64 = 180;

pub const HDR_CLIENT_PUB: &str = "x-citadel-client-pub";
pub const HDR_CLIENT_TS: &str = "x-citadel-client-ts";
pub const HDR_CLIENT_SIG: &str = "x-citadel-client-sig";
pub const HDR_VERIFIED_CLIENT: &str = "x-citadel-verified-client";

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

pub fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let clean = hex.trim();
    if clean.len() % 2 != 0 {
        bail!("Invalid hex length");
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    let bytes = clean.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let pair = std::str::from_utf8(&bytes[i..i + 2])?;
        out.push(u8::from_str_radix(pair, 16)?);
    }
    Ok(out)
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// LOCK 1: IFAC (Interface Access Code) Dark-Network Frame Masking
// ============================================================================

#[derive(Clone)]
pub struct IfacKey {
    key: [u8; 32],
    fingerprint: String,
}

impl std::fmt::Debug for IfacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IfacKey")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl IfacKey {
    /// Derives a 256-bit IFAC key from an arbitrary passphrase or secret bytes.
    pub fn from_passphrase(secret: &str) -> Self {
        let trimmed = secret.trim();
        let mut h = Sha256::new();
        h.update(b"CITADEL-IFAC-V1:");
        h.update(trimmed.as_bytes());
        let key: [u8; 32] = h.finalize().into();

        let mut fp = Sha256::new();
        fp.update(b"CITADEL-IFAC-FP:");
        fp.update(key);
        let fp_bytes = fp.finalize();
        let fingerprint = hex_encode(&fp_bytes[..4]);

        Self { key, fingerprint }
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Loads an IFAC key from an explicit passphrase or key file path (trimming whitespace).
    pub fn resolve(inline_key: Option<&str>, key_file: Option<&Path>) -> Result<Option<Self>> {
        if let Some(k) = inline_key {
            let t = k.trim();
            if !t.is_empty() {
                return Ok(Some(Self::from_passphrase(t)));
            }
        }
        if let Some(path) = key_file {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| anyhow!("Failed to read IFAC key file '{}': {e}", path.display()))?;
            let t = raw.trim();
            if t.is_empty() {
                bail!("IFAC key file '{}' is empty", path.display());
            }
            return Ok(Some(Self::from_passphrase(t)));
        }
        Ok(None)
    }

    fn xor_mask(&self, tag: &[u8; IFAC_TAG_LEN], data: &mut [u8]) {
        let mut counter: u32 = 0;
        let mut offset = 0;
        while offset < data.len() {
            let mut h = Sha256::new();
            h.update(self.key);
            h.update(tag);
            h.update(counter.to_be_bytes());
            let block = h.finalize();
            let take = (data.len() - offset).min(32);
            for i in 0..take {
                data[offset + i] ^= block[i];
            }
            offset += take;
            counter = counter.wrapping_add(1);
        }
    }

    /// Protects an outbound Reticulum packet: returns `tag(8B) || masked_packet`.
    pub fn seal_frame(&self, raw_packet: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts 32-byte key");
        mac.update(raw_packet);
        let full_tag = mac.finalize().into_bytes();
        let mut tag = [0u8; IFAC_TAG_LEN];
        tag.copy_from_slice(&full_tag[..IFAC_TAG_LEN]);

        let mut out = Vec::with_capacity(IFAC_TAG_LEN + raw_packet.len());
        out.extend_from_slice(&tag);
        out.extend_from_slice(raw_packet);
        self.xor_mask(&tag, &mut out[IFAC_TAG_LEN..]);
        out
    }

    /// Unmasks and authenticates an inbound frame in constant time.
    /// Returns `None` if tampered, truncated, or unauthenticated (caller silently drops).
    pub fn open_frame(&self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() <= IFAC_TAG_LEN + 2 {
            return None;
        }
        let mut tag = [0u8; IFAC_TAG_LEN];
        tag.copy_from_slice(&frame[..IFAC_TAG_LEN]);

        let mut plain = frame[IFAC_TAG_LEN..].to_vec();
        self.xor_mask(&tag, &mut plain);

        let mut mac = HmacSha256::new_from_slice(&self.key).ok()?;
        mac.update(&plain);
        mac.verify_truncated_left(&tag).ok()?;
        Some(plain)
    }
}

// ============================================================================
// LOCK 2: Mutual Ed25519 Client Identity & Per-Request Signing / Verification
// ============================================================================

#[derive(Clone)]
pub struct ClientIdentity {
    signing_key: SigningKey,
    pubkey_hex: String,
    client_id: String,
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("client_id", &self.client_id)
            .field("pubkey_hex", &self.pubkey_hex)
            .finish()
    }
}

pub fn default_client_key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".config")
        .join("bifrost")
        .join("client_ed25519.key")
}

pub fn derive_client_id(pubkey_bytes: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(pubkey_bytes);
    let digest = h.finalize();
    hex_encode(&digest[..16])
}

fn canonical_auth_payload(
    dest_hash: &str,
    method: &str,
    path: &str,
    ts: u64,
    body: &[u8],
) -> Vec<u8> {
    let body_hash = hex_encode(&Sha256::digest(body));
    format!(
        "CITADEL-AUTH-V1\n{}\n{}\n{}\n{}\n{}",
        dest_hash.trim().trim_matches('/').to_ascii_lowercase(),
        method.to_ascii_uppercase(),
        path,
        ts,
        body_hash
    )
    .into_bytes()
}

impl ClientIdentity {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let pubkey_hex = hex_encode(&pub_bytes);
        let client_id = derive_client_id(&pub_bytes);
        Self {
            signing_key,
            pubkey_hex,
            client_id,
        }
    }

    /// Loads or generates a persistent Ed25519 client identity keypair (`chmod 600`).
    pub fn load_or_create(path_opt: Option<&Path>) -> Result<Self> {
        let path = path_opt
            .map(PathBuf::from)
            .unwrap_or_else(default_client_key_path);

        if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            let bytes = hex_decode(raw.trim())?;
            if bytes.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                return Ok(Self::from_seed(seed));
            }
        }

        let signing_key = SigningKey::generate(&mut OsRng);
        let seed = signing_key.to_bytes();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&path, format!("{}\n", hex_encode(&seed)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self::from_seed(seed))
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    /// Attaches signed Ed25519 authentication headers into an outbound CHT2 request.
    pub fn sign_request_headers(
        &self,
        dest_hash: &str,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &mut HashMap<String, String>,
    ) {
        let ts = now_unix_secs();
        let msg = canonical_auth_payload(dest_hash, method, path, ts, body);
        let sig = self.signing_key.sign(&msg);
        headers.insert(HDR_CLIENT_PUB.into(), self.pubkey_hex.clone());
        headers.insert(HDR_CLIENT_TS.into(), ts.to_string());
        headers.insert(HDR_CLIENT_SIG.into(), hex_encode(&sig.to_bytes()));
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedClient {
    pub client_id: String,
    pub pubkey_hex: String,
}

/// Verifies the Ed25519 client signature on an inbound CHT2 request.
pub fn verify_request_signature(
    dest_hash: &str,
    method: &str,
    path: &str,
    body: &[u8],
    headers: &HashMap<String, String>,
) -> Result<VerifiedClient> {
    let find_hdr = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
    };

    let pub_hex = find_hdr(HDR_CLIENT_PUB)
        .ok_or_else(|| anyhow!("Missing Ed25519 client public key ({HDR_CLIENT_PUB})"))?;
    let ts_str = find_hdr(HDR_CLIENT_TS)
        .ok_or_else(|| anyhow!("Missing client auth timestamp ({HDR_CLIENT_TS})"))?;
    let sig_hex = find_hdr(HDR_CLIENT_SIG)
        .ok_or_else(|| anyhow!("Missing Ed25519 client signature ({HDR_CLIENT_SIG})"))?;

    let ts: u64 = ts_str.parse().map_err(|_| anyhow!("Invalid client auth timestamp"))?;
    let now = now_unix_secs();
    let skew = (now as i64) - (ts as i64);
    if skew.abs() > AUTH_MAX_SKEW_SECS {
        bail!("Client auth timestamp expired (skew={}s)", skew);
    }

    let pub_bytes = hex_decode(pub_hex)?;
    if pub_bytes.len() != 32 {
        bail!("Invalid Ed25519 public key length");
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_bytes);
    let vk = VerifyingKey::from_bytes(&pub_arr).map_err(|_| anyhow!("Invalid Ed25519 public key"))?;

    let sig_bytes = hex_decode(sig_hex)?;
    if sig_bytes.len() != 64 {
        bail!("Invalid Ed25519 signature length");
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    let msg = canonical_auth_payload(dest_hash, method, path, ts, body);
    vk.verify(&msg, &sig)
        .map_err(|_| anyhow!("Ed25519 client signature verification FAILED"))?;

    Ok(VerifiedClient {
        client_id: derive_client_id(&pub_arr),
        pubkey_hex: pub_hex.to_ascii_lowercase(),
    })
}

/// Evaluates whether a verified client is allowed by static CLI flags and/or a hot-reloaded file.
/// File format: one 32-hex Client ID (or 64-hex Ed25519 pubkey) per line; `#` comments ignored.
pub fn load_effective_allowlist(
    static_entries: &[String],
    file_path: Option<&Path>,
) -> HashSet<String> {
    let mut set = HashSet::new();
    for entry in static_entries {
        let clean = entry.trim().to_ascii_lowercase();
        if !clean.is_empty() {
            set.insert(clean);
        }
    }
    if let Some(p) = file_path {
        if let Ok(raw) = std::fs::read_to_string(p) {
            for line in raw.lines() {
                let without_comment = line.split('#').next().unwrap_or("").trim();
                let token = without_comment
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !token.is_empty() {
                    set.insert(token);
                }
            }
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifac_seal_open_and_reject_tamper() {
        let key_a = IfacKey::from_passphrase("dubai-bjarred-secret-mesh-2026");
        let key_b = IfacKey::from_passphrase("wrong-attacker-key");
        let msg = b"\x08\x00reticulum-encrypted-packet-payload-0123456789";

        let sealed = key_a.seal_frame(msg);
        // Must mask header/payload so plaintext does not appear on the wire
        assert_ne!(&sealed[IFAC_TAG_LEN..], msg);
        // Valid key opens cleanly
        assert_eq!(key_a.open_frame(&sealed).as_deref(), Some(&msg[..]));
        // Wrong key silently rejects
        assert!(key_b.open_frame(&sealed).is_none());
        // Single flipped bit silently rejects
        let mut tampered = sealed.clone();
        tampered[IFAC_TAG_LEN + 3] ^= 0x01;
        assert!(key_a.open_frame(&tampered).is_none());
        // Unmasked raw packet silently rejects
        assert!(key_a.open_frame(msg).is_none());
    }

    #[test]
    fn ed25519_client_auth_sign_verify_and_reject_tamper() {
        let id = ClientIdentity::from_seed([0x11u8; 32]);
        let dest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let body = b"{\"text\":\"hello over bjarred\"}";
        let mut hdrs = HashMap::new();
        id.sign_request_headers(dest, "POST", "/api/v1/huginn/messages", body, &mut hdrs);

        let verified = verify_request_signature(dest, "POST", "/api/v1/huginn/messages", body, &hdrs)
            .expect("valid Ed25519 signature must pass");
        assert_eq!(verified.client_id, id.client_id());
        assert_eq!(verified.pubkey_hex, id.pubkey_hex());

        // Tampered body must fail
        assert!(verify_request_signature(dest, "POST", "/api/v1/huginn/messages", b"tampered", &hdrs).is_err());
        // Replayed to different vault hash must fail
        assert!(verify_request_signature("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "POST", "/api/v1/huginn/messages", body, &hdrs).is_err());
        // Mutated HTTP path must fail
        assert!(verify_request_signature(dest, "POST", "/api/v1/huginn/admin", body, &hdrs).is_err());
        // Missing headers must fail
        assert!(verify_request_signature(dest, "POST", "/api/v1/huginn/messages", body, &HashMap::new()).is_err());
    }
}
