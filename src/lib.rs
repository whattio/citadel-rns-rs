//! CHT2 — Citadel HTTP-over-Reticulum Streaming Chunk Protocol (MIT Rust)
//!
//! Designed specifically for Reticulum's encrypted Link MTU (~431 bytes):
//!   Bytes  0..4  : Magic "CHT2"
//!   Byte   4     : PacketKind (1=ReqHead, 2=ReqChunk, 3=ReqEnd, 4=RespHead, 5=RespChunk, 6=RespEnd)
//!   Bytes  5..17 : 12-byte ASCII request ID
//!   Bytes 17..21 : u32 big-endian sequence number
//!   Bytes 21..   : payload slice (<= MAX_CHUNK = 400 bytes -> max 421 bytes/packet <= 431B MDU)
//!
//! Supports unlimited payload sizes (HTML, JS bundles, 3D GLB models) AND zero-buffer
//! Server-Sent Events (SSE) / streaming LLM tokens.

pub mod client;
pub mod fast_tcp;

pub mod chtp {
    use anyhow::{bail, Context, Result};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    pub const MAGIC: &[u8; 4] = b"CHT2";
    pub const HEADER_LEN: usize = 21;
    pub const MAX_CHUNK: usize = 400;
    pub const WINDOW_SIZE: u32 = 10;

    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PacketKind {
        ReqHead = 1,
        ReqChunk = 2,
        ReqEnd = 3,
        RespHead = 4,
        RespChunk = 5,
        RespEnd = 6,
        WindowAck = 7,
    }

    impl PacketKind {
        pub fn from_u8(v: u8) -> Result<Self> {
            match v {
                1 => Ok(Self::ReqHead),
                2 => Ok(Self::ReqChunk),
                3 => Ok(Self::ReqEnd),
                4 => Ok(Self::RespHead),
                5 => Ok(Self::RespChunk),
                6 => Ok(Self::RespEnd),
                7 => Ok(Self::WindowAck),
                _ => bail!("Unknown CHT2 packet kind: {v}"),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RequestMeta {
        pub method: String,
        pub path: String,
        #[serde(default)]
        pub headers: HashMap<String, String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ResponseMeta {
        pub status: u16,
        #[serde(default)]
        pub headers: Vec<(String, String)>,
    }

    #[derive(Debug, Clone)]
    pub struct ChtPacket {
        pub kind: PacketKind,
        pub req_id: [u8; 12],
        pub seq: u32,
        pub payload: Vec<u8>,
    }

    pub fn req_id_from_str(s: &str) -> [u8; 12] {
        let mut id = [b'0'; 12];
        let b = s.as_bytes();
        let n = b.len().min(12);
        id[..n].copy_from_slice(&b[..n]);
        id
    }

    pub fn req_id_to_string(id: &[u8; 12]) -> String {
        String::from_utf8_lossy(id).to_string()
    }

    pub fn encode_packet(kind: PacketKind, req_id: [u8; 12], seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(MAGIC);
        out.push(kind as u8);
        out.extend_from_slice(&req_id);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    pub fn decode_packet(raw: &[u8]) -> Result<ChtPacket> {
        if raw.len() < HEADER_LEN || &raw[0..4] != MAGIC {
            bail!("Invalid CHT2 packet header (len={})", raw.len());
        }
        let kind = PacketKind::from_u8(raw[4])?;
        let mut req_id = [0u8; 12];
        req_id.copy_from_slice(&raw[5..17]);
        let seq = u32::from_be_bytes([raw[17], raw[18], raw[19], raw[20]]);
        let payload = raw[HEADER_LEN..].to_vec();
        Ok(ChtPacket {
            kind,
            req_id,
            seq,
            payload,
        })
    }

    /// Split a JSON metadata blob into <= MAX_CHUNK packets of `kind`.
    pub fn encode_json_chunks<T: Serialize>(
        kind: PacketKind,
        req_id: [u8; 12],
        meta: &T,
    ) -> Result<Vec<Vec<u8>>> {
        let bytes = serde_json::to_vec(meta).context("serialize CHT2 JSON")?;
        if bytes.is_empty() {
            return Ok(vec![encode_packet(kind, req_id, 0, &[])]);
        }
        Ok(bytes
            .chunks(MAX_CHUNK)
            .enumerate()
            .map(|(i, c)| encode_packet(kind, req_id, i as u32, c))
            .collect())
    }
}
