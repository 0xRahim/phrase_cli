//! Internal helpers shared across `crypt` submodules.
//!
//! Nothing in this file is part of the public API.

/// Hand-crafts a minimal PGP Literal Data Packet (RFC 4880 §5.9, new-format tag 11).
///
/// This is necessary because the `pgp` crate's `Message` enum has no stable
/// public constructor — its internal `LiteralDataReader` type is not publicly
/// constructable in any 0.x release. We therefore build the raw bytes ourselves
/// and deserialise them via the always-available `Message::from_bytes` parser.
///
/// # Packet layout (new-format, one-octet body length)
/// ```text
/// 0xCB          — tag byte: 0xC0 | tag-11 (Literal Data)
/// <body_len>    — one-octet length; works for payloads < 192 bytes
/// 0x62  ('b')   — data format: binary
/// <fname_len>   — 1 byte filename length
/// <fname>       — filename bytes (always b"key" here)
/// 0x00000000    — 4-byte modification date (zeroed)
/// <payload>     — the actual data bytes
/// ```
///
/// # Panics
/// Panics if `payload.len()` would push the body past 191 bytes (the one-octet
/// length limit). The caller hex-encodes 32 bytes → 64 bytes, so the body is
/// always 73 bytes and this can never trigger.
pub fn build_literal_packet(payload: &[u8]) -> Vec<u8> {
    let fname = b"key";
    // body = format(1) + fname_len(1) + fname(3) + date(4) + payload
    let body_len = 1 + 1 + fname.len() + 4 + payload.len();
    assert!(
        body_len < 192,
        "payload too large for one-octet length encoding ({body_len} bytes)"
    );

    let mut pkt = Vec::with_capacity(2 + body_len);
    pkt.push(0xCB);              // new-format Literal Data tag
    pkt.push(body_len as u8);    // one-octet body length
    pkt.push(b'b');              // binary data format
    pkt.push(fname.len() as u8); // filename length
    pkt.extend_from_slice(fname);
    pkt.extend_from_slice(&[0u8; 4]); // modification date = zero
    pkt.extend_from_slice(payload);
    pkt
}