// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! On-wire frame codec (Master Guide, Appendix F).
//!
//! Four frame types (F.1/F.3/F.4/F.5), all Big-Endian, Length-Prefix mode, no magic
//! number, no frame-type field, no frame-level CRC:
//!
//! ```text
//! Phase one    [param_len(4)][param_json][identity_len(4)][identity][nonce_len(4)][nonce]
//! Phase two initiator [pub_len(4)][pk_A(32)][session_salt(32)]     (68B)
//! Phase two responder [pub_len(4)][pk_B(32)]                        (36B)
//! Phase three  [confirm_len(4)][tag(32)]                     (36B)
//! Phase four   [session_id(32)][seq(8)][ct_len(4)][ciphertext+tag]
//! ```
//!
//! **Limit checks must come before reading the corresponding payload** (Appendix F intro) — this is the
//! first gate against memory bombs; "allocating memory to the peer's declared length" is absolutely forbidden.
//!
//! Reading uses a **whole-frame shared deadline** (Appendix H.3 Slowloris protection): the entire read shares
//! one total budget, not a per-read timeout; budget exhausted after a partial read =
//! frame sync already broken, force-close the socket (half-packet timeout); not a single byte read (start timeout)
//! does not close, so the upper layer may retry safely.

use std::io::Read;
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use crate::crypto::{NEXT_SEED_LEN, SESSION_SALT_LEN, X25519_PUB_LEN};
use crate::errors::{Error, Result};
use crate::params::{MAX_CIPHERTEXT, MAX_IDENTITY, MAX_NONCE, MAX_PARAM_JSON};

pub const LEN_FIELD: usize = 4;
pub const CONFIRM_TAG_LEN: usize = 32;
pub const SEQ_LEN: usize = 8;
pub const TIMESTAMP_LEN: usize = 8;
pub const TOKEN_HASH_LEN: usize = 32;
pub const SESSION_ID_LEN: usize = 32;
pub const FMT_LEN: usize = 1;
pub const PAD_LEN_FIELD: usize = 2;
pub const FMT_NO_PADDING: u8 = 0x00;
pub const FMT_PADDING: u8 = 0x01;
pub const RECV_CHUNK: usize = 8192;

/// Minimum Phase-four payload = ts(8) + fmt(1) + dst(32) + src(32) + next_seed(32) (Heartbeat packet)
pub const MIN_PAYLOAD_LEN: usize = TIMESTAMP_LEN + FMT_LEN + TOKEN_HASH_LEN * 2 + NEXT_SEED_LEN; // 105

/// Force-close the socket, ignoring all errors (after a half-packet timeout frame sync is already broken — the only way out).
pub fn force_close_socket(sock: &TcpStream) {
    let _ = sock.shutdown(Shutdown::Both);
}

fn is_timeout_kind(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Read exactly `buf.len()` bytes from the socket deterministically (Appendix H.3 total-deadline semantics).
///
/// - `deadline` is a point on the monotonic clock; the whole read shares that budget, and before each read the
///   timeout is reset from the remaining time — an attacker cannot stall indefinitely with "1 byte every 14 seconds";
/// - when `deadline = None`, the socket's current read timeout serves as one shared budget;
/// - start timeout (no bytes read yet): returns [`Error::Timeout`], the socket is not closed;
/// - half-packet timeout (budget exhausted after a partial read): frame sync already broken, force-close the socket;
/// - peer close / connection error: returns [`Error::Io`] and force-closes the socket.
pub fn read_exact_deadline(
    sock: &mut TcpStream,
    buf: &mut [u8],
    field_name: &str,
    deadline: Option<Instant>,
) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let saved_timeout = sock.read_timeout().ok().flatten();
    let mut offset = 0usize;
    let result = (|| -> Result<()> {
        while offset < buf.len() {
            // Reset this read's timeout from the remaining budget
            let remaining: Option<Duration> = match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        if offset > 0 {
                            force_close_socket(sock);
                            return Err(Error::timeout(format!(
                                "reading {field_name} half-packet timeout (total deadline exhausted), frame sync broken, connection closed"
                            )));
                        }
                        return Err(Error::timeout(format!(
                            "reading {field_name} timed out (total deadline exhausted, Slowloris protection)"
                        )));
                    }
                    Some(d - now)
                }
                None => saved_timeout,
            };
            let _ = sock.set_read_timeout(remaining);
            match sock.read(&mut buf[offset..]) {
                Ok(0) => {
                    force_close_socket(sock);
                    return Err(Error::connection_closed(
                        "connection closed by peer before the read completed",
                    ));
                }
                Ok(n) => offset += n,
                Err(e) if is_timeout_kind(&e) => {
                    if offset > 0 {
                        force_close_socket(sock);
                        return Err(Error::timeout(format!(
                            "reading {field_name} half-packet timeout, frame sync broken, connection closed"
                        )));
                    }
                    return Err(Error::timeout(format!(
                        "reading {field_name} timed out (data-phase timeout or network latency)"
                    )));
                }
                Err(e) => {
                    force_close_socket(sock);
                    return Err(Error::Io(e));
                }
            }
        }
        Ok(())
    })();
    // Restore the original timeout (failure is ignored on an already force-closed socket)
    let _ = sock.set_read_timeout(saved_timeout);
    result
}

fn read_vec(
    sock: &mut TcpStream,
    n: usize,
    field_name: &str,
    deadline: Option<Instant>,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    read_exact_deadline(sock, &mut buf, field_name, deadline)?;
    Ok(buf)
}

fn read_u32(sock: &mut TcpStream, field: &str, deadline: Option<Instant>) -> Result<u32> {
    let mut b4 = [0u8; 4];
    read_exact_deadline(sock, &mut b4, field, deadline)?;
    Ok(u32::from_be_bytes(b4))
}

// =============================================================================
// Phase-one frame (Appendix F.1)
// =============================================================================

/// Encode a Phase-one frame. Limits also apply on the encoding side (local misconfiguration is surfaced early).
pub fn pack_phase_one(param_json: &[u8], identity: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if param_json.len() > MAX_PARAM_JSON {
        return Err(Error::protocol("param payload too large"));
    }
    if identity.len() > MAX_IDENTITY {
        return Err(Error::protocol("identity payload too large"));
    }
    if nonce.len() > MAX_NONCE {
        return Err(Error::protocol("nonce too long"));
    }
    let mut out = Vec::with_capacity(12 + param_json.len() + identity.len() + nonce.len());
    out.extend_from_slice(&(param_json.len() as u32).to_be_bytes());
    out.extend_from_slice(param_json);
    out.extend_from_slice(&(identity.len() as u32).to_be_bytes());
    out.extend_from_slice(identity);
    out.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
    out.extend_from_slice(nonce);
    Ok(out)
}

/// Parsed Phase-one frame. `raw` (including all length prefixes) must be kept verbatim — it feeds the
/// Phase-three transcript; any "normalized re-encoding" would cause a confirmation-tag mismatch (Appendix F.0 convention 6).
#[derive(Debug, Clone)]
pub struct PhaseOneFrame {
    pub raw: Vec<u8>,
    pub param_json: Vec<u8>,
    pub identity: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Read a Phase-one frame. All limit checks come before reading the corresponding payload; the same deadline spans
/// all fields (one total deadline shared by the whole frame).
pub fn read_phase_one(sock: &mut TcpStream, deadline: Option<Instant>) -> Result<PhaseOneFrame> {
    let plen = read_u32(sock, "param_len", deadline)? as usize;
    if plen > MAX_PARAM_JSON {
        return Err(Error::protocol("param payload too large"));
    }
    let param_raw = read_vec(sock, plen, "param_payload", deadline)?;

    let ilen = read_u32(sock, "identity_len", deadline)? as usize;
    if ilen > MAX_IDENTITY {
        return Err(Error::protocol("identity payload too large"));
    }
    let identity = read_vec(sock, ilen, "identity_blob", deadline)?;

    let nlen = read_u32(sock, "nonce_len", deadline)? as usize;
    if nlen > MAX_NONCE {
        return Err(Error::protocol("nonce too long"));
    }
    let nonce = read_vec(sock, nlen, "nonce", deadline)?;

    let mut raw = Vec::with_capacity(12 + param_raw.len() + identity.len() + nonce.len());
    raw.extend_from_slice(&(plen as u32).to_be_bytes());
    raw.extend_from_slice(&param_raw);
    raw.extend_from_slice(&(ilen as u32).to_be_bytes());
    raw.extend_from_slice(&identity);
    raw.extend_from_slice(&(nlen as u32).to_be_bytes());
    raw.extend_from_slice(&nonce);

    Ok(PhaseOneFrame {
        raw,
        param_json: param_raw,
        identity,
        nonce,
    })
}

// =============================================================================
// Phase-two frames (Appendix F.3)
// =============================================================================

/// Initiator frame: [pub_len(4)][pk_A(32)][session_salt(32)], 68B in total.
pub fn pack_initiator_key(pub_key: &[u8], session_salt: &[u8]) -> Result<Vec<u8>> {
    if pub_key.len() != X25519_PUB_LEN {
        return Err(Error::protocol("ephemeral public key length mismatch"));
    }
    if session_salt.len() != SESSION_SALT_LEN {
        return Err(Error::protocol("session salt length mismatch"));
    }
    let mut out = Vec::with_capacity(4 + X25519_PUB_LEN + SESSION_SALT_LEN);
    out.extend_from_slice(&(pub_key.len() as u32).to_be_bytes());
    out.extend_from_slice(pub_key);
    out.extend_from_slice(session_salt);
    Ok(out)
}

/// Responder frame: [pub_len(4)][pk_B(32)], 36B in total.
pub fn pack_responder_key(pub_key: &[u8]) -> Result<Vec<u8>> {
    if pub_key.len() != X25519_PUB_LEN {
        return Err(Error::protocol("ephemeral public key length mismatch"));
    }
    let mut out = Vec::with_capacity(4 + X25519_PUB_LEN);
    out.extend_from_slice(&(pub_key.len() as u32).to_be_bytes());
    out.extend_from_slice(pub_key);
    Ok(out)
}

/// Read [pub_len(4)][pk(32)]; pub_len ≠ 32 makes the frame invalid.
pub fn read_pub_key(sock: &mut TcpStream, deadline: Option<Instant>) -> Result<Vec<u8>> {
    let pub_len = read_u32(sock, "pub_len", deadline)? as usize;
    if pub_len != X25519_PUB_LEN {
        return Err(Error::protocol("peer public key length mismatch"));
    }
    read_vec(sock, pub_len, "peer_pub", deadline)
}

// =============================================================================
// Phase-three frame (Appendix F.4)
// =============================================================================

/// Confirmation frame: [confirm_len(4)][tag(32)], 36B in total.
pub fn pack_confirm(tag: &[u8]) -> Result<Vec<u8>> {
    if tag.len() != CONFIRM_TAG_LEN {
        return Err(Error::protocol("confirm tag length mismatch"));
    }
    let mut out = Vec::with_capacity(4 + CONFIRM_TAG_LEN);
    out.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    out.extend_from_slice(tag);
    Ok(out)
}

/// Read a confirmation frame. confirm_len ≠ 32 makes the frame invalid (frame-level error → silent drop by the responder).
pub fn read_confirm(sock: &mut TcpStream, deadline: Option<Instant>) -> Result<Vec<u8>> {
    let tlen = read_u32(sock, "confirm_len", deadline)? as usize;
    if tlen != CONFIRM_TAG_LEN {
        return Err(Error::protocol("confirm tag length mismatch"));
    }
    read_vec(sock, tlen, "confirm_tag", deadline)
}

// =============================================================================
// Phase-four data packet (Appendix F.5)
// =============================================================================

/// Data packet: [session_id(32)][seq(8)][ct_len(4)][ciphertext+tag].
pub fn pack_data_packet(session_id: &[u8], seq: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if session_id.len() != SESSION_ID_LEN {
        return Err(Error::protocol("session_id length mismatch"));
    }
    if ciphertext.len() > MAX_CIPHERTEXT {
        return Err(Error::protocol("ciphertext too large"));
    }
    let mut out = Vec::with_capacity(SESSION_ID_LEN + SEQ_LEN + LEN_FIELD + ciphertext.len());
    out.extend_from_slice(session_id);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// Data-packet plaintext header (44B fixed).
#[derive(Debug, Clone)]
pub struct DataHeader {
    pub session_id: [u8; SESSION_ID_LEN],
    pub seq: u64,
    pub ct_len: usize,
}

/// Read the 44-byte data-packet plaintext header. The ct_len limit check comes before reading the ciphertext (the first gate against memory bombs).
pub fn read_data_header(sock: &mut TcpStream, deadline: Option<Instant>) -> Result<DataHeader> {
    let sid_bytes = read_vec(sock, SESSION_ID_LEN, "session_id", deadline)?;
    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&sid_bytes);
    let seq_bytes = read_vec(sock, SEQ_LEN, "seq", deadline)?;
    let seq = u64::from_be_bytes(seq_bytes.try_into().unwrap());
    let ct_len = read_u32(sock, "ct_len", deadline)? as usize;
    if ct_len > MAX_CIPHERTEXT {
        return Err(Error::protocol("ciphertext length exceeds hard limit"));
    }
    Ok(DataHeader {
        session_id,
        seq,
        ct_len,
    })
}

/// 12B nonce = 0x00000000(4B) ‖ seq(8B uint64 BE) — the monotonically increasing
/// sequence number guarantees that the nonce under the same key is never reused (Appendix F.5).
pub fn gcm_nonce(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// AAD = session_id ‖ seq(8B BE) — routing fields are visible but tamper-proof (Appendix F.5).
/// No protocol identifier: the on-wire AAD carries no version string whatsoever.
pub fn build_aad(session_id: &[u8], seq: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(session_id.len() + 8);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Loopback TCP pair (equivalent of Python's socketpair; works on Windows).
    pub(crate) fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn phase_one_round_trip() {
        let (mut left, mut right) = pair();
        let frame = pack_phase_one(br#"{"a":1}"#, &[b'i'; 32], &[b'n'; 32]).unwrap();
        use std::io::Write;
        left.write_all(&frame).unwrap();
        let parsed = read_phase_one(&mut right, None).unwrap();
        assert_eq!(parsed.raw, frame);
        assert_eq!(parsed.param_json, br#"{"a":1}"#);
        assert_eq!(parsed.identity, &[b'i'; 32][..]);
        assert_eq!(parsed.identity.len(), 32);
        assert_eq!(parsed.nonce, vec![b'n'; 32]);
    }

    #[test]
    fn phase_one_rejects_oversize_before_read() {
        // A forged length header claims param_len > the limit: reject without reading any payload
        let (left, right) = pair();
        use std::io::Write;
        let mut left = left;
        left.write_all(&(MAX_PARAM_JSON as u32 + 1).to_be_bytes())
            .unwrap();
        let mut right = right;
        let err = read_phase_one(&mut right, None).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
        // The attacker sent only 4 bytes; the limit check takes effect before the payload read
    }

    #[test]
    fn key_frames_layout() {
        let pk = [1u8; 32];
        let salt = [2u8; 32];
        let init = pack_initiator_key(&pk, &salt).unwrap();
        assert_eq!(init.len(), 68);
        let mut expect = 32u32.to_be_bytes().to_vec();
        expect.extend_from_slice(&pk);
        expect.extend_from_slice(&salt);
        assert_eq!(init, expect);

        let resp = pack_responder_key(&pk).unwrap();
        assert_eq!(resp.len(), 36);
        assert_eq!(
            resp,
            32u32
                .to_be_bytes()
                .iter()
                .chain(pk.iter())
                .cloned()
                .collect::<Vec<u8>>()
        );
    }

    #[test]
    fn confirm_length_must_be_32() {
        assert!(pack_confirm(&[0u8; 31]).is_err());
        assert!(pack_confirm(&[0u8; 33]).is_err());
        let (left, right) = pair();
        use std::io::Write;
        let mut left = left;
        left.write_all(&31u32.to_be_bytes()).unwrap();
        let mut right = right;
        assert!(read_confirm(&mut right, None).is_err());
    }

    #[test]
    fn data_header_round_trip() {
        let (mut left, right) = pair();
        use std::io::Write;
        let sid = [b's'; 32];
        let ct = vec![7u8; 10];
        let packet = pack_data_packet(&sid, 7, &ct).unwrap();
        assert_eq!(packet.len(), 32 + 8 + 4 + 10);
        assert_eq!(&packet[..32], &sid);
        assert_eq!(&packet[32..40], &7u64.to_be_bytes());
        left.write_all(&packet).unwrap();
        let mut right = right;
        let h = read_data_header(&mut right, None).unwrap();
        assert_eq!(h.session_id, sid);
        assert_eq!(h.seq, 7);
        assert_eq!(h.ct_len, 10);
    }

    #[test]
    fn data_header_rejects_oversize_ciphertext() {
        let (mut left, right) = pair();
        use std::io::Write;
        left.write_all(&[b's'; 32]).unwrap();
        left.write_all(&0u64.to_be_bytes()).unwrap();
        left.write_all(&(MAX_CIPHERTEXT as u32 + 1).to_be_bytes())
            .unwrap();
        let mut right = right;
        assert!(read_data_header(&mut right, None).is_err());
    }

    #[test]
    fn min_payload_len_is_105() {
        assert_eq!(MIN_PAYLOAD_LEN, 105);
    }

    #[test]
    fn gcm_nonce_and_aad() {
        assert_eq!(gcm_nonce(0), [0u8; 12]);
        let n7 = gcm_nonce(7);
        assert_eq!(&n7[..11], &[0u8; 11]);
        assert_eq!(n7[11], 7);
        let sid = [b's'; 32];
        let aad = build_aad(&sid, 7);
        let mut expect = sid.to_vec();
        expect.extend_from_slice(&7u64.to_be_bytes());
        assert_eq!(aad, expect);
    }

    #[test]
    fn read_exact_total_deadline_not_per_recv() {
        // Attacker sends 1 byte every <timeout: the whole frame shares one deadline; failure when the budget is exhausted
        let (left, right) = pair();
        use std::io::Write;
        let mut left = left;
        let mut right = right;
        let _ = left.set_write_timeout(Some(std::time::Duration::from_secs(2)));
        let _ = right.set_read_timeout(Some(std::time::Duration::from_secs(2)));
        left.write_all(b"a").unwrap(); // send only 1 byte; 2 bytes need to be read
        let started = Instant::now();
        let mut buf = [0u8; 2];
        let err = read_exact_deadline(
            &mut right,
            &mut buf,
            "test",
            Some(started + Duration::from_millis(200)),
        )
        .unwrap_err();
        let elapsed = started.elapsed();
        assert!(matches!(err, Error::Timeout(_)));
        assert!(
            elapsed < Duration::from_secs(1),
            "well below the 2s+2s of per-byte re-timing; actual {elapsed:?}"
        );
    }

    #[test]
    fn read_exact_partial_then_eof_closes() {
        // Half-packet EOF: frame sync already broken → connection error
        let (left, right) = pair();
        use std::io::Write;
        let mut left = left;
        left.write_all(b"ab").unwrap();
        drop(left);
        let mut buf = [0u8; 4];
        let mut right = right;
        let err = read_exact_deadline(&mut right, &mut buf, "test", None).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }
}
