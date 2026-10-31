// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! Encrypted data session (Master Guide §4.2.4/4.2.5 / Appendix F.5 / Appendix G).
//!
//! Core invariants:
//! - **Consume state before attempting to send** (F.5): before the encrypted send, complete in order — generate next_seed
//!   → derive new_EK → wipe old EK and install new_EK → seq += 1. Even if the send fails, the key has already
//!   advanced and the session is unrecoverable (reconnect only), but the attacker can never exploit the fact that "send
//!   failure leaves state un-advanced" to replay;
//! - The order of the receive-verification pipeline is **fixed** (F.5's 8 steps): seq → session_id → GCM → length
//!   → fmt → structural self-consistency → bidirectional token hash → timestamp window;
//! - **Out-of-window packets are handled specially** (step 8): a packet that passed GCM authentication but is out of
//!   the timestamp window still rotates EK and advances seq_recv, discarding only the plaintext — to prevent the
//!   permanent desync of "sender rotated, receiver did not"; implementers must not omit this;
//! - On security/protocol verification failure: terminate the session + full wipe (Appendix H.4/H.6).

use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroize;

use crate::crypto::{aead_decrypt, aead_encrypt, secure_random, CryptoSuite, NEXT_SEED_LEN};
use crate::errors::{Error, Result};
use crate::frames::{
    build_aad, gcm_nonce, pack_data_packet, read_data_header, read_exact_deadline, DataHeader,
    FMT_LEN, FMT_NO_PADDING, FMT_PADDING, MIN_PAYLOAD_LEN, PAD_LEN_FIELD, SESSION_ID_LEN,
    TIMESTAMP_LEN, TOKEN_HASH_LEN,
};
use crate::handshake::{SessionMaterial, INFO_EK_ROTATE};
use crate::params::{MAX_PAD, MAX_PLAINTEXT};

// No Debug on this state: it holds both direction keys, and a future
// `{:?}` on it would print them. Redact by hand if formatting is needed.
struct SessionState {
    session_id: Option<[u8; SESSION_ID_LEN]>,
    send_ek: Option<Vec<u8>>,
    recv_ek: Option<Vec<u8>>,
    seq_send: u64,
    /// `None` = no packet has been received yet (Python-side initial value of seq_recv is -1)
    seq_recv: Option<u64>,
    closed: bool,
    last_recv_drop: Option<String>,
}

/// Full-duplex encrypted session built on the handshake artifacts (send/receive and ratchet state).
///
/// The three locks mirror the Python reference implementation's three-lock structure: `send_lock`/`recv_lock`
/// serialize the send/receive paths; `state` protects key material and sequence-number state. All cleanup paths are idempotent (H.6).
pub struct SecureSession {
    state: Mutex<SessionState>,
    send_lock: Mutex<()>,
    recv_lock: Mutex<()>,
    suite: CryptoSuite,
    pub params: crate::params::Params,
    pub local_hash: [u8; 32],
    pub peer_hash: [u8; 32],
    pub time_window: u64,
    pub padding: Option<(usize, usize)>,
    pub jitter: f64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl SecureSession {
    pub fn new(material: SessionMaterial) -> Self {
        let suite = CryptoSuite::new(
            material.params.hash_name.clone(),
            material.params.aead_name.clone(),
        )
        .expect("handshake verified the algorithm name");
        SecureSession {
            state: Mutex::new(SessionState {
                session_id: Some(material.session_id),
                send_ek: Some(material.send_ek),
                recv_ek: Some(material.recv_ek),
                seq_send: 0,
                seq_recv: None,
                closed: false,
                last_recv_drop: None,
            }),
            send_lock: Mutex::new(()),
            recv_lock: Mutex::new(()),
            suite,
            params: material.params,
            local_hash: material.local_hash,
            peer_hash: material.peer_hash,
            time_window: material.time_window,
            padding: material.padding,
            jitter: material.jitter,
        }
    }

    /// Record of the last out-of-window drop (for diagnostics / testing).
    pub fn last_recv_drop(&self) -> Option<String> {
        self.state.lock().unwrap().last_recv_drop.clone()
    }

    pub fn is_active(&self) -> bool {
        let st = self.state.lock().unwrap();
        !st.closed && st.send_ek.is_some()
    }

    // ------------------------------------------------------------------
    // Send (Appendix F.5 sender-side state advancement)
    // ------------------------------------------------------------------

    /// Encrypt and send one data packet. Empty plaintext = heartbeat packet. A send failure means the session is
    /// irreversibly out of sync (the key has advanced); reconnect only (Appendix H.4).
    pub fn send_packet(&self, sock: &mut TcpStream, plaintext: &[u8]) -> Result<()> {
        let _guard = self.send_lock.lock().unwrap();
        //  -  State advance (completed before encryption)  -
        // next_seed is generated only once: it drives the local ratchet advance and is also carried in the packet to the peer
        let (mut ek_snapshot, seq, sid_snapshot, mut next_seed) = {
            let mut st = self.state.lock().unwrap();
            if st.closed || st.send_ek.is_none() || st.session_id.is_none() {
                return Err(Error::session(
                    "session is irreversibly desynchronized or not established; reconnect required",
                ));
            }
            if plaintext.len() > MAX_PLAINTEXT {
                return Err(Error::protocol(format!(
                    "plaintext payload too large ({} > {MAX_PLAINTEXT})",
                    plaintext.len()
                )));
            }
            let ek_snapshot = st.send_ek.clone().expect("checked above");
            let seq = st.seq_send;
            let sid = st.session_id.expect("checked above");
            let next_seed = secure_random(NEXT_SEED_LEN)?;
            let mut ikm = ek_snapshot.clone();
            ikm.extend_from_slice(&next_seed);
            let new_ek =
                self.suite
                    .hkdf(&ikm, None, INFO_EK_ROTATE, self.params.key_len as usize)?;
            ikm.zeroize();
            if let Some(mut old) = st.send_ek.take() {
                old.zeroize();
            }
            st.send_ek = Some(new_ek);
            st.seq_send = seq + 1;
            (ek_snapshot, seq, sid, next_seed)
        };

        //  -  Build internal payload (pre-encryption): ts(8) ‖ fmt(1) ‖ dst(32) ‖ src(32)
        //    ‖ user plaintext ‖ [random padding ‖ pad_len(2)] ‖ next_seed(32)  -
        let mut payload = Vec::with_capacity(MIN_PAYLOAD_LEN + plaintext.len());
        payload.extend_from_slice(&now_ms().to_be_bytes());
        let fmt = if self.padding.is_some() {
            FMT_PADDING
        } else {
            FMT_NO_PADDING
        };
        payload.push(fmt);
        payload.extend_from_slice(&self.peer_hash);
        payload.extend_from_slice(&self.local_hash);
        payload.extend_from_slice(plaintext);
        let mut padding_part = match self.padding {
            // Random padding erases the length fingerprint; decided independently per packet, can be enabled on one side only (Appendix G.2)
            Some((pmin, pmax)) => self.build_padding(pmin, pmax)?,
            None => Vec::new(),
        };
        payload.extend_from_slice(&padding_part);
        padding_part.zeroize();
        payload.extend_from_slice(&next_seed);

        let nonce = gcm_nonce(seq);
        let aad = build_aad(&sid_snapshot, seq);
        let mut ciphertext = match aead_encrypt(&ek_snapshot, &nonce, &payload, &aad) {
            Ok(ct) => ct,
            Err(e) => {
                payload.zeroize();
                ek_snapshot.zeroize();
                next_seed.zeroize();
                return Err(e);
            }
        };
        payload.zeroize();
        let packet = match pack_data_packet(&sid_snapshot, seq, &ciphertext) {
            Ok(p) => p,
            Err(e) => {
                ciphertext.zeroize();
                ek_snapshot.zeroize();
                next_seed.zeroize();
                return Err(e);
            }
        };
        ciphertext.zeroize();
        // Wipe the key snapshot immediately after use (Appendix H.6: do not leave non-wipeable on-heap key copies)
        ek_snapshot.zeroize();

        //  -  Timing jitter: pure local send behavior, does not change the wire bytes (Appendix G.3)  -
        if self.jitter > 0.0 {
            let d: f64 = rand::random_range(0.0..self.jitter);
            std::thread::sleep(Duration::from_secs_f64(d));
        }
        // Send failure = session irreversibly out of sync (key has advanced, reconnect only)
        if let Err(e) = sock.write_all(&packet) {
            self.wipe();
            return Err(Error::session(format!(
                "send failed; session irreversibly desynchronized: {e}"
            )));
        }
        let _ = sock.flush();
        Ok(())
    }

    fn build_padding(&self, pmin: usize, pmax: usize) -> Result<Vec<u8>> {
        // Uniformly distributed within the interval; content is truly random bytes (all-zero strings are a low-entropy fingerprint, forbidden)
        let pad_len: usize = if pmax > pmin {
            rand::random_range(pmin..=pmax)
        } else {
            pmin
        };
        let mut pad = secure_random(pad_len)?;
        // The pad_len field sits immediately before next_seed: the receiver locates it at a fixed position from the tail
        pad.extend_from_slice(&(pad_len as u16).to_be_bytes());
        Ok(pad)
    }

    // ------------------------------------------------------------------
    // Receive (Appendix F.5 receive-verification pipeline, order fixed)
    // ------------------------------------------------------------------

    /// Receive and decrypt one data packet.
    ///
    /// Returns: plaintext bytes; empty Vec = heartbeat or out-of-window packet (state has advanced). On security/protocol
    /// verification failure: wipes the session and then throws [`Error::Security`] / [`Error::Protocol`]
    /// (Appendix H.4: session termination).
    pub fn recv_packet(&self, sock: &mut TcpStream) -> Result<Vec<u8>> {
        let _guard = self.recv_lock.lock().unwrap();
        let budget = sock.read_timeout().ok().flatten();
        let deadline = budget.map(|b| std::time::Instant::now() + b);
        let DataHeader {
            session_id,
            seq,
            ct_len,
        } = read_data_header(sock, deadline)?;
        let mut ct_buf = vec![0u8; ct_len];
        read_exact_deadline(sock, &mut ct_buf, "ciphertext", deadline)?;

        // Steps 1/2 + key snapshot (verification failure → session termination + full wipe, Appendix H.4)
        let (ek_snapshot, sid_local) = {
            let st = self.state.lock().unwrap();
            if st.closed || st.recv_ek.is_none() || st.session_id.is_none() {
                return Err(Error::session(
                    "session is irreversibly desynchronized or not established; reconnect required",
                ));
            }
            // Step 1: strictly increasing seq (initial seq_recv of None = Python's -1)
            if let Some(last) = st.seq_recv {
                if seq <= last {
                    drop(st);
                    self.wipe();
                    return Err(Error::security(format!(
                        "replay or out-of-order packet detected: seq={seq} <= last={last}"
                    )));
                }
            }
            // Step 2: session ID match (frequency crosstalk / stale-session residue)
            if st.session_id != Some(session_id) {
                drop(st);
                self.wipe();
                return Err(Error::security(
                    "session ID mismatch; packet dropped (cross-talk or stale session)",
                ));
            }
            (
                st.recv_ek.clone().expect("checked above"),
                st.session_id.expect("checked above"),
            )
        };

        // Step 3: GCM decryption and authentication (AAD participates in authentication)
        let nonce = gcm_nonce(seq);
        let aad = build_aad(&sid_local, seq);
        let payload = match aead_decrypt(&ek_snapshot, &nonce, &ct_buf, &aad) {
            Ok(p) => p,
            Err(e) => {
                ct_buf.zeroize();
                self.wipe();
                return Err(e);
            }
        };
        ct_buf.zeroize();

        // Steps 4–8; verification failure → session termination (Appendix H.4)
        match self.validate_payload(payload, seq) {
            Ok(pt) => Ok(pt),
            Err(e) => {
                self.wipe();
                Err(e)
            }
        }
    }

    /// Pipeline steps 4–8. Returns plaintext; heartbeat / out-of-window returns empty Vec (state has advanced).
    fn validate_payload(&self, mut payload: Vec<u8>, seq: u64) -> Result<Vec<u8>> {
        // Step 4: minimum payload length (105B, heartbeat-packet size)
        if payload.len() < MIN_PAYLOAD_LEN {
            return Err(Error::protocol(
                "payload too short to extract the inner structure",
            ));
        }
        // Step 5: payload format marker
        let fmt = payload[TIMESTAMP_LEN];
        if fmt != FMT_NO_PADDING && fmt != FMT_PADDING {
            return Err(Error::security(format!(
                "unknown payload format marker: {fmt:#04x}"
            )));
        }
        // Step 6: structural length self-consistency (prevents out-of-bounds / negative slicing; pad_len is stored
        // in the last 34-33 bytes of the payload, just before the trailing next_seed)
        let header_end = TIMESTAMP_LEN + FMT_LEN + TOKEN_HASH_LEN * 2;
        let mut tail = NEXT_SEED_LEN;
        if fmt == FMT_PADDING {
            let pad_start = payload.len() - NEXT_SEED_LEN - PAD_LEN_FIELD;
            let pad_len = u16::from_be_bytes([payload[pad_start], payload[pad_start + 1]]) as usize;
            if pad_len > MAX_PAD {
                return Err(Error::protocol(format!(
                    "padding length exceeds limit: {pad_len}"
                )));
            }
            tail += PAD_LEN_FIELD + pad_len;
        }
        if header_end + tail > payload.len() {
            return Err(Error::protocol("inconsistent payload structure length"));
        }
        // Step 7: bidirectional token-hash verification (traffic reflection / frequency crosstalk / identity spoofing)
        let dst_hash = &payload[TIMESTAMP_LEN + FMT_LEN..TIMESTAMP_LEN + FMT_LEN + TOKEN_HASH_LEN];
        let src_hash = &payload[TIMESTAMP_LEN + FMT_LEN + TOKEN_HASH_LEN..header_end];
        if dst_hash != self.local_hash {
            return Err(Error::security(
                "destination token hash mismatch (cross-talk or traffic reflection)",
            ));
        }
        if src_hash != self.peer_hash {
            return Err(Error::security(
                "source token hash mismatch (identity spoofing)",
            ));
        }
        // Ratchet rotation + sequence-number advance (must complete before step 8 — out-of-window packets also advance)
        let next_seed: [u8; NEXT_SEED_LEN] = payload[payload.len() - NEXT_SEED_LEN..]
            .try_into()
            .expect("length checked");
        {
            let mut st = self.state.lock().unwrap();
            let mut ikm = st.recv_ek.as_ref().expect("checked above").clone();
            ikm.extend_from_slice(&next_seed);
            let new_ek =
                self.suite
                    .hkdf(&ikm, None, INFO_EK_ROTATE, self.params.key_len as usize)?;
            ikm.zeroize();
            if let Some(mut old) = st.recv_ek.take() {
                old.zeroize();
            }
            st.recv_ek = Some(new_ek);
            st.seq_recv = Some(seq);
        }
        // Step 8: timestamp window — for out-of-window but authenticated packets: discard only the plaintext, do not terminate the session
        let ts = u64::from_be_bytes(payload[..TIMESTAMP_LEN].try_into().unwrap());
        let now = now_ms();
        let diff = (i128::from(now) - i128::from(ts)).abs();
        if diff > i128::from(self.time_window) * 1000 {
            let mut st = self.state.lock().unwrap();
            st.last_recv_drop = Some(format!("timestamp_window: ts={ts}ms, now={now}ms"));
            payload.zeroize();
            return Ok(Vec::new());
        }
        {
            let mut st = self.state.lock().unwrap();
            st.last_recv_drop = None;
        }
        let plaintext = payload[header_end..payload.len() - tail].to_vec();
        payload.zeroize();
        Ok(plaintext)
    }

    // ------------------------------------------------------------------
    // Wipe (Appendix H.6: idempotent)
    // ------------------------------------------------------------------

    /// Wipe all key material of the session and reset state (safe to call repeatedly).
    pub fn wipe(&self) {
        let mut st = self.state.lock().unwrap();
        st.closed = true;
        if let Some(mut k) = st.send_ek.take() {
            k.zeroize();
        }
        if let Some(mut k) = st.recv_ek.take() {
            k.zeroize();
        }
        st.session_id = None;
        st.seq_send = 0;
        st.seq_recv = None;
        st.last_recv_drop = None;
    }
}

impl Drop for SecureSession {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Force-close (for reuse by the transport layer).
pub fn shutdown_stream(sock: &TcpStream) {
    let _ = sock.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{HandshakePeer, Role};
    use crate::params::Params;
    use std::io::Read;
    use std::net::TcpListener;
    use std::time::Duration;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn make_sessions(
        padding: Option<(usize, usize)>,
    ) -> (SecureSession, SecureSession, TcpStream, TcpStream) {
        let psk = vec![9u8; 32];
        let (a, mut b) = pair();
        let mut init = HandshakePeer::new(
            psk.clone(),
            Params::new().unwrap(),
            Role::Initiator,
            padding,
            0.0,
            30,
            Duration::from_millis(200),
            Duration::from_secs(5),
        )
        .unwrap();
        let mut resp = HandshakePeer::new(
            psk,
            Params::new().unwrap(),
            Role::Responder,
            None,
            0.0,
            30,
            Duration::from_millis(200),
            Duration::from_secs(5),
        )
        .unwrap();
        let (ma, mb) = {
            // The handshake thread uses a handle cloned from a (same socket); a is retained and returned to the session layer
            let mut a_hs = a.try_clone().unwrap();
            let h = std::thread::spawn(move || init.perform_handshake(&mut a_hs));
            let m2 = resp.perform_handshake(&mut b).unwrap();
            (h.join().unwrap().unwrap(), m2)
        };
        (SecureSession::new(ma), SecureSession::new(mb), a, b)
    }

    #[test]
    fn round_trip() {
        let (sa, sb, mut a, mut b) = make_sessions(None);
        sa.send_packet(&mut a, b"hello").unwrap();
        let got = sb.recv_packet(&mut b).unwrap();
        assert_eq!(got, b"hello");
        sb.send_packet(&mut b, b"world").unwrap();
        let got2 = sa.recv_packet(&mut a).unwrap();
        assert_eq!(got2, b"world");
    }

    #[test]
    fn heartbeat_empty_payload_and_165b_size() {
        let (sa, sb, mut a, mut b) = make_sessions(None);
        // Heartbeat = empty plaintext; with default parameters the wire size is exactly 165 bytes (Appendix F.5)
        sa.send_packet(&mut a, b"").unwrap();
        let got = sb.recv_packet(&mut b).unwrap();
        assert!(got.is_empty());
        // Recompute the wire size of the heartbeat packet: 44 (header) + 105 (min payload) + 16 (GCM tag)
        assert_eq!(44 + MIN_PAYLOAD_LEN + 16, 165);
    }

    #[test]
    fn seq_regression_rejected() {
        let (sa, sb, mut a, mut b) = make_sessions(None);
        sa.send_packet(&mut a, b"m1").unwrap();
        assert_eq!(sb.recv_packet(&mut b).unwrap(), b"m1");
        // Construct a seq-regression packet (seq=0 equals last=0): the seq check happens before GCM -> replay error
        let sid = sa.state.lock().unwrap().session_id.unwrap();
        let mut packet = Vec::new();
        packet.extend_from_slice(&sid);
        packet.extend_from_slice(&0u64.to_be_bytes());
        packet.extend_from_slice(&16u32.to_be_bytes());
        packet.extend_from_slice(&[0u8; 16]);
        use std::io::Write;
        b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        a.write_all(&packet).unwrap();
        let err = sb.recv_packet(&mut b).unwrap_err();
        assert!(matches!(err, Error::Security(_)), "got {err}");
        assert!(!sb.is_active());
    }

    #[test]
    fn tampered_header_fails_pipeline() {
        let (sa, sb, mut a, mut b) = make_sessions(None);
        sa.send_packet(&mut a, b"data").unwrap();
        // Read the original packet off the wire, tamper with the session ID (step-2 check), and resend
        let mut head = [0u8; 44];
        b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        b.read_exact(&mut head).unwrap();
        let ct_len = u32::from_be_bytes(head[40..44].try_into().unwrap()) as usize;
        let mut ct = vec![0u8; ct_len];
        b.read_exact(&mut ct).unwrap();
        head[0] ^= 0xFF; // tamper with the first byte of session_id
        use std::io::Write;
        a.write_all(&head).unwrap();
        a.write_all(&ct).unwrap();
        let err = sb.recv_packet(&mut b).unwrap_err();
        assert!(matches!(err, Error::Security(_)), "got {err}");
        assert!(!sb.is_active());
    }

    #[test]
    fn padding_single_side_interop() {
        // One-sided padding interop: initiator enables padding, responder does not (per-packet fmt decides)
        let (sa, sb, mut a, mut b) = make_sessions(Some((100, 200)));
        sa.send_packet(&mut a, b"padded message").unwrap();
        let got = sb.recv_packet(&mut b).unwrap();
        assert_eq!(got, b"padded message");
        // Reverse direction without padding also interoperates
        sb.send_packet(&mut b, b"plain").unwrap();
        let got2 = sa.recv_packet(&mut a).unwrap();
        assert_eq!(got2, b"plain");
    }

    #[test]
    fn oversize_plaintext_rejected() {
        let (sa, _sb, mut a, _b) = make_sessions(None);
        let big = vec![0u8; MAX_PLAINTEXT + 1];
        let err = sa.send_packet(&mut a, &big).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn send_after_wipe_requires_reconnect() {
        let (sa, _sb, mut a, _b) = make_sessions(None);
        sa.wipe();
        let err = sa.send_packet(&mut a, b"x").unwrap_err();
        assert!(matches!(err, Error::Session(_)));
        assert!(!sa.is_active());
        // Idempotent: repeated wipe does not panic
        sa.wipe();
        sa.wipe();
    }

    #[test]
    fn stale_timestamp_advances_ratchet_without_plaintext() {
        // Construct an out-of-window but authenticated packet: manually encrypt a stale-timestamp payload with the session's internal state
        let (sa, sb, mut a, mut b) = make_sessions(None);
        let (ek_snap, sid, local, peer) = {
            let st = sa.state.lock().unwrap();
            (
                st.send_ek.clone().unwrap(),
                st.session_id.unwrap(),
                sa.local_hash,
                sa.peer_hash,
            )
        };
        let old_ts: u64 = now_ms().saturating_sub(10 * 60 * 1000); // 10 minutes ago
        let mut payload = Vec::new();
        payload.extend_from_slice(&old_ts.to_be_bytes());
        payload.push(FMT_NO_PADDING);
        payload.extend_from_slice(&peer); // dst = peer (from the initiator's perspective peer=resp)
        payload.extend_from_slice(&local); // src = local
        payload.extend_from_slice(&[0xAB_u8; 32]); // next_seed placeholder
        let seq: u64 = 0;
        let nonce = gcm_nonce(seq);
        let aad = build_aad(&sid, seq);
        let ct = aead_encrypt(&ek_snap, &nonce, &payload, &aad).unwrap();
        use std::io::Write;
        let packet = pack_data_packet(&sid, seq, &ct).unwrap();
        // The sender's state advances in sync with this handcrafted packet (equivalent to the advance semantics of send_packet):
        // send_ek → HKDF(ek_snap ‖ next_seed), seq_send → 1
        {
            let mut st = sa.state.lock().unwrap();
            let mut ikm = ek_snap.clone();
            ikm.extend_from_slice(&[0xAB_u8; 32]);
            let new_ek = sa
                .suite
                .hkdf(&ikm, None, INFO_EK_ROTATE, sa.params.key_len as usize)
                .unwrap();
            ikm.zeroize();
            st.send_ek = Some(new_ek);
            st.seq_send = 1;
        }
        b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        a.write_all(&packet).unwrap();
        // Receiver side: out-of-window → return empty plaintext (heartbeat semantics); state advances, no termination
        let got = sb.recv_packet(&mut b).unwrap();
        assert!(
            got.is_empty(),
            "out-of-window packet should yield empty plaintext"
        );
        assert!(sb.last_recv_drop().is_some());
        // Ratchet has advanced: the old key cannot decrypt the next packet — send one more normal packet to verify interop
        sa.send_packet(&mut a, b"after-stale").unwrap();
        let got2 = sb.recv_packet(&mut b).unwrap();
        assert_eq!(got2, b"after-stale");
    }
}
