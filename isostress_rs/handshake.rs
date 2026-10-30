// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! Four-phase handshake state machine (Master Guide, Sec. 4.2 / Appendix F / Appendix H.1·H.2·H.4).
//!
//! Three asymmetric points of the role state machine (Appendix H.2):
//! 1. Phase 1: the initiator sends first; the responder replies only after validation;
//! 2. Phase 2: the responder "receives the full frame first, computes DH first, then replies" - a low-order-point
//!    attacker must not be able to tell "DH failed" from "the connection was severed" by timing alone (Appendix F.3 ordering constraint);
//! 3. Silent drop constrains the responder only - the initiator actively disconnects on failure (Appendix F.2).
//!
//! The Phase 3 confirmation tag is "send-first-then-compare" (corrected against the reference implementation): the responder receives the frame (silent
//! only on frame-level errors) -> sends its own tag -> both sides compare in constant time; content mismatch -> both sides
//! wipe all keys and fail.
//!
//! After a successful handshake, MK, anchor, and PSK are all securely zeroized (4.2.3 step 6); the session retains only
//! EK_send / EK_recv / session ID / sequence number.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde_json::Value;
use zeroize::Zeroize;

use crate::crypto::{constant_time_eq, secure_random, CryptoSuite, SESSION_SALT_LEN};
use crate::errors::{Error, Result};
use crate::frames::{
    force_close_socket, pack_confirm, pack_initiator_key, pack_phase_one, pack_responder_key,
    read_confirm, read_exact_deadline, read_phase_one, read_pub_key, CONFIRM_TAG_LEN, RECV_CHUNK,
};
use crate::identity::{derive_p2p_identity, ROLE_INITIATOR, ROLE_RESPONDER};
use crate::kex::EphemeralSecret;
use crate::params::Params;

// =============================================================================
// Protocol constants (Master Guide, Sec. 4.2 / Appendix H.3)
// =============================================================================

// --- HKDF info / HMAC context tags (fixed byte-for-byte; any change fails the handshake) ---
pub const INFO_MK: &[u8] = b"ISOSTRESS-MK-v3";
pub const INFO_ANCHOR: &[u8] = b"ISOSTRESS-ANCHOR-v3";
pub const INFO_EK: &[u8] = b"ISOSTRESS-EK-v3";
pub const INFO_EK_ROTATE: &[u8] = b"ISOSTRESS-EK-ROTATE";
pub const INFO_SID: &[u8] = b"ISOSTRESS-SID-v3";
pub const INFO_NONCE: &[u8] = b"ISOSTRESS-PHASE1-NONCE-v3";
pub const INFO_CONFIRM_INIT: &[u8] = b"ISOSTRESS-CONFIRM-INIT-v3";
pub const INFO_CONFIRM_RESP: &[u8] = b"ISOSTRESS-CONFIRM-RESP-v3";

// --- Timers (full timer table, Appendix H.3) ---
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15); // per-phase total time limit for the handshake
pub const DATA_TIMEOUT: Duration = Duration::from_secs(60); // data-phase socket timeout
pub const SILENT_DROP_HOLD: Duration = Duration::from_secs(15); // strict silent-drop hold duration

pub const SESSION_ID_LEN: usize = 32;

/// Frame-level error set (Appendix H.4: the responder goes silent on frame-level errors).
fn is_frame_error(e: &Error) -> bool {
    matches!(e, Error::Protocol(_) | Error::Timeout(_) | Error::Io(_))
}

// =============================================================================
// Handshake artifacts
// =============================================================================

/// All state handed off to the session layer after a successful handshake (MK/anchor/PSK have been wiped; not listed here).
#[derive(Debug, Clone)]
pub struct SessionMaterial {
    pub session_id: [u8; SESSION_ID_LEN],
    pub send_ek: Vec<u8>,
    pub recv_ek: Vec<u8>,
    pub local_hash: [u8; 32],
    pub peer_hash: [u8; 32],
    pub params: Params,
    pub time_window: u64,
    pub padding: Option<(usize, usize)>,
    pub jitter: f64,
}

// =============================================================================
// Handshake peer
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Initiator => ROLE_INITIATOR,
            Role::Responder => ROLE_RESPONDER,
        }
    }
}

/// Performs the full four-phase handshake. peer is a **one-shot** object: after a successful handshake the PSK has been wiped per the protocol;
/// a reconnection must create a new HandshakePeer and supply the PSK again (Appendix H.6).
pub struct HandshakePeer {
    psk: Option<Vec<u8>>,
    params: Params,
    role: Role,
    suite: CryptoSuite,
    padding: Option<(usize, usize)>,
    jitter: f64,
    time_window: u64,
    silent_hold: Duration,
    handshake_timeout: Duration,
    local_hash: [u8; 32],
    peer_hash: [u8; 32],
    mk: Option<Vec<u8>>,
    anchor: Option<Vec<u8>>,
    session_salt: Option<Vec<u8>>,
    session_id: Option<[u8; SESSION_ID_LEN]>,
    ek_send: Option<Vec<u8>>,
    ek_recv: Option<Vec<u8>>,
    local_pub: Option<[u8; 32]>,
    peer_pub: Option<[u8; 32]>,
    local_nonce: Option<Vec<u8>>,
    peer_nonce: Option<Vec<u8>>,
    local_frame_raw: Option<Vec<u8>>,
    peer_frame_raw: Option<Vec<u8>>,
}

impl HandshakePeer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        psk: Vec<u8>,
        params: Params,
        role: Role,
        padding: Option<(usize, usize)>,
        jitter: f64,
        time_window: u64,
        silent_hold: Duration,
        handshake_timeout: Duration,
    ) -> Result<Self> {
        if psk.len() != 32 {
            return Err(Error::param("PSK must be exactly 32 bytes"));
        }
        if let Some((pmin, pmax)) = padding {
            if pmin > pmax || pmax > 2048 {
                return Err(Error::param(
                    "padding range is invalid: 0 <= min <= max <= 2048",
                ));
            }
        }
        if jitter < 0.0 {
            return Err(Error::param("jitter must be non-negative"));
        }
        if time_window == 0 {
            return Err(Error::param("time_window must be a positive integer"));
        }
        let (local_hash, peer_hash) = derive_p2p_identity(&psk, role.as_str())?;
        let suite = CryptoSuite::new(params.hash_name.clone(), params.aead_name.clone())?;
        Ok(HandshakePeer {
            psk: Some(psk),
            params,
            role,
            suite,
            padding,
            jitter,
            time_window,
            silent_hold,
            handshake_timeout,
            local_hash,
            peer_hash,
            mk: None,
            anchor: None,
            session_salt: None,
            session_id: None,
            ek_send: None,
            ek_recv: None,
            local_pub: None,
            peer_pub: None,
            local_nonce: None,
            peer_nonce: None,
            local_frame_raw: None,
            peer_frame_raw: None,
        })
    }

    // ------------------------------------------------------------------
    // Strict silent drop (Appendix F.2 five-element behavioral contract)
    // ------------------------------------------------------------------

    /// Sends no bytes and closes nothing proactively; holds on reading and discards the peer's subsequent data until the peer
    /// closes or the hold duration is exhausted. Diagnostics go only to local stderr, never to the wire.
    ///
    /// The held read constrains the whole drain with an **overall deadline**:
    /// the drain loop must not be delayed indefinitely by "dribbling 1 byte every 15 seconds".
    fn silent_drop(&self, sock: &mut TcpStream, reason: &str) {
        let saved = sock.read_timeout().ok().flatten();
        let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
        let deadline = Instant::now() + self.silent_hold;
        let mut buf = [0u8; RECV_CHUNK];
        loop {
            if Instant::now() >= deadline {
                break;
            }
            match sock.read(&mut buf) {
                Ok(0) => break, // peer closed
                Ok(_) => continue,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue; // keep waiting within the chunk timeout, until the overall deadline
                }
                Err(_) => break,
            }
        }
        let _ = sock.set_read_timeout(saved);
        eprintln!("[Silent Drop] {reason} (no data was sent to the peer)");
    }

    /// Responder failure path: after the strict silence, raise via [`Error::SilentDrop`] (the silent path has
    /// taken over; the upper layer must not touch the socket again); initiator failure path: disconnect proactively and raise a parameter error
    /// (F.2 initiator asymmetry).
    fn drop_or_raise(&self, sock: &mut TcpStream, reason: &str) -> Error {
        if self.role == Role::Responder {
            self.silent_drop(sock, reason);
            Error::silent_drop(reason)
        } else {
            force_close_socket(sock);
            Error::param(reason)
        }
    }

    // ------------------------------------------------------------------
    // Phase 1: identity announcement (Appendix F.1)
    // ------------------------------------------------------------------

    /// Builds the local Phase 1 frame: join nonce = HKDF-SHA3-256(IKM=PSK,
    /// salt=fresh local random salt (32B), info=PHASE1-NONCE-v3, L=random_len/8).
    /// The salt is not transmitted with the frame (the peer only checks the length and does not recompute the nonce).
    /// Public so that tests and tooling can drive it offline (the Python side is likewise an independently callable step).
    pub fn build_local_frame(&mut self) -> Result<()> {
        let psk = self
            .psk
            .as_ref()
            .ok_or_else(|| Error::session("PSK has been wiped"))?;
        let nonce_salt = secure_random(SESSION_SALT_LEN)?;
        let local_nonce = self.suite.hkdf(
            psk,
            Some(&nonce_salt),
            INFO_NONCE,
            self.params.random_len as usize,
        )?;
        if local_nonce.len() * 8 != self.params.random_len as usize {
            return Err(Error::protocol(format!(
                "join nonce length does not match the declared random_len: {} != {}",
                local_nonce.len() * 8,
                self.params.random_len
            )));
        }
        let mut identity_blob = Vec::with_capacity(64);
        identity_blob.extend_from_slice(&self.local_hash);
        identity_blob.extend_from_slice(&self.peer_hash);
        let local_frame = pack_phase_one(&self.params.to_json()?, &identity_blob, &local_nonce)?;
        self.local_nonce = Some(local_nonce);
        self.local_frame_raw = Some(local_frame);
        Ok(())
    }

    /// The built local Phase 1 raw frame (with all length prefixes; the bytes that enter the transcript).
    pub fn local_frame_raw(&self) -> Option<&[u8]> {
        self.local_frame_raw.as_deref()
    }

    fn send_all(&self, sock: &mut TcpStream, data: &[u8]) -> Result<()> {
        sock.write_all(data).map_err(Error::Io)
    }

    fn set_phase_timeouts(&self, sock: &TcpStream) {
        let _ = sock.set_read_timeout(Some(self.handshake_timeout));
        let _ = sock.set_write_timeout(Some(self.handshake_timeout));
    }

    fn phase1(&mut self, sock: &mut TcpStream) -> Result<()> {
        self.build_local_frame()?;
        let local_frame = self.local_frame_raw.clone().expect("local frame built");
        self.set_phase_timeouts(sock);
        let deadline = Instant::now() + self.handshake_timeout;

        let peer_frame = if self.role == Role::Initiator {
            self.send_all(sock, &local_frame)?;
            // The initiator reads the peer's frame: frame-level errors are raised directly (the initiator has already sent its frame; an active disconnect does not break silence)
            read_phase_one(sock, Some(deadline))?
        } else {
            // The responder receives the full frame first; frame-level error -> strict silence (Appendix F.2 full table of trigger points)
            match read_phase_one(sock, Some(deadline)) {
                Ok(f) => f,
                Err(e) if is_frame_error(&e) => {
                    self.silent_drop(sock, &format!("Phase 1 parsing failed: {e}"));
                    return Err(Error::silent_drop(format!("Phase 1 parsing failed: {e}")));
                }
                Err(e) => return Err(e),
            }
        };

        self.peer_frame_raw = Some(peer_frame.raw.clone());
        let peer_nonce = peer_frame.nonce.clone();

        // Parameter JSON parsing: all errors converge (responder -> silence; initiator -> disconnect and report)
        let text = match std::str::from_utf8(&peer_frame.param_json) {
            Ok(t) => t,
            Err(e) => {
                let reason = format!("parameter JSON is invalid: UTF-8 decoding failed: {e}");
                return Err(self.drop_or_raise(sock, &reason));
            }
        };
        let value: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                let reason = format!("parameter JSON is invalid: {e}");
                return Err(self.drop_or_raise(sock, &reason));
            }
        };
        let peer_params = match Params::from_value(&value) {
            Ok(p) => p,
            Err(e) => {
                let reason = format!("parameter JSON is invalid: {e}");
                return Err(self.drop_or_raise(sock, &reason));
            }
        };

        // Seven-item match check (F.1 fixed order; stop at the first mismatch)
        if let Some(mismatch) = self.params.match_error(&peer_params) {
            let reason = format!("parameter mismatch: {mismatch}");
            return Err(self.drop_or_raise(sock, &reason));
        }

        // Peer nonce length contract (the sole validation item of the core protocol)
        if peer_nonce.len() * 8 != peer_params.random_len as usize {
            let reason = "peer nonce length does not match the declared random_len";
            return Err(self.drop_or_raise(sock, reason));
        }
        self.peer_nonce = Some(peer_nonce);

        // Only after all parameter checks pass does the responder send back its own frame (Appendix F.1 exchange order)
        if self.role == Role::Responder {
            self.set_phase_timeouts(sock);
            self.send_all(sock, &local_frame)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Phase 2: key synchronization (Appendix F.3)
    // ------------------------------------------------------------------

    fn phase2(&mut self, sock: &mut TcpStream) -> Result<()> {
        let secret = EphemeralSecret::generate()?;
        let pub_bytes = secret.public_bytes();
        self.local_pub = Some(pub_bytes);
        self.set_phase_timeouts(sock);
        let deadline = Instant::now() + self.handshake_timeout;

        let mut dh: [u8; 32] = if self.role == Role::Initiator {
            let session_salt = secure_random(SESSION_SALT_LEN)?;
            self.session_salt = Some(session_salt.clone());
            self.send_all(sock, &pack_initiator_key(&pub_bytes, &session_salt)?)?;
            let peer_pub = read_pub_key(sock, Some(deadline))?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&peer_pub);
            self.peer_pub = Some(arr);
            // The initiator has already sent its frame: on a cryptographic error, disconnecting directly is normal behavior (F.2 asymmetry)
            secret.shared_secret(&peer_pub)?
        } else {
            let (peer_pub, session_salt) = {
                match (|| -> Result<(Vec<u8>, Vec<u8>)> {
                    let peer_pub = read_pub_key(sock, Some(deadline))?;
                    let mut buf = vec![0u8; SESSION_SALT_LEN];
                    read_exact_deadline(sock, &mut buf, "session_salt", Some(deadline))?;
                    Ok((peer_pub, buf))
                })() {
                    Ok(v) => v,
                    Err(e) if is_frame_error(&e) => {
                        self.silent_drop(sock, &format!("Phase 2 frame error: {e}"));
                        return Err(Error::silent_drop(format!("Phase 2 frame error: {e}")));
                    }
                    Err(e) => return Err(e),
                }
            };
            self.session_salt = Some(session_salt);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&peer_pub);
            self.peer_pub = Some(arr);
            // DH is computed before sending any byte (F.3 ordering constraint: prerequisite for low-order-point silence)
            let dh = match secret.shared_secret(&peer_pub) {
                Ok(d) => d,
                Err(e) => {
                    self.silent_drop(sock, &format!("Phase 2 key agreement failed: {e}"));
                    return Err(Error::silent_drop(format!(
                        "Phase 2 key agreement failed: {e}"
                    )));
                }
            };
            self.send_all(sock, &pack_responder_key(&pub_bytes)?)?;
            dh
        };

        // MK = HKDF-SHA3-256(IKM = PSK ‖ DH, salt = session_salt,
        //                    info = "ISOSTRESS-MK-v3", L = key_len)
        // session_salt is HKDF's salt parameter, not material concatenated into the IKM (common-mistake correction)
        let psk = self
            .psk
            .as_ref()
            .ok_or_else(|| Error::session("PSK has been wiped"))?;
        let salt = self.session_salt.as_ref().expect("session salt set");
        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(psk);
        ikm.extend_from_slice(&dh);
        let mk = self
            .suite
            .hkdf(&ikm, Some(salt), INFO_MK, self.params.key_len as usize)?;
        ikm.zeroize();
        dh.zeroize();
        self.mk = Some(mk);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Phase 3: anchor locking (Appendix F.4, send-first-then-compare)
    // ------------------------------------------------------------------

    /// transcript = initiator Phase 1 raw frame ‖ responder Phase 1 raw frame
    /// ‖ session_salt ‖ initiator ephemeral public key ‖ responder ephemeral public key (both sides splice
    /// independently with the same formula, in a fixed order; raw frames include all length prefixes, byte for byte).
    /// No protocol identifier: the transcript contains no version string.
    fn build_transcript(&self) -> Result<Vec<u8>> {
        let local_frame = self
            .local_frame_raw
            .as_ref()
            .ok_or_else(|| Error::protocol("Phase 1 raw frame not initialized"))?;
        let peer_frame = self
            .peer_frame_raw
            .as_ref()
            .ok_or_else(|| Error::protocol("Phase 1 raw frame not initialized"))?;
        let salt = self
            .session_salt
            .as_ref()
            .ok_or_else(|| Error::protocol("session salt not initialized"))?;
        let local_pub = self
            .local_pub
            .ok_or_else(|| Error::protocol("ephemeral public key not initialized"))?;
        let peer_pub = self
            .peer_pub
            .ok_or_else(|| Error::protocol("ephemeral public key not initialized"))?;
        let (init_frame, resp_frame, init_pub, resp_pub) = match self.role {
            Role::Initiator => (local_frame, peer_frame, local_pub, peer_pub),
            Role::Responder => (peer_frame, local_frame, peer_pub, local_pub),
        };
        let mut t = Vec::with_capacity(init_frame.len() + resp_frame.len() + 32 + 32 + 32);
        t.extend_from_slice(init_frame);
        t.extend_from_slice(resp_frame);
        t.extend_from_slice(salt);
        t.extend_from_slice(&init_pub);
        t.extend_from_slice(&resp_pub);
        Ok(t)
    }

    fn phase3(&mut self, sock: &mut TcpStream) -> Result<()> {
        let mk = self
            .mk
            .as_ref()
            .ok_or_else(|| Error::protocol("Phase 2 incomplete; cannot compute the anchor"))?
            .clone();

        // Anchor / session ID / directional EK (Appendix F.4 and 4.2.3)
        let anchor = self.suite.hmac(&mk, INFO_ANCHOR)?;
        self.anchor = Some(anchor.clone());
        let sid_full = self.suite.hkdf(&anchor, None, INFO_SID, 256)?;
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&sid_full[..SESSION_ID_LEN]);
        self.session_id = Some(session_id);

        let (role_byte, peer_role_byte) = match self.role {
            Role::Initiator => (0x01u8, 0x02u8),
            Role::Responder => (0x02u8, 0x01u8),
        };
        let mut ikm_send = Vec::with_capacity(mk.len() + 33);
        ikm_send.extend_from_slice(&mk);
        ikm_send.extend_from_slice(&anchor);
        ikm_send.push(role_byte);
        let ek_send = self
            .suite
            .hkdf(&ikm_send, None, INFO_EK, self.params.key_len as usize)?;
        ikm_send.clear();
        ikm_send.extend_from_slice(&mk);
        ikm_send.extend_from_slice(&anchor);
        ikm_send.push(peer_role_byte);
        let ek_recv = self
            .suite
            .hkdf(&ikm_send, None, INFO_EK, self.params.key_len as usize)?;
        ikm_send.zeroize();
        self.ek_send = Some(ek_send);
        self.ek_recv = Some(ek_recv);

        let transcript = self.build_transcript()?;
        let (local_label, peer_label) = match self.role {
            Role::Initiator => (INFO_CONFIRM_INIT, INFO_CONFIRM_RESP),
            Role::Responder => (INFO_CONFIRM_RESP, INFO_CONFIRM_INIT),
        };
        let mut msg = Vec::with_capacity(local_label.len() + transcript.len());
        msg.extend_from_slice(local_label);
        msg.extend_from_slice(&transcript);
        let local_tag = self.suite.hmac(&mk, &msg)?;
        msg.clear();
        msg.extend_from_slice(peer_label);
        msg.extend_from_slice(&transcript);
        let expected_peer_tag = self.suite.hmac(&mk, &msg)?;
        msg.zeroize();
        // Wipe local copies immediately after use (Appendix H.6: leave no un-wipeable heap copies)
        let mut mk = mk;
        mk.zeroize();
        let mut anchor = anchor;
        anchor.zeroize();

        self.set_phase_timeouts(sock);
        let deadline = Instant::now() + self.handshake_timeout;
        let peer_tag: Vec<u8> = if self.role == Role::Initiator {
            self.send_all(sock, &pack_confirm(&local_tag)?)?;
            read_confirm(sock, Some(deadline))?
        } else {
            // Send-first-then-compare (common-mistake correction): the responder is silent only on frame-level errors; when sending its
            // own tag, the peer's tag content has not yet been validated
            let peer_tag = match read_confirm(sock, Some(deadline)) {
                Ok(t) => t,
                Err(e) if is_frame_error(&e) => {
                    self.silent_drop(sock, &format!("Phase 3 frame error: {e}"));
                    return Err(Error::silent_drop(format!("Phase 3 frame error: {e}")));
                }
                Err(e) => return Err(e),
            };
            self.send_all(sock, &pack_confirm(&local_tag)?)?;
            peer_tag
        };

        if peer_tag.len() != CONFIRM_TAG_LEN {
            self.wipe();
            return Err(Error::security(
                "anchor confirmation failed - confirmation tag length is abnormal",
            ));
        }
        if !constant_time_eq(&expected_peer_tag, &peer_tag) {
            self.wipe();
            return Err(Error::security(
                "anchor confirmation failed - PSK mismatch, role mismatch, or reflection / MITM attack",
            ));
        }

        // Root key wipe (4.2.3 step 6): zero only MK, anchor, and PSK -
        // session_id and the directional EK are handed off to the session layer (a full wipe is the failure path)
        self.wipe_keys();
        Ok(())
    }

    // ------------------------------------------------------------------
    // Cleanup (Appendix H.6)
    // ------------------------------------------------------------------

    fn wipe_keys(&mut self) {
        if let Some(mut mk) = self.mk.take() {
            mk.zeroize();
        }
        if let Some(mut a) = self.anchor.take() {
            a.zeroize();
        }
        if let Some(mut psk) = self.psk.take() {
            psk.zeroize();
        }
    }

    /// Full cleanup (idempotent): called uniformly on every handshake failure path; never exit while holding keys.
    pub fn wipe(&mut self) {
        self.wipe_keys();
        if let Some(mut s) = self.session_salt.take() {
            s.zeroize();
        }
        self.session_id = None;
        if let Some(mut k) = self.ek_send.take() {
            k.zeroize();
        }
        if let Some(mut k) = self.ek_recv.take() {
            k.zeroize();
        }
        self.local_pub = None;
        self.peer_pub = None;
        self.local_nonce = None;
        self.peer_nonce = None;
        self.local_frame_raw = None;
        self.peer_frame_raw = None;
    }

    // ------------------------------------------------------------------
    // Handshake entry point (Appendix H.1/H.2)
    // ------------------------------------------------------------------

    /// Runs Phase 1 -> 2 -> 3. Any step failing: uniformly wipes all material PSK/MK/anchor/EK
    /// and propagates the error as-is (Appendix H.6). On success: returns the session material and restores the data-phase timeouts.
    pub fn perform_handshake(&mut self, sock: &mut TcpStream) -> Result<SessionMaterial> {
        let result = (|| -> Result<SessionMaterial> {
            self.phase1(sock)?;
            self.phase2(sock)?;
            self.phase3(sock)?;

            let session_id = self
                .session_id
                .ok_or_else(|| Error::session("session ID missing"))?;
            let send_ek = self
                .ek_send
                .take()
                .ok_or_else(|| Error::session("EK_send missing"))?;
            let recv_ek = self
                .ek_recv
                .take()
                .ok_or_else(|| Error::session("EK_recv missing"))?;
            self.session_id = None;
            Ok(SessionMaterial {
                session_id,
                send_ek,
                recv_ek,
                local_hash: self.local_hash,
                peer_hash: self.peer_hash,
                params: self.params.clone(),
                time_window: self.time_window,
                padding: self.padding,
                jitter: self.jitter,
            })
        })();
        match result {
            Ok(m) => {
                // Timeout split: the handshake uses a 15s timeout; the data phase uses 60s
                let _ = sock.set_read_timeout(Some(DATA_TIMEOUT));
                let _ = sock.set_write_timeout(Some(DATA_TIMEOUT));
                Ok(m)
            }
            Err(e) => {
                self.wipe();
                force_close_socket(sock);
                Err(e)
            }
        }
    }
}

impl Drop for HandshakePeer {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::TIME_WINDOW;

    /// Loopback TCP pair (equivalent to Python's socketpair; works on Windows).
    pub(crate) fn pair() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn quick_peer(psk: Vec<u8>, params: Params, role: Role) -> HandshakePeer {
        HandshakePeer::new(
            psk,
            params,
            role,
            None,
            0.0,
            TIME_WINDOW,
            Duration::from_millis(300),
            Duration::from_secs(5),
        )
        .unwrap()
    }

    #[test]
    fn full_handshake_success_and_message_flow() {
        let psk = vec![3u8; 32];
        let (mut a, mut b) = pair();
        let (mut init, mut resp) = (
            quick_peer(psk.clone(), Params::new().unwrap(), Role::Initiator),
            quick_peer(psk, Params::new().unwrap(), Role::Responder),
        );
        {
            let ha = std::thread::spawn(move || init.perform_handshake(&mut a));
            let hb = resp.perform_handshake(&mut b);
            let ha = ha
                .join()
                .unwrap_or_else(|_| panic!("initiator thread panicked"))
                .unwrap_or_else(|e| panic!("initiator handshake failed: {e}"));
            let hb = hb.unwrap_or_else(|e| panic!("responder handshake failed: {e}"));
            assert_eq!(ha.session_id, hb.session_id);
            // Directional key cross-check: A's send == B's recv
            assert_eq!(ha.send_ek, hb.recv_ek);
            assert_eq!(ha.recv_ek, hb.send_ek);
            assert_ne!(ha.send_ek, ha.recv_ek);
            // Raw hash cross-check: A's local == B's peer
            assert_eq!(ha.local_hash, hb.peer_hash);
            assert_eq!(ha.peer_hash, hb.local_hash);
        }
    }

    #[test]
    fn psk_mismatch_fails_both_sides_as_security_error() {
        let (mut a, mut b) = pair();
        let mut init = quick_peer(vec![1u8; 32], Params::new().unwrap(), Role::Initiator);
        let mut resp = quick_peer(vec![2u8; 32], Params::new().unwrap(), Role::Responder);
        let h = std::thread::spawn(move || init.perform_handshake(&mut a));
        let eb = resp.perform_handshake(&mut b).unwrap_err();
        let ea = h.join().unwrap().unwrap_err();
        // Both sides are security errors (tag mismatch), not silent drops
        assert!(matches!(eb, Error::Security(_)), "got {eb}");
        assert!(matches!(ea, Error::Security(_)), "got {ea}");
    }

    #[test]
    fn param_mismatch_responder_strict_silence() {
        let (mut a, mut b) = pair();
        let mut init = quick_peer(
            vec![1u8; 32],
            Params::build(
                512,
                1024,
                60,
                256,
                "SHA3-256".into(),
                "AES-256-GCM".into(),
                serde_json::json!({}),
            )
            .unwrap(),
            Role::Initiator,
        );
        let mut resp = quick_peer(vec![1u8; 32], Params::new().unwrap(), Role::Responder);
        let h = std::thread::spawn(move || init.perform_handshake(&mut a));
        let eb = resp.perform_handshake(&mut b).unwrap_err();
        let _ea = h.join().unwrap().unwrap_err();
        // Responder: SilentDropError (strict silence has occurred)
        assert!(eb.is_silent_drop(), "got {eb}");
    }

    #[test]
    fn param_mismatch_silence_sends_nothing() {
        // Drive directly: the silent path sends no bytes to the peer (F.2 element 1)
        let (mut left, right) = pair();
        let mut responder = quick_peer(vec![1u8; 32], Params::new().unwrap(), Role::Responder);
        let mut initiator = quick_peer(
            vec![1u8; 32],
            Params::build(
                512,
                1024,
                60,
                256,
                "SHA3-256".into(),
                "AES-256-GCM".into(),
                serde_json::json!({}),
            )
            .unwrap(),
            Role::Initiator,
        );
        let t = std::thread::spawn(move || {
            let mut r = right;
            let e = responder.perform_handshake(&mut r).unwrap_err();
            matches!(e, Error::SilentDrop(_))
        });
        initiator.build_local_frame().unwrap();
        let raw = initiator.local_frame_raw.clone().unwrap();
        use std::io::Write;
        left.write_all(&raw).unwrap();
        let _ = left.set_read_timeout(Some(Duration::from_millis(500)));
        let mut buf = [0u8; 4096];
        let received = left.read(&mut buf);
        assert!(t.join().unwrap());
        // No bytes received from the responder (timeout with no data, or peer closed)
        match received {
            Ok(n) => assert_eq!(n, 0, "the silent path must not send any bytes"),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("the silent path must not close the connection: {e}"),
        }
    }

    #[test]
    fn low_order_public_key_silent_before_reply() {
        // Attacker: legitimate Phase 1 frame -> read the responder's legitimate reply frame -> send an all-zero public key (low-order point)
        // The responder should enter strict silence: no Phase 2 response frame is sent
        let (mut left, right) = pair();
        let mut responder = quick_peer(vec![1u8; 32], Params::new().unwrap(), Role::Responder);
        let mut attacker = quick_peer(vec![1u8; 32], Params::new().unwrap(), Role::Initiator);
        let t = std::thread::spawn(move || {
            let mut r = right;
            let e = responder.perform_handshake(&mut r).unwrap_err();
            matches!(e, Error::SilentDrop(_))
        });
        attacker.build_local_frame().unwrap();
        let raw = attacker.local_frame_raw.clone().unwrap();
        use std::io::Write;
        left.write_all(&raw).unwrap();
        let parsed = read_phase_one(&mut left, None).unwrap(); // read the responder's Phase 1 frame
        assert!(!parsed.raw.is_empty());
        // The attacker replies with a valid pub_len header + all-zero public key + salt
        left.write_all(&32u32.to_be_bytes()).unwrap();
        left.write_all(&[0u8; 32]).unwrap();
        left.write_all(&[0x07u8; 32]).unwrap();

        let _ = left.set_read_timeout(Some(Duration::from_millis(800)));
        let mut buf = [0u8; 4096];
        let received = left.read(&mut buf);
        assert!(
            t.join().unwrap(),
            "the responder should enter strict silence"
        );
        if let Ok(n) = received {
            assert_eq!(
                n, 0,
                "low-order-point silence must not send the Phase 2 response frame"
            );
        } else if let Err(e) = received {
            if e.kind() != std::io::ErrorKind::WouldBlock
                && e.kind() != std::io::ErrorKind::TimedOut
            {
                panic!("the silent path must not close the connection: {e}");
            }
        }
    }

    #[test]
    fn confirm_labels_differ() {
        let psk = [5u8; 32];
        let transcript = b"transcript-bytes".to_vec();
        let suite = CryptoSuite::new("SHA3-256", "AES-256-GCM").unwrap();
        let mut m1 = INFO_CONFIRM_INIT.to_vec();
        m1.extend_from_slice(&transcript);
        let mut m2 = INFO_CONFIRM_RESP.to_vec();
        m2.extend_from_slice(&transcript);
        let t1 = suite.hmac(&psk, &m1).unwrap();
        let t2 = suite.hmac(&psk, &m2).unwrap();
        assert_ne!(t1, t2);
    }
}
