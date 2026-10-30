# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Four-phase handshake state machine (Master Guide Section 4.2 /
Appendix F / Appendix H.1, H.2, H.4).

Three asymmetries of the role state machine (Appendix H.2):
1. In phase one the initiator sends first and the responder replies only after
   verification completes;
2. In phase two the responder "receives the full frame first, computes DH
   first, then responds" -- a low-order point attacker must observe no timing
   difference between receiving the response frame and the connection being
   dropped (Appendix F.3 ordering constraint);
3. Silent Drop constrains only the responder -- the initiator actively
   disconnects on failure (Appendix F.2).

The phase three confirm tag is "send first, then compare" (corrected
against the reference implementation): the responder receives the frame (silent
only for frame-level errors) -> sends its own tag -> both sides compare in
constant time; on content mismatch -> both sides wipe all keys and fail.

After a successful handshake MK, anchor, and PSK are all securely zeroized
(Section 4.2.3 step 6); the session retains only EK_send / EK_recv / session ID /
sequence number.
"""

from __future__ import annotations

import json
import socket
import os
import sys


_DEBUG = os.environ.get("ZT_DSP_DEBUG") == "1"


def _diag(msg: str) -> None:
    """Diagnostics stay local and stay silent unless explicitly enabled.

    A drop path that prints by default is distinguishable from a normal path
    by anyone watching stderr, which defeats the silent-drop property.
    """
    if _DEBUG:
        print(msg, file=sys.stderr)


import time
from dataclasses import dataclass
from typing import Optional, Tuple

from .crypto import (
    SESSION_SALT_LEN,
    CryptoSuite,
    constant_time_compare,
    secure_random,
    secure_zero,
)
from .errors import (
    SilentDropError,
    ISOSTRESSCryptoError,
    ISOSTRESSParamError,
    ISOSTRESSProtocolError,
    ISOSTRESSSecurityError,
    ISOSTRESSTimeoutError,
)
from .frames import (
    CONFIRM_TAG_LEN,
    RECV_CHUNK,
    force_close_socket,
    pack_confirm,
    pack_initiator_key,
    pack_phase_one,
    pack_responder_key,
    read_confirm,
    read_exact,
    read_pub_key,
    unpack_phase_one,
)
from .identity import ROLE_INITIATOR, ROLE_RESPONDER, derive_p2p_identity
from .params import TIME_WINDOW, ISOSTRESSParams

# =============================================================================
# Protocol constants (Master Guide Section 4.2 / Appendix H.3)
# =============================================================================

# --- HKDF info / HMAC context labels (fixed byte for byte; any change breaks the handshake) ---
INFO_MK: str = "ISOSTRESS-MK-v3"
INFO_ANCHOR: bytes = b"ISOSTRESS-ANCHOR-v3"
INFO_EK: str = "ISOSTRESS-EK-v3"
INFO_EK_ROTATE: str = "ISOSTRESS-EK-ROTATE"
INFO_SID: str = "ISOSTRESS-SID-v3"
INFO_NONCE: str = "ISOSTRESS-PHASE1-NONCE-v3"
INFO_CONFIRM_INIT: bytes = b"ISOSTRESS-CONFIRM-INIT-v3"
INFO_CONFIRM_RESP: bytes = b"ISOSTRESS-CONFIRM-RESP-v3"

# --- Timers (complete timer table in Appendix H.3) ---
HANDSHAKE_TIMEOUT: float = 15.0  # Total per-phase handshake deadline (= total read deadline, Slowloris protection)
DATA_TIMEOUT: float = 60.0  # Data phase socket timeout (the 30s heartbeat still fits)
SILENT_DROP_HOLD: float = 15.0  # Strict silent hold duration (configurable; smaller is recommended for server embedding)

SESSION_ID_LEN: int = 32

_FRAME_ERRORS = (
    ISOSTRESSProtocolError,
    ISOSTRESSTimeoutError,
    ConnectionError,
    OSError,
)


# =============================================================================
# Handshake output
# =============================================================================


@dataclass
class SessionMaterial:
    """All state handed over to the session layer after a successful handshake
    (MK / anchor / PSK have already been wiped and are not listed here)."""

    session_id: bytes
    send_ek: bytearray
    recv_ek: bytearray
    local_hash: bytes
    peer_hash: bytes
    params: ISOSTRESSParams
    time_window: int
    padding: Optional[Tuple[int, int]]
    jitter: float


# =============================================================================
# Handshake peer
# =============================================================================


class HandshakePeer:
    """Performs the full four-phase handshake. A peer is a **single-use** object:
    the PSK has already been wiped per protocol after a successful handshake, so
    a reconnect must create a new HandshakePeer and supply the PSK again
    (Appendix H.6)."""

    __slots__ = (
        "psk",
        "params",
        "role",
        "suite",
        "padding",
        "jitter",
        "time_window",
        "silent_hold",
        "local_hash",
        "peer_hash",
        "_mk",
        "_anchor",
        "_session_salt",
        "_session_id",
        "_ek_send",
        "_ek_recv",
        "_local_pub",
        "_peer_pub",
        "_local_nonce",
        "_peer_nonce",
        "_local_frame_raw",
        "_peer_frame_raw",
        "_handshake_complete",
    )

    def __init__(
        self,
        psk: bytes,
        params: ISOSTRESSParams,
        role: str,
        suite: Optional[CryptoSuite] = None,
        padding: Optional[Tuple[int, int]] = None,
        jitter: float = 0.0,
        time_window: int = TIME_WINDOW,
        silent_hold: float = SILENT_DROP_HOLD,
    ) -> None:
        if not isinstance(psk, (bytes, bytearray)) or len(psk) != 32:
            raise ValueError("PSK must be exactly 32 bytes")
        if role not in (ROLE_INITIATOR, ROLE_RESPONDER):
            raise ValueError(f"role must be '{ROLE_INITIATOR}' or '{ROLE_RESPONDER}'")
        if padding is not None:
            pmin, pmax = padding
            if not (0 <= pmin <= pmax <= 2048):
                raise ValueError("invalid padding range: 0 <= min <= max <= 2048")
        if jitter < 0:
            raise ValueError("jitter must be non-negative")
        if time_window <= 0:
            raise ValueError("time_window must be a positive integer")

        self.psk = bytearray(psk)
        self.params = params
        self.role = role
        self.suite = suite or CryptoSuite(params.hash_name, params.aead_name)
        self.padding = padding
        self.jitter = jitter
        self.time_window = time_window
        self.silent_hold = silent_hold

        # P2P placeholder token hash (4.1.1): the local hash and the peer hash are derived symmetrically by role
        self.local_hash, self.peer_hash = derive_p2p_identity(bytes(psk), role)

        self._mk: Optional[bytearray] = None
        self._anchor: Optional[bytearray] = None
        self._session_salt: Optional[bytes] = None
        self._session_id: Optional[bytes] = None
        self._ek_send: Optional[bytearray] = None
        self._ek_recv: Optional[bytearray] = None
        self._local_pub: Optional[bytes] = None
        self._peer_pub: Optional[bytes] = None
        self._local_nonce: Optional[bytes] = None
        self._peer_nonce: Optional[bytes] = None
        self._local_frame_raw: Optional[bytes] = None
        self._peer_frame_raw: Optional[bytes] = None
        self._handshake_complete = False

    # ------------------------------------------------------------------
    # Strict Silent Drop (five-element behavioral contract in Appendix F.2)
    # ------------------------------------------------------------------
    def _silent_drop(self, sock: socket.socket, reason: str) -> None:
        """Sends no bytes and does not actively close; blocks on reads and discards
        subsequent peer data until the peer closes or the hold duration is
        exhausted. Diagnostics go only to local stderr and never onto the
        network side."""
        try:
            old_timeout = sock.gettimeout()
        except OSError:
            _diag(f"[Silent Drop] {reason} (connection already closed)")
            return
        try:
            try:
                sock.settimeout(self.silent_hold)
            except OSError:
                _diag(f"[Silent Drop] {reason} (connection already closed)")
                return
            try:
                while True:
                    chunk = sock.recv(RECV_CHUNK)
                    if not chunk:
                        break
            except socket.timeout:
                pass
            except KeyboardInterrupt:
                pass
            except OSError:
                pass
        finally:
            try:
                sock.settimeout(old_timeout)
            except OSError:
                pass
        _diag(f"[Silent Drop] {reason} (no data sent to peer)")

    def _drop_or_raise(self, sock: socket.socket, reason: str) -> None:
        """Responder failure path: after a strict silent hold, raise SilentDropError
        (the silent path has taken over, so upper layers must not touch the
        socket again); initiator failure path: actively disconnect and raise a
        parameter error (F.2 initiator asymmetry)."""
        if self.role == ROLE_RESPONDER:
            self._silent_drop(sock, reason)
            raise SilentDropError(reason)
        force_close_socket(sock)
        raise ISOSTRESSParamError(reason)

    # ------------------------------------------------------------------
    # Phase one: identity announcement (Appendix F.1)
    # ------------------------------------------------------------------
    def _build_local_frame(self) -> bytes:
        """Builds the local phase one frame: access nonce = HKDF-SHA3-256(IKM=PSK,
        salt=local fresh random salt (32B), info=PHASE1-NONCE-v3,
        L=random_len/8). The salt is not transmitted with the frame (the
        peer only checks the length and does not recompute the nonce)."""
        psk_bytes = bytes(self.psk)
        nonce_salt = secure_random(SESSION_SALT_LEN)
        local_nonce = self.suite.hkdf(
            psk_bytes, INFO_NONCE, self.params.random_len, salt=nonce_salt
        )
        if len(local_nonce) * 8 != self.params.random_len:
            raise ISOSTRESSProtocolError(
                f"access nonce length does not match declared random_len: "
                f"{len(local_nonce) * 8} != {self.params.random_len}"
            )
        self._local_nonce = local_nonce
        identity_blob = self.local_hash + self.peer_hash
        local_frame = pack_phase_one(self.params.to_json(), identity_blob, local_nonce)
        self._local_frame_raw = local_frame
        return local_frame

    def _phase1(self, sock: socket.socket) -> None:
        local_frame = self._build_local_frame()
        old_timeout = sock.gettimeout()
        try:
            sock.settimeout(HANDSHAKE_TIMEOUT)
            deadline = time.monotonic() + HANDSHAKE_TIMEOUT

            if self.role == ROLE_INITIATOR:
                sock.sendall(local_frame)
                peer_frame_raw, param_raw, _identity, peer_nonce = unpack_phase_one(
                    sock, deadline
                )
            else:
                # The responder receives the full frame first; frame parse failure -> strict silent drop (complete trigger table in Appendix F.2)
                try:
                    peer_frame_raw, param_raw, _identity, peer_nonce = unpack_phase_one(
                        sock, deadline
                    )
                except _FRAME_ERRORS as exc:
                    self._silent_drop(sock, f"phase one parse failure: {exc}")
                    raise SilentDropError(f"phase one parse failure: {exc}") from exc
        finally:
            try:
                sock.settimeout(old_timeout)
            except OSError:
                pass

        self._peer_frame_raw = peer_frame_raw

        # Parameter JSON parsing: all errors converge (responder -> silent drop; initiator -> disconnect with an error)
        try:
            payload = json.loads(param_raw.decode("utf-8"))
            peer_params = ISOSTRESSParams.from_wire(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            reason = f"parameter JSON invalid: {exc}"
            self._drop_or_raise(sock, reason)
            return
        except ISOSTRESSParamError as exc:
            self._drop_or_raise(sock, str(exc))
            return

        # Seven-item matching check (fixed order per F.1; stop at the first inequality)
        mismatch = self.params.match_error(peer_params)
        if mismatch is not None:
            self._drop_or_raise(sock, f"parameter mismatch: {mismatch}")
            return

        # Peer nonce length contract (the only check in the core protocol)
        if peer_nonce is None or len(peer_nonce) * 8 != peer_params.random_len:
            self._drop_or_raise(
                sock, "peer nonce length does not match declared random_len"
            )
            return

        self._peer_nonce = peer_nonce

        # Only after every parameter check passes does the responder send back its own frame (Appendix F.1 exchange order)
        if self.role == ROLE_RESPONDER:
            old_timeout = sock.gettimeout()
            try:
                sock.settimeout(HANDSHAKE_TIMEOUT)
                sock.sendall(local_frame)
            finally:
                try:
                    sock.settimeout(old_timeout)
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Phase two: key synchronization (Appendix F.3)
    # ------------------------------------------------------------------
    def _phase2(self, sock: socket.socket) -> None:
        priv, pub = self.suite.generate_ephemeral_keypair()
        self._local_pub = pub

        old_timeout = sock.gettimeout()
        try:
            sock.settimeout(HANDSHAKE_TIMEOUT)
            # The total deadline baseline must be taken after settimeout (it is None in blocking mode)
            deadline = time.monotonic() + HANDSHAKE_TIMEOUT

            if self.role == ROLE_INITIATOR:
                session_salt = secure_random(SESSION_SALT_LEN)
                self._session_salt = session_salt
                sock.sendall(pack_initiator_key(pub, session_salt))
                peer_pub = read_pub_key(sock, deadline)
                self._peer_pub = peer_pub
                # The initiator has already sent its frame: disconnecting on a cryptographic error is normal behavior (F.2 asymmetry)
                dh = self.suite.dh_exchange(priv, peer_pub)
            else:
                try:
                    peer_pub = read_pub_key(sock, deadline)
                    session_salt = read_exact(
                        sock, SESSION_SALT_LEN, "session_salt", deadline
                    )
                except _FRAME_ERRORS as exc:
                    self._silent_drop(sock, f"phase two frame error: {exc}")
                    raise SilentDropError(f"phase two frame error: {exc}") from exc
                self._session_salt = session_salt
                self._peer_pub = peer_pub
                try:
                    # DH is moved ahead of sending any byte (F.3 ordering constraint: the premise for low-order point silent drop)
                    dh = self.suite.dh_exchange(priv, peer_pub)
                except ISOSTRESSCryptoError as exc:
                    self._silent_drop(sock, f"phase two key agreement failed: {exc}")
                    raise SilentDropError(
                        f"phase two key agreement failed: {exc}"
                    ) from exc
                sock.sendall(pack_responder_key(pub))
        finally:
            try:
                sock.settimeout(old_timeout)
            except OSError:
                pass

        # MK = HKDF-<hash_name>(IKM = PSK ‖ DH, salt = session_salt,
        #                    info = "ISOSTRESS-MK-v3", L = key_len)
        # session_salt is the salt parameter of HKDF, not material concatenated into IKM (common-mistake correction)
        psk_bytes = bytes(self.psk)
        mk = self.suite.hkdf(
            psk_bytes + dh, INFO_MK, self.params.key_len, salt=self._session_salt
        )
        self._mk = bytearray(mk)

    # ------------------------------------------------------------------
    # Phase three: anchor locking (Appendix F.4, send first, then compare)
    # ------------------------------------------------------------------
    def _build_transcript(self) -> bytes:
        """transcript = initiator's phase-one raw frame ‖ responder's phase-one raw frame ‖ session_salt
        ‖ initiator's ephemeral public key ‖ responder's ephemeral public key (both sides
        assemble independently with the same formula; order fixed; the raw frames carry all length prefixes, byte for byte).

        No protocol identifier: transcript contains no version string.
        """
        if self._local_frame_raw is None or self._peer_frame_raw is None:
            raise ISOSTRESSProtocolError("phase one raw frames not initialized")
        if self._session_salt is None:
            raise ISOSTRESSProtocolError("session salt not initialized")
        if self._local_pub is None or self._peer_pub is None:
            raise ISOSTRESSProtocolError("ephemeral public keys not initialized")
        if self.role == ROLE_INITIATOR:
            init_frame, resp_frame = self._local_frame_raw, self._peer_frame_raw
            init_pub, resp_pub = self._local_pub, self._peer_pub
        else:
            init_frame, resp_frame = self._peer_frame_raw, self._local_frame_raw
            init_pub, resp_pub = self._peer_pub, self._local_pub
        return init_frame + resp_frame + self._session_salt + init_pub + resp_pub

    def _phase3(self, sock: socket.socket) -> None:
        if self._mk is None:
            raise ISOSTRESSProtocolError(
                "phase two not completed, cannot compute anchor"
            )
        mk_bytes = bytes(self._mk)

        # Anchor / session ID / directional EK (Appendix F.4 and 4.2.3)
        anchor = self.suite.hmac(mk_bytes, INFO_ANCHOR)
        self._anchor = bytearray(anchor)
        session_id = self.suite.hkdf(anchor, INFO_SID, 256)[:SESSION_ID_LEN]
        self._session_id = session_id

        role_byte = b"\x01" if self.role == ROLE_INITIATOR else b"\x02"
        peer_role_byte = b"\x02" if self.role == ROLE_INITIATOR else b"\x01"
        self._ek_send = bytearray(
            self.suite.hkdf(mk_bytes + anchor + role_byte, INFO_EK, self.params.key_len)
        )
        self._ek_recv = bytearray(
            self.suite.hkdf(
                mk_bytes + anchor + peer_role_byte, INFO_EK, self.params.key_len
            )
        )

        transcript = self._build_transcript()
        if self.role == ROLE_INITIATOR:
            local_label, peer_label = INFO_CONFIRM_INIT, INFO_CONFIRM_RESP
        else:
            local_label, peer_label = INFO_CONFIRM_RESP, INFO_CONFIRM_INIT
        local_tag = self.suite.hmac(mk_bytes, local_label + transcript)
        expected_peer_tag = self.suite.hmac(mk_bytes, peer_label + transcript)

        old_timeout = sock.gettimeout()
        try:
            sock.settimeout(HANDSHAKE_TIMEOUT)
            deadline = time.monotonic() + HANDSHAKE_TIMEOUT
            if self.role == ROLE_INITIATOR:
                sock.sendall(pack_confirm(local_tag))
                peer_tag = read_confirm(sock, deadline)
            else:
                # Send first, then compare (common-mistake correction): the responder silently
                # drops on frame-level errors only; its own tag is sent before the peer's tag content is validated
                try:
                    peer_tag = read_confirm(sock, deadline)
                except _FRAME_ERRORS as exc:
                    self._silent_drop(sock, f"phase three frame error: {exc}")
                    raise SilentDropError(f"phase three frame error: {exc}") from exc
                sock.sendall(pack_confirm(local_tag))
        finally:
            try:
                sock.settimeout(old_timeout)
            except OSError:
                pass

        if len(peer_tag) != CONFIRM_TAG_LEN:
            self._wipe_keys()
            raise ISOSTRESSSecurityError(
                "anchor confirmation failed - confirm tag length invalid"
            )
        if not constant_time_compare(expected_peer_tag, peer_tag):
            self._wipe_keys()
            raise ISOSTRESSSecurityError(
                "anchor confirmation failed - PSK mismatch, role mismatch, or reflection/man-in-the-middle attack"
            )

        self._handshake_complete = True
        # Root key wipe (4.2.3 step 6): MK, anchor, and PSK are all zeroed
        self._wipe_keys()

    # ------------------------------------------------------------------
    # Cleanup (Appendix H.6)
    # ------------------------------------------------------------------
    def _wipe_keys(self) -> None:
        secure_zero(self._mk)
        self._mk = None
        secure_zero(self._anchor)
        self._anchor = None
        secure_zero(self.psk)
        self.psk = None

    def wipe(self) -> None:
        """Full cleanup (idempotent): uniformly called on handshake failure paths; never exits while holding keys."""
        self._wipe_keys()
        self._session_salt = None
        self._session_id = None
        secure_zero(self._ek_send)
        self._ek_send = None
        secure_zero(self._ek_recv)
        self._ek_recv = None
        self._local_pub = None
        self._peer_pub = None
        self._local_nonce = None
        self._peer_nonce = None
        self._local_frame_raw = None
        self._peer_frame_raw = None
        self._handshake_complete = False

    # ------------------------------------------------------------------
    # Handshake entry point (Appendix H.1/H.2)
    # ------------------------------------------------------------------
    def perform_handshake(self, sock: socket.socket) -> SessionMaterial:
        """Runs phase one → two → three. Any step failing: uniformly wipes all
        PSK/MK/anchor/EK material, then re-raises as-is (Appendix H.6). On success: returns the session material and restores the data-phase timeout."""
        old_timeout = sock.gettimeout()
        try:
            self._phase1(sock)
            self._phase2(sock)
            self._phase3(sock)
        except Exception:
            self.wipe()
            raise

        material = SessionMaterial(
            session_id=self._session_id,
            send_ek=self._ek_send,
            recv_ek=self._ek_recv,
            local_hash=self.local_hash,
            peer_hash=self.peer_hash,
            params=self.params,
            time_window=self.time_window,
            padding=self.padding,
            jitter=self.jitter,
        )
        # EK ownership transfers to the session layer; this side only releases the reference (the original bytearray object is held by the session)
        self._ek_send = None
        self._ek_recv = None
        self._session_id = None

        # Timeout split: the handshake uses a 15s timeout; the data phase uses 60s
        restore_timeout = old_timeout if old_timeout is not None else DATA_TIMEOUT
        try:
            sock.settimeout(restore_timeout)
        except OSError:
            pass
        return material
