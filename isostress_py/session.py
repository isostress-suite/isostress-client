# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Encrypted data session (Master Guide sections 4.2.4/4.2.5 / appendices F.5 / G).

Core invariants:
- **Consume state first, attempt the send second** (F.5): before the encrypted send, complete in order:
  generate next_seed, derive new_EK, wipe the old EK and swap in new_EK, seq += 1. If the send fails the key
  has already been rolled forward and the session is unrecoverable (reconnect only); an attacker can never
  exploit "a failed send leaving state un-rolled" to replay;
- Receiver validation pipeline in **fixed order** (F.5, eight steps): seq -> session_id -> GCM -> length -> fmt -> structural consistency -> bidirectional token hash -> timestamp window;
- **Special handling of out-of-window packets** (step 8): a packet that passed GCM authentication but
  has a timestamp outside the window still rotates the EK and advances seq_recv, dropping only the plaintext
  -- preventing permanent desynchronization (rotated sender vs. un-rotated receiver); implementers must
  not omit this;
- Security/protocol validation failure: terminate the session + full wipe (appendices H.4/H.6).
"""

from __future__ import annotations

import secrets
import socket
import struct
import threading
import time
from typing import Optional, Tuple

from .crypto import NEXT_SEED_LEN, CryptoSuite, secure_random, secure_zero
from .errors import ISOSTRESSError, ISOSTRESSProtocolError, ISOSTRESSSecurityError
from .frames import (
    FMT_LEN,
    FMT_NO_PADDING,
    FMT_PADDING,
    MIN_PAYLOAD_LEN,
    PAD_LEN_FIELD,
    TIMESTAMP_LEN,
    TOKEN_HASH_LEN,
    build_aad,
    gcm_nonce,
    pack_data_packet,
    read_data_header,
    read_exact,
)
from .handshake import INFO_EK_ROTATE, SessionMaterial
from .params import MAX_PAD, MAX_PLAINTEXT


class SecureSession:
    """Full-duplex encrypted session built from the handshake artifacts (send/receive and ratchet state)."""

    __slots__ = (
        "session_id",
        "send_ek",
        "recv_ek",
        "params",
        "suite",
        "local_hash",
        "peer_hash",
        "time_window",
        "padding",
        "jitter",
        "seq_send",
        "seq_recv",
        "last_recv_drop",
        "_send_lock",
        "_recv_lock",
        "_state_lock",
        "_closed",
    )

    def __init__(self, material: SessionMaterial) -> None:
        self.session_id: Optional[bytes] = material.session_id
        self.send_ek: Optional[bytearray] = material.send_ek
        self.recv_ek: Optional[bytearray] = material.recv_ek
        self.params = material.params
        self.suite = CryptoSuite(material.params.hash_name, material.params.aead_name)
        self.local_hash: bytes = material.local_hash
        self.peer_hash: bytes = material.peer_hash
        self.time_window: int = material.time_window
        self.padding: Optional[Tuple[int, int]] = material.padding
        self.jitter: float = material.jitter
        self.seq_send: int = 0
        self.seq_recv: int = -1
        self.last_recv_drop: Optional[str] = None
        self._send_lock = threading.RLock()
        self._recv_lock = threading.RLock()
        self._state_lock = threading.RLock()
        self._closed = False

    # ------------------------------------------------------------------
    # Sending (appendix F.5: sender-side state forward-rolling)
    # ------------------------------------------------------------------
    def send_packet(self, sock: socket.socket, plaintext: bytes) -> None:
        """Encrypt and send one data packet. Empty plaintext = heartbeat. Send failure = irreversible session
        desynchronization (keys already rolled forward); reconnect only (appendix H.4)."""
        with self._send_lock:
            with self._state_lock:
                if self._closed or self.send_ek is None or self.session_id is None:
                    raise ISOSTRESSError(
                        "Session is irreversibly desynchronized or not yet established; reconnection required"
                    )
                if len(plaintext) > MAX_PLAINTEXT:
                    raise ISOSTRESSProtocolError(
                        f"Plaintext payload too large ({len(plaintext)} > {MAX_PLAINTEXT})"
                    )

                # -- state forward-rolling (completed before encryption) --
                # Working copy of the old EK: mutable, so it can be wiped once the packet is built.
                ek_work = bytearray(self.send_ek)
                seq = self.seq_send
                sid_snapshot = bytes(self.session_id)
                next_seed = secure_random(NEXT_SEED_LEN)
                ikm = bytearray(len(ek_work) + len(next_seed))
                ikm[: len(ek_work)] = ek_work
                ikm[len(ek_work) :] = next_seed
                try:
                    new_ek = self.suite.hkdf(ikm, INFO_EK_ROTATE, self.params.key_len)
                finally:
                    secure_zero(ikm)
                secure_zero(self.send_ek)
                self.send_ek = bytearray(new_ek)
                self.seq_send = seq + 1

            # -- build the internal payload (before encryption): ts(8) || fmt(1) || dst(32) || src(32)
            #    || user plaintext || [random padding || pad_len(2)] || next_seed(32) --
            timestamp = struct.pack(">Q", int(time.time() * 1000))
            fmt = FMT_NO_PADDING
            padding_part = b""
            if self.padding is not None:
                # Random padding removes length fingerprints; decided per packet, can be enabled unilaterally (appendix G.2)
                fmt = FMT_PADDING
                pmin, pmax = self.padding
                pad_len = secrets.randbelow(pmax - pmin + 1) + pmin
                # The pad_len field sits immediately before next_seed: the receiver locates it from a fixed position at the tail
                padding_part = secure_random(pad_len) + struct.pack(">H", pad_len)
            payload = (
                timestamp
                + struct.pack(">B", fmt)
                + self.peer_hash
                + self.local_hash
                + plaintext
                + padding_part
                + bytes(next_seed)
            )

            nonce = gcm_nonce(seq)
            aad = build_aad(sid_snapshot, seq)
            try:
                ciphertext = self.suite.aead_encrypt(ek_work, nonce, payload, aad)
            finally:
                secure_zero(ek_work)
            packet = pack_data_packet(sid_snapshot, seq, ciphertext)

            try:
                if self.jitter > 0:
                    # Timing jitter: purely local send behavior; on-the-wire bytes are unchanged (appendix G.3)
                    time.sleep(secrets.SystemRandom().uniform(0.0, self.jitter))
                sock.sendall(packet)
            except (BrokenPipeError, ConnectionError, OSError) as exc:
                self.wipe()
                raise ISOSTRESSError(
                    f"Send failed; session irreversibly desynchronized: {exc}"
                ) from exc

    # ------------------------------------------------------------------
    # Receiving (appendix F.5: receiver-side validation pipeline, fixed order)
    # ------------------------------------------------------------------
    def recv_packet(self, sock: socket.socket) -> Optional[bytes]:
        """Receive and decrypt one data packet.

        Returns: plaintext bytes; b"" = heartbeat or out-of-window packet (state already advanced); None
        is never returned (a closed connection is expressed as ConnectionError). Security/protocol
        validation failure: after wiping the session, raise ISOSTRESSSecurityError / ISOSTRESSProtocolError
        (appendix H.4: session termination)."""
        with self._recv_lock:
            t = sock.gettimeout()
            deadline = time.monotonic() + t if t is not None else None
            session_id, seq, ct_len = read_data_header(sock, deadline)
            ciphertext = read_exact(sock, ct_len, "ciphertext", deadline)

            with self._state_lock:
                if self._closed or self.recv_ek is None or self.session_id is None:
                    raise ISOSTRESSError(
                        "Session is irreversibly desynchronized or not yet established; reconnection required"
                    )
                # Step 1: seq must strictly increase (seq_recv is initialized to -1)
                if seq <= self.seq_recv:
                    self._terminate()
                    raise ISOSTRESSSecurityError(
                        f"Replay or out-of-order packet detected: seq={seq} <= last={self.seq_recv}"
                    )
                # Step 2: session ID must match (cross-channel crosstalk / residual old session)
                if session_id != bytes(self.session_id):
                    self._terminate()
                    raise ISOSTRESSSecurityError(
                        "Session ID mismatch; dropping packet (sub-channel crosstalk or residual old session)"
                    )
                ek_work = bytearray(self.recv_ek)
                aad = build_aad(session_id, seq)

            try:
                try:
                    # Step 3: GCM decryption and authentication (AAD takes part in authentication)
                    payload = self.suite.aead_decrypt(
                        ek_work, gcm_nonce(seq), ciphertext, aad
                    )
                finally:
                    secure_zero(ek_work)
                plaintext = self._validate_payload(payload, seq)
            except (ISOSTRESSSecurityError, ISOSTRESSProtocolError):
                self._terminate()
                raise

            return plaintext

    def _validate_payload(self, payload: bytes, seq: int) -> bytes:
        """Pipeline steps 4-8. Returns the plaintext; heartbeat / out-of-window returns b"" (state already advanced)."""
        with self._state_lock:
            # Step 4: minimum payload length (105B, heartbeat packet size)
            if len(payload) < MIN_PAYLOAD_LEN:
                raise ISOSTRESSProtocolError(
                    "Payload too short to extract internal structure"
                )

            # Step 5: payload format marker
            fmt = payload[TIMESTAMP_LEN]
            if fmt not in (FMT_NO_PADDING, FMT_PADDING):
                raise ISOSTRESSSecurityError(
                    f"Unknown payload format marker: {fmt:#04x}"
                )

            # Step 6: structural length consistency (guards against out-of-bounds / negative slicing; pad_len sits at bytes 34-33 from the payload end)
            header_end = TIMESTAMP_LEN + FMT_LEN + TOKEN_HASH_LEN * 2
            next_seed = payload[-NEXT_SEED_LEN:]
            tail = NEXT_SEED_LEN
            if fmt == FMT_PADDING:
                pad_len = struct.unpack(
                    ">H", payload[-NEXT_SEED_LEN - PAD_LEN_FIELD : -NEXT_SEED_LEN]
                )[0]
                if pad_len > MAX_PAD:
                    raise ISOSTRESSProtocolError(
                        f"Padding length exceeds maximum: {pad_len}"
                    )
                tail += PAD_LEN_FIELD + pad_len
            if header_end + tail > len(payload):
                raise ISOSTRESSProtocolError("Contradictory payload structure lengths")
            plaintext = payload[header_end : len(payload) - tail]

            # Step 7: bidirectional token hash check (traffic reflection / crosstalk / identity spoofing)
            dst_hash = payload[
                TIMESTAMP_LEN + FMT_LEN : TIMESTAMP_LEN + FMT_LEN + TOKEN_HASH_LEN
            ]
            src_hash = payload[TIMESTAMP_LEN + FMT_LEN + TOKEN_HASH_LEN : header_end]
            if dst_hash != self.local_hash:
                raise ISOSTRESSSecurityError(
                    "Destination token hash mismatch (sub-channel crosstalk or traffic reflection)"
                )
            if src_hash != self.peer_hash:
                raise ISOSTRESSSecurityError(
                    "Source token hash mismatch (identity spoofing)"
                )

            # Ratchet rotation + sequence number advance (must be completed before step 8 -- out-of-window packets are also rolled forward)
            # The HKDF input is a mutable working copy so it can be wiped after
            # use, symmetrically with the send side. hkdf() returns bytes, so the
            # derived copy below cannot be zeroed from Python; only the input is.
            ikm = bytearray(self.recv_ek)
            ikm += bytearray(next_seed)
            try:
                new_ek = self.suite.hkdf(
                    ikm,
                    INFO_EK_ROTATE,
                    self.params.key_len,
                )
            finally:
                secure_zero(ikm)
            secure_zero(self.recv_ek)
            self.recv_ek = bytearray(new_ek)
            self.seq_recv = seq

            # Step 8: timestamp window -- for an out-of-window but authenticated packet: only the plaintext is dropped, the session is not terminated
            ts = struct.unpack(">Q", payload[:TIMESTAMP_LEN])[0]
            now_ms = int(time.time() * 1000)
            if abs(now_ms - ts) > self.time_window * 1000:
                self.last_recv_drop = (
                    f"timestamp_window: ts={ts / 1000:.1f}s, now={now_ms / 1000:.1f}s"
                )
                return b""

            self.last_recv_drop = None
            return plaintext

    # ------------------------------------------------------------------
    # Cleanup (appendix H.6: idempotent)
    # ------------------------------------------------------------------
    def _terminate(self) -> None:
        """Security/protocol validation failure path: wipe fully and immediately (idempotent)."""
        self.wipe()

    def wipe(self) -> None:
        """Wipe all session key material and reset the state (safe to call repeatedly)."""
        with self._state_lock:
            self._closed = True
            secure_zero(self.send_ek)
            self.send_ek = None
            secure_zero(self.recv_ek)
            self.recv_ek = None
            self.session_id = None
            self.seq_send = 0
            self.seq_recv = -1
            self.last_recv_drop = None

    @property
    def is_active(self) -> bool:
        return not self._closed and self.send_ek is not None
