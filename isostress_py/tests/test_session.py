# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Encryption session tests: round-trip send/recv, replay rejection, AAD tampering, out-of-window ratchet, padding, desync (Appendix F.5/G)."""

import socket
import struct
import threading
from typing import Tuple
from unittest import mock

import pytest

from isostress_py.errors import ISOSTRESSError, ISOSTRESSSecurityError
from isostress_py.frames import force_close_socket
from isostress_py.handshake import HandshakePeer
from isostress_py.params import ISOSTRESSParams
from isostress_py.session import SecureSession

PSK = bytes(range(32))


class _CaptureSock:
    """Lightweight proxy that captures sendall data (socket attributes are read-only; instances cannot be monkeypatched).

    With forward=False it only captures without actually sending (used for tamper-and-reinjection scenarios).
    """

    def __init__(self, sock: socket.socket, forward: bool = True) -> None:
        self._sock = sock
        self.forward = forward
        self.captured: list = []

    def sendall(self, data):
        self.captured.append(bytes(data))
        if self.forward:
            return self._sock.sendall(data)


def _establish() -> Tuple[SecureSession, SecureSession, socket.socket, socket.socket]:
    """Run the full handshake and build both sessions (blocks until success)."""
    a = HandshakePeer(PSK, ISOSTRESSParams(), "initiator")
    b = HandshakePeer(PSK, ISOSTRESSParams(), "responder")
    left, right = socket.socketpair()
    left.settimeout(10)
    right.settimeout(10)
    errors = {}

    def run(peer, sock, side):
        try:
            errors[side] = peer.perform_handshake(sock)
        except Exception as exc:  # noqa: BLE001
            errors[side] = exc

    ta = threading.Thread(target=run, args=(a, left, "ma"))
    tb = threading.Thread(target=run, args=(b, right, "mb"))
    ta.start()
    tb.start()
    ta.join(15)
    tb.join(15)
    assert isinstance(errors["ma"], object) and not isinstance(
        errors["ma"], Exception
    ), f"initiator handshake failed: {errors['ma']}"
    assert not isinstance(errors["mb"], Exception), (
        f"responder handshake failed: {errors['mb']}"
    )
    return SecureSession(errors["ma"]), SecureSession(errors["mb"]), left, right


# =============================================================================
# Basic send/recv
# =============================================================================


def test_round_trip() -> None:
    sa, sb, left, right = _establish()
    try:
        sa.send_packet(left, "hello, isostress".encode("utf-8"))
        assert sb.recv_packet(right) == "hello, isostress".encode("utf-8")
        sb.send_packet(right, b"pong")
        assert sa.recv_packet(left) == b"pong"
    finally:
        force_close_socket(left)
        force_close_socket(right)
        sa.wipe()
        sb.wipe()


def test_heartbeat_empty_payload_and_165b_size() -> None:
    sa, sb, left, right = _establish()
    try:
        # Heartbeat packet = empty plaintext; total on-wire size is 165 B under default parameters (Appendix F.5 measured assertion)
        cap = _CaptureSock(left)
        sa.send_packet(cap, b"")
        assert len(cap.captured[0]) == 165
        # Receiver side: heartbeat yields empty plaintext (silently skipped); ratchet state has advanced
        assert sb.recv_packet(right) == b""
    finally:
        force_close_socket(left)
        force_close_socket(right)
        sa.wipe()
        sb.wipe()


# =============================================================================
# Replay / Tampering
# =============================================================================


def test_replay_rejection_terminates_session() -> None:
    sa, sb, left, right = _establish()
    try:
        cap = _CaptureSock(left)
        sa.send_packet(cap, b"hello")
        assert sb.recv_packet(right) == b"hello"

        # Resend the identical ciphertext packet verbatim (injected from the peer) -> duplicate seq -> security error + session terminated
        left.sendall(cap.captured[0])
        with pytest.raises(ISOSTRESSSecurityError):
            sb.recv_packet(right)
        assert not sb.is_active  # zeroized
    finally:
        force_close_socket(left)
        force_close_socket(right)
        sa.wipe()
        sb.wipe()


def test_tampered_header_fails_aad() -> None:
    sa, sb, left, right = _establish()
    try:
        cap = _CaptureSock(left, forward=False)  # capture only, no sending
        sa.send_packet(cap, b"auth")
        # Tamper the session ID in the plaintext header (offsets 0-31 are sid; flip 1 bit) -> verification fails
        packet = bytearray(cap.captured[0])
        packet[5] ^= 1
        left.sendall(bytes(packet))
        with pytest.raises(ISOSTRESSSecurityError):
            sb.recv_packet(right)
        assert not sb.is_active
    finally:
        force_close_socket(left)
        force_close_socket(right)
        sa.wipe()
        sb.wipe()


def test_seq_regression_rejected() -> None:
    sa, sb, left, right = _establish()
    try:
        sa.send_packet(left, b"one")  # sequence 0
        assert sb.recv_packet(right) == b"one"
        sa.send_packet(left, b"two")  # sequence 1
        assert sb.recv_packet(right) == b"two"
        # Craft a packet with seq=0 directly (the current key has already rotated, so GCM would fail - but the seq check is hit first)
        # Checked against the receiver's current state: header with matching sid but regressed seq (injected from the peer)
        bogus = (
            sb.session_id + struct.pack(">Q", 0) + struct.pack(">I", 16) + b"\x00" * 16
        )
        left.sendall(bogus)
        with pytest.raises(ISOSTRESSSecurityError):
            sb.recv_packet(right)
        assert not sb.is_active
    finally:
        force_close_socket(left)
        force_close_socket(right)
        sa.wipe()
        sb.wipe()


# =============================================================================
# Timestamp window: an out-of-window packet still rotates the EK and advances seq; only the plaintext is dropped (F.5 step 8)
# =============================================================================


def test_stale_timestamp_advances_ratchet_without_plaintext() -> None:
    sa, sb, left, right = _establish()
    try:
        real_time = __import__("time").time
        with mock.patch("isostress_py.session.time") as fake_time:
            fake_time.time.return_value = (
                real_time() - 120
            )  # timestamp 120 s in the past
            fake_time.sleep.return_value = None
            sa.send_packet(left, b"late")  # seq 0, out of window
        assert sb.recv_packet(right) == b""  # plaintext dropped
        # Ratchet has advanced (following the in-packet next_seed): the next "fresh" packet still decrypts normally
        sa.send_packet(left, b"current")  # sequence 1
        assert sb.recv_packet(right) == b"current"
    finally:
        force_close_socket(left)
        force_close_socket(right)
        sa.wipe()
        sb.wipe()


# =============================================================================
# Random padding (Appendix G.2)
# =============================================================================


def test_padding_single_side_interop() -> None:
    # Only the sender enables padding (padding_min=512, padding_max=1024); receiver uses default config
    a = HandshakePeer(PSK, ISOSTRESSParams(), "initiator", padding=(512, 1024))
    b = HandshakePeer(PSK, ISOSTRESSParams(), "responder")
    left, right = socket.socketpair()
    left.settimeout(10)
    right.settimeout(10)
    results = {}

    def run(peer, sock, side):
        results[side] = peer.perform_handshake(sock)

    ta = threading.Thread(target=run, args=(a, left, "ma"))
    tb = threading.Thread(target=run, args=(b, right, "mb"))
    ta.start()
    tb.start()
    ta.join(15)
    tb.join(15)
    sa, sb = SecureSession(results["ma"]), SecureSession(results["mb"])
    try:
        cap = _CaptureSock(left)
        sa.send_packet(cap, b"padded message")
        # Plaintext 14 B + padding 512~1024 B: on-wire packet is far larger than unpadded (105+14+16=135 B)
        assert len(cap.captured[0]) > 105 + 14 + 16 + 512
        assert (
            sb.recv_packet(right) == b"padded message"
        )  # receiver strips padding automatically
    finally:
        force_close_socket(left)
        force_close_socket(right)
        sa.wipe()
        sb.wipe()


# =============================================================================
# Send failure -> irreversible desync (H.4)
# =============================================================================


def test_send_failure_requires_reconnect() -> None:
    sa, _, left, _right = _establish()
    try:
        dead = socket.socket()
        dead.close()  # closed socket -> sendall will raise OSError
        with pytest.raises(ISOSTRESSError, match="irreversibly desynchronized"):
            sa.send_packet(dead, b"payload")
        assert not sa.is_active
        # A subsequent send is likewise rejected after desync
        with pytest.raises(ISOSTRESSError):
            sa.send_packet(dead, b"retry")
    finally:
        force_close_socket(left)
        sa.wipe()


# =============================================================================
# Plaintext size limit
# =============================================================================


def test_oversize_plaintext_rejected() -> None:
    sa, _, left, _right = _establish()
    try:
        from isostress_py.params import MAX_PLAINTEXT

        with pytest.raises(ISOSTRESSError):
            sa.send_packet(left, b"x" * (MAX_PLAINTEXT + 1))
    finally:
        force_close_socket(left)
        sa.wipe()
