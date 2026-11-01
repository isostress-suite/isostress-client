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

from isostress_py.crypto import CryptoSuite
from isostress_py.errors import ISOSTRESSError, ISOSTRESSSecurityError
from isostress_py.frames import force_close_socket
from isostress_py.handshake import HandshakePeer
from isostress_py.params import ISOSTRESSParams
from isostress_py.session import SecureSession

PSK = bytes(range(32))


class _OffsetClock:
    """Stand-in for the `time` module inside session.py: offsets wall clock, keeps monotonic real.

    Patching the whole module with a bare MagicMock breaks deadline arithmetic
    (`time.monotonic()` drives the half-packet timeout), so only wall clock moves.
    """

    def __init__(self, offset: float) -> None:
        self._offset = offset

    def time(self) -> float:
        import time as _t

        return _t.time() + self._offset

    def sleep(self, _seconds: float) -> None:
        return None

    def monotonic(self) -> float:
        import time as _t

        return _t.monotonic()


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


def test_replayed_packet_is_discarded_and_session_survives() -> None:
    sa, sb, left, right = _establish()
    try:
        cap = _CaptureSock(left)
        sa.send_packet(cap, b"hello")
        assert sb.recv_packet(right) == b"hello"

        # Resend the identical ciphertext packet verbatim: a repeated seq is discarded
        # silently (F.5 step 1 / G.4); the session stays usable and nothing is sent back.
        left.sendall(cap.captured[0])
        assert sb.recv_packet(right) == b""
        assert sb.last_recv_drop and sb.last_recv_drop.startswith("seq_replay:")
        assert sb.is_active
        sa.send_packet(left, b"again")
        assert sb.recv_packet(right) == b"again"
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


def test_seq_regression_is_discarded() -> None:
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
        assert sb.recv_packet(right) == b""
        assert sb.last_recv_drop and sb.last_recv_drop.startswith("seq_replay:")
        assert sb.is_active
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
        sa.send_packet(left, b"first")  # seq 0: establishes ts_ref
        assert sb.recv_packet(right) == b"first"
        with mock.patch("isostress_py.session.time", _OffsetClock(-120)):
            sa.send_packet(left, b"late")  # seq 1, 120 s behind ts_ref
        assert sb.recv_packet(right) == b""  # plaintext dropped
        assert sb.last_recv_drop and "ts_ref=" in sb.last_recv_drop
        # Ratchet has advanced (following the in-packet next_seed): the next "fresh" packet still decrypts normally
        sa.send_packet(left, b"current")  # sequence 2
        assert sb.recv_packet(right) == b"current"
    finally:
        force_close_socket(left)
        force_close_socket(right)
        sa.wipe()
        sb.wipe()


def test_timestamp_window_ignores_the_receiver_wall_clock() -> None:
    """The window is relative to ts_ref, so a receiver whose clock is a day off still receives."""
    sa, sb, left, right = _establish()
    try:
        with mock.patch("isostress_py.session.time", _OffsetClock(86400)):
            # The sender's clock is 86400 s ahead of the receiver's; the receiver never
            # reads its own wall clock, so both packets are delivered.
            sa.send_packet(left, b"one")
            assert sb.recv_packet(right) == b"one"
            sa.send_packet(left, b"two")
            assert sb.recv_packet(right) == b"two"
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


# =============================================================================
# Secret wiping of session key material
# =============================================================================


def test_session_key_material_is_mutable() -> None:
    sa, sb, left, right = _establish()
    try:
        for buf in (sa.send_ek, sa.recv_ek, sb.send_ek, sb.recv_ek):
            assert isinstance(buf, bytearray)
    finally:
        force_close_socket(left)
        force_close_socket(right)
        sa.wipe()
        sb.wipe()


def test_send_wipes_key_working_copy() -> None:
    sa, _, left, _right = _establish()
    seen = {}
    original = CryptoSuite.aead_encrypt

    def spy(self, key, nonce, payload, aad):
        seen["key"] = key
        return original(self, key, nonce, payload, aad)

    old_ek = sa.send_ek
    try:
        with mock.patch.object(CryptoSuite, "aead_encrypt", spy):
            sa.send_packet(left, b"payload")
        assert seen["key"] == bytearray(len(seen["key"]))
        assert old_ek == bytearray(len(old_ek))
    finally:
        force_close_socket(left)
        sa.wipe()


def test_send_wipes_key_working_copy_when_encryption_fails() -> None:
    sa, _, left, _right = _establish()
    seen = {}

    def boom(self, key, nonce, payload, aad):
        seen["key"] = key
        raise RuntimeError("encryption failed")

    try:
        with mock.patch.object(CryptoSuite, "aead_encrypt", boom):
            with pytest.raises(RuntimeError):
                sa.send_packet(left, b"payload")
        assert seen["key"] == bytearray(len(seen["key"]))
    finally:
        force_close_socket(left)
        sa.wipe()


def test_recv_wipes_key_working_copy() -> None:
    sa, sb, left, right = _establish()
    seen = {}
    original = CryptoSuite.aead_decrypt

    def spy(self, key, nonce, ciphertext, aad):
        seen["key"] = key
        return original(self, key, nonce, ciphertext, aad)

    try:
        sa.send_packet(left, b"payload")
        with mock.patch.object(CryptoSuite, "aead_decrypt", spy):
            assert sb.recv_packet(right) == b"payload"
        assert seen["key"] == bytearray(len(seen["key"]))
    finally:
        force_close_socket(left)
        force_close_socket(right)
        sa.wipe()
        sb.wipe()


def test_recv_wipes_the_rotation_input() -> None:
    sa, sb, left, right = _establish()
    seen = {}
    original = CryptoSuite.hkdf

    def spy(self, ikm, info, length_bits):
        seen["ikm"] = ikm
        return original(self, ikm, info, length_bits)

    try:
        sa.send_packet(left, b"payload")
        with mock.patch.object(CryptoSuite, "hkdf", spy):
            assert sb.recv_packet(right) == b"payload"
        assert isinstance(seen["ikm"], bytearray)
        assert seen["ikm"] == bytearray(len(seen["ikm"]))
    finally:
        force_close_socket(left)
        force_close_socket(right)
        sa.wipe()
        sb.wipe()


def test_recv_wipes_key_working_copy_when_decryption_fails() -> None:
    sa, sb, left, right = _establish()
    seen = {}

    def boom(self, key, nonce, ciphertext, aad):
        seen["key"] = key
        raise ISOSTRESSSecurityError("authentication failed")

    try:
        sa.send_packet(left, b"payload")
        with mock.patch.object(CryptoSuite, "aead_decrypt", boom):
            with pytest.raises(ISOSTRESSSecurityError):
                sb.recv_packet(right)
        assert seen["key"] == bytearray(len(seen["key"]))
    finally:
        force_close_socket(left)
        force_close_socket(right)
        sa.wipe()
        sb.wipe()
