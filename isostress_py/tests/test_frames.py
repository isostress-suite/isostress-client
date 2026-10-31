# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Frame codec tests (Appendix F: cap pre-validation, total-deadline read, nonce/AAD construction)."""

import socket
import struct
import time

import pytest

from isostress_py.errors import ISOSTRESSProtocolError, ISOSTRESSTimeoutError
from isostress_py.frames import (
    MIN_PAYLOAD_LEN,
    build_aad,
    gcm_nonce,
    pack_data_packet,
    pack_initiator_key,
    pack_phase_one,
    pack_responder_key,
    read_data_header,
    read_exact,
    unpack_phase_one,
)


# =============================================================================
# Phase one frame
# =============================================================================


def test_phase_one_round_trip() -> None:
    frame = pack_phase_one(b'{"a":1}', b"i" * 32 + b"p" * 32, b"n" * 32)
    left, right = socket.socketpair()
    try:
        left.settimeout(2)
        right.settimeout(2)
        left.sendall(frame)
        raw, param_raw, identity, nonce = unpack_phase_one(right)
        assert raw == frame
        assert param_raw == b'{"a":1}'
        assert identity == b"i" * 32 + b"p" * 32
        assert nonce == b"n" * 32
    finally:
        left.close()
        right.close()


def test_phase_one_rejects_oversize_before_read() -> None:
    # Cap check precedes payload read: param_len over 4096 -> reject immediately without reading payload
    left, right = socket.socketpair()
    try:
        left.settimeout(2)
        right.settimeout(2)
        left.sendall(
            struct.pack(">I", 4097) + b"x" * 100
        )  # Intentionally partial payload
        with pytest.raises(ISOSTRESSProtocolError):
            unpack_phase_one(right)
    finally:
        left.close()
        right.close()


def test_phase_one_pack_limits() -> None:
    with pytest.raises(ISOSTRESSProtocolError):
        pack_phase_one(b"x" * 4097, b"", b"")
    with pytest.raises(ISOSTRESSProtocolError):
        pack_phase_one(b"{}", b"x" * 8193, b"")
    with pytest.raises(ISOSTRESSProtocolError):
        pack_phase_one(b"{}", b"", b"x" * 513)


# =============================================================================
# Phase two/three frame
# =============================================================================


def test_key_frames_layout() -> None:
    # Initiator frame 68B: [len=32][pk 32][salt 32]; responder frame 36B
    init = pack_initiator_key(b"\x01" * 32, b"\x02" * 32)
    assert len(init) == 68
    assert init == struct.pack(">I", 32) + b"\x01" * 32 + b"\x02" * 32
    resp = pack_responder_key(b"\x03" * 32)
    assert len(resp) == 36


def test_confirm_length_must_be_32() -> None:
    from isostress_py.frames import pack_confirm, read_confirm

    with pytest.raises(ISOSTRESSProtocolError):
        pack_confirm(b"x" * 31)
    left, right = socket.socketpair()
    try:
        left.settimeout(2)
        right.settimeout(2)
        left.sendall(struct.pack(">I", 16) + b"x" * 16)  # confirm_len != 32
        with pytest.raises(ISOSTRESSProtocolError):
            read_confirm(right, None)
    finally:
        left.close()
        right.close()


# =============================================================================
# Phase four header and nonce/AAD
# =============================================================================


def test_data_header_round_trip() -> None:
    packet = pack_data_packet(b"s" * 32, 7, b"c" * 10)
    assert packet[:32] == b"s" * 32
    assert packet[32:40] == struct.pack(">Q", 7)
    left, right = socket.socketpair()
    try:
        left.settimeout(2)
        right.settimeout(2)
        left.sendall(packet)
        sid, seq, ct_len = read_data_header(right, None)
        assert sid == b"s" * 32
        assert seq == 7
        assert ct_len == 10
    finally:
        left.close()
        right.close()


def test_data_header_rejects_oversize_ciphertext() -> None:
    left, right = socket.socketpair()
    try:
        left.settimeout(2)
        right.settimeout(2)
        left.sendall(
            b"s" * 32 + struct.pack(">Q", 1) + struct.pack(">I", (1 << 20) + 1)
        )
        with pytest.raises(ISOSTRESSProtocolError):
            read_data_header(right, None)
    finally:
        left.close()
        right.close()


def test_min_payload_len_is_105() -> None:
    # Heartbeat packet inner payload: ts(8)+fmt(1)+dst(32)+src(32)+next_seed(32) = 105 (F.5)
    assert MIN_PAYLOAD_LEN == 105


def test_gcm_nonce_and_aad() -> None:
    assert gcm_nonce(0) == b"\x00" * 12
    assert gcm_nonce(7) == b"\x00" * 4 + b"\x00" * 7 + b"\x07"
    aad = build_aad(b"s" * 32, 7)
    assert aad == b"s" * 32 + struct.pack(">Q", 7)


# =============================================================================
# Total-deadline read (Appendix H.3 Slowloris protection)
# =============================================================================


def test_read_exact_total_deadline_not_per_recv() -> None:
    # Attacker sends 1 byte every <timeout: the whole frame shares one deadline; fail when the budget is exhausted
    left, right = socket.socketpair()
    try:
        left.settimeout(2)
        right.settimeout(2)
        left.sendall(b"a")  # Send only 1 byte; the read expects 2 bytes
        started = time.monotonic()
        with pytest.raises(ISOSTRESSTimeoutError):
            read_exact(right, 2, deadline=started + 0.2)
        elapsed = time.monotonic() - started
        assert elapsed < 1.0  # Far below the 2s+2s of per-byte re-timing
    finally:
        left.close()
        right.close()


def test_read_exact_partial_then_eof_closes() -> None:
    # Partial packet then EOF: frame sync already broken -> ConnectionError
    left, right = socket.socketpair()
    try:
        left.settimeout(2)
        right.settimeout(2)
        left.sendall(b"ab")
        left.close()
        with pytest.raises(ConnectionError):
            read_exact(right, 4)
    finally:
        right.close()
