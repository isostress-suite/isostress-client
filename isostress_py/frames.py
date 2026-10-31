# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Online frame encode/decode (Master Guide, Appendix F).

Four frame classes (F.1/F.3/F.4/F.5), all big-endian (network byte order),
length-prefix mode, no magic, no frame-type field, no frame-level CRC:

  Phase 1     [param_len(4)][param_json][identity_len(4)][identity][nonce_len(4)][nonce]
  Phase 2 initiation [pub_len(4)][pk_A(32)][session_salt(32)]     (68B)
  Phase 2 response [pub_len(4)][pk_B(32)]                        (36B)
  Phase 3     [confirm_len(4)][tag(32)]                     (36B)
  Phase 4     [session_id(32)][seq(8)][ct_len(4)][ciphertext+tag]

**Size-limit checks must come before reading the corresponding payload**
(Appendix F intro) - this is the first gate against memory bombs;
never "allocate memory to the length declared by the peer".

Reading uses a **frame-wide shared deadline** (Appendix H.3 Slowloris
defense): the whole read shares one total budget, not one timeout per
recv; budget exhausted after partial bytes = frame sync broken,
force-close the socket (half-packet timeout); zero bytes read (initial
timeout) stays open, allowing the upper layer to safely retry.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any, Optional, Tuple

from .crypto import NEXT_SEED_LEN, SESSION_SALT_LEN, X25519_PUB_LEN
from .errors import ISOSTRESSProtocolError, ISOSTRESSTimeoutError
from .params import MAX_CIPHERTEXT, MAX_IDENTITY, MAX_NONCE, MAX_PARAM_JSON

LEN_FIELD: int = 4
CONFIRM_TAG_LEN: int = 32
SEQ_LEN: int = 8
TIMESTAMP_LEN: int = 8
TOKEN_HASH_LEN: int = 32
SESSION_ID_LEN: int = 32
FMT_LEN: int = 1
PAD_LEN_FIELD: int = 2
FMT_NO_PADDING: int = 0x00
FMT_PADDING: int = 0x01
RECV_CHUNK: int = 8192

# Minimum Phase 4 payload = ts(8) + fmt(1) + dst(32) + src(32) + next_seed(32) (heartbeat packet)
MIN_PAYLOAD_LEN: int = (
    TIMESTAMP_LEN + FMT_LEN + TOKEN_HASH_LEN * 2 + NEXT_SEED_LEN
)  # 105


def force_close_socket(sock: socket.socket) -> None:
    """Force-close the socket, ignoring all errors (frame synchronization is already broken after a half-packet timeout; this is the only way out)."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def read_exact(
    sock: socket.socket,
    n: int,
    field_name: str = "data",
    deadline: Optional[float] = None,
) -> bytes:
    """Deterministically read n bytes from the socket (Appendix H.3
    total-timeout semantics).

    - deadline is a monotonic time point; the whole read shares that
      budget, and before each recv the timeout is reset to the remaining
      time - an attacker cannot stall it forever by "sending 1 byte every 14 s";
    - initial timeout (no bytes read): raise ISOSTRESSTimeoutError, socket not closed;
    - half-packet timeout (budget exhausted after partial bytes): frame
      synchronization broken, force-close the socket;
    - peer closed / connection error: raise ConnectionError and force-close.
    """
    if n <= 0:
        return b""
    if deadline is None:
        timeout = sock.gettimeout()
        deadline = time.monotonic() + timeout if timeout is not None else None
    saved_timeout = sock.gettimeout()
    buf = bytearray(n)
    view = memoryview(buf)
    offset = 0
    try:
        while offset < n:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    if offset > 0:
                        force_close_socket(sock)
                        raise ISOSTRESSTimeoutError(
                            f"reading {field_name} half-packet timeout (total deadline exhausted),"
                            f"frame synchronization broken, connection closed"
                        )
                    raise ISOSTRESSTimeoutError(
                        f"reading {field_name} timed out (total deadline exhausted, Slowloris defense)"
                    )
                sock.settimeout(remaining)
            try:
                chunk = sock.recv(min(n - offset, RECV_CHUNK))
            except socket.timeout:
                if offset > 0:
                    force_close_socket(sock)
                    raise ISOSTRESSTimeoutError(
                        f"reading {field_name} half-packet timeout, frame synchronization broken, connection closed"
                    )
                raise ISOSTRESSTimeoutError(
                    f"reading {field_name} timed out (data-stage timeout or network latency)"
                )
            if not chunk:
                force_close_socket(sock)
                raise ConnectionError(
                    "connection closed by peer before the read completed"
                )
            view[offset : offset + len(chunk)] = chunk
            offset += len(chunk)
        return bytes(buf)
    except ISOSTRESSTimeoutError:
        raise
    except ConnectionError:
        force_close_socket(sock)
        raise
    except Exception:
        force_close_socket(sock)
        raise
    finally:
        try:
            sock.settimeout(saved_timeout)
        except OSError:
            pass


def _deadline_from(sock: socket.socket, deadline: Optional[float]) -> Optional[float]:
    if deadline is not None:
        return deadline
    timeout = sock.gettimeout()
    return time.monotonic() + timeout if timeout is not None else None


# =============================================================================
# Phase 1 frame (Appendix F.1)
# =============================================================================


def pack_phase_one(param_json: bytes, identity: bytes, nonce: bytes) -> bytes:
    """Encode a Phase 1 frame. The size limits also apply on the encoding side (expose local misconfiguration early)."""
    if len(param_json) > MAX_PARAM_JSON:
        raise ISOSTRESSProtocolError("parameter payload exceeds the size limit")
    if len(identity) > MAX_IDENTITY:
        raise ISOSTRESSProtocolError(
            "identity announcement payload exceeds the size limit"
        )
    if len(nonce) > MAX_NONCE:
        raise ISOSTRESSProtocolError("nonce too long")
    return (
        struct.pack(">I", len(param_json))
        + param_json
        + struct.pack(">I", len(identity))
        + identity
        + struct.pack(">I", len(nonce))
        + nonce
    )


def unpack_phase_one(
    sock: socket.socket, deadline: Optional[float] = None
) -> Tuple[bytes, Any, bytes, bytes]:
    """Read a Phase 1 frame. Returns (raw frame bytes, parameter JSON bytes,
    identity_blob, nonce).

    The raw frame bytes (including all length prefixes) must be kept as-is
    - they enter the Phase 3 transcript, and any "canonicalized re-encoding"
    would cause the confirmation tag to mismatch (Appendix F.0, Convention 6).
    """
    deadline = _deadline_from(sock, deadline)
    parts = []

    plen = struct.unpack(">I", read_exact(sock, LEN_FIELD, "param_len", deadline))[0]
    if plen > MAX_PARAM_JSON:
        raise ISOSTRESSProtocolError("parameter payload exceeds the size limit")
    param_raw = read_exact(sock, plen, "param_payload", deadline)
    parts += [struct.pack(">I", plen), param_raw]

    ilen = struct.unpack(">I", read_exact(sock, LEN_FIELD, "identity_len", deadline))[0]
    if ilen > MAX_IDENTITY:
        raise ISOSTRESSProtocolError(
            "identity announcement payload exceeds the size limit"
        )
    identity = read_exact(sock, ilen, "identity_blob", deadline)
    parts += [struct.pack(">I", ilen), identity]

    nlen = struct.unpack(">I", read_exact(sock, LEN_FIELD, "nonce_len", deadline))[0]
    if nlen > MAX_NONCE:
        raise ISOSTRESSProtocolError("nonce too long")
    nonce = read_exact(sock, nlen, "nonce", deadline)
    parts += [struct.pack(">I", nlen), nonce]

    return b"".join(parts), param_raw, identity, nonce


# =============================================================================
# Phase 2 frame (Appendix F.3)
# =============================================================================


def pack_initiator_key(pub: bytes, session_salt: bytes) -> bytes:
    """Initiator frame: [pub_len(4)][pk_A(32)][session_salt(32)], 68B total."""
    if len(pub) != X25519_PUB_LEN:
        raise ISOSTRESSProtocolError("ephemeral public key length abnormal")
    if len(session_salt) != SESSION_SALT_LEN:
        raise ISOSTRESSProtocolError("session salt length abnormal")
    return struct.pack(">I", len(pub)) + pub + session_salt


def pack_responder_key(pub: bytes) -> bytes:
    """Responder frame: [pub_len(4)][pk_B(32)], 36B total."""
    if len(pub) != X25519_PUB_LEN:
        raise ISOSTRESSProtocolError("ephemeral public key length abnormal")
    return struct.pack(">I", len(pub)) + pub


def read_pub_key(sock: socket.socket, deadline: Optional[float]) -> bytes:
    """Read [pub_len(4)][pk(32)]; pub_len != 32 makes the frame invalid."""
    pub_len = struct.unpack(">I", read_exact(sock, LEN_FIELD, "pub_len", deadline))[0]
    if pub_len != X25519_PUB_LEN:
        raise ISOSTRESSProtocolError("peer public key length abnormal")
    return read_exact(sock, pub_len, "peer_pub", deadline)


# =============================================================================
# Phase 3 frame (Appendix F.4)
# =============================================================================


def pack_confirm(tag: bytes) -> bytes:
    """Confirmation frame: [confirm_len(4)][tag(32)], 36B total."""
    if len(tag) != CONFIRM_TAG_LEN:
        raise ISOSTRESSProtocolError("confirmation tag length mismatch")
    return struct.pack(">I", len(tag)) + tag


def read_confirm(sock: socket.socket, deadline: Optional[float]) -> bytes:
    """Read the confirmation frame. confirm_len != 32 makes the frame invalid
    (frame-level error -> the responder stays silent)."""
    tlen = struct.unpack(">I", read_exact(sock, LEN_FIELD, "confirm_len", deadline))[0]
    if tlen != CONFIRM_TAG_LEN:
        raise ISOSTRESSProtocolError("confirmation tag length abnormal")
    return read_exact(sock, tlen, "confirm_tag", deadline)


# =============================================================================
# Phase 4 data packets (Appendix F.5)
# =============================================================================


def pack_data_packet(session_id: bytes, seq: int, ciphertext: bytes) -> bytes:
    """Data packet: [session_id(32)][seq(8)][ct_len(4)][ciphertext+tag]."""
    if len(session_id) != SESSION_ID_LEN:
        raise ISOSTRESSProtocolError("session_id length mismatch")
    if len(ciphertext) > MAX_CIPHERTEXT:
        raise ISOSTRESSProtocolError("ciphertext too large")
    return (
        session_id
        + struct.pack(">Q", seq)
        + struct.pack(">I", len(ciphertext))
        + ciphertext
    )


def read_data_header(
    sock: socket.socket, deadline: Optional[float]
) -> Tuple[bytes, int, int]:
    """Read the 44-byte plaintext header of a data packet,
    returning (session_id, seq, ct_len).
    The ct_len limit check runs before the ciphertext is read
    (first gate against memory bombs)."""
    deadline = _deadline_from(sock, deadline)
    session_id = read_exact(sock, SESSION_ID_LEN, "session_id", deadline)
    seq = struct.unpack(">Q", read_exact(sock, SEQ_LEN, "seq", deadline))[0]
    ct_len = struct.unpack(">I", read_exact(sock, LEN_FIELD, "ct_len", deadline))[0]
    if ct_len > MAX_CIPHERTEXT:
        raise ISOSTRESSProtocolError("ciphertext length exceeds the hard limit")
    return session_id, seq, ct_len


def gcm_nonce(seq: int) -> bytes:
    """12B nonce = 0x00000000(4B) || seq(8B uint64 BE) - the monotonically
    increasing sequence number guarantees the nonce is never reused under
    the same key (Appendix F.5)."""
    return b"\x00" * 4 + struct.pack(">Q", seq)


def build_aad(session_id: bytes, seq: int) -> bytes:
    """AAD = session_id || seq(8B BE) - routing fields are visible but
    tamper-proof (Appendix F.5).

    No protocol identity: no version string of any kind in the on-the-wire
    AAD.
    """
    return session_id + struct.pack(">Q", seq)
