# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Four-phase handshake test: both ends succeed, directional key cross-check, confirmation tags, strict silent path (Appendix F/H)."""

import socket
import struct
import threading
from typing import Dict, Tuple

from isostress_py.errors import SilentDropError, ISOSTRESSSecurityError
from isostress_py.frames import force_close_socket, unpack_phase_one
from isostress_py.handshake import HANDSHAKE_TIMEOUT, HandshakePeer
from isostress_py.params import ISOSTRESSParams

PSK = bytes(range(32))


def _pair() -> Tuple[socket.socket, socket.socket]:
    left, right = socket.socketpair()
    left.settimeout(10)
    right.settimeout(10)
    return left, right


def _run_handshake(
    psk_a: bytes = PSK,
    psk_b: bytes = PSK,
    params_a: ISOSTRESSParams = None,
    params_b: ISOSTRESSParams = None,
    **kwargs,
) -> Tuple[Dict, Tuple[socket.socket, socket.socket]]:
    """Run the full handshake in one thread per socketpair end and collect the results."""
    params_a = params_a or ISOSTRESSParams()
    params_b = params_b or ISOSTRESSParams()
    a = HandshakePeer(psk_a, params_a, "initiator", **kwargs)
    b = HandshakePeer(psk_b, params_b, "responder", **kwargs)
    left, right = _pair()
    results: Dict[str, Dict] = {"a": {}, "b": {}}

    def run(side: str, peer: HandshakePeer, sock: socket.socket) -> None:
        try:
            material = peer.perform_handshake(sock)
            results[side]["material"] = material
        except Exception as exc:  # noqa: BLE001 (test must collect any exception)
            results[side]["error"] = exc
        finally:
            results[side]["psk_left"] = peer.psk

    ta = threading.Thread(target=run, args=("a", a, left))
    tb = threading.Thread(target=run, args=("b", b, right))
    ta.start()
    tb.start()
    # The join must outlast the protocol deadline (HANDSHAKE_TIMEOUT), not merely equal it:
    # a slow CI runner would otherwise return while the initiator is still inside its own
    # read deadline, leaving results[side] empty (flaky 2026-10-11).
    join_budget = HANDSHAKE_TIMEOUT + 10
    ta.join(join_budget)
    tb.join(join_budget)
    return results, (left, right)


# =============================================================================
# Success path
# =============================================================================


def test_full_handshake_success_and_cross_keys() -> None:
    results, (left, right) = _run_handshake()
    try:
        assert "error" not in results["a"], results["a"].get("error")
        assert "error" not in results["b"], results["b"].get("error")
        ma = results["a"]["material"]
        mb = results["b"]["material"]
        # Session ID matches; directional key cross-check: A.send == B.recv, A.recv == B.send
        assert ma.session_id == mb.session_id
        assert bytes(ma.send_ek) == bytes(mb.recv_ek)
        assert bytes(ma.recv_ek) == bytes(mb.send_ek)
        assert bytes(ma.send_ek) != bytes(ma.recv_ek)
        # Identity hash cross-check
        assert ma.local_hash == mb.peer_hash
        assert ma.peer_hash == mb.local_hash
        # Root key material has been securely zeroized (Appendix H.6 / 4.2.3 step 6)
        assert results["a"]["psk_left"] is None
        assert results["b"]["psk_left"] is None
    finally:
        left.close()
        right.close()


# =============================================================================
# Failure path: PSK mismatch → confirmation tag mismatch → each side zeroizes and raises a security error
# =============================================================================


def test_psk_mismatch_fails_both_sides() -> None:
    results, (left, right) = _run_handshake(psk_b=bytes(range(32, 64)))
    try:
        ea = results["a"].get("error")
        eb = results["b"].get("error")
        assert isinstance(ea, ISOSTRESSSecurityError)
        # Responder "send first, compare after" (F.4): content comparison fails → security error, not the silent path
        assert isinstance(eb, ISOSTRESSSecurityError)
        assert results["a"]["psk_left"] is None
        assert results["b"]["psk_left"] is None
    finally:
        force_close_socket(left)
        force_close_socket(right)


# =============================================================================
# Failure path: parameter mismatch → responder stays strictly silent (zero bytes, no active close, F.2)
# =============================================================================


def test_param_mismatch_responder_strict_silence() -> None:
    results, (left, right) = _run_handshake(params_a=ISOSTRESSParams(random_len=512))
    try:
        eb = results["b"].get("error")
        assert isinstance(eb, SilentDropError)
        # While the responder is in silent hold, the initiator waits only for a close/timeout, not for any protocol data
        ea = results["a"].get("error")
        assert ea is not None and not isinstance(ea, ISOSTRESSSecurityError)
    finally:
        force_close_socket(left)
        force_close_socket(right)


def test_param_mismatch_silence_sends_nothing() -> None:
    # Direct drive: the silent path sends no bytes to the peer (F.2 element 1)
    initiator = HandshakePeer(PSK, ISOSTRESSParams(random_len=512), "initiator")
    responder = HandshakePeer(PSK, ISOSTRESSParams(), "responder", silent_hold=0.1)
    left, right = _pair()
    outcome: Dict[str, object] = {"received": "unset"}

    def run_responder() -> None:
        try:
            responder.perform_handshake(right)
        except SilentDropError as exc:
            outcome["responder_error"] = exc

    tb = threading.Thread(target=run_responder)
    tb.start()

    initiator._build_local_frame()
    left.sendall(initiator._local_frame_raw)
    try:
        left.settimeout(0.5)
        outcome["received"] = left.recv(4096)
    except (TimeoutError, ConnectionError, OSError):
        outcome["received"] = None
    tb.join(5)

    assert isinstance(outcome.get("responder_error"), SilentDropError)
    # No bytes received from the responder (None = timeout with no data; b"" = peer closed)
    assert outcome["received"] in (None, b"")
    force_close_socket(left)
    force_close_socket(right)


# =============================================================================
# Failure path: low-order public key → responder stays silent before sending any byte (F.3 ordering constraint)
# =============================================================================


def test_low_order_public_key_silent_before_reply() -> None:
    initiator = HandshakePeer(PSK, ISOSTRESSParams(), "initiator")
    responder = HandshakePeer(PSK, ISOSTRESSParams(), "responder", silent_hold=0.2)
    left, right = _pair()
    outcome: Dict[str, object] = {}

    def run_responder() -> None:
        try:
            responder.perform_handshake(right)
        except Exception as exc:  # noqa: BLE001
            outcome["responder_error"] = exc

    tb = threading.Thread(target=run_responder)
    tb.start()

    # Attacker: legitimate phase-one frame → read the responder's legitimate reply frame → send an all-zero public key (low-order point)
    initiator._build_local_frame()
    left.sendall(initiator._local_frame_raw)
    raw, _p, _i, _n = unpack_phase_one(left)
    initiator._peer_frame_raw = raw
    left.sendall(struct.pack(">I", 32) + b"\x00" * 32 + b"\x07" * 32)

    # The responder should stay strictly silent: no phase-two response frame is sent
    try:
        left.settimeout(1.0)
        leak = left.recv(4096)
    except (TimeoutError, ConnectionError, OSError):
        leak = None
    tb.join(10)

    assert leak in (None, b""), (
        f"responder leaked a reply frame before DH failure: {leak!r}"
    )
    assert isinstance(outcome.get("responder_error"), SilentDropError)
    force_close_socket(left)
    force_close_socket(right)


# =============================================================================
# Constant reflection guard: the INIT/RESP labels differ (F.4)
# =============================================================================


def test_confirm_labels_differ() -> None:
    from isostress_py.handshake import INFO_CONFIRM_INIT, INFO_CONFIRM_RESP

    assert INFO_CONFIRM_INIT != INFO_CONFIRM_RESP
    assert INFO_CONFIRM_INIT == b"ISOSTRESS-CONFIRM-INIT-v3"
    assert INFO_CONFIRM_RESP == b"ISOSTRESS-CONFIRM-RESP-v3"
