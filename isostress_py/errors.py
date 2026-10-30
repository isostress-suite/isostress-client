# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Protocol-layer exception hierarchy (Master Guide, Appendix H.5).

The upper layer must distinguish "retry" from "terminate" by exception type:
- ISOSTRESSSecurityError: security event — always terminate the session and
  securely wipe the keys; never retry;
- ISOSTRESSParamError: parameter problem — handshake-phase failure;
- SilentDropError (a subclass of ISOSTRESSParamError): a signal that **this
  side has already entered strict silence** — once the upper layer catches it,
  it must never again send any data to the peer or close the connection
  (the silent path has taken over; see Appendix F.2);
- ISOSTRESSProtocolError: frame-format problem;
- ISOSTRESSCryptoError: cryptographic failure (a low-order point is an attack in
  itself; handle it as a security event);
- ISOSTRESSTimeoutError: timeout (a half-packet timeout must be accompanied by a
  forced socket close).
"""

from __future__ import annotations


class ISOSTRESSError(Exception):
    """Base class for isostress protocol exceptions."""


class ISOSTRESSSecurityError(ISOSTRESSError):
    """Security event: PSK mismatch, anchor confirmation failure, replay /
    out-of-order delivery, session-ID mismatch, AEAD decryption failure,
    unknown payload format, two-way Token Hash verification failure, etc."""


class ISOSTRESSParamError(ISOSTRESSError):
    """Parameter problem: parameters on the two sides do not match, or a
    parameter value is illegal."""


class SilentDropError(ISOSTRESSParamError):
    """Strict silence signal (Appendix F.2): this side (the responder) has
    entered silent suspension — it sends no bytes and does not close the
    connection actively. The upper layer must never write data to the peer
    or close the connection again."""


class ISOSTRESSProtocolError(ISOSTRESSError):
    """Frame-format problem: length over the limit, invalid JSON, structural
    length contradiction, nonce length mismatch, etc."""


class ISOSTRESSCryptoError(ISOSTRESSError):
    """Cryptographic failure: weak DH output (low-order point / all-zero),
    derivation failure, algorithm not supported."""


class ISOSTRESSTimeoutError(ISOSTRESSError):
    """Timeout: handshake timeout, total read deadline exhausted, half-packet
    timeout, no packets in the data phase."""
