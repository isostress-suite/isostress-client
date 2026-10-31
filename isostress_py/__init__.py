# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""isostress (ISTS).

Reference implementation (client version ISOSTRESS_PY-1.0.0, applying to the
"isostress Protocol Master Guide", total-guide version 1.0.0).

Programming usage:

    from isostress_py import ISOSTRESSParams, HandshakePeer, SecureSession

    peer = HandshakePeer(psk, ISOSTRESSParams(), role="responder")
    material = peer.perform_handshake(sock)      # blocks until the four-phase handshake completes
    session = SecureSession(material)
    session.send_packet(sock, b"hello")
    plaintext = session.recv_packet(sock)

This minimal release implements the protocol itself only (four-phase handshake +
full-duplex encrypted transmission). The extension modules (hook system, TCA,
AORS, Ocean Mode, and Emergency Mode) are out of scope.
"""

from .errors import (
    SilentDropError,
    ISOSTRESSCryptoError,
    ISOSTRESSError,
    ISOSTRESSParamError,
    ISOSTRESSProtocolError,
    ISOSTRESSSecurityError,
    ISOSTRESSTimeoutError,
)
from .handshake import HandshakePeer, SessionMaterial
from .identity import derive_p2p_identity
from .params import ISOSTRESSParams
from .session import SecureSession
from .version import (
    CODE_VERSION,
    DOCS_VERSION,
    FOLLOWS_DOC,
    FOLLOWS_DOC_PATH,
    IMPLEMENTATION_ID,
    LANGUAGE_PREFIX,
    format_version,
)

__version__ = CODE_VERSION
__docs_version__ = DOCS_VERSION
__implementation__ = IMPLEMENTATION_ID

__all__ = [
    "CODE_VERSION",
    "DOCS_VERSION",
    "FOLLOWS_DOC",
    "FOLLOWS_DOC_PATH",
    "IMPLEMENTATION_ID",
    "LANGUAGE_PREFIX",
    "format_version",
    "__version__",
    "__docs_version__",
    "__implementation__",
    "ISOSTRESSParams",
    "HandshakePeer",
    "SessionMaterial",
    "SecureSession",
    "derive_p2p_identity",
    "ISOSTRESSError",
    "ISOSTRESSSecurityError",
    "ISOSTRESSParamError",
    "SilentDropError",
    "ISOSTRESSProtocolError",
    "ISOSTRESSCryptoError",
    "ISOSTRESSTimeoutError",
]
