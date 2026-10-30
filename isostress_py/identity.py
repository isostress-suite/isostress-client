# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""P2P placeholder Token Hash (Master Guide, Section 4.1.1, "P2P direct placeholder path without TCA").

When no TCA token is present, both sides derive a placeholder address via PSK,
ensuring that Phase-1 identity_blob and Phase-4 Token Hash cross-verify self-consistently:

    placeholder hash = first 32 bytes of HMAC-SHA3-256(PSK, role label)
    initiator's own = HMAC(PSK, "ISOSTRESS-TOKEN-INITIATOR-v3")
    responder's own = HMAC(PSK, "ISOSTRESS-TOKEN-RESPONDER-v3")

Thus A's local hash exactly equals B's peer hash (A.local == B.peer, A.peer == B.local),
and src/dst is naturally symmetric from each side's view. This path only guarantees frame integrity
and identity binding to PSK, without TCA's "third-party notarization" property.
"""

from __future__ import annotations

from typing import Tuple

from .crypto import hmac_sha3

TOKEN_LABEL_INITIATOR: bytes = b"ISOSTRESS-TOKEN-INITIATOR-v3"
TOKEN_LABEL_RESPONDER: bytes = b"ISOSTRESS-TOKEN-RESPONDER-v3"

TOKEN_HASH_LEN: int = 32

ROLE_INITIATOR = "initiator"
ROLE_RESPONDER = "responder"


def derive_p2p_identity(psk: bytes, role: str) -> Tuple[bytes, bytes]:
    """Derive (local hash, peer hash) by role.

    Initiator's view: local=HMAC(INITIATOR label), peer=HMAC(RESPONDER label);
    Responder's view: the two labels are swapped.
    """
    if role == ROLE_INITIATOR:
        my_label, peer_label = TOKEN_LABEL_INITIATOR, TOKEN_LABEL_RESPONDER
    elif role == ROLE_RESPONDER:
        my_label, peer_label = TOKEN_LABEL_RESPONDER, TOKEN_LABEL_INITIATOR
    else:
        raise ValueError(f"role must be '{ROLE_INITIATOR}' or '{ROLE_RESPONDER}'")
    local_hash = hmac_sha3(psk, my_label)[:TOKEN_HASH_LEN]
    peer_hash = hmac_sha3(psk, peer_label)[:TOKEN_HASH_LEN]
    return local_hash, peer_hash
