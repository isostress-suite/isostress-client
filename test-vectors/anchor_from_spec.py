# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers
"""Anchor values computed from the specification text alone.

This file imports nothing from isostress_py. It implements HKDF-SHA3-256 and the
derivations written in Master Guide 4.x directly on hashlib and hmac, so the
numbers it prints are an outside reference for the library rather than a copy
of what the library already produces.

Run it: python test-vectors/anchor_from_spec.py
"""

import hashlib
import hmac

HASH = hashlib.sha3_256
HASH_LEN = 32
ZERO_SALT = bytes(HASH_LEN)  # RFC 5869 when no salt is given


def hmac_sha3(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA3-256, per the specification's anchor derivation."""
    return hmac.new(key, msg, HASH).digest()


def hkdf(ikm: bytes, info: bytes, length: int = HASH_LEN, salt: bytes = ZERO_SALT) -> bytes:
    """HKDF-SHA3-256, RFC 5869 extract-then-expand."""
    prk = hmac_sha3(salt, ikm)
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac_sha3(prk, block + info + bytes([counter]))
        out += block
        counter += 1
    return out[:length]


# Fixed inputs so the numbers are reproducible by hand.
MK = bytes(range(32))
ANCHOR = hmac_sha3(MK, b"ISOSTRESS-ANCHOR-v3")
SID = hkdf(ANCHOR, b"ISOSTRESS-SID-v3")[:32]
EK_SEND = hkdf(MK + ANCHOR + b"\x01", b"ISOSTRESS-EK-v3")
EK_RECV = hkdf(MK + ANCHOR + b"\x02", b"ISOSTRESS-EK-v3")

VALUES = {
    "mk": MK.hex(),
    "anchor": ANCHOR.hex(),
    "session_id": SID.hex(),
    "ek_send": EK_SEND.hex(),
    "ek_recv": EK_RECV.hex(),
}

if __name__ == "__main__":
    for k, v in VALUES.items():
        print("%-11s %s" % (k, v))
