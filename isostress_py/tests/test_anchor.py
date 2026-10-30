# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers
"""Compare the library against values computed from the specification text.

The reference lives in test-vectors/anchor_from_spec.py and imports nothing
from this package. If the two disagree, either the library or the
specification is wrong, and that is the point of the comparison.
"""

import importlib.util
import os

from isostress_py.crypto import CryptoSuite, hmac_sha3

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
REF = os.path.join(ROOT, "test-vectors", "anchor_from_spec.py")


def _load_reference():
    spec = importlib.util.spec_from_file_location("anchor_from_spec", REF)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_kdf_chain_matches_specification():
    ref = _load_reference()
    suite = CryptoSuite()
    mk = bytes.fromhex(ref.VALUES["mk"])

    assert hmac_sha3(mk, b"ISOSTRESS-ANCHOR-v3").hex() == ref.VALUES["anchor"], "anchor"
    anchor = bytes.fromhex(ref.VALUES["anchor"])

    assert (
        suite.hkdf(anchor, "ISOSTRESS-SID-v3", 256)[:32].hex()
        == ref.VALUES["session_id"]
    ), "session id"
    assert (
        suite.hkdf(mk + anchor + b"\x01", "ISOSTRESS-EK-v3", 256).hex()
        == ref.VALUES["ek_send"]
    ), "ek_send"
    assert (
        suite.hkdf(mk + anchor + b"\x02", "ISOSTRESS-EK-v3", 256).hex()
        == ref.VALUES["ek_recv"]
    ), "ek_recv"
