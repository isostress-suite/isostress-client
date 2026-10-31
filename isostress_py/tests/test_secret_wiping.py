# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Tests for the wiping of secret material.

The Python client cannot erase an immutable `bytes` object, so every buffer that
holds key material must be a `bytearray`. These tests pin that contract.
"""

from isostress_py.crypto import secure_zero


def test_secure_zero_wipes_a_mutable_buffer() -> None:
    buf = bytearray(b"secret-key-material")
    assert secure_zero(buf) is True
    assert buf == bytearray(len(buf))


def test_secure_zero_reports_failure_for_immutable_bytes() -> None:
    # bytes cannot be zeroed from Python; the call must report that instead of
    # raising or pretending the copy is gone.
    assert secure_zero(b"secret-key-material") is False


def test_secure_zero_accepts_none_and_memoryview() -> None:
    assert secure_zero(None) is True
    view = memoryview(bytearray(b"secret"))
    assert secure_zero(view) is True
    assert bytes(view) == b"\x00" * 6


def test_secure_zero_does_not_widen_the_input() -> None:
    buf = bytearray(b"abc")
    secure_zero(buf)
    assert len(buf) == 3
