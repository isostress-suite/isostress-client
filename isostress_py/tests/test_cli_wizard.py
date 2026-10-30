# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Wizard tests -- reference-client README quick start (interactive wizard)."""

from __future__ import annotations

import binascii
import subprocess
import sys
from pathlib import Path

from isostress_py.cli import (
    DEFAULT_HOST_CONNECT,
    DEFAULT_HOST_LISTEN,
    DEFAULT_PORT,
    RANDOM_LEN,
    RANDOM_RATE,
    WINDOW,
    generate_psk,
    psk_to_hex,
    run_wizard,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


class _Feed:
    """Deterministic stand-in for input(): records prompts, replays answers."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.prompts = []

    def __call__(self, prompt=""):
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


def _wizard(answers):
    feed = _Feed(answers)
    lines = []
    result = run_wizard(input_fn=feed, print_fn=lambda line="": lines.append(line))
    return result, feed, lines


def test_wizard_defaults_on_enter():
    """Every step accepts Enter: listen on the default host/port with a fresh PSK."""
    result, _, lines = _wizard(["", "", "", "", "", "", ""])
    assert result is not None
    assert result["role"] == "listen"
    assert result["host"] == DEFAULT_HOST_LISTEN
    assert result["port"] == DEFAULT_PORT
    assert result["random_len"] == RANDOM_LEN
    assert result["random_rate"] == RANDOM_RATE
    assert result["window"] == WINDOW
    assert len(result["psk_bytes"]) == 32
    # step 3 must print the generated PSK so the user can hand it to the peer
    assert psk_to_hex(result["psk_bytes"]) in "\n".join(lines)


def test_wizard_connect_with_explicit_values():
    hex_psk = psk_to_hex(generate_psk())
    result, _, _ = _wizard(["2", "10.0.0.5", "4444", hex_psk, "128", "256", "30"])
    assert result is not None
    assert result["role"] == "connect"
    assert result["host"] == "10.0.0.5"
    assert result["port"] == 4444
    assert result["psk_bytes"] == binascii.unhexlify(hex_psk)
    assert (result["random_len"], result["random_rate"], result["window"]) == (
        128,
        256,
        30,
    )


def test_wizard_retries_invalid_input():
    """Invalid role/port/PSK/random_len are re-asked instead of crashing."""
    hex_psk = psk_to_hex(generate_psk())
    result, feed, _ = _wizard(
        ["9", "1", "", "abc", "0", "8080", "not-a-psk!!", hex_psk, "7", "8", "9", "9"]
    )
    assert result is not None
    assert result["role"] == "listen"
    assert result["port"] == 8080
    assert result["psk_bytes"] == binascii.unhexlify(hex_psk)
    assert result["random_len"] == 8
    assert len(feed.prompts) >= 12


def test_wizard_aborts_on_eof():
    result, _, _ = _wizard([])
    assert result is None


def test_wizard_loads_psk_from_file(tmp_path):
    psk = generate_psk()
    path = tmp_path / "psk.txt"
    path.write_text(psk_to_hex(psk), encoding="ascii")
    result, _, _ = _wizard(["1", "", "", str(path), "", "", ""])
    assert result is not None
    assert result["psk_bytes"] == psk


def test_no_arguments_without_tty_prints_usage_and_exits():
    """Redirected stdin/stdout must never block on a prompt (CI safety)."""
    proc = subprocess.run(
        [sys.executable, "-m", "isostress_py"],
        cwd=str(REPO_ROOT),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert proc.returncode == 0
    assert "usage:" in (proc.stdout + proc.stderr).lower()
