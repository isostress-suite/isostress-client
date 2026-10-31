# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""PSK file permission warning: POSIX only.

Windows reports synthetic mode bits (0o666 for a regular file), so the POSIX
"accessible to group/other users" check warned on every PSK file. The Rust
implementation already skips the check under cfg(unix).
"""

from __future__ import annotations

from types import SimpleNamespace

from isostress_py import cli
from isostress_py.cli import generate_psk, load_psk_from_file, psk_to_hex

WARNING = "accessible to group/other users"


def _write_psk(tmp_path) -> tuple[str, bytes]:
    raw = generate_psk()
    path = tmp_path / "psk.key"
    path.write_text(psk_to_hex(raw), encoding="ascii")
    return str(path), raw


def _fake_os(name: str):
    """Stand-in for the `os` module used by cli; stat reports a world-readable file."""
    return SimpleNamespace(
        name=name,
        stat=lambda _path: SimpleNamespace(st_mode=0o100666),
    )


def test_windows_skips_permission_warning(tmp_path, monkeypatch, capsys):
    path, raw = _write_psk(tmp_path)
    monkeypatch.setattr(cli, "os", _fake_os("nt"))

    assert load_psk_from_file(path) == raw
    assert WARNING not in capsys.readouterr().err


def test_posix_warns_on_world_readable_file(tmp_path, monkeypatch, capsys):
    path, raw = _write_psk(tmp_path)
    monkeypatch.setattr(cli, "os", _fake_os("posix"))

    assert load_psk_from_file(path) == raw
    assert WARNING in capsys.readouterr().err


def test_posix_stays_quiet_on_owner_only_file(tmp_path, monkeypatch, capsys):
    path, raw = _write_psk(tmp_path)
    fake = _fake_os("posix")
    fake.stat = lambda _path: SimpleNamespace(st_mode=0o100600)
    monkeypatch.setattr(cli, "os", fake)

    assert load_psk_from_file(path) == raw
    assert WARNING not in capsys.readouterr().err
