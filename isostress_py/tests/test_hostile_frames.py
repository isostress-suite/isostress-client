# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""帧读取器的敌意输入回归 —— 也就是 fuzz 目标的**前提**，在这里变成一次性测试。

fuzz/fuzz_frames.py 需要 atheris（要单独装、跑得慢），不适合当每次提交的
门禁。但它成立的前提是「这四个入口可以被 fuzz 目标那样调用，且敌意输入只会得到
协议文档化过的拒绝」。前提本身应该每次都验。

这一版的由来：写 fuzz 目标时把 `deadline` 漏掉了，四个读取器有三个要这个位置参数
——它会在第一次调用就 TypeError，整台机器什么都没 fuzz。**一个从不运行的测试目标
比没有更危险**，所以前提必须进门禁。
"""

from __future__ import annotations

import socket
import struct
import time

import pytest

from isostress_py.errors import ISOSTRESSProtocolError, ISOSTRESSTimeoutError
from isostress_py.frames import (
    read_confirm,
    read_data_header,
    read_pub_key,
    unpack_phase_one,
)

DEADLINE_SECONDS = 0.25

# 协议文档化过的拒绝。漏出这里的任何类型都是真缺陷——
# 对端是攻击者，它必须无法把解析器推进未处理状态。
EXPECTED = (
    ISOSTRESSProtocolError,
    ISOSTRESSTimeoutError,
    ConnectionError,
    OSError,
    struct.error,
)

MAX_INT = b"\xff\xff\xff\xff"

HOSTILE = {
    "empty": b"",
    "len-only": struct.pack(">I", 10),
    "huge-param-len": struct.pack(">I", 0x7FFFFFFF) + b"\x00" * 16,
    "max-param-len": MAX_INT + b"\x00" * 16,
    "negative-ish": b"\xff\xff\xff\xfe" + b"\x00" * 8,
    "zero-lengths": struct.pack(">I", 0) * 3,
    "truncated-tag": struct.pack(">I", 32) + b"\x00" * 7,
    "short-header": b"\x00" * 10,
    "header-only-44": b"\x00" * 44,
    "huge-ct": b"\x00" * 32 + struct.pack(">Q", 1) + MAX_INT,
    "random-ish": bytes(range(256)),
    "all-ff": b"\xff" * 512,
}

READERS = (unpack_phase_one, read_pub_key, read_confirm, read_data_header)


def _feed(data):
    writer, reader = socket.socketpair()
    try:
        writer.sendall(data)
    except OSError:
        pass
    try:
        writer.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    reader.settimeout(0.3)
    return writer, reader


@pytest.mark.parametrize("name", sorted(HOSTILE))
@pytest.mark.parametrize("reader", READERS, ids=lambda f: f.__name__)
def test_hostile_input_only_raises_documented_errors(name, reader):
    data = HOSTILE[name]
    writer, sock = _feed(data)
    try:
        try:
            reader(sock, time.monotonic() + DEADLINE_SECONDS)
        except EXPECTED:
            return  # correct rejection
        except Exception as exc:  # noqa: BLE001 - that is the whole point
            pytest.fail(
                "%s / %s leaked %s: %s -- an attacker must not be able to steer the "
                "parser into an undocumented state"
                % (name, reader.__name__, type(exc).__name__, exc)
            )
    finally:
        for s in (writer, sock):
            try:
                s.close()
            except OSError:
                pass


def test_readers_are_callable_the_way_the_fuzz_target_calls_them():
    """锁住 fuzz 目标的调用签名。三个读取器要位置参数 `deadline`；
    漏掉它不会报错，只会静默地把 fuzz 机器变成空转。"""
    import inspect

    for fn in READERS:
        params = list(inspect.signature(fn).parameters)
        assert len(params) >= 2, (
            "%s takes fewer parameters than the harness passes" % fn.__name__
        )
        assert params[1] == "deadline", (
            "%s: second parameter is %r, harness passes a deadline positionally"
            % (fn.__name__, params[1])
        )


def test_fuzz_target_imports_its_own_symbols():
    """fuzz 目标引用的名字必须真的存在。它没被 CI 跑，所以 import 坏了没人会发现。"""
    import ast
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[2] / "fuzz" / "fuzz_frames.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.update(a.name for a in node.names)
    assert {
        "unpack_phase_one",
        "read_pub_key",
        "read_confirm",
        "read_data_header",
    } <= imported
    # 曾经写成 read_phase_one（那是 Rust 的名字）—— import 期就炸，什么都没 fuzz。
    assert "read_phase_one" not in imported
