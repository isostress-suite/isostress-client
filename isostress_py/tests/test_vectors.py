# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""isostress 共享测试向量 —— Python 侧消费者。

`test-vectors/vectors.json` 由**两侧共同**读取，不是 Python 的自证：
Rust 侧有 `isostress_rs/vectors.rs` 读同一份文件。改这个 JSON 会同时改两边的期望值，
所以它必须是提交进仓、人工复核过 diff 的产物，而不是 CI 里现生成的。

覆盖：
- RFC 5869 A.1 / A.3 —— 第三方权威常量，验证 HKDF 本身
- RFC 7748 §6.1 —— 第三方权威常量，验证 X25519 本身
- 协议推导链 —— PSK‖DH → MK → anchor → session_id → 方向性 EK → 棘轮
- 线格式 —— 握手帧、nonce、AAD 的逐字节布局
- AEAD —— 固定输入下的确定性密文

数据源：../test-vectors/vectors.json（相对本文件）。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from isostress_py.crypto import CryptoSuite
from isostress_py.frames import (
    build_aad,
    gcm_nonce,
    pack_confirm,
    pack_initiator_key,
    pack_responder_key,
)
from isostress_py.handshake import (
    INFO_ANCHOR,
    INFO_CONFIRM_INIT,
    INFO_CONFIRM_RESP,
    INFO_EK,
    INFO_EK_ROTATE,
    INFO_MK,
    INFO_SID,
)

VECTOR_FILE = Path(__file__).resolve().parents[2] / "test-vectors" / "vectors.json"
DOC = json.loads(VECTOR_FILE.read_text(encoding="utf-8"))
VECTORS = DOC["vectors"]


def _by_kind(kind: str) -> list[dict]:
    return [v for v in VECTORS if v["kind"] == kind]


def _dh(sk: bytes, pk: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    return X25519PrivateKey.from_private_bytes(sk).exchange(
        X25519PublicKey.from_public_bytes(pk)
    )


# --------------------------------------------------------------------------
# 向量文件本身的完整性 —— 缺了或读错，后面的绿灯全是假的
# --------------------------------------------------------------------------


def test_vector_file_is_present_and_populated():
    assert VECTOR_FILE.exists(), "共享向量文件缺失：跨实现比对无从谈起"
    assert len(VECTORS) >= 9


def test_every_vector_kind_is_consumed_by_this_file():
    """新增一种 kind 而忘了写消费者 = 那一类向量白生成。
    这里列出本文件认识的 kind；多出来的会让这个测试变红。"""
    known = {"hkdf", "x25519", "session", "frame", "aead"}
    seen = {v["kind"] for v in VECTORS}
    assert seen <= known, "有向量种类没有对应的 Python 消费者：%s" % (seen - known)
    assert seen == known, "本文件有消费者，但向量里缺这类：%s" % (known - seen)


def test_protocol_labels_match_source_constants():
    """向量里的 HKDF label 必须与 handshake.py 的常量逐字一致。
    改了 label 却没重新生成向量，是最容易发生的静默漂移。"""
    assert DOC["labels"] == {
        "INFO_MK": INFO_MK,
        "INFO_ANCHOR": INFO_ANCHOR.decode("ascii"),
        "INFO_EK": INFO_EK,
        "INFO_SID": INFO_SID,
        "INFO_EK_ROTATE": INFO_EK_ROTATE,
        "INFO_CONFIRM_INIT": INFO_CONFIRM_INIT.decode("ascii"),
        "INFO_CONFIRM_RESP": INFO_CONFIRM_RESP.decode("ascii"),
    }


# --------------------------------------------------------------------------
# RFC 5869 —— 第三方权威常量
# --------------------------------------------------------------------------


@pytest.mark.parametrize("v", _by_kind("hkdf"), ids=lambda v: v["name"])
def test_hkdf_matches_rfc5869(v):
    """RFC 5869 A.1 / A.3。两侧都必须命中官方常量——
    这是判定 HKDF 实现对错的**外部**依据，不是自己跟自己比。"""
    got = CryptoSuite(v["hash"]).hkdf(
        bytes.fromhex(v["ikm"]),
        bytes.fromhex(v["info"]),  # 二进制 info：RFC 向量必须是 bytes
        v["length_bits"],
        salt=bytes.fromhex(v["salt"]),
    )
    assert got.hex() == v["okm"]
    assert len(got) * 8 == v["length_bits"]


def test_hkdf_accepts_str_and_bytes_info_equivalently():
    """info 收两种类型是 2026-10-13 的修复：此前只收 str，
    导致 Python **无法**表达 RFC 的二进制 info 向量，也就无法自证 HKDF。
    Rust 侧一直是 &[u8]；这条锁住 Python 不再退回单类型。"""
    suite = CryptoSuite("SHA-256")
    a = suite.hkdf(b"\x0b" * 22, "abc", 256, salt=b"\x01\x02")
    b = suite.hkdf(b"\x0b" * 22, b"abc", 256, salt=b"\x01\x02")
    assert a == b


# --------------------------------------------------------------------------
# RFC 7748 —— 第三方权威常量
# --------------------------------------------------------------------------


@pytest.mark.parametrize("v", _by_kind("x25519"), ids=lambda v: v["name"])
def test_x25519_matches_rfc7748(v):
    got = _dh(bytes.fromhex(v["scalar"]), bytes.fromhex(v["peer_public"]))
    assert got.hex() == v["shared"]


# --------------------------------------------------------------------------
# 协议推导链
# --------------------------------------------------------------------------


@pytest.mark.parametrize("v", _by_kind("session"), ids=lambda v: v["name"])
def test_session_derivation_chain(v):
    """PSK‖DH → MK → anchor → session_id → 方向性 EK → 棘轮，全链逐段比对。"""
    suite = CryptoSuite(v["hash"])
    key_len = v["key_len_bits"]
    psk = bytes.fromhex(v["psk"])
    salt = bytes.fromhex(v["session_salt"])
    sk_a = bytes.fromhex(v["sk_a"])
    sk_b = bytes.fromhex(v["sk_b"])

    dh = _dh(sk_a, bytes.fromhex(v["pk_b"]))
    assert dh.hex() == v["dh"]

    mk = suite.hkdf(psk + dh, INFO_MK, key_len, salt=salt)
    assert mk.hex() == v["mk"]

    anchor = suite.hmac(mk, INFO_ANCHOR)
    assert anchor.hex() == v["anchor"]

    session_id = suite.hkdf(anchor, INFO_SID, 256)[:32]
    assert session_id.hex() == v["session_id"]

    init_send = suite.hkdf(mk + anchor + b"\x01", INFO_EK, key_len)
    init_recv = suite.hkdf(mk + anchor + b"\x02", INFO_EK, key_len)
    resp_send = suite.hkdf(mk + anchor + b"\x02", INFO_EK, key_len)
    resp_recv = suite.hkdf(mk + anchor + b"\x01", INFO_EK, key_len)
    assert init_send.hex() == v["initiator_send_ek"]
    assert init_recv.hex() == v["initiator_recv_ek"]
    assert resp_send.hex() == v["responder_send_ek"]
    assert resp_recv.hex() == v["responder_recv_ek"]

    # 方向性必须交叉：这是「双向独立通道」的全部意义
    assert init_send == resp_recv
    assert init_recv == resp_send

    rotated = suite.hkdf(
        init_send + bytes.fromhex(v["next_seed"]), INFO_EK_ROTATE, key_len
    )
    assert rotated.hex() == v["rotated_ek"]
    # A 转完必须等于 B 用接收密钥转完，否则棘轮两端分叉
    peer_rotated = suite.hkdf(
        resp_recv + bytes.fromhex(v["next_seed"]), INFO_EK_ROTATE, key_len
    )
    assert peer_rotated == rotated


def test_session_vectors_cover_both_documented_hash_suites():
    """两套哈希各一份：只测一套时，另一套的回归无人发现。"""
    hashes = {v["hash"] for v in _by_kind("session")}
    assert {"SHA3-256", "SHA-256"} <= hashes


# --------------------------------------------------------------------------
# 线格式（附录 F）
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "v",
    [v for v in _by_kind("frame") if v["name"] == "frames-phase2-phase3"],
    ids=lambda v: v["name"],
)
def test_handshake_frame_bytes(v):
    assert (
        pack_initiator_key(bytes(range(32)), bytes(range(32, 64))).hex()
        == v["initiator_key"]
    )
    assert pack_responder_key(bytes(range(64, 96))).hex() == v["responder_key"]
    assert pack_confirm(bytes(range(96, 128))).hex() == v["confirm"]
    assert (
        len(pack_initiator_key(bytes(range(32)), bytes(range(32, 64))))
        == v["initiator_key_len"]
        == 68
    )
    assert len(pack_responder_key(bytes(range(64, 96)))) == v["responder_key_len"] == 36
    assert len(pack_confirm(bytes(range(96, 128)))) == v["confirm_len"] == 36


@pytest.mark.parametrize(
    "v",
    [v for v in _by_kind("frame") if v["name"] == "frames-phase4-nonce-aad"],
    ids=lambda v: v["name"],
)
def test_nonce_and_aad_bytes(v):
    """nonce = 0000 ‖ seq(8B BE)，AAD = session_id ‖ seq(8B BE)。
    seq 必须铺满整个 uint64 域——两端若在这里分叉，长跑会话必然失步。"""
    sid = bytes.fromhex(v["session_id"])
    assert gcm_nonce(v["seq"]).hex() == v["nonce_seq0"]
    assert build_aad(sid, v["seq"]).hex() == v["aad_seq0"]
    assert gcm_nonce(v["seq_max"]).hex() == v["nonce_seq_max"]
    assert build_aad(sid, v["seq_max"]).hex() == v["aad_seq_max"]
    # 全零 nonce 的前 4 字节恒定，保证 nonce 永不重复
    assert gcm_nonce(v["seq"])[:4] == b"\x00" * 4
    assert gcm_nonce(v["seq_max"])[:4] == b"\x00" * 4


# --------------------------------------------------------------------------
# AEAD（附录 F.5）
# --------------------------------------------------------------------------


@pytest.mark.parametrize("v", _by_kind("aead"), ids=lambda v: v["name"])
def test_aead_deterministic_ciphertext(v):
    """GCM 无随机化：固定 key/nonce/plaintext/aad 必须产出同一密文。
    两侧密文不同 = 两实现的 payload 布局或 AAD 不同。"""
    suite = CryptoSuite(v["hash"]) if "hash" in v else CryptoSuite("SHA3-256")
    ct = suite.aead_encrypt(
        bytes.fromhex(v["key"]),
        bytes.fromhex(v["nonce"]),
        bytes.fromhex(v["plaintext"]),
        bytes.fromhex(v["aad"]),
    )
    assert ct.hex() == v["ciphertext"]
    assert (
        suite.aead_decrypt(
            bytes.fromhex(v["key"]),
            bytes.fromhex(v["nonce"]),
            ct,
            bytes.fromhex(v["aad"]),
        ).hex()
        == v["plaintext"]
    )
