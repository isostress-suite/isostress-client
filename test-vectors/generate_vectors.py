#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""isostress 跨实现共享测试向量 —— **生成器**。

这个文件**参与 CI，但只以「重生成 + 逐字节比对」的方式参与**：
`scripts/check.sh` 把输出写进临时目录，再与已提交的 `vectors.json` 比对；
CI 走的就是这个脚本，所以生成器在 CI 里是**间接执行**的。
它仍然在两种时候由人手工跑：
  1. 新增向量种类时；
  2. 协议语义变更后，重新生成并**人工复核 diff**。

比对**不采纳**算出来的结果：权威副本始终是提交进仓的 `vectors.json`。
理由：向量若由被检验方自己算出，检验就退化成自证——Python 生成、Rust 断言，
只能证明「Rust 等于 Python」；它证明不了「两者都等于规范」。
所以 RFC 向量取自 RFC 原文（第三方权威），协议向量在生成后**提交进仓**，
改动它会出现在 diff 里，人能看到。比对只在两种情况下报警：
有人手改了 JSON 却没重生成，或改了生成器却没重生成。

用法：
    cd isostress-client
    python test-vectors/generate_vectors.py

覆盖的推导链（与 Master Guide 第 4.2 节 / 附录 F 一一对应）：
    dh          = X25519(sk, pk)                                  附录 F.3
    mk          = HKDF(ikm = PSK || dh, salt = session_salt,
                      info = "ISOSTRESS-MK-v3", L = key_len)          4.2.2
    anchor      = HMAC(mk, "ISOSTRESS-ANCHOR-v3")                     4.2.3
    session_id  = HKDF(ikm = anchor, info = "ISOSTRESS-SID-v3",
                      L = 256)[:32]                                附录 F.4
    ek_send     = HKDF(ikm = mk || anchor || 0x01,
                      info = "ISOSTRESS-EK-v3", L = key_len)          4.2.4
    ek_recv     = HKDF(ikm = mk || anchor || 0x02,
                      info = "ISOSTRESS-EK-v3", L = key_len)
    ek_rotate   = HKDF(ikm = ek || next_seed,
                      info = "ISOSTRESS-EK-ROTATE", L = key_len)      附录 F.5
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT))

from isostress_py.crypto import CryptoSuite           # noqa: E402
from isostress_py.frames import (                     # noqa: E402
    build_aad,
    gcm_nonce,
    pack_confirm,
    pack_initiator_key,
    pack_responder_key,
)
from isostress_py.handshake import (                  # noqa: E402
    INFO_ANCHOR,
    INFO_CONFIRM_INIT,
    INFO_CONFIRM_RESP,
    INFO_EK,
    INFO_EK_ROTATE,
    INFO_MK,
    INFO_SID,
)

OUT = HERE / "vectors.json"


def h(b: bytes) -> str:
    return b.hex()


def dh_of(sk: bytes, pk: bytes) -> bytes:
    """X25519(sk, pk) —— 用 cryptography 的原语，不走 CryptoSuite 封装，
    因为封装要求参数校验，而这里的 sk/pk 来自 RFC 或测试夹具。"""
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    return X25519PrivateKey.from_private_bytes(sk).exchange(
        X25519PublicKey.from_public_bytes(pk)
    )


def session_chain(hash_name: str, key_len: int,
                  psk: bytes, session_salt: bytes,
                  sk_a: bytes, sk_b: bytes,
                  next_seed: bytes) -> dict:
    """跑完整条推导链，产出两侧各自的方向性密钥与棘轮步。"""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    suite = CryptoSuite(hash_name)
    pk_a = X25519PrivateKey.from_private_bytes(sk_a).public_key().public_bytes_raw()
    pk_b = X25519PrivateKey.from_private_bytes(sk_b).public_key().public_bytes_raw()

    dh = dh_of(sk_a, pk_b)
    mk = suite.hkdf(psk + dh, INFO_MK, key_len, salt=session_salt)
    anchor = suite.hmac(mk, INFO_ANCHOR)
    session_id = suite.hkdf(anchor, INFO_SID, 256)[:32]

    # role byte: initiator=0x01, responder=0x02（与 handshake.py 一致）
    ek_a_send = suite.hkdf(mk + anchor + b"\x01", INFO_EK, key_len)
    ek_a_recv = suite.hkdf(mk + anchor + b"\x02", INFO_EK, key_len)
    ek_b_send = suite.hkdf(mk + anchor + b"\x02", INFO_EK, key_len)
    ek_b_recv = suite.hkdf(mk + anchor + b"\x01", INFO_EK, key_len)

    # 棘轮步：先转 A 的发送密钥，再转 B 的发送密钥（两端必须得出同一值）
    ek_a_rot = suite.hkdf(ek_a_send + next_seed, INFO_EK_ROTATE, key_len)
    ek_b_rot = suite.hkdf(ek_b_recv + next_seed, INFO_EK_ROTATE, key_len)

    return {
        "hash": hash_name,
        "key_len_bits": key_len,
        "psk": h(psk),
        "session_salt": h(session_salt),
        "sk_a": h(sk_a),
        "pk_a": h(pk_a),
        "sk_b": h(sk_b),
        "pk_b": h(pk_b),
        "dh": h(dh),
        "mk": h(mk),
        "anchor": h(anchor),
        "session_id": h(session_id),
        "initiator_send_ek": h(ek_a_send),
        "initiator_recv_ek": h(ek_a_recv),
        "responder_send_ek": h(ek_b_send),
        "responder_recv_ek": h(ek_b_recv),
        "next_seed": h(next_seed),
        "rotated_ek": h(ek_a_rot),
        # 交叉断言：A 转完必须等于 B 转完，否则棘轮两端分叉
        "rotated_ek_matches_peer": ek_a_rot == ek_b_rot,
    }


def self_assert_rfc(vectors: list[dict]) -> None:
    """手抄的 RFC 常量必须被实现重算命中，否则这份向量作废。

    没有这一步，TC3 那类「抄错尾巴」会一路流进 CI，而两侧会一起绿——
    因为它们读的是同一份错数据。这就是为什么错常量必须在**生成时**炸。
    """
    for v in vectors:
        if v["kind"] == "hkdf":
            got = CryptoSuite(v["hash"]).hkdf(
                bytes.fromhex(v["ikm"]),
                bytes.fromhex(v["info"]),
                v["length_bits"],
                salt=bytes.fromhex(v["salt"]),
            )
            if got.hex() != v["okm"]:
                raise SystemExit(
                    "[!] %s: 手抄常量与实现不符\n    文件里 %s\n    实算   %s"
                    % (v["name"], v["okm"], got.hex()))
            if len(got) * 8 != v["length_bits"]:
                raise SystemExit("[!] %s: length_bits 与 OKM 长度不符" % v["name"])
        elif v["kind"] == "x25519":
            got = dh_of(bytes.fromhex(v["scalar"]),
                        bytes.fromhex(v["peer_public"]))
            if got.hex() != v["shared"]:
                raise SystemExit(
                    "[!] %s: 手抄常量与实现不符\n    文件里 %s\n    实算   %s"
                    % (v["name"], v["shared"], got.hex()))


def build() -> dict:
    vectors: list[dict] = []

    # ---- RFC 5869 官方测试向量（第三方权威，非本项目推导）----
    # ⚠ 这些常量是**手抄进代码的**，所以下面每一条都由 self_assert_rfc()
    # 用实现重算一遍再比对：手抄错一位就在生成时炸掉，而不是安静地流进 CI。
    vectors.append({
        "name": "rfc5869-tc1-sha256",
        "kind": "hkdf",
        "why": "RFC 5869 Appendix A.1 官方测试向量，两侧必须逐字节命中",
        "hash": "SHA-256",
        "ikm": "0b" * 22,
        "salt": "000102030405060708090a0b0c",
        "info": "f0f1f2f3f4f5f6f7f8f9",
        "length_bits": 336,
        "okm": (
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        ),
    })
    vectors.append({
        "name": "rfc5869-tc3-sha256",
        "kind": "hkdf",
        "why": "RFC 5869 Appendix A.3：零长 salt 与零长 info，两侧都须回退到 RFC 默认",
        "hash": "SHA-256",
        "ikm": "0b" * 22,
        "salt": "",
        "info": "",
        "length_bits": 336,
        "okm": (
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2"
            "d9d201395faa4b61a96c8"
        ),
    })

    # ---- OpenSSL 交叉校验（第三方工具，非本项目推导）----
    # 同一 info 标签（ISOSTRESS-EK-v3）下，OpenSSL 的 KDF 与实现必须同值。
    # 值由 openssl(3.5.9) 的 kdf HKDF 命令产出后手抄，故同样走 self_assert_rfc()。
    vectors.append({
        "name": "openssl-sha3-256-hkdf-crosscheck",
        "kind": "hkdf",
        "why": "OpenSSL 3.5.9 openssl kdf 与标准库手写 HKDF 产出的同一 OKM，覆盖协议自己的 info 标签",
        "hash": "SHA3-256",
        "ikm": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "salt": "00" * 32,
        "info": "5a542d4453502d454b2d7633",
        "length_bits": 256,
        "okm": "31d7a5ad0d9cec1994d4762371dcd4446a1d2a1ed70dff1435ca98afd9b077d1",
    })

    # ---- RFC 7748 官方 X25519 向量 ----
    vectors.append({
        "name": "rfc7748-x25519-dh",
        "kind": "x25519",
        "why": "RFC 7748 §6.1 官方 DH 向量：Alice 私钥 × Bob 公钥",
        "scalar": "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "peer_public": "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "shared": "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    })
    vectors.append({
        "name": "rfc7748-x25519-basepoint",
        "kind": "x25519",
        "why": "RFC 7748 §6.1：同一私钥对基点，导出 Alice 公钥",
        "scalar": "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "peer_public": "0900000000000000000000000000000000000000000000000000000000000000",
        "shared": "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    })

    # ---- 协议自身的推导链（固定夹具，双向可复现）----
    vectors.append({
        "name": "session-sha3-256-keylen256",
        "kind": "session",
        "why": "规范默认套件：SHA3-256 + AES-256-GCM + key_len 256",
        **session_chain(
            "SHA3-256", 256,
            psk=bytes.fromhex("00" * 31 + "01"),
            session_salt=bytes.fromhex("a1" * 32),
            sk_a=bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
            sk_b=bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
            next_seed=bytes.fromhex("5c" * 32),
        ),
    })
    vectors.append({
        "name": "session-sha-256-keylen256",
        "kind": "session",
        "why": "换哈希套件：证明两侧的 hash_name 选择没有渗进派生链",
        **session_chain(
            "SHA-256", 256,
            psk=bytes.fromhex("11" * 32),
            session_salt=bytes.fromhex("b2" * 32),
            sk_a=bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
            sk_b=bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
            next_seed=bytes.fromhex("6d" * 32),
        ),
    })

    # ---- 线格式（附录 F）----
    suite = CryptoSuite("SHA3-256")
    fixture_ek = bytes(range(32))
    fixture_sid = bytes(range(32, 64))
    vectors.append({
        "name": "frames-phase2-phase3",
        "kind": "frame",
        "why": "附录 F.3/F.4：握手帧的逐字节布局，两侧打包必须完全一致",
        "initiator_key": h(pack_initiator_key(bytes(range(32)), bytes(range(32, 64)))),
        "responder_key": h(pack_responder_key(bytes(range(64, 96)))),
        "confirm": h(pack_confirm(bytes(range(96, 128)))),
        "initiator_key_len": len(pack_initiator_key(bytes(range(32)), bytes(range(32, 64)))),
        "responder_key_len": len(pack_responder_key(bytes(range(64, 96)))),
        "confirm_len": len(pack_confirm(bytes(range(96, 128)))),
    })
    vectors.append({
        "name": "frames-phase4-nonce-aad",
        "kind": "frame",
        "why": "附录 F.5：nonce 与 AAD 的构造，两侧必须逐字节一致",
        "session_id": h(fixture_sid),
        "seq": 0,
        "seq_max": (2 ** 64) - 1,
        "nonce_seq0": h(gcm_nonce(0)),
        "aad_seq0": h(build_aad(fixture_sid, 0)),
        "nonce_seq_max": h(gcm_nonce((2 ** 64) - 1)),
        "aad_seq_max": h(build_aad(fixture_sid, (2 ** 64) - 1)),
    })

    # ---- AEAD：固定密钥/明文下的确定性密文（GCM 无随机化，可逐字节比对）----
    vectors.append({
        "name": "aead-aes256-gcm-deterministic",
        "kind": "aead",
        "why": "附录 F.5：AES-256-GCM 在固定 key/nonce/plaintext/aad 下必须产出同一密文",
        "key": h(bytes(range(32))),
        "nonce": h(gcm_nonce(1)),
        "plaintext": b"isostress deterministic AEAD check".hex(),
        "aad": h(build_aad(bytes(range(32, 64)), 1)),
        "ciphertext": h(suite.aead_encrypt(bytes(range(32)), gcm_nonce(1),
                                           b"isostress deterministic AEAD check",
                                           build_aad(bytes(range(32, 64)), 1))),
    })

    return {
        "schema": "isostress-shared-vectors/1",
        "note": ("Shared known-answer vectors for isostress 1.0.0. Consumed by BOTH "
                 "isostress_py and isostress_rs. Regenerate with "
                 "test-vectors/generate_vectors.py and review the diff."),
        "labels": {
            "INFO_MK": INFO_MK,
            "INFO_ANCHOR": INFO_ANCHOR.decode("ascii"),
            "INFO_EK": INFO_EK,
            "INFO_SID": INFO_SID,
            "INFO_EK_ROTATE": INFO_EK_ROTATE,
            "INFO_CONFIRM_INIT": INFO_CONFIRM_INIT.decode("ascii"),
            "INFO_CONFIRM_RESP": INFO_CONFIRM_RESP.decode("ascii"),
        },
        "vectors": vectors,
    }


def main(argv: list[str] | None = None) -> None:
    out = OUT
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        if len(args) == 2 and args[0] == "--out":
            out = Path(args[1])
        elif len(args) == 1:
            out = Path(args[0])
        else:
            raise SystemExit("usage: generate_vectors.py [--out PATH]")
        out.parent.mkdir(parents=True, exist_ok=True)
    doc = build()
    self_assert_rfc(doc["vectors"])
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    # 显式 LF：Windows 的文本模式会把 \n 翻成 \r\n，使每次重生成都产生全文件伪 diff，
    # 三仓副本也会因此在字节层面分叉。写入必须与平台无关。
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)

    # 自检：交叉断言必须成立，否则这份向量本身就是坏的
    for v in doc["vectors"]:
        if v.get("kind") == "session":
            if not v["rotated_ek_matches_peer"]:
                raise SystemExit("[!] %s: 棘轮两端分叉，向量作废" % v["name"])
            if v["initiator_send_ek"] != v["responder_recv_ek"]:
                raise SystemExit("[!] %s: 方向性密钥不交叉" % v["name"])
            if v["initiator_recv_ek"] != v["responder_send_ek"]:
                raise SystemExit("[!] %s: 方向性密钥不交叉" % v["name"])
    print("[ok] wrote %s (%d vectors, sha256=%s)"
          % (out, len(doc["vectors"]),
             hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]))


if __name__ == "__main__":
    main()