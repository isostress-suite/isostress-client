# Shared test vectors

`vectors.json` 由本目录的 `generate_vectors.py` 生成，是规范附录 J 的一致性向量。
三仓（`isostress-client` / `isostress-server` / `isostress-docs`）各存一份**逐字节相同**的副本；
规范附录 J.2 以 `isostress-docs` 那份为权威副本，生成器产出的字节必须与它一致。

- 当前指纹：`sha256 = da526e0e81f159e6bf3fdc6819a8d4a62f6524cadc3c058838a5218c7e7eaf55`
- 条数：10（2 条 RFC 5869 HKDF、1 条 OpenSSL 交叉校验、2 条 RFC 7748 X25519、
  2 条会话 nonce/AAD 派生、2 条帧、1 条 AEAD）
- `note` 版本：1.0.0

## 这里有什么

三个文件：`vectors.json`（10 条共享向量）、`generate_vectors.py`（字节的唯一来源）、`anchor_from_spec.py`（从规范正文抽锚点做外部核对）。

## 按什么找

要改向量看「怎么生成」；要查某条值不对，看它的 `why` 字段再回规范对应附录；要查三仓是否分叉，跑 `scripts/check.sh`。

## 怎么生成

```bash
python test-vectors/generate_vectors.py                  # 写回本目录
python test-vectors/generate_vectors.py --out /tmp/v.json # 只产出到别处
```

生成器**只走 LF**（`open(..., newline="\n")`）。Windows 的文本模式默认把 `\n` 翻成 `\r\n`，
会让每次重生成都产生全文件伪 diff，三仓副本也会因此在字节层分叉。

## 为什么不会漂

`scripts/check.sh` 会把生成器重跑一遍到临时目录，再与已提交的 `vectors.json` 逐字节比对；
不一致即判失败。所以「生成器改了但没人重生成」和「有人手改了 JSON」都会在本地自检时暴露。

## 第 10 条从哪来

`openssl-sha3-256-hkdf-crosscheck` 原先只存在于 `isostress-docs` 那份，导致三份条数分叉（9 / 9 / 10）。
2026-10-28 起并入三份共享集：

- 它是**第三方工具**产出：OpenSSL 3.5.9 的 `kdf` 命令，用协议自己的 `info` 标签 `ISOSTRESS-EK-v3`；
- 它挡住「自证闭环」：RFC 5869 向量只验通用 HKDF，验不到本协议的标签串；
- 并入后规范附录 J.2 的「10 条」与三仓实际条数一致（此前 J.2 写 10、client/server 只有 9）。

## 与其它两份的关系

1. 在这里生成；
2. 把生成结果**按字节**复制到 `isostress-server/test-vectors/` 与 `isostress-docs/test-vectors/`；
3. 三份 `sha256` 必须相同。见 `isostress-server/test-vectors/README.md` 的同步步骤。

- 消费者：`isostress_py/tests/test_vectors.py`（逐条复算，并断言没有未知 kind）、
  `isostress_rs/vectors.rs`（逐条复算）、`isostress-server/src/version.rs`（只比对 7 个标签）。
