需要者：提交 PR 的人
不读会错什么：评审要问的问题答不全，PR 会被退回

# 合并请求

本仓交付的是一套安全协议。评审把每个 diff 先当安全相关看，直到证明不是。

## 开单之前

- [ ] `python -m pytest isostress_py/tests -q` 通过
- [ ] `cd isostress_rs && cargo test --release` 通过
- [ ] 动过任一实现时，`python isostress_rs/interop_test.py --suite interop` 通过。这是唯一在真实连接上让两种语言互相对打的检查。

- [ ] 版本声明：版本数字是否前进；只换日期段时写出新日期

## 评审会问什么

**你改了线格式、密钥派生或握手吗？** 那么 `isostress-docs` 里的 Master Guide 必须同步改，`cn/` 与 `en/` 两份都改。代码与规范分属两个仓，互不拉取——没进规范的协议变更就是改了一个没写下来的协议。

**你动了任一实现吗？** 两份都是参考实现。改了一边，就确认另一边仍然一致。`test-vectors/vectors.json` 里的共享向量让这件事可验：派生变了就重生成向量，并预期出现 diff。

**你改了常量吗？** HKDF 标签（`INFO_*`）、帧偏移、长度上限是逐字节的协议表面。它们由共享向量与标签守卫测试钉死。

**你加了依赖吗？** 在 PR 描述里说明理由。这份代码连的是密码协议；依赖数量是安全属性。

## 上报漏洞

漏洞不要开公开 issue。见 `SECURITY.md`。

## CLA 与关联缺陷

CLA-Agreed: yes

外部贡献者填 yes 表示已读 LICENSING。CI 按整行精确读取本行，大小写与冒号不改。

Fixes #<缺陷编号>

没有关联就写 `Fixes #无`。
---

# Pull requests

This repository ships a security protocol. Reviewers should treat every diff as
security-relevant until shown otherwise.

## Before you open

- [ ] `python -m pytest isostress_py/tests -q` is green
- [ ] `cd isostress_rs && cargo test --release` is green
- [ ] `python isostress_rs/interop_test.py --suite interop` passes, **if** you touched
      either implementation. This is the only check that exercises both languages
      against each other over a real connection.

## What reviewers will ask

**Did you change wire format, key derivation, or the handshake?** Then the Master Guide
must change too, in `isostress-docs`, in **both** `cn/` and `en/`. Code and spec are
separate repositories and neither pulls from the other — a protocol change that is not
in the spec is a change to an undocumented protocol.

**Did you touch either implementation?** Both are reference implementations. If you change one side,
confirm the other still agrees. The shared vectors in `test-vectors/vectors.json` are
what make that checkable: if a derivation changes, regenerate them and expect the diff.

**Did you change a constant?** HKDF labels (`INFO_*`), frame offsets, and length limits
are byte-for-byte protocol surface. They are pinned by the shared vectors and by the
label-guard test.

**Did you add a dependency?** Justify it in the PR description. This code links a
cryptographic protocol; dependency count is a security property.

## Reporting vulnerabilities

Do not open a public issue for a vulnerability. See `SECURITY.md`.

## CLA and linked issue

CLA-Agreed: yes

An outside contributor writes yes to confirm they have read LICENSING. CI reads this line verbatim.

Fixes #<issue number>

Write `Fixes #none` when the pull request has no linked issue.
