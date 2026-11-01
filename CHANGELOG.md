# Changelog

All notable changes to this repository are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Note:** this file is a convenience record, not the source of truth. The change history
lives in `git log`. If the two ever disagree, `git log` wins.

## [Unreleased]

### Added

- **Shared known-answer test vectors** (`test-vectors/vectors.json`), consumed by *both*
  the Python and the Rust implementation. Before this, each implementation had its own
  private tests and the only cross-implementation evidence was a live loopback
  handshake. The vectors pin RFC 5869 (HKDF), RFC 7748 (X25519), the full ZT-DSP
  derivation chain (PSK‖DH → MK → anchor → session_id → directional EK → ratchet), the
  wire format, and a deterministic AEAD ciphertext.
- Fuzz targets for the frame parsers (`fuzz/`, atheris + cargo-fuzz), run weekly
  by `.github/workflows/fuzz.yml`. The frame readers consume attacker-controlled length
  prefixes; they now have continuous coverage instead of hand-written cases only.
- Library target for the Rust crate (`zt_dsp_rs`), so the protocol can be depended on
  and the fuzz target can link against it.
- `dependabot.yml` for pip, cargo and GitHub Actions.
- `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, and a pull request template.

### Changed

- **Document version aligned to 1.0.2.** Both implementations now report
  `(docs 1.0.2)`; the program version stays 1.0.0. The three READMEs drop the
  deprecated hardware key-storage notices.
- **`--no-stdin`.** The session reads nothing from the input and sends no application
  data; heartbeats continue. A server process started in the background has no
  terminal on its input, and the flag keeps the process from waiting for one.
- CI now pins **every** action to a commit SHA. Two steps in the interop job were left
  on movable tags, which contradicted the stated policy on that file's own header.
- The interop CI job is renamed from `Interop (Python <-> Rust, byte-level)` to
  `Live handshake interop`. It verifies a real handshake in both directions; byte-level
  equality is verified by the shared vectors, not by this job.
- `interop_test.py` no longer synchronises with fixed `time.sleep()` calls. It waits for
  the actual readiness and handshake markers, and asserts per side rather than on the
  concatenated output.
- The Rust integration tests moved from the binary entry point into the library, so they
  can reach the modules directly.
- **The single-file collection rule is dropped.** The `合并 / 收录提议` row of `cn/README.md`
  and its `en/README.md` counterpart no longer require an implementation to be collected
  into one file, and the accompanying ban on new directory trees under the mainline
  directory is withdrawn as well: implementations follow the ordinary engineering layout
  of the language in use, including subdirectories.

### Fixed

- **The `zt-dsp-sv` wheel was unbuildable and under-declared.** Its pyproject
  listed a package directory that does not exist (no `package-dir`, so
  `pip wheel` failed with "package directory 'zt_dsp_sv_py' does not exist"),
  declared no dependency on `zt-dsp-py` although `server.py` imports it,
  carried no license file, and claimed `requires-python >=3.9` while the
  dependency needs >=3.10. The pyproject now maps the flat layout, depends
  on `zt-dsp-py>=1.0.0`, carries `LICENSE` verbatim, and requires Python
  >=3.10; `pip wheel` produces a wheel whose METADATA shows all fields.
- **A packet outside the timestamp window vanished without a line of output.** The
  receiver computed the reason and dropped the plaintext, as the specification
  requires, but nothing printed it, so a clock difference between the two ends
  looked like a dead link. The receiver now prints the reason with both timestamps.
- **The end of the input closed the connection.** The client read the input in the
  main thread and shut the session down in a `finally` block, so a process started
  in the background -- where the input ends at once -- closed the connection as soon
  as the handshake finished. The peer then read the end of the stream, wiped its
  session, and reported "session is irreversibly desynchronized or not established"
  on its first send. An end of the input now stops the sending only; the receiving
  goes on until the peer disconnects.
- **20 source references pointed at appendix letters that no longer exist.** The docs repo
  commit `6e1d425` ("Prune stale appendices") removed appendices A / D / E, whose content
  had moved into the client README, but 20 docstrings and comments across `cli.py`,
  `crypto.py`, `cli.rs`, `crypto.rs`, `integration_tests.rs` and three test modules still
  cited "Appendix E" / E.2 / E.3 / E.4 / E.5 -- including `cli.py:148`, a string printed to
  the user. The existing docs-to-code checks compare constants and values, not
  cross-references, so nothing caught it. All 20 now point at the location that actually
  holds the material (client README, or Master Guide Appendix B for the PSK rules).
- Added `test_doc_refs.py`, which parses the appendix headings out of the spec and fails on
  any cited letter that is absent, so this class of defect cannot return silently. It skips
  when the docs repo is not checked out (this repo's own CI).
- `CryptoSuite.hkdf` accepted only `str` for `info`, so the Python implementation
  **could not express RFC 5869's binary-info test vectors** and could not validate its
  own HKDF against the RFC. It now accepts `str` or `bytes`, matching the Rust signature
  (`&[u8]`) and RFC 5869.

## [1.0.0]

- Initial protocol implementation, following ZT-DSP Protocol Master Guide 1.0.0.