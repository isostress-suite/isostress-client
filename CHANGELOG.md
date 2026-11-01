# Changelog

All notable changes to this repository are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Note:** this file is a convenience record, not the source of truth. The change history
lives in `git log`. If the two ever disagree, `git log` wins.

## [Unreleased]

### Added

- **isostress 1.0.0 specification additions (normative).** The 1.0.0 working tree adds a
  normative resource bound to H.3 -- per held connection: hold duration, concurrent
  held-connection count, and buffered-byte bound; the hold duration range is `(0, 15s]`
  and the 15 s ceiling cannot be relaxed -- plus three matching `C.1` checklist items
  that record those bound values. Both are new normative obligations for an
  implementation. `C.1` also now matches §4.2.3 on sequence numbers: drop the packet
  **and** terminate the session.
- **Build-date segment in the implementation identifier.** `BUILD_DATE` is empty by
  default, so `--version` keeps the release form. A non-empty value must be eight
  digits and is appended as `-YYYYMMDD` on development builds only; release
  candidates and releases drop the segment. Both implementations
  compose the identifier through one helper, so a malformed date fails there.
- **Shared known-answer test vectors** (`test-vectors/vectors.json`), consumed by *both*
  the Python and the Rust implementation. Before this, each implementation had its own
  private tests and the only cross-implementation evidence was a live loopback
  handshake. The vectors pin RFC 5869 (HKDF), RFC 7748 (X25519), the full isostress
  derivation chain (PSK‖DH → MK → anchor → session_id → directional EK → ratchet), the
  wire format, and a deterministic AEAD ciphertext.
- Fuzz targets for the frame parsers (`fuzz/`, atheris + cargo-fuzz), run weekly
  by `.github/workflows/fuzz.yml`. The frame readers consume attacker-controlled length
  prefixes; they now have continuous coverage instead of hand-written cases only.
- Library target for the Rust crate (`isostress_rs`), so the protocol can be depended on
  and the fuzz target can link against it.
- `dependabot.yml` for pip, cargo and GitHub Actions.
- `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, and a pull request template.

### Changed

- **Environment variables renamed.** The four environment variables now use the
  `ISOSTRESS_` prefix: `ISOSTRESS_PSK`, `ISOSTRESS_NO_BANNER`, `ISOSTRESS_DEBUG`
  and `ISOSTRESS_RS_BIN`. Scripts and CI jobs that export the retired prefix must
  switch; the old names are no longer read. Breaking for tooling only, not for the
  wire format.
- **Project renamed to isostress (ISTS); numbering reset.** The retired name is gone
  from modules, packages, identifiers and prose: `isostress_py` / `isostress_rs` /
  `isostress_sv_py`, packages `isostress-py` / `isostress-rs`, identifiers
  `ISOSTRESS_PY` / `ISOSTRESS_RS` / `ISOSTRESS_SV`. The ten KDF context strings carry
  the `ISOSTRESS-` prefix, so every derived key changes and the shared vectors were
  regenerated. Numbering restarts at 1.0.0 on 2026-10-29: development builds advance
  only the `-YYYYMMDD` segment; a numeric bump happens only on a wire-format change or
  a release.
- **The Rust key-holding structs no longer expose themselves to `{:?}`.**
  `SessionMaterial`, `SessionState` and `SessionConfig` carried derived
  `Debug`, and the first and last also derived `Clone`. `SessionMaterial`
  holds the session keys, `SessionState` holds both direction keys,
  `SessionConfig` holds the PSK, and the CLI `Args` holds the `--psk`
  string: one `{:?}` print of a live value emits key bytes, and a `Clone`
  produces key copies outside the wipe paths. `SessionMaterial` and
  `SessionConfig` now carry hand-written `Debug` impls that print lengths
  only; `SessionState` and `Args` lost `Debug`; the two `Clone` derives
  are gone. Two tests pin that the Debug output shows lengths and never
  key bytes.
- **Document version aligned to 1.0.0.** Both implementations now report
  `(docs 1.0.0)`; the program version stays 1.0.0. The three READMEs drop the
  deprecated hardware key-storage notices.
- Development builds now carry the build-date segment in the program identifier
  (`ISOSTRESS_PY-1.0.0-20261030`, `ISOSTRESS_RS-1.0.0-20261030`, `ISOSTRESS_SV-1.0.0-20261030`).
  The numeric version stays `1.0.0`, package metadata stays numeric-only, and the
  compatibility lists keep the date-free release form.
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

### Fixed

- **A legal JSON number crashed the responder outside the funnel.** `json.loads`
  parses `1e999` to float infinity, and `int(inf)` raises `OverflowError`, which
  neither `ISOSTRESSParams.from_wire` (`params.py`) nor the handshake's parameter
  convergence (`handshake.py`) caught — a peer could produce a bare traceback
  where Appendix H.4 demands a funnelled, silent rejection. Both capture tuples
  now include `OverflowError`. The Rust path was audited and needs no change:
  serde_json rejects out-of-range numbers at parse time and `coerce_u64`'s float
  branch refuses non-finite values. Hostile-but-legal values are pinned by
  `test_primitives.py`, a responder-level silent-drop test, and a Rust parser
  rejection assertion.

- **The `isostress-sv` wheel was unbuildable and under-declared.** Its pyproject
  listed a package directory that does not exist (no `package-dir`, so
  `pip wheel` failed with "package directory 'isostress_sv_py' does not exist"),
  declared no dependency on `isostress-py` although `server.py` imports it,
  carried no license file, and claimed `requires-python >=3.9` while the
  dependency needs >=3.10. The pyproject now maps the flat layout, depends
  on `isostress-py>=1.0.0`, carries `LICENSE` verbatim, and requires Python
  >=3.10; `pip wheel` produces a wheel whose METADATA shows all fields.
- **A packet outside the timestamp window vanished without a line of output.** The
  receiver computed the reason and dropped the plaintext, as the specification
  requires, but nothing printed it, so a clock difference between the two ends
  looked like a dead link. The receiver now prints the reason with both timestamps.
- **Session diagnostics moved to stderr.** `[Dropped]`, `[Input closed]`,
  `[Input disabled]`, `[Send failed]`, `[Timeout error]`, `[Security error]`,
  `[Heartbeat failed]` and `[Input error]` are local notices, not wire bytes: they
  now go to stderr in both implementations, while `[Peer]` text and the input
  prompt stay on stdout. A piped session therefore no longer mixes local notices
  into the data stream.
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

- Initial protocol implementation, following isostress Protocol Master Guide 1.0.0.