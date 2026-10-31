# isostress (Client Edition)

## 这里有什么

Python and Rust implementations, test vectors, and the licence set.

## 按什么找

Build with the [DEV-GUIDE](https://github.com/isostress-suite/isostress-docs/blob/main/en/DEV-GUIDE.md); judge conformance with the [CONFORMANCE-GUIDE](https://github.com/isostress-suite/isostress-docs/blob/main/en/CONFORMANCE-GUIDE.md).

**中文** ｜ [English](en/README.md)

> isostress（ISTS）. This repository is the **client (reference) implementation**.

## Documentation

| 中文 | English |
|---|---|
| [cn/README.md](cn/README.md) | [en/README.md](en/README.md) |

Documentation follows a bilingual mirror layout: `cn/` and `en/` contain the same documents in Chinese and English respectively.

## Code

| Implementation directory | Language | Implementation ID |
|---|---|---|
| `isostress_py/` | Python | `ISOSTRESS_PY-1.0.0-20261030` |
| `isostress_rs/` | Rust | `ISOSTRESS_RS-1.0.0-20261030` |
| `isostress_sv_py/` | Python | `ISOSTRESS_SV-1.0.0-20261030` |

The development languages are **Python** and **Rust**; all implementations are
first-class and follow the same Protocol Master Guide (docs 1.0.0). Other languages can be
added following the implementation-identifier rule `isostress_<prefix>-<implementation version>`.

Source comments and docstrings are in English.

## Build and test

```bash
# Install -- the package metadata lives inside isostress_py/, so point pip at that directory
python -m pip install -e ./isostress_py

# Test suite: run from the repository root (the package is isostress_py, not isostress)
python -m pytest isostress_py/tests -q

# Interactive wizard: run with no arguments on a terminal.
# With stdin/stdout redirected it prints usage and exits 0 instead of blocking.
python -m isostress_py

# Direct command line
python -m isostress_py --role listen  --port 37291 --psk-file ./psk.txt
python -m isostress_py --role connect --host <peer ip> --port 37291 --psk-file ./psk.txt
```

Two known traps:

1. `pyproject.toml` sits inside `isostress_py/`, so the install path is `./isostress_py`, not the
   repository root; and the test suite imports `isostress_py` only when run from the repository root
   (`pytest` started inside `isostress_py/` fails with `No module named isostress_py`).
2. Building the Rust crate from a non-ASCII working directory (for example a Chinese path on
   Windows) requires `CARGO_TARGET_DIR` to point at an ASCII path.

Rust reference implementation (`isostress_rs/`):

```bash
cd isostress_rs
cargo test --release
cargo build --release
```

## Related repositories

| Repository | Role |
|---|---|
| [isostress-docs](https://github.com/isostress-suite/isostress-docs) | Protocol specification and terminology |
| `isostress-client` (this repository; local directory `isostress-client`) | Client edition (reference implementation) |
| `isostress-server` | Server edition (in design) |

## License

Licensed under **GNU AGPL-3.0-or-later**, or under a **commercial license** by separate arrangement. See [LICENSING.md](LICENSING.md) and [LICENSE](LICENSE).
