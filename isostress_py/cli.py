# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Minimal command-line interface (reference-client guide: see the isostress-client README).

Design boundary (this version builds the protocol itself only):
- Provides `--role listen/connect` direct CLI, the interactive wizard (README quick start), and `--version`;
- Running with no arguments starts the wizard on a terminal; when stdin or stdout is
  redirected (pipes, CI) it prints usage instead, so automation never blocks on a prompt;
- PSK injection priority (README main parameters): --psk-file (recommended, 0600) > --psk-env > --psk
  (plain text on the command line, visible in the process list, temporary tests only);
- Extension modules (TCA/AORS/Ocean Mode, etc.) stay out of scope for this release.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import sys
from typing import Optional

from .crypto import check_entropy, secure_random
from .errors import ISOSTRESSError
from .params import (
    AEAD_NAME,
    HASH_NAME,
    KEY_LEN,
    MAX_PAD,
    RANDOM_LEN,
    RANDOM_RATE,
    TIME_WINDOW,
    WINDOW,
    ISOSTRESSParams,
)
from .transport import (
    DEFAULT_CONNECT_RETRY_COUNT,
    DEFAULT_CONNECT_RETRY_INTERVAL,
    DEFAULT_HOST_CONNECT,
    DEFAULT_HOST_LISTEN,
    DEFAULT_PORT,
    run_session,
)
from .version import CODE_VERSION, DOCS_VERSION, FOLLOWS_DOC, format_version

PSK_LEN: int = 32
_FORBIDDEN_DEFAULT_PSK: str = "isostress-default-psk-32bytes-long!!"


def generate_psk() -> bytes:
    """Generate a 256-bit high-entropy PSK."""
    return secure_random(PSK_LEN)


def psk_to_hex(psk: bytes) -> str:
    return binascii.hexlify(psk).decode("ascii")


def normalize_psk(psk_input: str) -> bytes:
    """Normalize the user-provided PSK: exactly 32 bytes, 64-character hex or standard Base64.
    Rejects the public default value and weak keys with too-low entropy (README security notes)."""
    s = psk_input.strip()
    if not s or s == _FORBIDDEN_DEFAULT_PSK:
        raise ValueError(
            "Weak or public default PSK rejected. Please provide 64-character hex or standard Base64 of 32 bytes."
        )
    raw = None
    if len(s) == 64:
        try:
            raw = binascii.unhexlify(s)
        except binascii.Error:
            pass
    if raw is None:
        try:
            raw = base64.b64decode(s, validate=True)
        except (binascii.Error, ValueError):
            pass
    if raw is None or len(raw) != PSK_LEN:
        raise ValueError(
            "PSK must be exactly 32 bytes of random data, encoded as 64-character hex or standard Base64."
        )
    check_entropy(raw)
    return raw


def load_psk_from_file(path: str) -> bytes:
    """Load the PSK from a file (warns if accessible to group/other users; 0600 permissions recommended)."""
    try:
        st = os.stat(path)
        # Windows reports synthetic mode bits (0o666 for a regular file), so the POSIX
        # permission check would warn on every file. The Rust implementation skips it
        # under cfg(unix); keep both sides aligned.
        if os.name == "posix" and st.st_mode & 0o077:
            print(
                f"[!] Warning: {path} is accessible to group/other users"
                f"(permissions {oct(st.st_mode & 0o777)}). Recommended: set to 0600.",
                file=sys.stderr,
            )
    except OSError:
        pass
    with open(path, "r", encoding="utf-8") as f:
        return normalize_psk(f.read())


def load_psk_from_env() -> Optional[bytes]:
    """Load the PSK from the ISOSTRESS_PSK environment variable."""
    raw = os.environ.get("ISOSTRESS_PSK")
    if raw:
        return normalize_psk(raw)
    return None


class WizardAborted(Exception):
    """Internal signal: the interactive wizard was interrupted (Ctrl+C / EOF)."""


def _wizard_ask(prompt: str, input_fn, print_fn) -> str:
    """Read one line from the terminal; Ctrl+C or EOF aborts the wizard cleanly."""
    try:
        return input_fn(prompt)
    except (EOFError, KeyboardInterrupt):
        raise WizardAborted from None


def _wizard_int(
    prompt: str, label: str, default: int, ok, hint: str, input_fn, print_fn
) -> int:
    """Ask for an integer (Enter takes the default), re-asking until ok() holds."""
    while True:
        raw = _wizard_ask(prompt, input_fn, print_fn).strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print_fn(f"[!] {label} must be an integer.")
            continue
        if ok(value):
            return value
        print_fn(f"[!] {hint}")


def run_wizard(input_fn=None, print_fn=None):
    """Interactive wizard -- reference-client README quick start (recommended for beginners).

    Four steps: role -> address/port -> PSK -> protocol parameters. Every step accepts
    Enter to take the default. Input and output are injectable, so the wizard is testable
    without a TTY. Returns the resolved settings, or None if the user aborted.
    """
    if input_fn is None:
        input_fn = input
    if print_fn is None:
        print_fn = print

    try:
        print_fn(
            "isostress interactive wizard (see the isostress-client README quick start)"
        )
        print_fn()

        # Step 1 -- role
        while True:
            answer = (
                _wizard_ask(
                    "① Role: 1 = listen (responder), 2 = connect (initiator) [1]: ",
                    input_fn,
                    print_fn,
                )
                .strip()
                .lower()
                or "1"
            )
            if answer in ("1", "listen"):
                role = "listen"
                break
            if answer in ("2", "connect"):
                role = "connect"
                break
            print_fn("[!] Please enter 1 or 2.")

        # Step 2 -- address and port
        default_host = DEFAULT_HOST_LISTEN if role == "listen" else DEFAULT_HOST_CONNECT
        host = (
            _wizard_ask(
                f"② Bind/target address [{default_host}]: ", input_fn, print_fn
            ).strip()
            or default_host
        )
        port = _wizard_int(
            f"   Port [{DEFAULT_PORT}]: ",
            "Port",
            DEFAULT_PORT,
            lambda v: 1 <= v <= 65535,
            "Port must be within 1-65535.",
            input_fn,
            print_fn,
        )

        # Step 3 -- PSK
        print_fn(
            "③ PSK: press Enter to generate a new high-entropy PSK (printed for the peer),"
        )
        print_fn("   or give a file path / paste 64-character hex or standard Base64.")
        while True:
            raw = _wizard_ask("   PSK: ", input_fn, print_fn).strip()
            if not raw:
                psk = generate_psk()
                print_fn()
                print_fn("   New PSK (hand this to the peer over a trusted channel):")
                print_fn(f"   {psk_to_hex(psk)}")
                print_fn()
                break
            try:
                # A path to an existing file wins; otherwise treat the text as PSK material.
                psk = (
                    load_psk_from_file(raw)
                    if os.path.isfile(raw)
                    else normalize_psk(raw)
                )
                break
            except (ValueError, OSError) as e:
                print_fn(f"[!] {e}")

        # Step 4 -- protocol parameters (ranges are re-validated on the shared path in main())
        print_fn(
            f"④ Protocol parameters: Enter takes the defaults "
            f"(random_len={RANDOM_LEN}, random_rate={RANDOM_RATE}, window={WINDOW})."
        )
        random_len = _wizard_int(
            f"   random_len [{RANDOM_LEN}]: ",
            "random_len",
            RANDOM_LEN,
            lambda v: v > 0 and v % 8 == 0 and v // 8 <= 512,
            "random_len must be a positive multiple of 8 (at most 4096 bits / 512 bytes).",
            input_fn,
            print_fn,
        )
        random_rate = _wizard_int(
            f"   random_rate [{RANDOM_RATE}]: ",
            "random_rate",
            RANDOM_RATE,
            lambda v: v > 0,
            "random_rate must be a positive integer.",
            input_fn,
            print_fn,
        )
        window = _wizard_int(
            f"   window [{WINDOW}]: ",
            "window",
            WINDOW,
            lambda v: v > 0,
            "window must be a positive integer.",
            input_fn,
            print_fn,
        )
    except WizardAborted:
        return None

    return {
        "role": role,
        "host": host,
        "port": port,
        "psk_bytes": psk,
        "random_len": random_len,
        "random_rate": random_rate,
        "window": window,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="isostress-py",
        description=f"isostress Core {CODE_VERSION} — Core protocol (conforms to {FOLLOWS_DOC})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Listener side (responder)
  isostress-py --role listen --port 37291 --psk-file psk.txt
  # Connector side (initiator)
  isostress-py --role connect --host <peer IP> --port 37291 --psk-file psk.txt
  # PSK via environment variable
  export ISOSTRESS_PSK=$(python -c "import secrets; print(secrets.token_hex(32))")
  isostress-py --role listen --port 37291 --psk-env

PSK security recommendations:
  1. Prefer --psk-file (permissions 0600)
  2. Then --psk-env (environment variable ISOSTRESS_PSK)
  3. Last resort --psk (command line, insecure, visible in the process list)

Running without arguments on a terminal starts the interactive wizard (README quick start);
with input or output redirected, this usage is printed instead. Extension modules
(TCA/AORS/Ocean Mode, etc.) are not within the scope of this minimal release.

License:
  AGPL-3.0-or-later, or a commercial license — see LICENSING.md
  Copyright (c) 2026 isostress Suite maintainers
  Source: https://github.com/isostress-suite/isostress-docs
""",
    )
    parser.add_argument(
        "--role",
        choices=["listen", "connect"],
        default=None,
        help="Role: listen=listener (responder), connect=connector (initiator)",
    )
    parser.add_argument("--host", default=None, help="Bind/target address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port number")
    parser.add_argument(
        "--psk", default=None, help="PSK (64-character hex or Base64; insecure)"
    )
    parser.add_argument("--psk-file", default=None, help="PSK file path (recommended)")
    parser.add_argument(
        "--psk-env",
        action="store_true",
        help="Read from environment variable ISOSTRESS_PSK",
    )
    parser.add_argument(
        "--random-len",
        type=int,
        default=RANDOM_LEN,
        help=f"Random data length in bits (default {RANDOM_LEN})",
    )
    parser.add_argument(
        "--random-rate",
        type=int,
        default=RANDOM_RATE,
        help=f"Generation rate in counts per second (default {RANDOM_RATE})",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=WINDOW,
        help=f"Negotiation window in seconds; both peers must match (default {WINDOW})",
    )
    parser.add_argument(
        "--time-window",
        type=int,
        default=TIME_WINDOW,
        help=f"Timestamp window in seconds (default {TIME_WINDOW})",
    )
    parser.add_argument(
        "--retry-count",
        type=int,
        default=DEFAULT_CONNECT_RETRY_COUNT,
        help=f"Connection retry count (default {DEFAULT_CONNECT_RETRY_COUNT})",
    )
    parser.add_argument(
        "--retry-interval",
        type=float,
        default=DEFAULT_CONNECT_RETRY_INTERVAL,
        help=f"Retry interval in seconds (default {DEFAULT_CONNECT_RETRY_INTERVAL})",
    )
    parser.add_argument(
        "--padding-min",
        type=int,
        default=None,
        help="Random padding minimum in bytes (enabled only when --padding-max is also given)",
    )
    parser.add_argument(
        "--padding-max",
        type=int,
        default=None,
        help=f"Random padding maximum in bytes (<= {MAX_PAD})",
    )
    parser.add_argument(
        "--jitter",
        type=float,
        default=0.0,
        help="Transmission timing jitter in seconds (default 0 = off)",
    )
    parser.add_argument(
        "--silent-hold",
        type=float,
        default=15.0,
        help="Strict silent hold duration in seconds (default 15)",
    )
    parser.add_argument("--version", action="version", version=format_version())
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Do not print the startup banner (also via ISOSTRESS_NO_BANNER)",
    )
    parser.add_argument(
        "--no-stdin",
        action="store_true",
        help="Do not read the input; the session only receives",
    )
    return parser


_BANNER_RULE = "\u2500" * 52


def _render_banner() -> str:
    """The startup banner. Two lines of text and one rule, nothing larger."""
    return (
        f"isostress \u00b7 {CODE_VERSION} (docs {DOCS_VERSION})\n"
        f"{_BANNER_RULE}\n"
        "isostress (ISTS) \u00b7 AGPL-3.0-or-later"
    )


def _emit_banner(stream):
    """Write the banner to stream, degrading to ASCII when the console cannot encode it."""
    try:
        stream.write(_render_banner() + "\n\n")
        stream.flush()
    except (UnicodeEncodeError, OSError):
        stream.write(
            f"isostress - {CODE_VERSION} (docs {DOCS_VERSION})\n"
            + "-" * 52
            + "\nisostress (ISTS) - AGPL-3.0-or-later\n\n"
        )
        stream.flush()


def main() -> None:
    """CLI entry point."""
    # Windows console Chinese output
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = build_parser()
    ns = parser.parse_args()

    wizard: Optional[dict] = None
    if ns.role is None:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            # Non-interactive context (pipe, CI, IDE runner): print usage instead of hanging.
            parser.print_help()
            return
        if not ns.no_banner and not os.environ.get("ISOSTRESS_NO_BANNER"):
            _emit_banner(sys.stderr)
        wizard = run_wizard()
        if wizard is None:
            print("[!] Wizard aborted; no session started.", file=sys.stderr)
            sys.exit(1)
        ns.role = wizard["role"]
        ns.host = wizard["host"]
        ns.port = wizard["port"]
        ns.random_len = wizard["random_len"]
        ns.random_rate = wizard["random_rate"]
        ns.window = wizard["window"]

    host = ns.host or (
        DEFAULT_HOST_LISTEN if ns.role == "listen" else DEFAULT_HOST_CONNECT
    )

    # --- Parameter range validation (invalid values never reach the protocol layer) ---
    if not (1 <= ns.port <= 65535):
        parser.error("Port must be within 1-65535")
    if ns.random_len <= 0 or ns.random_len % 8 != 0:
        parser.error("random_len must be a positive integer and a multiple of 8")
    if ns.random_len // 8 > 512:
        parser.error(
            "random_len/8 must not exceed the 512-byte cap on attached random data"
        )
    if ns.random_rate <= 0:
        parser.error("random_rate must be a positive integer")
    if ns.window <= 0:
        parser.error("window must be a positive integer")
    if ns.time_window <= 0:
        parser.error("time_window must be a positive integer")
    if ns.retry_count <= 0:
        parser.error("retry_count must be a positive integer")
    if ns.retry_interval <= 0:
        parser.error("retry_interval must be a positive number")
    if (ns.padding_min is None) != (ns.padding_max is None):
        parser.error("--padding-min and --padding-max must be given together")
    if ns.padding_min is not None:
        if not (0 <= ns.padding_min <= ns.padding_max <= MAX_PAD):
            parser.error("Padding range must satisfy 0 <= min <= max <= MAX_PAD")
    if ns.jitter < 0:
        parser.error("jitter must be non-negative")
    if ns.silent_hold <= 0:
        parser.error("silent_hold must be a positive number")

    # --- PSK injection (README priority order) ---
    psk_bytes: Optional[bytes] = wizard["psk_bytes"] if wizard else None
    if ns.psk_file:
        try:
            psk_bytes = load_psk_from_file(ns.psk_file)
        except (ValueError, OSError) as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)
    elif ns.psk_env:
        psk_bytes = load_psk_from_env()
        if psk_bytes is None:
            print("[!] Environment variable ISOSTRESS_PSK is not set", file=sys.stderr)
            sys.exit(1)
    elif ns.psk:
        print("[!] Warning: command-line --psk is insecure", file=sys.stderr)
        try:
            psk_bytes = normalize_psk(ns.psk)
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)
    elif psk_bytes is None:
        parser.error("One of --psk-file, --psk-env or --psk must be provided")

    try:
        params = ISOSTRESSParams(
            random_len=ns.random_len,
            random_rate=ns.random_rate,
            window=ns.window,
            key_len=KEY_LEN,
            hash_name=HASH_NAME,
            aead_name=AEAD_NAME,
        )
    except ISOSTRESSError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)

    run_session(
        {
            "role": ns.role,
            "host": host,
            "port": ns.port,
            "psk_bytes": psk_bytes,
            "params": params,
            "time_window": ns.time_window,
            "retry_count": ns.retry_count,
            "retry_interval": ns.retry_interval,
            "padding": (
                (ns.padding_min, ns.padding_max) if ns.padding_min is not None else None
            ),
            "jitter": ns.jitter,
            "silent_hold": ns.silent_hold,
            "read_stdin": not ns.no_stdin,
        }
    )


if __name__ == "__main__":
    main()
