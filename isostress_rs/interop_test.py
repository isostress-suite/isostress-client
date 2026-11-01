#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""ISOSTRESS_RS-1.0.0 cross-language interop verification (single file).

All scenarios bind to the 127.0.0.1 loopback only. Suites:

  [interop]  with ISOSTRESS_PY-1.0.0 (the current Python reference implementation, conforming to docs 1.0.0)
    A. Python listens (responder) ← Rust connects (initiator)   → expected: handshake + bidirectional message exchange
    B. Rust listens (responder)   ← Python connects (initiator) → expected: handshake + bidirectional message exchange

Usage:
  python interop_test.py [--rust-bin <isostress-rs executable path>] [--suite interop]

Default binary lookup order:
  1) --rust-bin argument
  2) environment variable ISOSTRESS_RS_BIN
  3) target/release/isostress-rs(.exe)   (standard build path inside this directory)
"""

import argparse
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent                 # isostress_rs → repository root

MSG_RS_TO_PY = "hello-from-rust-installer"
MSG_PY_TO_RS = "hello-from-python-reference"

py = sys.executable


def find_rust_bin(arg):
    candidates = []
    if arg:
        candidates.append(Path(arg))
    env = os.environ.get("ISOSTRESS_RS_BIN")
    if env:
        candidates.append(Path(env))
    exe = "isostress-rs.exe" if os.name == "nt" else "isostress-rs"
    candidates.append(HERE / "target" / "release" / exe)
    for c in candidates:
        if c.is_file():
            return c
    raise SystemExit(
        "[!] isostress-rs executable not found. Build it first and pass the path via "
        "--rust-bin, or set the environment variable ISOSTRESS_RS_BIN."
    )


def spawn(cmd, **kw):
    """Spawn a child and drain its output on a background thread.

    The thread matters: with a pipe and no reader, the child blocks once the OS pipe
    buffer fills, and our side cannot see the readiness marker. Threads are used rather
    than fcntl/O_NONBLOCK because this harness must also run on Windows.
    """
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True,
                         encoding="utf-8", errors="replace", bufsize=1, **kw)
    p._ztbuf = ""

    def _pump():
        try:
            for line in iter(p.stdout.readline, ""):
                p._ztbuf += line
        except Exception:
            pass

    t = threading.Thread(target=_pump, daemon=True)
    t.start()
    p._ztthread = t
    return p


def key_lines(t):
    keep = []
    for line in (t or "").splitlines():
        s = line.strip()
        if any(k in s for k in ("Handshake complete", "Handshake failed", "Anchor confirmed", "Security error",
                                "Silent Drop", "Connection", "Listening", "Failed", "Error")):
            keep.append("    " + s)
    return "\n".join(keep[-12:]) or "    (no key output)"


def wait_for(procs, needle, timeout=30.0, poll=0.05):
    """Wait until `needle` appears in every named process's output.

    Fixed `time.sleep()` is the textbook cause of a flaky CI test: it is either too
    short on a loaded runner (handshake has not finished yet) or wasteful on a fast
    one. Polling for the actual milestone makes the test both faster and deterministic
    in the sense that matters -- it waits for the state, not for a guessed duration.

    Returns True if all processes reached the milestone within `timeout`.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(needle in _drain(p) for p in procs):
            return True
        if any(p.poll() is not None for p in procs):
            # A process exited; one last read decides whether it said the magic words.
            return all(needle in _drain(p) for p in procs)
        time.sleep(poll)
    return False


def _drain(proc):
    """Everything the child has emitted so far (read by the background pump thread)."""
    return getattr(proc, "_ztbuf", "")


def run_scenario(name, listen_cmd, connect_cmd, verbose=False, exchange=True):
    print(f"\n=== {name} ===")
    la = spawn(listen_cmd)
    # Wait for the listener to actually bind instead of sleeping a guessed interval.
    if not wait_for([la], "Listening", timeout=20.0):
        la.kill()
        print("[!] listener never reported readiness")
    ca = spawn(connect_cmd)
    ok = False
    try:
        if exchange:
            # The milestone is the handshake completing on both sides, not a timer.
            ok = wait_for([la, ca], "Handshake complete", timeout=40.0)
            if not ok:
                print("[!] handshake did not complete within 40 s on both sides")
            assert ca.stdin and la.stdin
            ca.stdin.write(MSG_RS_TO_PY + "\n")
            ca.stdin.flush()
            # Give the peer a moment to consume, but only as a floor under polling.
            wait_for([la], MSG_RS_TO_PY, timeout=5.0)
            la.stdin.write(MSG_PY_TO_RS + "\n")
            la.stdin.flush()
            wait_for([ca], MSG_PY_TO_RS, timeout=5.0)
            la.stdin.write("/quit\n")
            ca.stdin.write("/quit\n")
            la.stdin.flush()
            ca.stdin.flush()
        # The pump thread owns stdout, so communicate() only closes stdin and reaps.
        # Everything we assert on has already been accumulated in _ztbuf.
        la.communicate(timeout=40)
        ca.communicate(timeout=40)
        la._ztthread.join(timeout=2)
        ca._ztthread.join(timeout=2)
        lo = _drain(la)
        co = _drain(ca)
    except subprocess.TimeoutExpired:
        la.kill(); ca.kill()
        la.communicate(); ca.communicate()
        lo = _drain(la)
        co = _drain(ca)
        print("[timeout] process did not exit within 40 s (force-killed)")
    if verbose:
        print("--- listener full output ---")
        print(lo)
        print("--- connector full output ---")
        print(co)
    print("--- listener key output ---")
    print(key_lines(lo))
    print("--- connector key output ---")
    print(key_lines(co))
    # Return the two streams separately so the caller can assert per side.
    return lo or "", co or ""


# =============================================================================
# [interop] interop with the current Python reference implementation
# =============================================================================

def suite_interop(rust_bin, port):
    psk = secrets.token_hex(32)
    # The Python side needs the repo root on PYTHONPATH to run as -m isostress_py;
    # inject it into this process's environment; all children inherit it.
    # Prepend the repo root instead of replacing PYTHONPATH: a developer running the
    # suite against a local virtualenv or an extra path would otherwise lose it.
    _existing = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = (
        str(REPO_ROOT) + os.pathsep + _existing if _existing else str(REPO_ROOT)
    )
    os.environ["PYTHONIOENCODING"] = "utf-8"
    py_launch = [py, "-u", "-m", "isostress_py"]

    def rust_cmd(role, p):
        return [str(rust_bin), "--role", role, "--host", "127.0.0.1",
                "--port", str(p), "--psk", psk]

    def py_cmd(role, p):
        return py_launch + ["--role", role, "--port", str(p), "--psk", psk]

    ok = True
    for name, lcmd, ccmd, port_off in [
        ("A (Python listens ← Rust connects)", py_cmd("listen", port), rust_cmd("connect", port), 0),
        ("B (Rust listens ← Python connects)", rust_cmd("listen", port + 1), py_cmd("connect", port + 1), 0),
    ]:
        lo, co = run_scenario(name, lcmd, ccmd)
        # Per-side assertions. Concatenating both outputs and searching the result
        # would pass even if one side died after the handshake, since the other
        # side's echo still carries the marker.
        passed = (
            "Handshake complete" in lo
            and "Handshake complete" in co
            # Each message must be echoed by the *other* side, i.e. appear in the
            # listener's output when Rust sent it and vice versa.
            and MSG_RS_TO_PY in lo
            and MSG_PY_TO_RS in co
        )
        print(f">> Result: {'[OK] pass: handshake + bidirectional message exchange' if passed else '[!] fail'}")
        if not passed:
            print("    listener saw handshake=%s msg=%s" % (
                "Handshake complete" in lo, MSG_RS_TO_PY in lo))
            print("    connector saw handshake=%s msg=%s" % (
                "Handshake complete" in co, MSG_PY_TO_RS in co))
        ok = ok and passed
        time.sleep(1)

    if ok:
        print("\n[[ok]] interop suite passed: ISOSTRESS_RS-1.0.0 and ISOSTRESS_PY-1.0.0 interoperate on the wire"
              "(both conforming to docs 1.0.0)")
    else:
        print("\n[!] interop suite has failing scenarios")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rust-bin", default=None)
    ap.add_argument("--suite", choices=["all", "interop"], default="all")
    ap.add_argument("--port", type=int, default=37441)
    args = ap.parse_args()

    rust_bin = find_rust_bin(args.rust_bin)
    print(f"Rust binary: {rust_bin}")

    ok = True
    if args.suite in ("all", "interop"):
        ok = suite_interop(rust_bin, args.port) and ok

    print("\n[[ok]] all selected suites passed" if ok else "\n[!] failing scenarios present, see output above")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
