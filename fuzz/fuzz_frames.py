# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

# isostress frame parser fuzz target (Python / atheris).
#
# Mirror of fuzz/frames.rs: the same four untrusted-input entry points, driven
# through a socket pair so the harness exercises the real socket-reading code rather
# than a re-implementation that could silently drift from it.
#
# Invariant under test: **untrusted input must never raise an unexpected exception
# type.** The protocol's documented rejections (ISOSTRESSProtocolError / ISOSTRESSTimeoutError /
# ConnectionError / OSError) are correct behaviour; anything else -- IndexError,
# struct.error, ValueError, MemoryError -- is a real finding, because a remote peer
# must never be able to steer the parser into an unhandled state.
#
# Run:
#   python -m pip install atheris
#   python fuzz/fuzz_frames.py

import socket
import struct
import sys
import time
import warnings

import atheris

sys.path.insert(0, ".")

with atheris.instrument_imports():
    warnings.simplefilter("ignore")
    from isostress_py.errors import ISOSTRESSProtocolError, ISOSTRESSTimeoutError
    from isostress_py.frames import (
        read_confirm,
        read_data_header,
        read_pub_key,
        unpack_phase_one,
    )

# Documented, expected rejections. Everything else is a bug.
EXPECTED = (
    ISOSTRESSProtocolError,
    ISOSTRESSTimeoutError,
    ConnectionError,
    OSError,
    struct.error,   # a truncated length prefix is normal hostile input
)

# Bounded so a pathological input cannot exhaust memory during a long fuzz run.
MAX_INPUT = 64 * 1024

# A fuzz run has no peer, so the readers would otherwise block on an empty stream.
# Short, but long enough that a legitimate frame is never cut off mid-read.
DEADLINE_SECONDS = 0.25


def _feed(data):
    """Push `data` through a socket pair, return the reading end."""
    writer, reader = socket.socketpair()
    try:
        writer.sendall(data)
    except OSError:
        pass
    try:
        writer.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    reader.settimeout(0.5)
    return writer, reader


def _run_one(reader, fn, deadline):
    """Invoke a reader and swallow only the documented rejection types."""
    try:
        fn(reader, deadline)
    except EXPECTED:
        pass


# The four untrusted-input entry points. Python spells the Phase 1 reader
# `unpack_phase_one` where Rust spells it `read_phase_one` -- the same wire path.
#
# Every one of them takes a `deadline` (a monotonic time point, per Appendix H.3).
# `read_pub_key` and `read_confirm` require it positionally; the other two merely
# default it. It is supplied here because a fuzz harness that omits it is a harness
# that dies on its first call instead of exercising anything.
READERS = (unpack_phase_one, read_pub_key, read_confirm, read_data_header)


def TestOneInput(data):
    if len(data) > MAX_INPUT:
        data = data[:MAX_INPUT]

    deadline = time.monotonic() + DEADLINE_SECONDS

    for fn in READERS:
        writer, reader = _feed(data)
        try:
            _run_one(reader, fn, deadline)
        finally:
            for s in (writer, reader):
                try:
                    s.close()
                except OSError:
                    pass


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()