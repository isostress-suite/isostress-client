# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers
"""Cross-implementation interop, wired into pytest.

Before this file existed, interop_test.py ran nowhere: pytest did not
collect it and cargo had no test target for it. A green unit suite then
said nothing about whether the two implementations agree.
"""

import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
RS_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "isostress_rs"))
INTEROP = os.path.join(RS_DIR, "interop_test.py")


def _binary():
    for name in ("isostress-rs", "isostress-rs.exe"):
        for profile in ("release", "debug"):
            p = os.path.join(RS_DIR, "target", profile, name)
            if os.path.exists(p):
                return p
    return None


@pytest.mark.skipif(not os.path.exists(INTEROP), reason="interop_test.py not present")
def test_cross_implementation_interop():
    binary = _binary()
    if binary is None:
        pytest.skip("Rust binary not built; run cargo build --release in isostress_rs")
    # interop_test.py looks for target/release unless told otherwise; pass the path this
    # wrapper found so a debug-only build is tested instead of skipped then failed.
    r = subprocess.run(
        [sys.executable, "interop_test.py", "--rust-bin", binary],
        cwd=RS_DIR,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )
    out = (r.stdout or "") + (r.stderr or "")
    assert r.returncode == 0, f"interop subprocess exit={r.returncode}\n{out[-1500:]}"
    assert "interop suite passed" in out.lower(), (
        f"missing success marker (exit={r.returncode})\n{out[-800:]}"
    )
