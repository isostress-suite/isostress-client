#!/usr/bin/env bash
# Repository-local self-check. Runs in the git root.
set -eu
root=$(git rev-parse --show-toplevel)
cd "$root"

PYTHONPATH=zt_dsp_py python -m pytest zt_dsp_py/tests -q
python -m py_compile fuzz/fuzz_frames.py
python -m ruff format --check zt_dsp_py
(cd zt_dsp_rs && cargo fmt --check)

# The server implementation exists (ZT-DSP-server#1; zt_dsp_sv_py in this
# repository). A stale "placeholder, not implemented yet" claim about the
# server once shipped in the READMEs and misdirected readers; the wording
# must not come back. Removal landed through the server-version-rows change;
# this guard holds after it.
if grep -rn -E "占位，尚未实现|placeholder, not implemented yet" README.md cn/README.md en/README.md; then
  echo "client self-check FAILED: stale server-placeholder claim in a README" >&2
  exit 1
fi
echo "client self-check passed"
