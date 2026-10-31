# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Cross-document reference checks: every appendix letter cited in code must exist in the spec.

Context: commit 6e1d425 of isostress-docs ("Prune stale appendices") removed appendices A / D / E,
but 20 references in the client repo kept pointing at appendix letters that no longer existed --
including one string printed to the user (cli.py). The existing docs-to-code declaration checks only
compare constants and values, so they could not catch it. This test turns "cross-references still
resolve" into an invariant that a test run enforces.

The spec lives in another repository: skip when it cannot be found (e.g. in this repo's own CI,
which checks out only this repository), to avoid false reds.
"""

import re
from pathlib import Path

import pytest

CLIENT_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = CLIENT_ROOT.parent
SPEC_DIRS = [
    WORKSPACE_ROOT / "isostress-docs" / "cn" / "spec",
    WORKSPACE_ROOT / "isostress-docs" / "en" / "spec",
]
SOURCE_DIRS = [CLIENT_ROOT / "isostress_py", CLIENT_ROOT / "isostress_rs"]
SKIP_DIRS = {"__pycache__", "target", ".pytest_cache", ".git"}

APPENDIX_HEADING = re.compile(r"^#{1,6}\s*(?:附录|Appendix)\s+([A-Z])\b", re.MULTILINE)
APPENDIX_CITATION = re.compile(r"(?:Appendix|附录)\s+([A-Z])\b")


def _spec_files():
    files = [p for d in SPEC_DIRS if d.is_dir() for p in d.glob("*.md")]
    return files


def _existing_letters(spec_files):
    letters = set()
    for path in spec_files:
        letters.update(APPENDIX_HEADING.findall(path.read_text(encoding="utf-8")))
    return letters


def _source_files():
    out = []
    for root in SOURCE_DIRS:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.suffix not in (".py", ".rs"):
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            out.append(path)
    return sorted(out)


def test_no_cited_appendix_is_missing():
    spec_files = _spec_files()
    if not spec_files:
        pytest.skip(
            "isostress-docs spec not found (cross-repo check, runs in the full workspace)"
        )

    existing = _existing_letters(spec_files)
    assert existing, "no appendix headings parsed; the heading pattern may have drifted"

    dangling = []
    for path in _source_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for letter in APPENDIX_CITATION.findall(line):
                if letter not in existing:
                    rel = path.relative_to(CLIENT_ROOT).as_posix()
                    dangling.append(f"{rel}:{lineno} cites Appendix {letter}")

    assert not dangling, "appendix citations that do not resolve:\n  " + "\n  ".join(
        dangling
    )
