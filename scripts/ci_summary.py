# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Render JUnit and coverage results into a GitHub Actions job summary.

Used by .github/workflows/ci.yml. Writes to $GITHUB_STEP_SUMMARY when that variable is
set (so the numbers appear on the workflow run page) and otherwise prints to stdout, so
the script can also be run locally:

    python scripts/ci_summary.py junit.xml coverage.xml
"""

from __future__ import annotations

import os
import sys
import xml.etree.ElementTree as ET


def read_junit(path: str) -> str:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        return f"_junit: not available ({exc})_"
    suites = [root] if root.tag == "testsuite" else list(root)
    total = failures = errors = skipped = 0
    for suite in suites:
        total += int(suite.get("tests", 0))
        failures += int(suite.get("failures", 0))
        errors += int(suite.get("errors", 0))
        skipped += int(suite.get("skipped", 0))
    passed = total - failures - errors - skipped
    mark = "PASS" if failures + errors == 0 else "FAIL"
    return f"**{mark}** -- {passed} passed, {failures} failed, {errors} errored, {skipped} skipped ({total} total)"


def read_coverage(path: str) -> str:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        return f"_coverage: not available ({exc})_"
    line_rate = float(root.get("line-rate", 0.0)) * 100
    branch_rate = float(root.get("branch-rate", 0.0)) * 100
    return f"line {line_rate:.1f}%, branch {branch_rate:.1f}%"


def main(argv: list[str]) -> int:
    lines = ["## Test summary", ""]
    for path in argv[1:]:
        if not os.path.exists(path):
            continue
        if path.endswith("junit.xml"):
            lines.append(f"- {read_junit(path)}")
        elif path.endswith("coverage.xml"):
            lines.append(f"- Coverage: {read_coverage(path)}")
    text = "\n".join(lines) + "\n"
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
