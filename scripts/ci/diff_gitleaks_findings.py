#!/usr/bin/env python3
"""Report gitleaks findings that a change *introduces*, by secret value.

Used by ``.github/workflows/secret-scan.yml``. The workflow materializes the
changed files at the base revision and at HEAD, scans each into a JSON report,
and calls this to decide which findings are new.

Why not ``gitleaks --baseline-path``
------------------------------------
A baseline entry is matched on location (file, rule, line) plus ``Entropy``,
and ``Entropy`` is a rounded float over the secret's characters. So a
*different* secret at the same path, rule and line is suppressed whenever the
two entropies coincide — and any permutation of the baselined value collides
exactly. Verified against gitleaks 8.24.3: replacing a flagged fixture
credential with a different real one on the same line reported "no leaks
found".

That is exactly the merge-resolution case the content pass exists to catch
("replace the placeholder with the real key"), so keying the exemption on
location is the wrong choice. This keys on the secret's value instead.

Deliberately *not* part of the key
----------------------------------
File and line. A secret that merely moved was not introduced by the change,
and one whose value changed was — wherever it happens to sit. Keying on
location would report every line shift and miss every in-place replacement,
which is backwards on both counts.

Secrets are never printed. Only the path, line and rule of a new finding are
reported; the reports themselves stay in the caller's temp dirs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load(path: Path) -> list[dict]:
    """Read a gitleaks JSON report, tolerating the empty-report shapes."""
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SystemExit(f"cannot read gitleaks report {path}: {exc}") from exc
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        # Refuse rather than treat an unparseable report as "nothing found" —
        # a check that silently passes on a broken input is worse than none.
        raise SystemExit(f"gitleaks report {path} is not valid JSON: {exc}") from exc
    if data is None:
        return []
    if not isinstance(data, list):
        raise SystemExit(f"gitleaks report {path} is not a list of findings")
    return data


def key(finding: dict) -> tuple[str, str]:
    return (str(finding.get("RuleID", "")), str(finding.get("Secret", "")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", type=Path, help="gitleaks JSON for the base revision")
    parser.add_argument("head", type=Path, help="gitleaks JSON for HEAD")
    args = parser.parse_args(argv)

    base = load(args.base)
    head = load(args.head)

    known = {key(f) for f in base}
    new = [f for f in head if key(f) not in known]

    for finding in new:
        print(
            f"::error file={finding.get('File')},line={finding.get('StartLine')}::"
            f"{finding.get('RuleID')}: secret introduced by this change"
        )
    print(
        f"content scan: {len(head)} finding(s) in changed files, "
        f"{len(base)} already present at the base, {len(new)} new"
    )
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
