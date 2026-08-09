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

Counted as a multiset
---------------------
Occurrences are compared by count, not by set membership. A resolution that
adds a *second* copy of a credential already present in the changed files
leaves the key unchanged, so plain membership would exempt both copies and
report nothing new. Only as many occurrences as existed at the base are
exempt.

Secrets are never printed. Only the path, line and rule of a new finding are
reported; the reports themselves stay in the caller's temp dirs.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
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
    parser.add_argument(
        "--extra-base",
        type=Path,
        action="append",
        default=[],
        metavar="REPORT",
        help=(
            "another slice of the SAME base snapshot, covering paths the main "
            "report could not. Counts add, because the slices are disjoint: "
            "deleted files are scanned into their own tree only because a file "
            "and a directory cannot share a name."
        ),
    )
    parser.add_argument(
        "--alt-base",
        type=Path,
        action="append",
        default=[],
        metavar="REPORT",
        help=(
            "an ALTERNATIVE base snapshot of the same paths — the branch's "
            "previous head alongside the target's tip. Counts are combined by "
            "maximum, not by sum: the snapshots overlap, so adding them would "
            "exempt two copies of a credential that each parent holds once, "
            "and a merge resolution that duplicates it would pass."
        ),
    )
    args = parser.parse_args(argv)

    base = load(args.base)
    for extra in args.extra_base:
        base.extend(load(extra))
    head = load(args.head)

    # Within a snapshot, occurrences add. Across snapshots they do not: each is
    # a complete account of the same paths at a different revision, so what is
    # exempt is the most any single parent actually held.
    remaining = Counter(key(f) for f in base)
    for alt in args.alt_base:
        counts = Counter(key(f) for f in load(alt))
        for k, n in counts.items():
            if n > remaining[k]:
                remaining[k] = n
    exempt = sum(remaining.values())

    new = []
    for finding in head:
        k = key(finding)
        if remaining[k] > 0:
            remaining[k] -= 1
            continue
        new.append(finding)

    for finding in new:
        print(
            f"::error file={finding.get('File')},line={finding.get('StartLine')}::"
            f"{finding.get('RuleID')}: secret introduced by this change"
        )
    print(
        f"content scan: {len(head)} finding(s) in changed files, "
        f"{exempt} already present at the base, {len(new)} new"
    )
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
