"""Tests for scripts/ci/diff_gitleaks_findings.py.

The script decides which gitleaks findings a change *introduced*. Its key
choice — (rule, secret) rather than (file, rule, line) — is what makes an
in-place credential replacement visible, so it is pinned here.
"""

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "diff_gitleaks_findings.py"


def _load():
    spec = importlib.util.spec_from_file_location("diff_gitleaks_findings", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load()


def _finding(secret: str, *, rule: str = "anthropic-api-key", file: str = "a.py", line: int = 1):
    return {"RuleID": rule, "Secret": secret, "File": file, "StartLine": line}


def _write(tmp_path: Path, name: str, findings) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(findings), encoding="utf-8")
    return path


def _run(tmp_path, base, head) -> int:
    return mod.main([str(_write(tmp_path, "b.json", base)), str(_write(tmp_path, "h.json", head))])


def test_unchanged_secret_is_not_new(tmp_path):
    f = [_finding("AAA")]
    assert _run(tmp_path, f, f) == 0


def test_replaced_secret_at_the_same_location_is_new(tmp_path):
    """The case gitleaks' own --baseline-path misses on an entropy collision."""
    assert _run(tmp_path, [_finding("AAA")], [_finding("BBB")]) == 1


def test_moved_secret_is_not_new(tmp_path):
    """A line shift or a rename is not an introduction."""
    base = [_finding("AAA", file="a.py", line=1)]
    head = [_finding("AAA", file="b.py", line=99)]
    assert _run(tmp_path, base, head) == 0


def test_same_value_under_a_different_rule_is_new(tmp_path):
    assert _run(tmp_path, [_finding("AAA", rule="r1")], [_finding("AAA", rule="r2")]) == 1


def test_added_secret_alongside_an_existing_one(tmp_path):
    assert _run(tmp_path, [_finding("AAA")], [_finding("AAA"), _finding("BBB")]) == 1


def test_removed_secret_is_not_a_failure(tmp_path):
    assert _run(tmp_path, [_finding("AAA"), _finding("BBB")], [_finding("AAA")]) == 0


@pytest.mark.parametrize("empty", ["", "[]", "null"])
def test_empty_reports(tmp_path, empty):
    base = tmp_path / "b.json"
    head = tmp_path / "h.json"
    base.write_text(empty, encoding="utf-8")
    head.write_text(empty, encoding="utf-8")
    assert mod.main([str(base), str(head)]) == 0


def test_unparseable_report_fails_closed(tmp_path):
    """A broken report must not read as 'nothing found'."""
    base = tmp_path / "b.json"
    base.write_text("not json", encoding="utf-8")
    head = _write(tmp_path, "h.json", [])
    with pytest.raises(SystemExit):
        mod.main([str(base), str(head)])


def test_non_list_report_fails_closed(tmp_path):
    base = tmp_path / "b.json"
    base.write_text('{"findings": []}', encoding="utf-8")
    head = _write(tmp_path, "h.json", [])
    with pytest.raises(SystemExit):
        mod.main([str(base), str(head)])


def test_secret_values_are_never_printed(tmp_path, capsys):
    secret = "sk-ant-api03-THIS-MUST-NOT-APPEAR"
    _run(tmp_path, [], [_finding(secret)])
    out = capsys.readouterr()
    assert secret not in out.out
    assert secret not in out.err
    assert "a.py" in out.out and "anthropic-api-key" in out.out
