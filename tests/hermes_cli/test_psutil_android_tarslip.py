"""Regression tests for archive-extraction safety and StepFun region inference.

`_install_psutil_android_compat` downloads a psutil sdist and extracts it. The
download's checksum is not verified, so the tarball is untrusted input even
though the URL is pinned — a compromised or MITM'd sdist could otherwise write
outside the temp dir via `../` members (CodeQL `py/tarslip`).
"""

import io
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from hermes_cli.main import _infer_stepfun_region, _install_psutil_android_compat


def _make_tarball(path: Path, member_name: str, payload: bytes = b"pwned\n") -> None:
    """Build a one-member tarball whose member is named `member_name` verbatim.

    The TarInfo is constructed by hand rather than via ``gettarinfo(arcname=…)``,
    because that helper normalizes a leading ``/`` away — which would silently
    turn an absolute-path test case into a relative one and never exercise the
    guard's ``startswith("/")`` branch.
    """
    info = tarfile.TarInfo(name=member_name)
    info.size = len(payload)
    with tarfile.open(path, "w:gz") as tar:
        tar.addfile(info, io.BytesIO(payload))


class TestPsutilSdistExtractionIsGuarded:
    """A malicious sdist must not escape the extraction directory."""

    @pytest.mark.parametrize(
        "member_name",
        [
            "../escaped.txt",
            "psutil-7.2.2/../../escaped.txt",
            "/tmp/absolute-escape.txt",
        ],
    )
    def test_traversal_member_is_rejected(self, tmp_path, member_name):
        staging = tmp_path / "staging"
        staging.mkdir()
        malicious = staging / "psutil.tar.gz"
        _make_tarball(malicious, member_name)

        def fake_urlretrieve(url, filename):
            Path(filename).write_bytes(malicious.read_bytes())
            return str(filename), None

        with patch("urllib.request.urlretrieve", side_effect=fake_urlretrieve):
            with pytest.raises(tarfile.TarError, match="refusing to extract unsafe path"):
                _install_psutil_android_compat(["pip"])

    def test_benign_member_is_not_rejected(self, tmp_path):
        """The guard must not reject an ordinary sdist layout.

        Extraction succeeds, so the function proceeds past the tar step and
        fails later on the absent psutil source tree — proving the guard let
        a well-formed archive through rather than short-circuiting everything.
        """
        staging = tmp_path / "staging"
        staging.mkdir()
        benign = staging / "psutil.tar.gz"
        _make_tarball(benign, "psutil-7.2.2/README")

        def fake_urlretrieve(url, filename):
            Path(filename).write_bytes(benign.read_bytes())
            return str(filename), None

        with patch("urllib.request.urlretrieve", side_effect=fake_urlretrieve):
            with pytest.raises(Exception) as exc:
                _install_psutil_android_compat(["pip"])
        assert "refusing to extract unsafe path" not in str(exc.value)

    def test_no_file_is_written_outside_the_temp_dir(self, tmp_path, monkeypatch):
        """End-to-end: the traversal target must never appear on disk."""
        sentinel_root = tmp_path / "outside"
        sentinel_root.mkdir()
        sentinel = sentinel_root / "escaped.txt"

        staging = tmp_path / "staging"
        staging.mkdir()
        malicious = staging / "psutil.tar.gz"
        _make_tarball(malicious, f"../../{sentinel_root.name}/{sentinel.name}")

        real_mkdtemp = tempfile.mkdtemp

        def nested_tmp(*a, **kw):
            return real_mkdtemp(dir=str(sentinel_root.parent))

        monkeypatch.setattr(tempfile, "mkdtemp", nested_tmp)

        def fake_urlretrieve(url, filename):
            Path(filename).write_bytes(malicious.read_bytes())
            return str(filename), None

        with patch("urllib.request.urlretrieve", side_effect=fake_urlretrieve):
            with pytest.raises(tarfile.TarError):
                _install_psutil_android_compat(["pip"])

        assert not sentinel.exists(), "traversal member escaped the extraction dir"


class TestStepFunRegionInference:
    """Host is matched exactly, not by substring."""

    def test_real_china_endpoint(self):
        assert _infer_stepfun_region("https://api.stepfun.com/step_plan/v1") == "china"

    def test_real_international_endpoint(self):
        assert (
            _infer_stepfun_region("https://api.stepfun.ai/step_plan/v1") == "international"
        )

    @pytest.mark.parametrize(
        "url",
        [
            "https://api.stepfun.com.example.net/step_plan/v1",
            "https://evil.example/?next=https://api.stepfun.com/step_plan/v1",
            "https://api.stepfun.com.evil.example/v1",
        ],
    )
    def test_lookalike_hosts_are_not_china(self, url):
        assert _infer_stepfun_region(url) == "international"

    @pytest.mark.parametrize("url", ["", None, "   "])
    def test_empty_input_defaults_to_international(self, url):
        assert _infer_stepfun_region(url) == "international"

    def test_bare_host_without_scheme(self):
        assert _infer_stepfun_region("api.stepfun.com") == "china"

    def test_trailing_dot_host_is_normalized(self):
        assert _infer_stepfun_region("https://api.stepfun.com./v1") == "china"
