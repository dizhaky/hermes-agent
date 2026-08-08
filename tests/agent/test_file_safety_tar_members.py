"""Regression tests for ``agent.file_safety.assert_safe_tar_members``.

The guard stands in for ``tarfile``'s ``filter="data"`` on interpreters that
predate it. ``requires-python`` is ``>=3.11`` and the parameter landed in
3.11.4, so 3.11.0–3.11.3 take the unfiltered ``extractall`` fallback and the
guard is the only thing between an untrusted archive and the filesystem.

Its live consumer is ``agent.curator_backup``, which extracts a snapshot into
the **skills** directory — executable content, not a throwaway temp dir.
"""

import io
import tarfile
from pathlib import Path

import pytest

from agent.file_safety import assert_safe_tar_members


def _tar_with(path: Path, *members: tarfile.TarInfo) -> Path:
    """Write a tarball whose members are used verbatim.

    Each ``TarInfo`` is constructed by hand rather than via
    ``gettarinfo(arcname=…)``, because that helper normalizes a leading ``/``
    away — which would silently turn an absolute-path case into a relative one
    and never exercise the guard's ``startswith("/")`` branch.
    """
    with tarfile.open(path, "w:gz") as tar:
        for member in members:
            if member.isreg() and member.size:
                tar.addfile(member, io.BytesIO(b"x" * member.size))
            else:
                tar.addfile(member)
    return path


def _file(name: str, size: int = 4) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    return info


def _dir(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    return info


def _link(name: str, target: str, *, hard: bool) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.LNKTYPE if hard else tarfile.SYMTYPE
    info.linkname = target
    return info


class TestMemberNames:
    @pytest.mark.parametrize(
        "member_name",
        [
            "../escaped.txt",
            "psutil-7.2.2/../../escaped.txt",
            "/tmp/absolute-escape.txt",
        ],
    )
    def test_traversal_name_is_rejected(self, tmp_path, member_name):
        archive = _tar_with(tmp_path / "t.tar.gz", _file(member_name))
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError, match="refusing to extract unsafe path"):
                assert_safe_tar_members(tar)

    def test_ordinary_layout_is_accepted(self, tmp_path):
        archive = _tar_with(
            tmp_path / "t.tar.gz", _dir("skills/demo"), _file("skills/demo/SKILL.md")
        )
        with tarfile.open(archive) as tar:
            assert_safe_tar_members(tar)


class TestWindowsPathSemantics:
    r"""`extractall` builds paths with `os.path`, which on Windows also splits
    on `\` and honours drive letters. A member that looks like one opaque POSIX
    component there is a multi-component escape at extraction time, so both
    readings have to agree — and the guard runs the same on every host, since
    the archive, not the host, decides what the names are.
    """

    @pytest.mark.parametrize(
        "member_name",
        [
            r"..\outside.txt",
            r"skills\..\..\outside.txt",
            r"C:\outside.txt",
            r"\\server\share\outside.txt",
            r"C:outside.txt",
        ],
    )
    def test_windows_style_traversal_is_rejected(self, tmp_path, member_name):
        archive = _tar_with(tmp_path / "t.tar.gz", _file(member_name))
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError, match="refusing to extract unsafe path"):
                assert_safe_tar_members(tar)

    def test_windows_style_link_target_is_rejected(self, tmp_path):
        archive = _tar_with(
            tmp_path / "t.tar.gz", _link("snap/link", r"..\..\outside", hard=False)
        )
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError, match="target escapes"):
                assert_safe_tar_members(tar)

    def test_drive_qualified_link_target_is_rejected(self, tmp_path):
        archive = _tar_with(
            tmp_path / "t.tar.gz", _link("snap/link", r"C:\Windows", hard=False)
        )
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError, match="absolute target"):
                assert_safe_tar_members(tar)


class TestSymlinkTargets:
    """A clean *name* is not enough — the target has to be checked too."""

    def test_escaping_target_is_rejected(self, tmp_path):
        """The gap a name-only check misses.

        ``link`` has a clean name, so member-name validation passes; the
        unfiltered fallback then writes ``link/pwned.txt`` outside the
        destination *through* the link.
        """
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _link("snap/link", "../../outside", hard=False),
            _file("snap/link/pwned.txt"),
        )
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError, match="target escapes"):
                assert_safe_tar_members(tar)

    def test_absolute_target_is_rejected(self, tmp_path):
        archive = _tar_with(tmp_path / "t.tar.gz", _link("snap/link", "/etc", hard=False))
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError, match="absolute target"):
                assert_safe_tar_members(tar)

    def test_internal_relative_target_is_allowed(self, tmp_path):
        """A symlink is resolved from its own directory, so this stays inside."""
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _dir("snap/sub"),
            _file("snap/README"),
            _link("snap/sub/link", "../README", hard=False),
        )
        with tarfile.open(archive) as tar:
            assert_safe_tar_members(tar)


class TestHardlinkTargets:
    """Hardlinks resolve from a **different base** than symlinks.

    ``tarfile`` resolves a hardlink itself, joining ``linkname`` onto the
    extraction root (``TarFile._extract_member`` sets ``tarinfo._link_target =
    os.path.join(path, tarinfo.linkname)``), whereas a symlink is handed to
    ``os.symlink`` verbatim and read by the kernel relative to the link's own
    directory. Applying symlink semantics to a hardlink under-resolves it.
    """

    def test_root_relative_escape_is_rejected(self, tmp_path):
        """``a/b/link -> ../victim`` escapes as a hardlink but not as a symlink.

        Under the link's parent it reads as the harmless ``a/victim``; under the
        extraction root it is ``<root>/../victim`` — a file beside the
        destination that a later write through the link overwrites.
        """
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _dir("a"),
            _dir("a/b"),
            _file("a/victim.txt"),
            _link("a/b/link", "../victim.txt", hard=True),
        )
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError, match="target escapes"):
                assert_safe_tar_members(tar)

    def test_same_target_is_allowed_as_a_symlink(self, tmp_path):
        """The asymmetry is the point: identical linkname, opposite verdicts."""
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _dir("a"),
            _dir("a/b"),
            _file("a/victim.txt"),
            _link("a/b/link", "../victim.txt", hard=False),
        )
        with tarfile.open(archive) as tar:
            assert_safe_tar_members(tar)

    def test_root_relative_target_inside_the_tree_is_allowed(self, tmp_path):
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _dir("a"),
            _dir("a/b"),
            _file("a/victim.txt"),
            _link("a/b/link", "a/victim.txt", hard=True),
        )
        with tarfile.open(archive) as tar:
            assert_safe_tar_members(tar)

    def test_absolute_target_is_rejected(self, tmp_path):
        archive = _tar_with(tmp_path / "t.tar.gz", _link("a/link", "/etc/passwd", hard=True))
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError, match="absolute target"):
                assert_safe_tar_members(tar)

    def test_extractall_would_actually_link_outside(self, tmp_path):
        """Ground the semantics claim in observed behaviour, not documentation.

        Without the guard, the unfiltered ``extractall`` this stands in for
        hardlinks the member to a file *outside* the destination, and writing
        through it mutates that outside file.
        """
        victim = tmp_path / "victim.txt"
        victim.write_text("ORIGINAL\n")
        dest = tmp_path / "dest"
        dest.mkdir()

        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _dir("a"),
            _dir("a/b"),
            _link("a/b/link", "../victim.txt", hard=True),
        )
        with tarfile.open(archive) as tar:
            tar.extractall(dest)

        link = dest / "a" / "b" / "link"
        assert link.stat().st_ino == victim.stat().st_ino
        link.write_text("PWNED\n")
        assert victim.read_text() == "PWNED\n"

        # ...and the guard refuses exactly that archive.
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError, match="target escapes"):
                assert_safe_tar_members(tar)


class TestSpecialMembers:
    """``filter="data"`` refuses non-regular members; so does the guard."""

    @pytest.mark.parametrize(
        "member_type", [tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE]
    )
    def test_device_and_fifo_members_are_rejected(self, tmp_path, member_type):
        info = tarfile.TarInfo("snap/weird")
        info.type = member_type
        archive = _tar_with(tmp_path / "t.tar.gz", info)
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError, match="special member"):
                assert_safe_tar_members(tar)
