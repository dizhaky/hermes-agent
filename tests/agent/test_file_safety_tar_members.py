"""Regression tests for ``agent.file_safety.safe_extract_tar``.

``tarfile``'s ``filter="data"`` landed in 3.11.4 while ``requires-python`` is
``>=3.11``, so 3.11.0–3.11.3 have no filter. This module's contract is that
extraction is safe on those interpreters *too* — not by validating members and
then calling an unfiltered ``extractall``, but by never calling it.

The tests therefore assert the property that matters — **nothing lands outside
the destination** — by extracting for real and looking at the filesystem,
rather than asserting that a particular check fires. Three separate bypasses of
the previous lexical check are pinned here as escape scenarios; each one passed
that check while writing outside.

Its live consumer is ``agent.curator_backup``, which extracts into the
**skills** directory — executable content, not a throwaway temp dir.
"""

import io
import os
import sys
import tarfile
from pathlib import Path

import pytest

from agent.file_safety import safe_extract_tar

# The manual path is only reachable on 3.11.0-3.11.3. Everywhere else the real
# filter runs, so force the manual path too and assert both are safe.
FORCE_MANUAL = [False, True]


@pytest.fixture(params=FORCE_MANUAL, ids=["stdlib-filter", "manual-fallback"])
def extract(request, monkeypatch):
    """Run ``safe_extract_tar`` via the stdlib filter and via the fallback."""
    if request.param:
        real = tarfile.TarFile.extractall

        def no_filter(self, path=".", members=None, **kwargs):
            if "filter" in kwargs:
                raise TypeError("extractall() got an unexpected keyword argument 'filter'")
            return real(self, path, members, **kwargs)

        monkeypatch.setattr(tarfile.TarFile, "extractall", no_filter)
    return safe_extract_tar


def _tar_with(path: Path, *members: tarfile.TarInfo) -> Path:
    """Write a tarball whose members are used verbatim.

    Each ``TarInfo`` is built by hand rather than via ``gettarinfo(arcname=…)``,
    because that helper normalizes a leading ``/`` away — which would silently
    turn an absolute-path case into a relative one.
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


def _extract_expecting_containment(extract, archive: Path, dest: Path) -> None:
    """Extract and require containment, however the implementation achieves it.

    The two paths legitimately differ in *mechanism*: the manual fallback
    refuses an unsafe member outright, while the stdlib ``data`` filter often
    neutralizes it instead — it strips a leading ``/``, and on POSIX a name like
    ``..\\outside`` is one legal filename component, so it lands inside as a
    literal file. Both satisfy the contract, which is containment, not raising.
    Asserting the mechanism would pin an implementation detail of CPython.
    """
    with tarfile.open(archive) as tar:
        try:
            extract(tar, dest)
        except tarfile.TarError:
            pass


def _nothing_outside(tmp_path: Path, dest: Path) -> None:
    """Assert the extraction wrote nothing outside ``dest``."""
    strays = [
        p
        for p in tmp_path.rglob("*")
        if p.is_file() and dest not in p.parents and p.suffix != ".gz"
    ]
    assert not strays, f"content escaped the destination: {strays}"


class TestEscapesAreBlocked:
    """Each case is a real bypass of the lexical check this replaced."""

    def test_traversal_name(self, tmp_path, extract):
        dest = tmp_path / "dest"
        dest.mkdir()
        archive = _tar_with(tmp_path / "t.tar.gz", _file("../escaped.txt"))
        _extract_expecting_containment(extract, archive, dest)
        _nothing_outside(tmp_path, dest)

    def test_absolute_name(self, tmp_path, extract):
        dest = tmp_path / "dest"
        dest.mkdir()
        # Absolute member names are expressed under tmp_path so the assertion
        # is about this run, not about global filesystem state.
        outside = tmp_path / "outside-abs.txt"
        archive = _tar_with(tmp_path / "t.tar.gz", _file(str(outside)))
        _extract_expecting_containment(extract, archive, dest)
        assert not outside.exists()
        _nothing_outside(tmp_path, dest)

    def test_symlink_target_escapes_and_a_later_member_writes_through_it(
        self, tmp_path, extract
    ):
        """Bypass #1: clean *name*, escaping *target*."""
        dest = tmp_path / "dest"
        dest.mkdir()
        (tmp_path / "outside").mkdir()
        payload = b"pwned\n"
        through = tarfile.TarInfo("snap/link/pwned.txt")
        through.size = len(payload)
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _dir("snap"),
            _link("snap/link", "../../outside", hard=False),
            through,
        )
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError):
                extract(tar, dest)
        assert not (tmp_path / "outside" / "pwned.txt").exists()
        _nothing_outside(tmp_path, dest)

    def test_hardlink_target_resolves_from_the_extraction_root(self, tmp_path, extract):
        """Bypass #2: hardlinks resolve from the root, not the link's parent.

        ``tarfile`` sets ``tarinfo._link_target = os.path.join(path, linkname)``
        with ``path`` the extraction root, so ``a/b/link -> ../victim`` reads as
        the harmless ``a/victim`` under the link's parent but lands beside the
        destination.
        """
        dest = tmp_path / "dest"
        dest.mkdir()
        victim = tmp_path / "victim.txt"
        victim.write_text("ORIGINAL\n")
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _dir("a"),
            _dir("a/b"),
            _link("a/b/link", "../victim.txt", hard=True),
        )
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError):
                extract(tar, dest)
        assert victim.read_text() == "ORIGINAL\n"

    def test_earlier_symlink_changes_what_a_later_path_means(self, tmp_path, extract):
        """Bypass #3, the one that retired the lexical check.

        With ``a -> .``, the member ``a/b/link`` has lexical depth 2 but real
        depth 1, so ``../../outside`` normalizes as contained while resolving
        outside. No check over member metadata can see this, because it depends
        on what an earlier member created.
        """
        dest = tmp_path / "dest"
        dest.mkdir()
        (tmp_path / "outside").mkdir()
        payload = b"PWNED\n"
        through = tarfile.TarInfo("a/b/link/pwned")
        through.size = len(payload)
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _link("a", ".", hard=False),
            _dir("a/b"),
            _link("a/b/link", "../../outside", hard=False),
            through,
        )
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError):
                extract(tar, dest)
        assert not (tmp_path / "outside" / "pwned").exists()
        _nothing_outside(tmp_path, dest)

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
    def test_windows_style_paths(self, tmp_path, member_name, extract):
        r"""`os.path` on Windows splits on `\` and honours drive letters, so
        these are escapes there while looking like one opaque POSIX component.
        The archive decides, not the host, so they are refused everywhere.
        """
        dest = tmp_path / "dest"
        dest.mkdir()
        archive = _tar_with(tmp_path / "t.tar.gz", _file(member_name))
        _extract_expecting_containment(extract, archive, dest)
        _nothing_outside(tmp_path, dest)

    @pytest.mark.parametrize(
        "member_type", [tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE]
    )
    def test_device_and_fifo_members(self, tmp_path, member_type, extract):
        dest = tmp_path / "dest"
        dest.mkdir()
        info = tarfile.TarInfo("snap/weird")
        info.type = member_type
        archive = _tar_with(tmp_path / "t.tar.gz", info)
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError):
                extract(tar, dest)


class TestDestinationStateCannotRedirect:
    """The archive is not the only source of a redirect.

    ``curator_backup`` preserves ``skills/.hub`` across a rollback, so the
    destination can already contain a symlink when extraction starts. No link
    member in the archive is required.
    """

    def test_existing_symlink_in_destination_is_refused(self, tmp_path, extract):
        outside = tmp_path / "outside"
        outside.mkdir()
        victim = outside / "victim.txt"
        victim.write_text("ORIGINAL\n")

        dest = tmp_path / "skills"
        (dest / ".hub").mkdir(parents=True)
        (dest / ".hub" / "link").symlink_to(outside, target_is_directory=True)

        payload = b"PWNED\n"
        through = tarfile.TarInfo(".hub/link/victim.txt")
        through.size = len(payload)
        archive = _tar_with(
            tmp_path / "t.tar.gz", _dir(".hub"), _dir(".hub/link"), through
        )
        with tarfile.open(archive) as tar:
            try:
                extract(tar, dest)
            except tarfile.TarError:
                pass
        assert victim.read_text() == "ORIGINAL\n", "wrote through a pre-existing symlink"


class TestHardlinksInRealSnapshots:
    """``tarfile.add()`` stores a repeated inode as a LNKTYPE member.

    A skills tree containing hardlinks therefore produces a snapshot with link
    members through no fault of the archive's author, and refusing those would
    make ``snapshot_skills()`` output unrestorable on the very interpreters
    this fallback exists for.
    """

    def test_snapshot_with_hardlinks_round_trips(self, tmp_path, extract):
        skills = tmp_path / "skills" / "demo"
        skills.mkdir(parents=True)
        (skills / "a.txt").write_text("content\n")
        os.link(skills / "a.txt", skills / "b.txt")

        archive = tmp_path / "snap.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for entry in sorted((tmp_path / "skills").iterdir()):
                tar.add(str(entry), arcname=entry.name, recursive=True)
        with tarfile.open(archive) as tar:
            assert any(m.islnk() for m in tar.getmembers()), "fixture must contain a hardlink"

        dest = tmp_path / "dest"
        dest.mkdir()
        with tarfile.open(archive) as tar:
            extract(tar, dest)

        a, b = dest / "demo" / "a.txt", dest / "demo" / "b.txt"
        assert a.read_text() == "content\n"
        assert b.read_text() == "content\n", "hardlinked sibling was not restored"

    def test_hardlink_is_materialized_as_a_copy(self, tmp_path, monkeypatch):
        """A copy has the same content but cannot reach anything else."""
        skills = tmp_path / "skills" / "demo"
        skills.mkdir(parents=True)
        (skills / "a.txt").write_text("content\n")
        os.link(skills / "a.txt", skills / "b.txt")
        archive = tmp_path / "snap.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for entry in sorted((tmp_path / "skills").iterdir()):
                tar.add(str(entry), arcname=entry.name, recursive=True)

        real = tarfile.TarFile.extractall

        def no_filter(self, path=".", members=None, **kwargs):
            if "filter" in kwargs:
                raise TypeError("no filter")
            return real(self, path, members, **kwargs)

        monkeypatch.setattr(tarfile.TarFile, "extractall", no_filter)
        dest = tmp_path / "dest"
        dest.mkdir()
        with tarfile.open(archive) as tar:
            safe_extract_tar(tar, dest)
        a, b = dest / "demo" / "a.txt", dest / "demo" / "b.txt"
        assert a.stat().st_ino != b.stat().st_ino


class TestOrdinaryArchivesStillExtract:
    """The guard must not be safe by refusing everything."""

    def test_files_and_directories_round_trip(self, tmp_path, extract):
        dest = tmp_path / "dest"
        dest.mkdir()
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _dir("skills"),
            _dir("skills/demo"),
            _file("skills/demo/SKILL.md", size=11),
        )
        with tarfile.open(archive) as tar:
            extract(tar, dest)
        written = dest / "skills" / "demo" / "SKILL.md"
        assert written.is_file()
        assert written.read_bytes() == b"x" * 11

    def test_mode_is_preserved(self, tmp_path, extract):
        dest = tmp_path / "dest"
        dest.mkdir()
        info = _file("skills/run.sh", size=3)
        info.mode = 0o755
        archive = _tar_with(tmp_path / "t.tar.gz", _dir("skills"), info)
        with tarfile.open(archive) as tar:
            extract(tar, dest)
        assert (dest / "skills" / "run.sh").stat().st_mode & 0o777 == 0o755

    def test_a_real_archive_of_repo_content(self, tmp_path, extract):
        """Built the way ``snapshot_skills()`` builds one, from real files."""
        src = Path(__file__).resolve().parents[2] / "docs"
        if not src.is_dir():
            pytest.skip("docs/ not present")
        archive = tmp_path / "real.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for entry in sorted(src.iterdir()):
                tar.add(str(entry), arcname=entry.name, recursive=True)
        dest = tmp_path / "dest"
        dest.mkdir()
        with tarfile.open(archive) as tar:
            extract(tar, dest)
        assert sum(1 for p in dest.rglob("*") if p.is_file()) > 0


class TestManualPathIsStricterThanData:
    """Documented divergence, asserted so it can't drift silently."""

    def test_internal_symlink_allowed_by_filter_refused_by_fallback(self, tmp_path):
        """``data`` permits a contained symlink; the fallback refuses all links.

        Supporting them safely would mean resolving through links already
        created — the complexity that produced every bypass above.
        """
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _dir("snap"),
            _file("snap/README"),
            _link("snap/link", "README", hard=False),
        )

        if sys.version_info >= (3, 11, 4):
            dest_ok = tmp_path / "with_filter"
            dest_ok.mkdir()
            with tarfile.open(archive) as tar:
                safe_extract_tar(tar, dest_ok)
            assert (dest_ok / "snap" / "link").is_symlink()

        real = tarfile.TarFile.extractall

        def no_filter(self, path=".", members=None, **kwargs):
            if "filter" in kwargs:
                raise TypeError("no filter")
            return real(self, path, members, **kwargs)

        dest_manual = tmp_path / "manual"
        dest_manual.mkdir()
        original = tarfile.TarFile.extractall
        tarfile.TarFile.extractall = no_filter  # type: ignore[method-assign]
        try:
            with tarfile.open(archive) as tar:
                with pytest.raises(tarfile.TarError, match="non-regular member"):
                    safe_extract_tar(tar, dest_manual)
        finally:
            tarfile.TarFile.extractall = original  # type: ignore[method-assign]
