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

from agent import file_safety
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


class TestPlatformsWithoutDirFdAreRefused:
    """No enforcement means no extraction, not extraction without enforcement.

    Windows has neither ``O_NOFOLLOW`` nor ``dir_fd`` support, so the
    component walk cannot run there. An earlier version fell back to plain path
    operations and documented the hole; that fallback would follow a directory
    junction already present in the destination — the very redirect the walk
    exists to refuse.
    """

    def test_extraction_is_refused_without_dir_fd(self, tmp_path, monkeypatch):
        monkeypatch.setattr(file_safety, "_HAVE_DIR_FD", False)
        real = tarfile.TarFile.extractall

        def no_filter(self, path=".", members=None, **kwargs):
            if "filter" in kwargs:
                raise TypeError("no filter")
            return real(self, path, members, **kwargs)

        monkeypatch.setattr(tarfile.TarFile, "extractall", no_filter)

        dest = tmp_path / "dest"
        dest.mkdir()
        archive = _tar_with(
            tmp_path / "t.tar.gz", _dir("skills"), _file("skills/a.md", size=3)
        )
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError, match="3.11.4"):
                safe_extract_tar(tar, dest)
        assert not (dest / "skills" / "a.md").exists(), "wrote without enforcement"

    def test_the_filtered_path_is_unaffected(self, tmp_path, monkeypatch):
        """Only the fallback is refused — 3.11.4+ never reaches the walk."""
        monkeypatch.setattr(file_safety, "_HAVE_DIR_FD", False)
        dest = tmp_path / "dest"
        dest.mkdir()
        archive = _tar_with(
            tmp_path / "t.tar.gz", _dir("skills"), _file("skills/a.md", size=3)
        )
        with tarfile.open(archive) as tar:
            safe_extract_tar(tar, dest)
        assert (dest / "skills" / "a.md").is_file()


class TestFileModesMatchTheStdlib:
    """Regular-file modes are sanitized exactly as ``filter="data"`` does.

    Unlike directories — which ``data`` ignores — it *does* sanitize regular
    files: drop group/other write, clear all execute bits unless the owner had
    execute, then guarantee owner read/write. Applying the archived mode
    verbatim restored a 0777 member world-writable on the fallback and 0755
    everywhere else.
    """

    @pytest.mark.parametrize(
        ("archived", "expected"),
        [(0o777, 0o755), (0o666, 0o644), (0o755, 0o755),
         (0o600, 0o600), (0o400, 0o600), (0o444, 0o644)],
    )
    def test_mode_is_sanitized(self, tmp_path, extract, archived, expected):
        dest = tmp_path / "dest"
        dest.mkdir()
        info = _file("skills/a.md", size=3)
        info.mode = archived
        archive = _tar_with(tmp_path / "t.tar.gz", _dir("skills"), info)
        with tarfile.open(archive) as tar:
            extract(tar, dest)
        got = (dest / "skills" / "a.md").stat().st_mode & 0o777
        assert got == expected, f"{archived:04o} -> {got:04o}, expected {expected:04o}"

    def test_helper_matches_the_stdlib_for_every_mode(self):
        """Exhaustive rather than sampled — the rule is only 3 lines."""
        for mode in range(0o1000):
            sanitized = file_safety._data_filter_mode(mode)
            expected = mode & 0o755
            if not expected & 0o100:
                expected &= ~0o111
            expected |= 0o600
            assert sanitized == expected, f"{mode:04o}"
            assert not sanitized & 0o022, f"{mode:04o} left group/other write"
            assert sanitized & 0o600 == 0o600, f"{mode:04o} lost owner rw"


class TestDirectoryModesMatchTheStdlib:
    """The two paths must agree on directory permissions.

    ``filter="data"`` does **not** restore a directory's archived mode — a
    0700 member comes out 0755. Verified against this interpreter, not assumed.
    So the fallback does not restore it either: making the fallback stricter
    would make a restored snapshot's permissions depend on the Python version,
    which is the divergence this function exists to remove.
    """

    def _extract_private_dir(self, tmp_path, extract, dest_name):
        dest = tmp_path / dest_name
        dest.mkdir()
        private = _dir("skills/private")
        private.mode = 0o700
        archive = _tar_with(
            tmp_path / f"{dest_name}.tar.gz",
            _dir("skills"),
            private,
            _file("skills/private/secret.md", size=5),
        )
        with tarfile.open(archive) as tar:
            extract(tar, dest)
        assert (dest / "skills" / "private" / "secret.md").is_file()
        return (dest / "skills" / "private").stat().st_mode & 0o777

    def test_both_paths_agree(self, tmp_path, extract):
        """Whatever the mode ends up being, both paths must produce the same.

        Parameterized over both, so a change in either direction — the stdlib
        starting to preserve modes, or the fallback drifting — fails here.
        """
        mode = self._extract_private_dir(tmp_path, extract, "dest")
        assert mode == 0o755, (
            f"expected parity with filter='data' (0755), got {mode:04o}"
        )


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


class TestContainedSymlinksRoundTrip:
    """Both paths restore a contained symlink, and neither restores an escape.

    The fallback used to refuse *every* link member, which was the same
    "legitimate snapshot cannot be restored" failure as the hardlink case —
    ``agent/skill_utils.py`` supports symlinked skills, so a snapshot of one
    would not come back on 3.11.0–3.11.3.

    Two mechanisms make restoring them safe. The load-bearing one is that the
    component walk refuses to traverse *any* symlink, including one this
    extraction just created, so nothing is written through a link whenever it
    is created. Creating links last is defence in depth on top of that —
    checked by making creation inline, where every escape case below still
    fails. Containment is then confirmed with ``realpath`` over the finished
    tree, which resolves through whatever chain the archive built.
    """

    def test_contained_symlink_is_restored(self, tmp_path, extract):
        dest = tmp_path / "dest"
        dest.mkdir()
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _dir("demo"),
            _file("demo/REAL", size=3),
            _link("demo/README", "REAL", hard=False),
        )
        with tarfile.open(archive) as tar:
            extract(tar, dest)
        link = dest / "demo" / "README"
        assert link.is_symlink()
        assert link.read_bytes() == b"xxx", "link does not resolve to its target"

    def test_escaping_symlink_is_refused_and_not_left_behind(self, tmp_path, extract):
        dest = tmp_path / "dest"
        dest.mkdir()
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _dir("demo"),
            _link("demo/bad", "../../../../etc/passwd", hard=False),
        )
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError):
                extract(tar, dest)
        assert not (dest / "demo" / "bad").is_symlink(), "failed restore left a link"

    def test_a_link_chain_that_escapes_is_caught_by_realpath(self, tmp_path, extract):
        """Lexically each hop is contained; only resolution shows the escape."""
        dest = tmp_path / "dest"
        dest.mkdir()
        archive = _tar_with(
            tmp_path / "t.tar.gz",
            _dir("a"),
            _dir("a/b"),
            _link("a/b/up", "../..", hard=False),
            _link("a/b/out", "up/../../outside", hard=False),
        )
        with tarfile.open(archive) as tar:
            with pytest.raises(tarfile.TarError):
                extract(tar, dest)
        _nothing_outside(tmp_path, dest)


class TestMtimesMatchTheStdlib:
    """``data`` preserves archived mtimes; the fallback must too.

    ``build_skill_nodes()`` falls back to ``SKILL.md``'s mtime for skills with
    no usage record, so a restore that stamps "now" changes behaviour rather
    than just metadata.
    """

    def test_a_hardlinked_sibling_keeps_its_mtime(self, tmp_path, extract):
        """The copy must carry the archived time, like the regular-file path.

        tarfile.add() stores a repeated inode as LNKTYPE, so in a real snapshot
        the second of two hardlinked files takes the copy path — and would
        otherwise restore stamped "now" while its twin kept 2000-01-01.
        """
        archived = 946684800
        skills = tmp_path / "skills" / "demo"
        skills.mkdir(parents=True)
        (skills / "a.txt").write_text("content\n")
        os.link(skills / "a.txt", skills / "b.txt")
        os.utime(skills / "a.txt", (archived, archived))

        archive = tmp_path / "snap.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for entry in sorted((tmp_path / "skills").iterdir()):
                tar.add(str(entry), arcname=entry.name, recursive=True)
        with tarfile.open(archive) as tar:
            assert any(m.islnk() for m in tar.getmembers())

        dest = tmp_path / "dest"
        dest.mkdir()
        with tarfile.open(archive) as tar:
            extract(tar, dest)
        for name in ("a.txt", "b.txt"):
            got = int((dest / "demo" / name).stat().st_mtime)
            assert got == archived, f"{name} restored with mtime {got}"

    def test_file_and_directory_mtimes_are_preserved(self, tmp_path, extract):
        archived = 946684800  # 2000-01-01
        dest = tmp_path / "dest"
        dest.mkdir()
        d = _dir("skills")
        d.mtime = archived
        f = _file("skills/SKILL.md", size=3)
        f.mtime = archived
        archive = _tar_with(tmp_path / "t.tar.gz", d, f)
        with tarfile.open(archive) as tar:
            extract(tar, dest)
        assert int((dest / "skills" / "SKILL.md").stat().st_mtime) == archived
        assert int((dest / "skills").stat().st_mtime) == archived, (
            "directory mtime was clobbered by writing its children"
        )
