from __future__ import annotations

import io
import os
import tarfile
import unicodedata
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts.demo_e2e import archive as archive_module
from scripts.demo_e2e.archive import CleanArchiveError, extract_tracked_archive


def test_safe_archive_extracts_regular_files_without_links(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar"
    destination = tmp_path / "checkout"
    _write_tar(archive, [("tracked/file.txt", b"synthetic")])

    extract_tracked_archive(archive, destination)

    assert (destination / "tracked/file.txt").read_bytes() == b"synthetic"


@pytest.mark.parametrize("name", ["../escape.txt", "/absolute.txt", "dir\\file.txt"])
def test_archive_rejects_path_traversal_and_noncanonical_names(tmp_path: Path, name: str) -> None:
    archive = tmp_path / "source.tar"
    destination = tmp_path / "checkout"
    _write_tar(archive, [(name, b"synthetic")])

    with pytest.raises(CleanArchiveError):
        extract_tracked_archive(archive, destination)


def test_archive_rejects_symbolic_links(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar"
    destination = tmp_path / "checkout"
    with tarfile.open(archive, "w") as bundle:
        link = tarfile.TarInfo("tracked/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        bundle.addfile(link)

    with pytest.raises(CleanArchiveError, match="forbidden entry"):
        extract_tracked_archive(archive, destination)


@pytest.mark.parametrize("entry_type", [tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE])
def test_archive_rejects_hard_links_devices_and_fifos(tmp_path: Path, entry_type: bytes) -> None:
    archive = tmp_path / "source.tar"
    destination = tmp_path / "checkout"
    with tarfile.open(archive, "w") as bundle:
        entry = tarfile.TarInfo("tracked/forbidden")
        entry.type = entry_type
        if entry_type == tarfile.LNKTYPE:
            entry.linkname = "tracked/target"
        bundle.addfile(entry)

    with pytest.raises(CleanArchiveError, match="forbidden entry"):
        extract_tracked_archive(archive, destination)


def test_archive_enforces_member_and_total_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "source.tar"
    destination = tmp_path / "checkout"
    _write_tar(archive, [("tracked/large.txt", b"0123456789")])
    monkeypatch.setattr(archive_module, "MAX_MEMBER_BYTES", 4)

    with pytest.raises(CleanArchiveError, match="invalid file"):
        extract_tracked_archive(archive, destination)


def test_archive_enforces_entry_count_and_expanded_total_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "source.tar"
    destination = tmp_path / "checkout"
    _write_tar(archive, [("one.txt", b"1234"), ("two.txt", b"5678")])
    monkeypatch.setattr(archive_module, "MAX_EXTRACTED_BYTES", 7)

    with pytest.raises(CleanArchiveError, match="safe limit"):
        extract_tracked_archive(archive, destination)

    second_destination = tmp_path / "checkout-count"
    monkeypatch.setattr(archive_module, "MAX_EXTRACTED_BYTES", 100)
    monkeypatch.setattr(archive_module, "MAX_MEMBERS", 1)
    with pytest.raises(CleanArchiveError, match="too many"):
        extract_tracked_archive(archive, second_destination)


@pytest.mark.parametrize(
    "members",
    [
        [("a/b", b"one"), ("a//b", b"two")],
        [("a/b", b"one"), ("a/./b", b"two")],
        [("a", b"file"), ("a/b", b"child")],
        [("a/b", b"child"), ("a", b"file")],
        [("duplicate", b"one"), ("duplicate", b"two")],
    ],
)
def test_archive_rejects_normalized_duplicate_and_prefix_collisions(
    tmp_path: Path, members: list[tuple[str, bytes]]
) -> None:
    archive = tmp_path / "source.tar"
    _write_tar(archive, members)

    with pytest.raises(CleanArchiveError):
        extract_tracked_archive(archive, tmp_path / "checkout")


def test_archive_rejects_casefold_and_unicode_normalization_collisions(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar"
    composed = "caf\N{LATIN SMALL LETTER E WITH ACUTE}"
    decomposed = unicodedata.normalize("NFD", composed)
    members = [(f"{composed}/one", b"one"), (f"{decomposed}/one", b"two")]
    _write_tar(archive, members)

    with pytest.raises(CleanArchiveError):
        extract_tracked_archive(archive, tmp_path / "unicode")

    if os.name == "nt":
        _write_tar(archive, [("Package/one", b"one"), ("package/two", b"two")])
        with pytest.raises(CleanArchiveError):
            extract_tracked_archive(archive, tmp_path / "casefold")


def test_archive_rejects_existing_nonempty_destination(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar"
    _write_tar(archive, [("tracked/file", b"value")])
    destination = tmp_path / "checkout"
    destination.mkdir()
    (destination / "foreign").write_text("foreign", encoding="utf-8")

    with pytest.raises(CleanArchiveError, match="new absolute"):
        extract_tracked_archive(archive, destination)

    assert (destination / "foreign").read_text(encoding="utf-8") == "foreign"


def test_archive_rejects_pax_and_gnu_traversal_after_name_expansion(tmp_path: Path) -> None:
    pax_archive = tmp_path / "pax.tar"
    with tarfile.open(pax_archive, "w", format=tarfile.PAX_FORMAT) as bundle:
        member = tarfile.TarInfo("safe")
        member.pax_headers = {"path": "../escape"}
        member.size = 1
        bundle.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(CleanArchiveError):
        extract_tracked_archive(pax_archive, tmp_path / "pax")

    gnu_archive = tmp_path / "gnu.tar"
    with tarfile.open(gnu_archive, "w", format=tarfile.GNU_FORMAT) as bundle:
        member = tarfile.TarInfo("../" + "x" * 150)
        member.size = 1
        bundle.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(CleanArchiveError):
        extract_tracked_archive(gnu_archive, tmp_path / "gnu")


def test_archive_rejects_sparse_and_removes_partial_root(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar"
    with tarfile.open(archive, "w") as bundle:
        safe = tarfile.TarInfo("safe")
        safe.size = 1
        bundle.addfile(safe, io.BytesIO(b"x"))
        sparse = tarfile.TarInfo("sparse")
        sparse.type = tarfile.GNUTYPE_SPARSE
        bundle.addfile(sparse)
    destination = tmp_path / "checkout"

    with pytest.raises(CleanArchiveError):
        extract_tracked_archive(archive, destination)

    assert not destination.exists()


def test_archive_rejects_unsupported_pax_metadata_before_writing(tmp_path: Path) -> None:
    archive = tmp_path / "pax.tar"
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as bundle:
        member = tarfile.TarInfo("safe")
        member.pax_headers = {"SCHILY.xattr.user.demo": "synthetic"}
        member.size = 1
        bundle.addfile(member, io.BytesIO(b"x"))
    destination = tmp_path / "checkout"

    with pytest.raises(CleanArchiveError, match="unsupported PAX"):
        extract_tracked_archive(archive, destination)

    assert not destination.exists()


def test_archive_rejects_directory_file_collision_before_writing(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar"
    with tarfile.open(archive, "w") as bundle:
        directory = tarfile.TarInfo("same")
        directory.type = tarfile.DIRTYPE
        bundle.addfile(directory)
        file_entry = tarfile.TarInfo("same")
        file_entry.size = 1
        bundle.addfile(file_entry, io.BytesIO(b"x"))

    with pytest.raises(CleanArchiveError, match="duplicate"):
        extract_tracked_archive(archive, tmp_path / "checkout")


def test_archive_rejects_truncated_member_and_removes_partial_root(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar"
    _write_tar(archive, [("first", b"one"), ("second", b"two")])
    content = archive.read_bytes()
    archive.write_bytes(content[: 1_024 + 1])
    destination = tmp_path / "checkout"

    with pytest.raises(CleanArchiveError):
        extract_tracked_archive(archive, destination)

    assert not destination.exists()


def test_archive_rejects_parent_reparse_substitution_without_deleting_changed_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "source.tar"
    _write_tar(archive, [("nested/file", b"synthetic")])
    destination = tmp_path / "checkout"
    original_lstat = Path.lstat
    target_reads = 0

    def substituted_lstat(path: Path) -> object:
        nonlocal target_reads
        metadata = original_lstat(path)
        if path == destination:
            target_reads += 1
            if target_reads >= 2:
                values = {
                    name: getattr(metadata, name)
                    for name in dir(metadata)
                    if name.startswith("st_")
                }
                values["st_file_attributes"] = 0x400
                return SimpleNamespace(**values)
        return metadata

    monkeypatch.setattr(Path, "lstat", substituted_lstat)

    with pytest.raises(CleanArchiveError, match="identity changed"):
        extract_tracked_archive(archive, destination)

    assert destination.exists()


def _write_tar(path: Path, members: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w") as bundle:
        for name, content in members:
            metadata = tarfile.TarInfo(name)
            metadata.size = len(content)
            bundle.addfile(metadata, io.BytesIO(content))
