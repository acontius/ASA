"""Build a source-only release archive.

The archive contains application code, schemas, docs, the license, and
synthetic tests. It never contains scan datasets, output directories, or
SQLite databases.
"""

from __future__ import annotations

import hashlib
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOW_PREFIXES = ("app/", "schemas/", "tests/", "docs/", "tools/", ".github/")
ALLOW_FILES = {"README.md", "LICENSE"}
EXCLUDE_PARTS = {"__pycache__", "out", "dist", ".git"}
EXCLUDE_NAMES = {"PartOfMe.json"}
EXCLUDE_SUFFIXES = {".sqlite", ".sqlite-journal", ".sqlite-wal", ".sqlite-shm", ".pyc", ".env"}


def iter_files() -> list[Path]:
    chosen: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        parts = set(path.relative_to(ROOT).parts)
        if parts & EXCLUDE_PARTS or path.name in EXCLUDE_NAMES or path.suffix in EXCLUDE_SUFFIXES:
            continue
        if relative in ALLOW_FILES or relative.startswith(ALLOW_PREFIXES):
            chosen.append(path)
    return sorted(chosen, key=lambda item: item.relative_to(ROOT).as_posix())


def build(destination: Path) -> tuple[Path, Path]:
    destination.mkdir(parents=True, exist_ok=True)
    archive_path = destination / "asa-source.tar.gz"
    with tarfile.open(archive_path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
        for path in iter_files():
            info = archive.gettarinfo(path, arcname=path.relative_to(ROOT).as_posix())
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            with path.open("rb") as handle:
                archive.addfile(info, handle)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path = destination / "asa-source.tar.gz.sha256"
    checksum_path.write_text(f"{digest}  asa-source.tar.gz\n", encoding="utf-8")
    return archive_path, checksum_path


def main(argv: list[str]) -> int:
    destination = Path(argv[1] if len(argv) > 1 else "dist")
    archive_path, checksum_path = build(destination)
    print(archive_path)
    print(checksum_path.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
