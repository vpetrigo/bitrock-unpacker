from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitrock_unpacker.cookfs import FsEntry, PageReader

CHUNK_RE = re.compile(r"^(?P<base>.+?)___bitrockBigFile(?P<idx>\d+)$")


def split_chunk_path(path: str) -> tuple[str, int] | None:
    m = CHUNK_RE.match(path)
    if not m:
        return None
    return m.group("base"), int(m.group("idx"))


def chunk_index(path: str) -> int:
    split = split_chunk_path(path)
    return split[1] if split else -1


def build_chunk_maps(
    entries: list[FsEntry],
) -> tuple[dict[str, FsEntry], dict[str, list[FsEntry]]]:
    base_files: dict[str, FsEntry] = {}
    chunk_groups: dict[str, list[FsEntry]] = {}
    for e in entries:
        if e.kind != "file":
            continue
        split = split_chunk_path(e.path)
        if split:
            base, _ = split
            chunk_groups.setdefault(base, []).append(e)
        else:
            base_files[e.path] = e
    for chunks in chunk_groups.values():
        chunks.sort(key=lambda e: chunk_index(e.path))
    return base_files, chunk_groups


def visible_file_entries(
    entries: list[FsEntry], *, raw_chunks: bool = False
) -> list[FsEntry]:
    out: list[FsEntry] = [e for e in entries if e.kind == "directory"]
    for e in entries:
        if e.kind != "file":
            continue
        if split_chunk_path(e.path):
            if raw_chunks:
                out.append(e)
            continue
        out.append(e)
    return out


def select_entries(
    entries: list[FsEntry], prefix: str | None, *, raw_chunks: bool
) -> list[FsEntry]:
    visible = visible_file_entries(entries, raw_chunks=raw_chunks)
    if not prefix:
        return visible
    if raw_chunks:
        return [e for e in visible if e.path.startswith(prefix)]
    base_files, chunk_groups = build_chunk_maps(entries)
    base = base_files.get(prefix)
    if base:
        return [base, *chunk_groups.get(prefix, [])]
    return [e for e in visible if e.path.startswith(prefix)]


def resolve_stitch_entries(
    entries: list[FsEntry], prefix: str | None, *, raw_chunks: bool
) -> list[FsEntry]:
    if raw_chunks:
        return [
            e
            for e in entries
            if e.kind == "file" and (not prefix or e.path.startswith(prefix))
        ]
    selected: list[FsEntry] = []
    for e in entries:
        if e.kind != "file" or split_chunk_path(e.path):
            continue
        if prefix and not e.path.startswith(prefix):
            continue
        selected.append(e)
    return selected


def write_entry_data(f, page_reader: PageReader, entry: FsEntry) -> None:
    for page_index, off_in_page, size in entry.blocks:
        page = page_reader.get(page_index)
        f.write(page[off_in_page : off_in_page + size])


def write_stitched_file(
    page_reader: PageReader, entry: FsEntry, chunks: list[FsEntry], out_path: str
) -> None:
    with open(out_path, "wb") as f:
        write_entry_data(f, page_reader, entry)
        for chunk in chunks:
            write_entry_data(f, page_reader, chunk)
