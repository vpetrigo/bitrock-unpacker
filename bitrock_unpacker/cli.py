from __future__ import annotations

import argparse
import logging
import os
from typing import TYPE_CHECKING

from bitrock_unpacker.cookfs import (
    CookFSInfo,
    FsEntry,
    PageReader,
    build_cookfs_layout,
    decompress_index_blob,
    find_cookfsinfo,
    find_zlib_stream,
    parse_fsindex,
)
from bitrock_unpacker.extract import (
    build_chunk_maps,
    resolve_stitch_entries,
    select_entries,
    write_stitched_file,
)
from bitrock_unpacker.pe import parse_pe_overlay
from bitrock_unpacker.tcllist import parse_manifest

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)
MARKERS = [
    b"bitrock-lzma-4.0",
    b"Jbitrock-lzma-4.0",
    b"manifest.txt",
    b"cookfsinfo.txt",
]


def find_all(data: bytes, needle: bytes) -> Iterator[int]:
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            return
        yield idx
        start = idx + 1


def recover_manifest(data: bytes, overlay_start: int) -> str | None:
    hay = data[overlay_start:]
    hits = []
    for marker in (b"manifest.txt", b"cookfsinfo.txt"):
        hits.extend(overlay_start + i for i in find_all(hay, marker))
    for pos in sorted(set(hits)):
        dec = find_zlib_stream(data, pos)
        if dec:
            return dec.decode("utf-8", "replace")
    return None


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("installer", nargs="?")
    ap.add_argument("--out")
    ap.add_argument("--manifest-only", action="store_true")
    ap.add_argument("--list-pages", action="store_true")
    ap.add_argument("--extract-pages")
    ap.add_argument("--list-files", action="store_true")
    ap.add_argument("--extract")
    ap.add_argument("--path")
    ap.add_argument("--yes-all", action="store_true")
    ap.add_argument("--raw-chunks", action="store_true")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--debug", action="store_true")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    ns = ap.parse_args(argv)
    logging.basicConfig(
        format="%(message)s", level=logging.DEBUG if ns.debug else logging.INFO
    )
    if not ns.installer:
        ap.error("installer.exe is required")
    with open(ns.installer, "rb") as f:
        data = f.read()
    pe = parse_pe_overlay(data)
    if ns.debug:
        logger.debug("overlay start=%s length=%s", pe.overlay_start, pe.overlay_length)
        for m in MARKERS:
            logger.debug("%s: %s", m.decode(), len(list(find_all(data, m))))
    info: CookFSInfo = build_cookfs_layout(
        data, pe.overlay_start, find_cookfsinfo(data, pe.overlay_start)
    )
    fs_entries: list[FsEntry] = []
    if info.index_blob_offset is not None:
        idx = decompress_index_blob(data, info)
        if idx:
            fs_entries = parse_fsindex(idx)
    manifest_text = recover_manifest(data, pe.overlay_start)
    if manifest_text is None:
        logger.error("manifest recovery failed")
        return 2
    _, counts, total = parse_manifest(manifest_text)
    logger.info(
        "manifest entries: file=%s directory=%s link=%s declared_file_bytes=%s",
        counts["file"],
        counts["directory"],
        counts["link"],
        total,
    )
    if ns.out:
        os.makedirs(ns.out, exist_ok=True)
        with open(
            os.path.join(ns.out, "manifest.txt"), "w", encoding="utf-8", newline="\n"
        ) as f:
            f.write(manifest_text)
        logger.info("wrote %s", os.path.join(ns.out, "manifest.txt"))
    if not ns.manifest_only:
        logger.info("CookFS fsindex entries: %s", len(fs_entries))
    if ns.list_pages or ns.extract_pages:
        if info.num_pages is None:
            logger.error("cookfs layout unavailable")
            return 2
        limit = ns.limit if ns.limit is not None else 20
        page_reader = PageReader(data, info)
        for count, idx in enumerate(range(info.num_pages), start=1):
            page = page_reader.get(idx)
            off = page_reader.offsets[idx]
            sz = page_reader.sizes[idx]
            logger.info(
                "page %06d off=0x%x size=%s tag=%s dec=%s",
                idx,
                off,
                sz,
                page_reader.tag(idx),
                len(page),
            )
            if ns.extract_pages:
                os.makedirs(ns.extract_pages, exist_ok=True)
                with open(
                    os.path.join(ns.extract_pages, f"page_{idx:06d}.bin"), "wb"
                ) as f:
                    f.write(page)
            if count >= limit:
                break
    if ns.list_files or ns.extract:
        filtered = select_entries(fs_entries, ns.path, raw_chunks=ns.raw_chunks)
        limit = ns.limit if ns.limit is not None else 20
        for e in filtered[:limit]:
            if (
                e.kind == "file"
                and not ns.raw_chunks
                and not e.path.endswith("___bitrockBigFile1")
            ):
                _, chunk_groups = build_chunk_maps(fs_entries)
                chunks = len(chunk_groups.get(e.path, []))
                if chunks:
                    logger.info(
                        "%s %s blocks=%s chunks=%s",
                        e.kind,
                        e.path,
                        len(e.blocks),
                        chunks + 1,
                    )
                else:
                    logger.info("%s %s blocks=%s", e.kind, e.path, len(e.blocks))
            else:
                logger.info("%s %s blocks=%s", e.kind, e.path, len(e.blocks))
    if ns.extract:
        if ns.limit is None and not ns.yes_all:
            logger.error("refusing full extraction without --yes-all")
            return 2
        page_reader = PageReader(data, info)
        _, chunk_groups = build_chunk_maps(fs_entries)
        os.makedirs(ns.extract, exist_ok=True)
        for e in resolve_stitch_entries(fs_entries, ns.path, raw_chunks=ns.raw_chunks)[
            : (ns.limit if ns.limit is not None else 10**9)
        ]:
            out_path = os.path.join(ns.extract, e.path.replace("/", os.sep))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            chunks = [] if ns.raw_chunks else chunk_groups.get(e.path, [])
            write_stitched_file(page_reader, e, chunks, out_path)
            logger.info("wrote %s", out_path)
    return 0
