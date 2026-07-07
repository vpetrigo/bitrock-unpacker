import struct
import zlib

from bitrock_unpacker.cookfs import FsEntry, decompress_page, parse_old_suffix
from bitrock_unpacker.extract import build_chunk_maps
from bitrock_unpacker.pe import parse_pe_overlay
from bitrock_unpacker.tcllist import parse_manifest, tokenize_tcl_list

DECLARED_BYTES = 19335
MANIFEST = f"a {{file 00644 1 0 {{{{0 {DECLARED_BYTES}}}}}}} b {{directory 040755 2 0 {{0 0}}}}"


def test_tokenize_tcl_list_and_parse_manifest():
    assert list(tokenize_tcl_list(MANIFEST))[1].startswith("file ")

    _, counts, total = parse_manifest(f"{MANIFEST} c {{link target}}")
    assert counts == {"file": 1, "directory": 1, "link": 1}
    assert total == DECLARED_BYTES


def test_overlay_suffix_decompression_and_chunk_maps():
    overlay = parse_pe_overlay(
        b"MZ"
        + b"\x00" * 58
        + struct.pack("<I", 0x80)
        + b"\x00" * (0x80 - 64)
        + b"PE\x00\x00"
        + b"\x00" * 20
        + b"\x00" * 224
    )
    assert overlay.overlay_start >= 0

    assert parse_old_suffix(
        b"X" * 84 + struct.pack(">II", 1, 2) + bytes([255]) + b"CFS0002",
        100,
    ) == (
        1,
        2,
        255,
    )

    compressor = zlib.compressobj(level=9, wbits=-15)
    raw_deflate = compressor.compress(b"hello") + compressor.flush()
    assert zlib.decompress(raw_deflate, wbits=-15) == b"hello"
    assert decompress_page(b"\x01" + raw_deflate) == b"hello"

    fs_entries = [
        FsEntry("a", "file", 0, []),
        FsEntry("a___bitrockBigFile1", "file", 0, []),
    ]
    _, chunk_groups = build_chunk_maps(fs_entries)
    assert len(chunk_groups["a"]) == 1
