from __future__ import annotations

import struct
from dataclasses import dataclass

PE_MAGIC = b"MZ"
MIN_PE_SIZE = 0x40
PE_SIGNATURE_OFFSET = 0x3C
PE_SIGNATURE = b"PE\x00\x00"
PE_SIGNATURE_SIZE = 24
PE_SECTION_SIZE = 40
VALUE_NOT_PE = "not a PE/COFF executable"
VALUE_TOO_SMALL = "file too small"
VALUE_BAD_SIGNATURE = "invalid PE signature"


@dataclass(frozen=True)
class PEInfo:
    overlay_start: int
    overlay_length: int


def parse_pe_overlay(data: bytes) -> PEInfo:
    if data[:2] != PE_MAGIC:
        raise ValueError(VALUE_NOT_PE)
    if len(data) < MIN_PE_SIZE:
        raise ValueError(VALUE_TOO_SMALL)
    e_lfanew = struct.unpack_from("<I", data, PE_SIGNATURE_OFFSET)[0]
    if (
        e_lfanew + PE_SIGNATURE_SIZE > len(data)
        or data[e_lfanew : e_lfanew + 4] != PE_SIGNATURE
    ):
        raise ValueError(VALUE_BAD_SIGNATURE)
    file_hdr_off = e_lfanew + 4
    number_of_sections = struct.unpack_from("<H", data, file_hdr_off + 2)[0]
    size_of_optional_header = struct.unpack_from("<H", data, file_hdr_off + 16)[0]
    section_off = file_hdr_off + 20 + size_of_optional_header
    max_end = 0
    for i in range(number_of_sections):
        off = section_off + i * PE_SECTION_SIZE
        if off + PE_SECTION_SIZE > len(data):
            break
        ptr_raw = struct.unpack_from("<I", data, off + 20)[0]
        size_raw = struct.unpack_from("<I", data, off + 16)[0]
        if ptr_raw and size_raw:
            max_end = max(max_end, ptr_raw + size_raw)
    overlay_start = min(max_end, len(data))
    return PEInfo(
        overlay_start=overlay_start, overlay_length=max(0, len(data) - overlay_start)
    )
