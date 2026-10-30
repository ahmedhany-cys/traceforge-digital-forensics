"""Builds small, harmless Windows PE32+ images for static-analysis testing.

The images are structurally valid (DOS header, NT headers, section table,
import directory) so that real tooling such as ``pefile`` and YARA's ``pe``
module parse them. Their code section contains only ``xor eax, eax; ret``
followed by ``int3`` padding: there is no behaviour to execute. Suspicious
traits (imports, strings, high-entropy data, RWX sections) are *descriptive
data only* and exist so the analysis engine has something to explain.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
IMAGE_BASE = 0x140000000

SCN_CODE = 0x00000020
SCN_INIT_DATA = 0x00000040
SCN_EXEC = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass
class Section:
    name: str
    data: bytes
    characteristics: int
    virtual_size: int | None = None


@dataclass
class PESpec:
    timestamp: datetime
    imports: dict[str, list[str]]
    data_strings: list[str] = field(default_factory=list)
    wide_strings: list[str] = field(default_factory=list)
    extra_sections: list[Section] = field(default_factory=list)
    subsystem: int = 2  # GUI
    overlay: bytes = b""


DOS_STUB = (
    b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7
)


def _build_import_section(rva: int, imports: dict[str, list[str]]) -> tuple[bytes, int, int, int, int]:
    """Lay out descriptors, ILTs, IATs, hint/name entries and DLL names.

    Returns (section bytes, import dir rva, import dir size, iat rva, iat size).
    """
    dlls = list(imports.items())
    desc_size = 20 * (len(dlls) + 1)
    lookup_sizes = [8 * (len(funcs) + 1) for _, funcs in dlls]
    ilt_start = desc_size
    iat_start = ilt_start + sum(lookup_sizes)
    names_start = iat_start + sum(lookup_sizes)

    names = bytearray()
    hint_rvas: list[list[int]] = []
    dll_name_rvas: list[int] = []
    for dll, funcs in dlls:
        rvas = []
        for hint, fn in enumerate(funcs):
            if (names_start + len(names)) % 2:
                names += b"\x00"
            rvas.append(rva + names_start + len(names))
            names += struct.pack("<H", hint) + fn.encode("ascii") + b"\x00"
        hint_rvas.append(rvas)
    for dll, _ in dlls:
        dll_name_rvas.append(rva + names_start + len(names))
        names += dll.encode("ascii") + b"\x00"

    out = bytearray(names_start)
    ilt_off = ilt_start
    iat_off = iat_start
    for i, ((dll, funcs), size) in enumerate(zip(dlls, lookup_sizes)):
        struct.pack_into("<IIIII", out, 20 * i, rva + ilt_off, 0, 0, dll_name_rvas[i], rva + iat_off)
        for j, hrva in enumerate(hint_rvas[i]):
            struct.pack_into("<Q", out, ilt_off + 8 * j, hrva)
            struct.pack_into("<Q", out, iat_off + 8 * j, hrva)
        ilt_off += size
        iat_off += size
    out += names
    return bytes(out), rva, desc_size, rva + iat_start, sum(lookup_sizes)


def build_pe(spec: PESpec) -> bytes:
    n_sections = 3 + len(spec.extra_sections)
    headers_size = _align(0x80 + 4 + 20 + 0xF0 + 40 * n_sections, FILE_ALIGN)

    text = b"\x31\xc0\xc3" + b"\xcc" * 0x1FD  # xor eax,eax ; ret ; int3 padding
    sections: list[Section] = [Section(".text", text, SCN_CODE | SCN_EXEC | SCN_READ)]

    rdata_rva = SECT_ALIGN * 2
    import_bytes, imp_rva, imp_size, iat_rva, iat_size = _build_import_section(rdata_rva, spec.imports)
    sections.append(Section(".rdata", import_bytes, SCN_INIT_DATA | SCN_READ))

    data = bytearray()
    for s in spec.data_strings:
        data += s.encode("ascii") + b"\x00"
        data += b"\x00" * ((-len(data)) % 8)
    for s in spec.wide_strings:
        data += s.encode("utf-16-le") + b"\x00\x00"
        data += b"\x00" * ((-len(data)) % 8)
    sections.append(Section(".data", bytes(data) or b"\x00", SCN_INIT_DATA | SCN_READ | SCN_WRITE))
    sections.extend(spec.extra_sections)

    # assign RVAs / file offsets
    layout = []
    rva = SECT_ALIGN
    raw = headers_size
    for sec in sections:
        vsize = sec.virtual_size or len(sec.data)
        raw_size = _align(len(sec.data), FILE_ALIGN)
        layout.append((sec, rva, vsize, raw, raw_size))
        rva += _align(max(vsize, 1), SECT_ALIGN)
        raw += raw_size
    size_of_image = rva
    assert layout[1][1] == rdata_rva, "import section must be laid out at its precomputed RVA"

    image = bytearray(headers_size)
    struct.pack_into("<2s", image, 0, b"MZ")
    struct.pack_into("<HHHHHHHHHHHHH", image, 2, 0x90, 3, 0, 4, 0, 0xFFFF, 0, 0xB8, 0, 0, 0, 0x40, 0)
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x40 : 0x40 + len(DOS_STUB)] = DOS_STUB

    pe = 0x80
    image[pe : pe + 4] = b"PE\x00\x00"
    ts = int(spec.timestamp.astimezone(timezone.utc).timestamp())
    struct.pack_into("<HHIIIHH", image, pe + 4, 0x8664, len(sections), ts, 0, 0, 0xF0, 0x0022)

    opt = pe + 24
    size_code = sum(l[4] for l in layout if l[0].characteristics & SCN_CODE)
    size_init = sum(l[4] for l in layout if l[0].characteristics & SCN_INIT_DATA)
    struct.pack_into(
        "<HBBIIIII",
        image,
        opt,
        0x20B,  # PE32+
        14,
        36,
        size_code,
        size_init,
        0,
        layout[0][1],  # entry point = start of .text
        layout[0][1],
    )
    struct.pack_into(
        "<QIIHHHHHHIIIIHHQQQQII",
        image,
        opt + 24,
        IMAGE_BASE,
        SECT_ALIGN,
        FILE_ALIGN,
        6, 0, 0, 0, 6, 0,
        0,
        size_of_image,
        headers_size,
        0,
        spec.subsystem,
        0x8160,  # DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE | HIGH_ENTROPY_VA
        0x100000, 0x1000, 0x100000, 0x1000,
        0,
        16,
    )
    dd = opt + 112
    struct.pack_into("<II", image, dd + 8 * 1, imp_rva, imp_size)
    struct.pack_into("<II", image, dd + 8 * 12, iat_rva, iat_size)

    sh = opt + 0xF0
    for i, (sec, srva, vsize, raw_off, raw_size) in enumerate(layout):
        name = sec.name.encode("ascii")[:8].ljust(8, b"\x00")
        struct.pack_into("<8sIIIIIIHHI", image, sh + 40 * i, name, vsize, srva, raw_size, raw_off, 0, 0, 0, 0, sec.characteristics)

    body = bytearray()
    for sec, _, _, _, raw_size in layout:
        body += sec.data + b"\x00" * (raw_size - len(sec.data))
    return bytes(image) + bytes(body) + spec.overlay


def high_entropy_blob(size: int, seed: int) -> bytes:
    """Deterministic pseudo-random bytes (stand-in for packed/encrypted data)."""
    return random.Random(seed).randbytes(size)
