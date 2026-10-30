"""Minimal, deterministic writer for Windows XML Event Log (EVTX) files.

The writer exists so the synthetic Meridian dataset can ship *real* EVTX
binaries that are parsed by the same code path as evidence acquired from a
Windows host. It implements the subset of the format needed for that:

* file header (4096 bytes, CRC32 over the first 0x78 bytes)
* 64 KiB chunks with header and data CRC32 checksums
* event records with binary XML (BinXML) bodies
* one resident template per record, with typed substitution values

Each record carries its own template definition. Real Windows logs share
templates between records; doing it per-record is less space-efficient but is
still a valid encoding and keeps the writer simple and auditable.

This module never claims to emulate Windows exactly. Files it produces are
labelled as synthetic by the dataset generator.
"""

from __future__ import annotations

import binascii
import hashlib
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Sequence, Union

CHUNK_SIZE = 0x10000
CHUNK_HEADER_SIZE = 0x200
FILE_HEADER_SIZE = 0x1000

# BinXML tokens
TOK_EOF = 0x00
TOK_OPEN_START = 0x01
TOK_CLOSE_START = 0x02
TOK_CLOSE_EMPTY = 0x03
TOK_END_ELEMENT = 0x04
TOK_VALUE = 0x05
TOK_ATTRIBUTE = 0x06
TOK_TEMPLATE_INSTANCE = 0x0C
TOK_NORMAL_SUBST = 0x0D
TOK_FRAGMENT_HEADER = 0x0F
FLAG_MORE = 0x40  # "has attributes" on elements / "more attributes" on attributes

# Variant value types
T_NULL = 0x00
T_WSTRING = 0x01
T_UINT8 = 0x04
T_UINT16 = 0x06
T_UINT32 = 0x08
T_UINT64 = 0x0A
T_GUID = 0x0F
T_FILETIME = 0x11
T_SID = 0x13
T_HEX32 = 0x14
T_HEX64 = 0x15

EPOCH_AS_FILETIME = 116444736000000000


def to_filetime(dt: datetime) -> int:
    if dt.tzinfo is None:
        raise ValueError("EVTX timestamps must be timezone-aware")
    dt = dt.astimezone(timezone.utc)
    delta = dt - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return EPOCH_AS_FILETIME + (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def _name_hash(name: str) -> int:
    value = 0
    for ch in name.encode("utf-16-le").decode("utf-16-le"):
        value = (value * 65599 + ord(ch)) & 0xFFFFFFFF
    return value & 0xFFFF


def encode_sid(sid: str) -> bytes:
    parts = sid.split("-")
    if parts[0] != "S" or len(parts) < 3:
        raise ValueError(f"invalid SID: {sid}")
    revision = int(parts[1])
    authority = int(parts[2])
    subs = [int(p) for p in parts[3:]]
    return (
        struct.pack("<BB", revision, len(subs))
        + authority.to_bytes(6, "big")
        + b"".join(struct.pack("<I", s) for s in subs)
    )


def encode_guid(guid: str) -> bytes:
    import uuid

    return uuid.UUID(guid.strip("{}")).bytes_le


@dataclass
class Value:
    """A typed substitution value."""

    vtype: int
    value: object

    def encode(self) -> bytes:
        v = self.value
        if self.vtype == T_NULL or v is None:
            return b""
        if self.vtype == T_WSTRING:
            return str(v).encode("utf-16-le")
        if self.vtype == T_UINT8:
            return struct.pack("<B", int(v))
        if self.vtype == T_UINT16:
            return struct.pack("<H", int(v))
        if self.vtype == T_UINT32:
            return struct.pack("<I", int(v))
        if self.vtype in (T_UINT64,):
            return struct.pack("<Q", int(v))
        if self.vtype == T_HEX32:
            return struct.pack("<I", int(v))
        if self.vtype == T_HEX64:
            return struct.pack("<Q", int(v))
        if self.vtype == T_FILETIME:
            return struct.pack("<Q", to_filetime(v))  # type: ignore[arg-type]
        if self.vtype == T_SID:
            return encode_sid(str(v))
        if self.vtype == T_GUID:
            return encode_guid(str(v))
        raise ValueError(f"unsupported variant type {self.vtype:#x}")


def S(text: object) -> Value:
    return Value(T_WSTRING, "" if text is None else str(text))


Content = Union["Element", Value]


@dataclass
class Element:
    name: str
    attrs: Sequence[tuple[str, Value]] = field(default_factory=list)
    children: Sequence[Content] = field(default_factory=list)


class _TemplateBuilder:
    """Serialises an element tree into a template body plus substitutions."""

    def __init__(self, base_offset: int):
        # base_offset: chunk-relative offset where the template body starts.
        self.base = base_offset
        self.buf = bytearray()
        self.values: list[Value] = []

    def _pos(self) -> int:
        return self.base + len(self.buf)

    def _inline_name(self, name: str) -> None:
        encoded = name.encode("utf-16-le")
        self.buf += struct.pack("<IHH", 0, _name_hash(name), len(name))
        self.buf += encoded + b"\x00\x00"

    def _subst(self, value: Value) -> None:
        index = len(self.values)
        self.values.append(value)
        self.buf += struct.pack("<BHB", TOK_NORMAL_SUBST, index, value.vtype)

    def element(self, el: Element) -> None:
        start = len(self.buf)
        token = TOK_OPEN_START | (FLAG_MORE if el.attrs else 0)
        self.buf += struct.pack("<BHI", token, 0xFFFF, 0)  # dependency id, data size (patched)
        name_offset = self._pos() + 4
        self.buf += struct.pack("<I", name_offset)
        self._inline_name(el.name)
        attr_size_pos = None
        if el.attrs:
            attr_size_pos = len(self.buf)
            self.buf += struct.pack("<I", 0)
            attr_start = len(self.buf)
            for i, (aname, aval) in enumerate(el.attrs):
                more = FLAG_MORE if i < len(el.attrs) - 1 else 0
                self.buf += struct.pack("<B", TOK_ATTRIBUTE | more)
                self.buf += struct.pack("<I", self._pos() + 4)
                self._inline_name(aname)
                self._subst(aval)
            struct.pack_into("<I", self.buf, attr_size_pos, len(self.buf) - attr_start)
        if el.children:
            self.buf.append(TOK_CLOSE_START)
            for child in el.children:
                if isinstance(child, Element):
                    self.element(child)
                else:
                    self._subst(child)
            self.buf.append(TOK_END_ELEMENT)
        else:
            self.buf.append(TOK_CLOSE_EMPTY)
        # data size counts the bytes that follow the size field itself
        struct.pack_into("<I", self.buf, start + 3, len(self.buf) - (start + 7))

    def build(self, root: Element) -> bytes:
        self.buf += bytes([TOK_FRAGMENT_HEADER, 1, 1, 0])
        self.element(root)
        self.buf.append(TOK_EOF)
        return bytes(self.buf)


def _encode_record_body(root: Element, record_offset_in_chunk: int, template_id: int) -> bytes:
    """Return BinXML for a record: fragment header, template instance, resident template, substitutions."""
    out = bytearray()
    out += bytes([TOK_FRAGMENT_HEADER, 1, 1, 0])
    instance_offset = record_offset_in_chunk + 0x18 + len(out)
    template_offset = instance_offset + 10
    out += struct.pack("<BBII", TOK_TEMPLATE_INSTANCE, 1, template_id, template_offset)

    body_offset = template_offset + 0x18
    tb = _TemplateBuilder(body_offset)
    body = tb.build(root)
    guid = hashlib.md5(body).digest()
    guid = struct.pack("<I", template_id) + guid[4:]
    out += struct.pack("<I", 0) + guid + struct.pack("<I", len(body))
    out += body

    encoded = [v.encode() for v in tb.values]
    out += struct.pack("<I", len(encoded))
    for v, data in zip(tb.values, encoded):
        out += struct.pack("<HBB", len(data), v.vtype if data else T_NULL, 0)
    for data in encoded:
        out += data
    return bytes(out)


@dataclass
class EventRecord:
    timestamp: datetime
    root: Element


class _Chunk:
    def __init__(self, first_record_number: int):
        self.data = bytearray()
        self.first = first_record_number
        self.last = first_record_number - 1
        self.last_record_offset = 0

    def try_add(self, record: EventRecord, record_number: int) -> bool:
        offset = CHUNK_HEADER_SIZE + len(self.data)
        body = _encode_record_body(record.root, offset, template_id=record_number & 0xFFFFFFFF)
        size = 0x18 + len(body) + 4
        pad = (-size) % 8
        size += pad
        if offset + size > CHUNK_SIZE:
            return False
        rec = bytearray()
        rec += struct.pack("<IIQQ", 0x00002A2A, size, record_number, to_filetime(record.timestamp))
        rec += body + b"\x00" * pad
        rec += struct.pack("<I", size)
        self.last_record_offset = offset
        self.data += rec
        self.last = record_number
        return True

    def serialise(self) -> bytes:
        free = CHUNK_HEADER_SIZE + len(self.data)
        header = bytearray(CHUNK_HEADER_SIZE)
        header[0:8] = b"ElfChnk\x00"
        struct.pack_into("<QQQQ", header, 8, self.first, self.last, self.first, self.last)
        struct.pack_into("<III", header, 0x28, 0x80, self.last_record_offset, free)
        data_crc = binascii.crc32(bytes(self.data)) & 0xFFFFFFFF
        struct.pack_into("<I", header, 0x34, data_crc)
        header_crc = binascii.crc32(bytes(header[0:0x78]) + bytes(header[0x80:0x200])) & 0xFFFFFFFF
        struct.pack_into("<I", header, 0x7C, header_crc)
        chunk = bytes(header) + bytes(self.data)
        return chunk + b"\x00" * (CHUNK_SIZE - len(chunk))


def write_evtx(records: Iterable[EventRecord]) -> bytes:
    """Serialise records (in the given order) into an EVTX file image."""
    chunks: list[_Chunk] = []
    number = 1
    current = _Chunk(number)
    for record in records:
        if not current.try_add(record, number):
            if current.last < current.first:
                raise ValueError("record too large for a single chunk")
            chunks.append(current)
            current = _Chunk(number)
            if not current.try_add(record, number):
                raise ValueError("record too large for a single chunk")
        number += 1
    if current.last >= current.first:
        chunks.append(current)

    header = bytearray(FILE_HEADER_SIZE)
    header[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", header, 8, 0, max(len(chunks) - 1, 0), number)
    struct.pack_into("<IHHHH", header, 0x20, 0x80, 1, 3, 0x1000, len(chunks))
    struct.pack_into("<I", header, 0x78, 0)  # flags: clean
    struct.pack_into("<I", header, 0x7C, binascii.crc32(bytes(header[0:0x78])) & 0xFFFFFFFF)
    return bytes(header) + b"".join(c.serialise() for c in chunks)


# --------------------------------------------------------------------------
# Convenience builder for the standard Windows <Event> schema
# --------------------------------------------------------------------------

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def windows_event(
    *,
    provider: str,
    provider_guid: str | None,
    event_id: int,
    timestamp: datetime,
    record_id: int,
    channel: str,
    computer: str,
    level: int = 0,
    task: int = 0,
    opcode: int = 0,
    version: int = 0,
    keywords: int = 0x8020000000000000,
    process_id: int = 4,
    thread_id: int = 100,
    user_sid: str | None = None,
    event_data: Sequence[tuple[str, Value | str]] | None = None,
    user_data: Element | None = None,
) -> EventRecord:
    provider_attrs: list[tuple[str, Value]] = [("Name", S(provider))]
    if provider_guid:
        provider_attrs.append(("Guid", S(provider_guid)))
    system_children: list[Content] = [
        Element("Provider", provider_attrs),
        Element("EventID", [], [Value(T_UINT16, event_id)]),
        Element("Version", [], [Value(T_UINT8, version)]),
        Element("Level", [], [Value(T_UINT8, level)]),
        Element("Task", [], [Value(T_UINT16, task)]),
        Element("Opcode", [], [Value(T_UINT8, opcode)]),
        Element("Keywords", [], [Value(T_HEX64, keywords)]),
        Element("TimeCreated", [("SystemTime", Value(T_FILETIME, timestamp))]),
        Element("EventRecordID", [], [Value(T_UINT64, record_id)]),
        Element("Correlation"),
        Element("Execution", [("ProcessID", Value(T_UINT32, process_id)), ("ThreadID", Value(T_UINT32, thread_id))]),
        Element("Channel", [], [S(channel)]),
        Element("Computer", [], [S(computer)]),
        Element("Security", [("UserID", Value(T_SID, user_sid))] if user_sid else []),
    ]
    children: list[Content] = [Element("System", [], system_children)]
    if event_data is not None:
        data_elems = []
        for name, val in event_data:
            v = val if isinstance(val, Value) else S(val)
            data_elems.append(Element("Data", [("Name", S(name))], [v]))
        children.append(Element("EventData", [], data_elems))
    if user_data is not None:
        children.append(Element("UserData", [], [user_data]))
    root = Element("Event", [("xmlns", S(EVENT_NS))], children)
    return EventRecord(timestamp=timestamp, root=root)
