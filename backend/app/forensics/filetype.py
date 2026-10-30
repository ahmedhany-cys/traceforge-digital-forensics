"""Content-based file type identification.

TraceForge never trusts a filename extension or client-supplied MIME type. The
type of every upload is decided from its bytes, and the declared extension must
be consistent with the detected type before the file is accepted.

``python-magic`` was deliberately not used: it requires the native libmagic
library (an extra system dependency with a history of parser CVEs) while the
handful of formats TraceForge accepts have simple, well-documented signatures.
"""

from __future__ import annotations

import csv
import io
import json
import struct
from dataclasses import dataclass
from pathlib import Path

SNIFF_BYTES = 64 * 1024


@dataclass(frozen=True)
class DetectedType:
    kind: str  # machine identifier, e.g. "evtx", "pe32+", "sqlite3"
    description: str
    artifact_type: str | None  # analyzer family or None if not an accepted evidence format


# extension -> artifact types it may legitimately contain
ALLOWED_EXTENSIONS: dict[str, set[str]] = {
    ".evtx": {"windows_evtx"},
    ".sqlite": {"browser_history"},
    ".db": {"browser_history"},
    ".sqlite3": {"browser_history"},
    "": {"browser_history"},  # Chromium names the file simply "History"
    ".csv": {"csv_log"},
    ".json": {"json_events"},
    ".jsonl": {"json_events"},
    ".log": {"text_log"},
    ".txt": {"text_log"},
    ".exe": {"pe_executable"},
    ".dll": {"pe_executable"},
    ".sys": {"pe_executable"},
    ".bin": {"pe_executable"},
}


def _pe_kind(head: bytes) -> DetectedType | None:
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 0x18 + 2 > len(head):
        return DetectedType("mz", "MS-DOS executable (no valid PE header within sniff window)", None)
    if head[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return DetectedType("mz", "MS-DOS executable (no PE signature)", None)
    magic = struct.unpack_from("<H", head, e_lfanew + 0x18)[0]
    characteristics = struct.unpack_from("<H", head, e_lfanew + 0x16)[0]
    is_dll = bool(characteristics & 0x2000)
    if magic == 0x20B:
        kind, desc = "pe32+", "PE32+ executable (64-bit)"
    elif magic == 0x10B:
        kind, desc = "pe32", "PE32 executable (32-bit)"
    else:
        return DetectedType("pe-unknown", "PE image with unrecognised optional header", None)
    return DetectedType(kind, desc + (" DLL" if is_dll else ""), "pe_executable")


def _looks_textual(head: bytes) -> str | None:
    if b"\x00" in head:
        return None
    for encoding in ("utf-8-sig", "utf-8"):
        try:
            return head.decode(encoding)
        except UnicodeDecodeError as exc:
            # tolerate a multi-byte sequence cut at the sniff boundary
            if exc.start >= len(head) - 4:
                return head[: exc.start].decode(encoding, errors="strict")
    return None


def detect_bytes(head: bytes, total_size: int) -> DetectedType:
    if total_size == 0:
        return DetectedType("empty", "Empty file", None)
    if head.startswith(b"ElfFile\x00"):
        return DetectedType("evtx", "Windows XML Event Log (EVTX)", "windows_evtx")
    if head.startswith(b"SQLite format 3\x00"):
        return DetectedType("sqlite3", "SQLite 3 database", "browser_history")
    pe = _pe_kind(head)
    if pe:
        return pe
    if head.startswith(b"\x7fELF"):
        return DetectedType("elf", "ELF executable", None)
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return DetectedType("macho", "Mach-O binary", None)
    if head.startswith(b"PK\x03\x04"):
        return DetectedType("zip", "ZIP archive", None)
    if head.startswith(b"%PDF-"):
        return DetectedType("pdf", "PDF document", None)
    if head.startswith(b"\x1f\x8b"):
        return DetectedType("gzip", "gzip compressed data", None)

    text = _looks_textual(head)
    if text is None:
        return DetectedType("binary", "Unrecognised binary data", None)
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        candidate = stripped if total_size <= SNIFF_BYTES else None
        if candidate is not None:
            try:
                json.loads(candidate)
                return DetectedType("json", "JSON document", "json_events")
            except json.JSONDecodeError:
                pass
        # JSON Lines, or a JSON document larger than the sniff window
        first_line = stripped.splitlines()[0] if stripped else ""
        try:
            json.loads(first_line)
            return DetectedType("jsonl", "JSON Lines", "json_events")
        except json.JSONDecodeError:
            if total_size > SNIFF_BYTES and stripped.startswith(("{", "[")):
                return DetectedType("json", "JSON document (validated during parsing)", "json_events")
    lines = [ln for ln in text.splitlines() if ln.strip()][:20]
    if len(lines) >= 2:
        try:
            dialect = csv.Sniffer().sniff("\n".join(lines), delimiters=",;\t|")
            rows = list(csv.reader(io.StringIO("\n".join(lines)), dialect))
            widths = {len(r) for r in rows}
            if len(widths) == 1 and widths.pop() >= 2:
                return DetectedType("csv", "Delimited text (CSV)", "csv_log")
        except csv.Error:
            pass
    return DetectedType("text", "Plain text", "text_log")


def detect_file(path: Path) -> DetectedType:
    size = path.stat().st_size
    with open(path, "rb") as fh:
        head = fh.read(SNIFF_BYTES)
    return detect_bytes(head, size)


def extension_of(filename: str) -> str:
    name = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if "." not in name.strip("."):
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def check_extension(filename: str, detected: DetectedType) -> tuple[bool, str]:
    """Return (accepted, reason)."""
    ext = extension_of(filename)
    if detected.artifact_type is None:
        return False, f"content identified as '{detected.description}', which is not a supported evidence format"
    allowed = ALLOWED_EXTENSIONS.get(ext)
    if allowed is None:
        return False, f"extension '{ext or '(none)'}' is not accepted"
    # Text-based logs are interchangeable: a .log file may hold CSV or JSON lines and vice versa.
    textual = {"csv_log", "json_events", "text_log"}
    if detected.artifact_type in allowed:
        return True, "extension consistent with content"
    if detected.artifact_type in textual and allowed & textual:
        return True, f"textual content parsed as {detected.artifact_type}"
    return False, (
        f"extension '{ext or '(none)'}' does not match detected content '{detected.description}'"
    )
