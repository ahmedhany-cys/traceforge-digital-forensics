"""Printable string extraction and categorisation (ASCII and UTF-16LE)."""

from __future__ import annotations

import re
from dataclasses import dataclass

MIN_LEN = 5
MAX_STRINGS = 5000

_ASCII = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)


@dataclass(frozen=True)
class ExtractedString:
    offset: int
    encoding: str
    value: str


# Each category: (name, compiled regex, explanation shown to the analyst)
CATEGORIES: list[tuple[str, re.Pattern[str], str]] = [
    ("url", re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{4,}", re.I), "Embedded URL – possible network destination"),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "Embedded IPv4 address"),
    ("powershell", re.compile(r"powershell(?:\.exe)?|-enc(?:odedcommand)?\b|-nop\b|-w(?:indowstyle)?\s+hidden|FromBase64String|Invoke-WebRequest|Invoke-Expression|\bIEX\b|Compress-Archive", re.I),
     "PowerShell usage or obfuscation keyword"),
    ("persistence", re.compile(r"CurrentVersion\\Run|schtasks|\\Microsoft\\Windows\\[^\s]+|CreateService|sc\.exe\s+create", re.I),
     "Reference to an autostart / persistence location or tool"),
    ("registry", re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+|Software\\)[^\s]*", re.I), "Registry path"),
    ("filepath", re.compile(r"[A-Za-z]:\\[^\s\"'<>|*?]{3,}|\\\\[A-Za-z0-9._-]+\\[^\s\"'<>|*?]+"), "Windows file system path"),
    ("user_agent", re.compile(r"Mozilla/\d\.\d \([^)]*\)[^\"]*", re.I), "HTTP User-Agent string"),
    ("staging", re.compile(r"\\Documents\\Confidential|\.zip\b|\.7z\b|\.rar\b|-Method\s+Post|upload", re.I),
     "Possible data collection / staging / upload reference"),
]


def extract_strings(data: bytes, limit: int = MAX_STRINGS) -> list[ExtractedString]:
    found: list[ExtractedString] = []
    for m in _ASCII.finditer(data):
        found.append(ExtractedString(m.start(), "ascii", m.group().decode("ascii")))
        if len(found) >= limit:
            break
    for m in _UTF16.finditer(data):
        if len(found) >= limit * 2:
            break
        found.append(ExtractedString(m.start(), "utf-16le", m.group().decode("utf-16-le")))
    found.sort(key=lambda s: s.offset)
    return found[:limit]


def categorise(strings: list[ExtractedString]) -> list[dict]:
    """Return only the strings that fall into an interesting category, with an explanation."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for s in strings:
        for name, pattern, why in CATEGORIES:
            if pattern.search(s.value):
                key = (name, s.value)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"category": name, "value": s.value[:400], "offset": s.offset,
                            "encoding": s.encoding, "explanation": why})
    return out
