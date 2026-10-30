"""Indicator-of-compromise extraction, validation and normalisation.

Extraction never implies maliciousness. Every indicator is stored with its
namespace classification (e.g. private vs documentation IP range), the
evidence it was seen in, and an *assessment* that is only raised above
"observed" when there is a concrete, explainable reason (watchlist match or a
reference from a suspicious finding).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .netclass import classify_domain, classify_ip

# Extensions that look like TLDs inside filenames/paths and would otherwise create false-positive "domains".
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "psm1", "vbs", "js", "jse", "msi", "lnk", "zip", "rar",
    "7z", "gz", "tar", "cab", "iso", "img", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "txt", "csv",
    "log", "json", "xml", "html", "htm", "evtx", "sqlite", "db", "dat", "tmp", "ini", "cfg", "conf", "yar", "yara",
    "py", "jpg", "jpeg", "png", "gif", "bmp", "ico", "mp4", "mov", "wav", "md", "local", "manifest", "mui", "cpl",
    "ocx", "drv", "bin", "pf", "etl", "reg", "hta", "jar", "class", "apk", "dylib",
}
# Real TLDs that collide with extensions (.com, .zip, .mov, .md ...) are a known trade-off: .com and .net are
# kept as domains; .zip/.mov/.md are treated as file extensions (documented in docs/LIMITATIONS.md).
# .NET namespaces such as System.Net.WebClient are excluded explicitly.
_DOTNET_NAMESPACE = re.compile(r"^(system|microsoft|windows)\.", re.I)

EXECUTABLE_EXT = {"exe", "dll", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "msi", "lnk", "jar"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab", "iso"}

RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\]\[(){}|\\^`]{3,2048}", re.I)
RE_IPV4 = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
RE_DOMAIN = re.compile(r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])", re.I)
RE_SHA256 = re.compile(r"(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])", re.I)
RE_SHA1 = re.compile(r"(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])", re.I)
RE_MD5 = re.compile(r"(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])", re.I)


@dataclass(frozen=True)
class Indicator:
    ioc_type: str
    value: str
    normalized: str
    classification: str


def refang(text: str) -> str:
    return (text.replace("hxxps://", "https://").replace("hxxp://", "http://")
            .replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[:]", ":").replace("[://]", "://"))


def normalize_domain(value: str) -> str | None:
    d = value.strip().strip(".").lower()
    if len(d) > 253 or ".." in d or "." not in d:
        return None
    labels = d.split(".")
    if any(not lbl or len(lbl) > 63 or lbl.startswith("-") or lbl.endswith("-") for lbl in labels):
        return None
    tld = labels[-1]
    if not tld.isalpha() or tld in FILE_EXTENSIONS:
        return None
    if _DOTNET_NAMESPACE.match(d):
        return None
    try:
        d.encode("idna")
    except UnicodeError:
        return None
    return d


def make_ip(value: str) -> Indicator | None:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if ip.version != 4:
        return None
    norm = str(ip)
    return Indicator("ipv4", value.strip(), norm, classify_ip(norm) or "invalid")


def make_domain(value: str) -> Indicator | None:
    norm = normalize_domain(value)
    if not norm:
        return None
    return Indicator("domain", value, norm, classify_domain(norm))


def make_url(value: str) -> tuple[Indicator, Indicator | None] | None:
    raw = refang(value).rstrip(".,;:'\")]}>")
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.hostname:
        return None
    host = parts.hostname.lower()
    ip_ind = make_ip(host)
    host_ind = ip_ind or make_domain(host)
    if host_ind is None:
        return None
    netloc = host + (f":{parts.port}" if parts.port else "")
    norm = f"{parts.scheme.lower()}://{netloc}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")
    return Indicator("url", raw, norm, host_ind.classification), host_ind


def make_hash(value: str) -> Indicator | None:
    v = value.strip().lower()
    kinds = {64: "sha256", 40: "sha1", 32: "md5"}
    if len(v) not in kinds or not re.fullmatch(r"[a-f0-9]+", v) or len(set(v)) < 4:
        return None
    return Indicator(kinds[len(v)], value, v, "file_hash")


def make_filename(path_or_name: str) -> Indicator | None:
    name = re.split(r"[\\/]", path_or_name.strip())[-1]
    if "." not in name or len(name) > 255 or not name:
        return None
    ext = name.rsplit(".", 1)[-1].lower()
    parts = name.lower().split(".")
    if len(parts) >= 3 and parts[-1] in EXECUTABLE_EXT and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png", "zip", "rtf", "csv"}:
        cls = "double_extension_executable"
    elif ext in EXECUTABLE_EXT:
        cls = "executable"
    elif ext in ARCHIVE_EXT:
        cls = "archive"
    else:
        return None  # ordinary documents are not reported as filename IOCs
    return Indicator("filename", name, name.lower(), cls)


def make_process(image_path: str) -> Indicator | None:
    name = re.split(r"[\\/]", image_path.strip())[-1]
    if not name.lower().endswith((".exe", ".com", ".scr")):
        return None
    return Indicator("process", image_path, name.lower(), "process_image")


def extract_from_text(text: str) -> list[Indicator]:
    """Regex extraction over free text (strings, script blocks, messages)."""
    if not text:
        return []
    text = refang(text)
    found: dict[tuple[str, str], Indicator] = {}
    url_spans: list[tuple[int, int]] = []
    for m in RE_URL.finditer(text):
        res = make_url(m.group())
        if res:
            url_ind, host_ind = res
            found[(url_ind.ioc_type, url_ind.normalized)] = url_ind
            if host_ind:
                found[(host_ind.ioc_type, host_ind.normalized)] = host_ind
            url_spans.append(m.span())
    for m in RE_IPV4.finditer(text):
        ind = make_ip(m.group())
        if ind:
            found[(ind.ioc_type, ind.normalized)] = ind
    for m in RE_DOMAIN.finditer(text):
        if any(s <= m.start() < e for s, e in url_spans):
            continue
        ind = make_domain(m.group())
        if ind:
            found[(ind.ioc_type, ind.normalized)] = ind
    for regex in (RE_SHA256, RE_SHA1, RE_MD5):
        for m in regex.finditer(text):
            ind = make_hash(m.group())
            if ind:
                found[(ind.ioc_type, ind.normalized)] = ind
    return list(found.values())
