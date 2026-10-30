"""Streaming cryptographic hashing of evidence files."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

CHUNK = 1024 * 1024


@dataclass(frozen=True)
class FileHashes:
    sha256: str
    sha1: str
    md5: str
    size: int


def hash_stream(stream: BinaryIO) -> FileHashes:
    """Hash a binary stream with SHA-256, SHA-1 and MD5 in a single pass.

    MD5 and SHA-1 are reported only for interoperability with other tools and
    threat-intel sources; integrity decisions in TraceForge use SHA-256.
    """
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(usedforsecurity=False), hashlib.md5(usedforsecurity=False)
    size = 0
    while True:
        block = stream.read(CHUNK)
        if not block:
            break
        size += len(block)
        sha256.update(block)
        sha1.update(block)
        md5.update(block)
    return FileHashes(sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest(), size)


def hash_file(path: Path) -> FileHashes:
    with open(path, "rb") as fh:
        return hash_stream(fh)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
