"""Shannon entropy helpers."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 – 8.0).

    0.0 means every byte is identical; 8.0 means the bytes are uniformly
    distributed. Compressed or encrypted data typically scores above ~7.2, but
    so do legitimate compressed resources, images and installers. Entropy is
    therefore reported as an *indicator* and never as a verdict.
    """
    if not data:
        return 0.0
    total = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def entropy_profile(data: bytes, block_size: int = 4096) -> list[float]:
    """Entropy of consecutive fixed-size blocks, useful for locating packed regions."""
    return [round(shannon_entropy(data[i : i + block_size]), 4) for i in range(0, len(data), block_size)]


def describe_entropy(value: float) -> str:
    if value >= 7.2:
        return "very high – consistent with compressed or encrypted content"
    if value >= 6.5:
        return "elevated"
    if value >= 3.0:
        return "typical for code or mixed data"
    return "low – mostly repetitive or padding bytes"
