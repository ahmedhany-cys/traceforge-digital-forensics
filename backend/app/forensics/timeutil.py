"""Timestamp normalisation.

All timestamps are normalised to timezone-aware UTC ``datetime`` objects while
the original textual representation is preserved alongside them. When a source
value carries no timezone information, the configured *assumed* timezone is
applied and the result is explicitly flagged as assumed so that analysts (and
reports) can see that the UTC value depends on an assumption.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

FILETIME_EPOCH_OFFSET = 116444736000000000  # 100ns intervals between 1601-01-01 and 1970-01-01
WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
MIN_PLAUSIBLE = datetime(1990, 1, 1, tzinfo=timezone.utc)
MAX_PLAUSIBLE = datetime(2100, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class NormalizedTime:
    utc: datetime
    original: str
    timezone_assumed: bool = False


def filetime_to_datetime(value: int) -> datetime | None:
    """Windows FILETIME (100ns ticks since 1601-01-01 UTC) -> aware UTC datetime, exact to the microsecond."""
    if value <= 0:
        return None
    micros = (value - FILETIME_EPOCH_OFFSET) // 10
    try:
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micros)
    except OverflowError:
        return None


def webkit_to_datetime(value: int | None) -> datetime | None:
    """Chromium/WebKit timestamp (microseconds since 1601-01-01 UTC). Zero means 'not set'."""
    if not value or value <= 0:
        return None
    try:
        return WEBKIT_EPOCH + timedelta(microseconds=int(value))
    except OverflowError:
        return None


def resolve_zone(name: str) -> timezone | ZoneInfo:
    if name.upper() in ("UTC", "Z", "GMT"):
        return timezone.utc
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"unknown timezone '{name}'") from exc


_OFFSET_SUFFIX = re.compile(r"\s([+-]\d{2}):?(\d{2})$")
_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
)


def parse_timestamp(text: str, assumed_tz: str = "UTC") -> NormalizedTime:
    """Parse a textual timestamp into UTC. Raises ValueError when unparseable or implausible."""
    original = text
    value = text.strip()
    if not value:
        raise ValueError("empty timestamp")

    # Epoch seconds / milliseconds
    if re.fullmatch(r"\d{9,13}(\.\d+)?", value):
        number = float(value)
        if number > 1e11:
            number /= 1000.0
        dt = datetime.fromtimestamp(number, tz=timezone.utc)
        return _plausible(NormalizedTime(dt, original, False))

    normalised = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    m = _OFFSET_SUFFIX.search(normalised)
    if m:  # "2026-10-14 09:41:44.204 -0400"
        normalised = normalised[: m.start()] + f"{m.group(1)}:{m.group(2)}"
    try:
        dt = datetime.fromisoformat(normalised)
    except ValueError:
        dt = None
        for fmt in _FORMATS:
            try:
                dt = datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            raise ValueError(f"unrecognised timestamp format: {text!r}")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=resolve_zone(assumed_tz))
        return _plausible(NormalizedTime(dt.astimezone(timezone.utc), original, True))
    return _plausible(NormalizedTime(dt.astimezone(timezone.utc), original, False))


def _plausible(nt: NormalizedTime) -> NormalizedTime:
    if not (MIN_PLAUSIBLE <= nt.utc <= MAX_PLAUSIBLE):
        raise ValueError(f"timestamp outside plausible range: {nt.original!r}")
    return nt


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
