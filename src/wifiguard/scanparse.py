"""Parsing of airodump-ng CSV output (pure functions, no subprocess).

airodump-ng writes a CSV with two sections separated by a blank line:

1. access points, headed by ``BSSID, First time seen, ...``
2. stations (clients), headed by ``Station MAC, First time seen, ...``

Fields are separated by ``", "``. An ESSID may itself contain commas,
so AP rows are parsed positionally: the first 13 fields are fixed,
the last field is the key, and everything in between is the ESSID.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")


@dataclass
class Station:
    mac: str
    power: int | None
    packets: int
    bssid: str  # AP MAC, or "(not associated)"
    probed_essids: list[str] = field(default_factory=list)


@dataclass
class AccessPoint:
    bssid: str
    essid: str  # "" when the network hides its ESSID
    hidden: bool
    channel: int | None
    privacy: str  # e.g. "WPA2", "WPA3", "OPN"
    cipher: str  # e.g. "CCMP"
    authentication: str  # e.g. "PSK", "SAE", "MGT"
    power: int | None  # dBm; -1 means "not reported"
    beacons: int
    ivs: int
    clients: list[Station] = field(default_factory=list)


@dataclass
class ScanResult:
    aps: list[AccessPoint] = field(default_factory=list)
    stations: list[Station] = field(default_factory=list)


def _to_int(text: str) -> int | None:
    try:
        return int(text.strip())
    except (ValueError, AttributeError):
        return None


def _split(line: str) -> list[str]:
    return [part.strip() for part in line.split(",")]


def _parse_ap_row(parts: list[str]) -> AccessPoint | None:
    # Fixed layout: 0 BSSID, 1 first seen, 2 last seen, 3 channel,
    # 4 speed, 5 privacy, 6 cipher, 7 authentication, 8 power,
    # 9 beacons, 10 IVs, 11 LAN IP, 12 ID-length, 13..-2 ESSID, -1 key.
    if len(parts) < 15 or not _MAC_RE.match(parts[0]):
        return None
    essid_raw = ", ".join(parts[13:-1])
    essid = essid_raw.replace("\x00", "").strip()
    return AccessPoint(
        bssid=parts[0].upper(),
        essid=essid,
        hidden=(essid == ""),
        channel=_to_int(parts[3]),
        privacy=parts[5],
        cipher=parts[6],
        authentication=parts[7],
        power=_to_int(parts[8]),
        beacons=_to_int(parts[9]) or 0,
        ivs=_to_int(parts[10]) or 0,
    )


def _parse_station_row(parts: list[str]) -> Station | None:
    # 0 station MAC, 1 first seen, 2 last seen, 3 power, 4 packets,
    # 5 BSSID, 6.. probed ESSIDs.
    if len(parts) < 6 or not _MAC_RE.match(parts[0]):
        return None
    probed = [p for p in parts[6:] if p]
    return Station(
        mac=parts[0].upper(),
        power=_to_int(parts[3]),
        packets=_to_int(parts[4]) or 0,
        bssid=parts[5].upper() if _MAC_RE.match(parts[5]) else parts[5],
        probed_essids=probed,
    )


def parse_airodump_csv(text: str) -> ScanResult:
    """Parse the full text of an airodump-ng CSV file.

    Tolerant of CRLF line endings, blank lines, and malformed rows
    (they are skipped, never fatal). Stations are also attached to
    their access point's ``clients`` list when the BSSID matches.
    """
    result = ScanResult()
    section: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("BSSID,"):
            section = "ap"
            continue
        if line.startswith("Station MAC,"):
            section = "station"
            continue
        parts = _split(line)
        if section == "ap":
            ap = _parse_ap_row(parts)
            if ap is not None:
                result.aps.append(ap)
        elif section == "station":
            station = _parse_station_row(parts)
            if station is not None:
                result.stations.append(station)

    by_bssid = {ap.bssid: ap for ap in result.aps}
    for station in result.stations:
        ap = by_bssid.get(station.bssid)
        if ap is not None:
            ap.clients.append(station)
    return result


def format_scan_table(result: ScanResult) -> str:
    """Render a scan result as a plain-text table."""
    if not result.aps:
        return "No access points found."
    lines = [
        f"{'BSSID':<18} {'ESSID':<28} {'CH':>3} {'ENCRYPTION':<14} "
        f"{'PWR':>5} {'CLIENTS':>7}",
        "-" * 79,
    ]
    for ap in result.aps:
        essid = ap.essid if not ap.hidden else "<hidden>"
        encryption = " ".join(
            p for p in (ap.privacy, ap.cipher, ap.authentication) if p
        )
        power = str(ap.power) if ap.power is not None else "?"
        channel = str(ap.channel) if ap.channel is not None else "?"
        lines.append(
            f"{ap.bssid:<18} {essid:<28.28} {channel:>3} "
            f"{encryption:<14.14} {power:>5} {len(ap.clients):>7}"
        )
    lines.append(f"\n{len(result.aps)} access point(s), "
                 f"{len(result.stations)} station(s) seen.")
    return "\n".join(lines)
