"""Targeted handshake capture (``capture`` subcommand).

Safety gates live in :mod:`wifiguard.safety` and are enforced by the
CLI before this module runs, and again here for direct API users:
the deauth count is validated against the hard cap and the duration
against the maximum. Deauthentication targets only the named BSSID
and, optionally, one client MAC the user supplies.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass

from wifiguard.safety import (
    MAX_CAPTURE_SECONDS,
    validate_deauth,
    validate_duration,
)

_HANDSHAKE_LINE_RE = re.compile(
    r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}).*?WPA \((\d+) handshakes?\)"
)


@dataclass
class CaptureResult:
    bssid: str
    channel: int
    interface: str
    cap_file: str
    handshake_found: bool
    handshake_count: int
    deauth_sent: int
    duration_seconds: int

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "channel": self.channel,
            "interface": self.interface,
            "cap_file": self.cap_file,
            "handshake_found": self.handshake_found,
            "handshake_count": self.handshake_count,
            "deauth_sent": self.deauth_sent,
            "duration_seconds": self.duration_seconds,
        }


def parse_handshakes(aircrack_output: str) -> dict[str, int]:
    """Map BSSID -> handshake count from aircrack-ng output (pure).

    aircrack-ng lists each network in a capture like::

        1  8C:42:6D:6A:2F:70  HomeWiFi   WPA (1 handshake)
    """
    counts: dict[str, int] = {}
    for line in aircrack_output.splitlines():
        m = _HANDSHAKE_LINE_RE.search(line)
        if m:
            counts[m.group(1).upper()] = int(m.group(2))
    return counts


def parse_handshake_count(aircrack_output: str,
                          bssid: str | None = None) -> int:
    """Handshake count for ``bssid`` (or the maximum seen) — pure."""
    counts = parse_handshakes(aircrack_output)
    if not counts:
        return 0
    if bssid is not None:
        return counts.get(bssid.upper(), 0)
    return max(counts.values())


def check_handshake(cap_file: str, bssid: str | None = None,
                    run=subprocess.run) -> int:
    """Run aircrack-ng on a capture and return the handshake count."""
    try:
        proc = run(["aircrack-ng", cap_file], stdin=subprocess.DEVNULL,
                   capture_output=True, text=True, timeout=60)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "aircrack-ng not found — install it with: "
            "sudo apt install aircrack-ng"
        ) from exc
    except subprocess.TimeoutExpired:
        return 0
    return parse_handshake_count(proc.stdout or "", bssid)


def run_capture(*, bssid: str, channel: int, interface: str,
                output_prefix: str, duration: int = 120, deauth: int = 0,
                client: str | None = None, popen=None, run=None,
                sleep=time.sleep) -> CaptureResult:
    """Capture packets for one AP for a bounded time.

    With ``deauth`` > 0, a single capped aireplay-ng burst is sent
    partway through the capture to prompt a reconnect (and therefore
    a handshake) from the user's own device. ``popen``/``run``/
    ``sleep`` are injectable for tests.
    """
    validate_deauth(deauth)
    validate_duration(duration, MAX_CAPTURE_SECONDS, "capture")
    popen = popen or subprocess.Popen
    run = run or subprocess.run
    bssid = bssid.upper()

    cmd = ["airodump-ng", "-c", str(channel), "--bssid", bssid,
           "-w", output_prefix, "--output-format", "cap,csv", interface]
    try:
        proc = popen(cmd, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "airodump-ng not found — install it with: "
            "sudo apt install aircrack-ng"
        ) from exc

    deauth_sent = 0
    try:
        if deauth > 0:
            sleep(min(5, max(1, duration // 4)))
            deauth_cmd = ["aireplay-ng", "--deauth", str(deauth),
                          "-a", bssid]
            if client:
                deauth_cmd += ["-c", client.upper()]
            deauth_cmd.append(interface)
            try:
                run(deauth_cmd, capture_output=True, text=True, timeout=60)
                deauth_sent = deauth
            except (OSError, subprocess.SubprocessError):
                deauth_sent = 0  # capture continues passively
            sleep(max(0, duration - min(5, max(1, duration // 4))))
        else:
            sleep(duration)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    cap_file = f"{output_prefix}-01.cap"
    count = 0
    if os.path.exists(cap_file):
        count = check_handshake(cap_file, bssid, run=run)
    return CaptureResult(
        bssid=bssid,
        channel=channel,
        interface=interface,
        cap_file=cap_file,
        handshake_found=count > 0,
        handshake_count=count,
        deauth_sent=deauth_sent,
        duration_seconds=duration,
    )
