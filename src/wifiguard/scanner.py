"""Bounded airodump-ng scan (``scan`` subcommand).

Passive only: a scan listens for beacons for a fixed duration and
then stops. It never transmits, never deauthenticates, and never
runs indefinitely.
"""
from __future__ import annotations

import os
import subprocess
import time

from wifiguard.safety import MAX_SCAN_SECONDS, validate_duration
from wifiguard.scanparse import ScanResult, parse_airodump_csv


def run_scan(interface: str, duration: int = 20, workdir: str = ".",
             prefix: str = "wifiguard-scan", popen=None,
             sleep=time.sleep) -> ScanResult:
    """Run airodump-ng for ``duration`` seconds and parse its CSV.

    ``popen``/``sleep`` are injectable so tests can fake the tool.
    """
    validate_duration(duration, MAX_SCAN_SECONDS, "scan")
    popen = popen or subprocess.Popen
    os.makedirs(workdir, exist_ok=True)
    base = os.path.join(workdir, prefix)
    cmd = ["airodump-ng", "-w", base, "--output-format", "csv", interface]
    try:
        proc = popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "airodump-ng not found — install it with: "
            "sudo apt install aircrack-ng"
        ) from exc
    try:
        sleep(duration)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
    csv_path = f"{base}-01.csv"
    if not os.path.exists(csv_path):
        raise RuntimeError(
            f"airodump-ng produced no output file ({csv_path}). "
            "Is the interface in monitor mode and are you root?"
        )
    with open(csv_path, encoding="utf-8", errors="ignore") as fh:
        return parse_airodump_csv(fh.read())
