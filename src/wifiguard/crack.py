"""Wordlist cracking of a captured handshake (``crack`` subcommand).

Two engines, both driven through their real command-line interfaces:

- **aircrack-ng** — always available with the suite; parses the
  ``KEY FOUND! [ password ]`` line from its output.
- **hashcat mode 22000** — optional faster route, used only when
  both ``hcxpcapngtool`` and ``hashcat`` are installed. The capture
  is converted to a 22000 hash file and the recovered password is
  read back with ``hashcat --show``.

All output parsing is in pure functions so it is unit-testable from
fixtures on machines without any of these tools installed.

A "not found" result means exactly one thing: the password is not
in the wordlist that was tried. It does not mean the password is
uncrackable.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-B]")
_KEY_FOUND_LINE_RE = re.compile(r"KEY FOUND!\s*\[\s*(.*?)\s*\]")
_SPEED_RE = re.compile(r"\(([\d.]+) k/s\)")
_TESTED_RE = re.compile(r"(\d+)\s*/\s*(\d+) keys tested")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences aircrack-ng emits on a TTY."""
    return _ANSI_RE.sub("", text)


@dataclass
class CrackOutcome:
    found: bool
    password: str | None
    keys_per_sec: float | None
    keys_tested: int | None


@dataclass
class CrackResult:
    cap_file: str
    wordlist: str
    found: bool
    password: str | None
    method: str  # "aircrack-ng" or "hashcat (mode 22000)"
    elapsed_seconds: float
    keys_per_sec: float | None

    def to_dict(self) -> dict:
        return {
            "cap_file": self.cap_file,
            "wordlist": self.wordlist,
            "found": self.found,
            "password": self.password,
            "method": self.method,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "keys_per_sec": self.keys_per_sec,
        }


def parse_aircrack_result(output: str) -> CrackOutcome:
    """Parse aircrack-ng cracking output (pure).

    Success looks like ``KEY FOUND! [ thepassword ]``; progress lines
    look like ``[00:00:07] 114688/999999 keys tested (16384.00 k/s)``.

    Real TTY output is full of ANSI escapes and screen redraws that
    repeat the KEY FOUND line, so parse line-by-line on the cleaned
    text and never let a match span lines.
    """
    cleaned = strip_ansi(output)
    password = None
    for line in re.split(r"[\r\n]+", cleaned):
        if "KEY FOUND!" in line:
            m = _KEY_FOUND_LINE_RE.search(line)
            if m:
                password = m.group(1)
    speeds = _SPEED_RE.findall(cleaned)
    tested = _TESTED_RE.findall(cleaned)
    return CrackOutcome(
        found=password is not None,
        password=password,
        keys_per_sec=float(speeds[-1]) if speeds else None,
        keys_tested=int(tested[-1][0]) if tested else None,
    )


def parse_hashcat_show(output: str) -> str | None:
    """Password from ``hashcat --show`` output (pure).

    Mode 22000 hashes contain no ':' (fields are '*'-separated), so
    the first ':' on a ``WPA*`` line separates hash from password.
    """
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("WPA*") and ":" in line:
            return line.split(":", 1)[1]
    return None


def parse_hashcat_status(output: str) -> bool:
    """True if a hashcat status/report output says it cracked."""
    if re.search(r"Status\.+:\s*Cracked", output):
        return True
    m = re.search(r"Recovered\.+:\s*(\d+)/\1", output)
    return m is not None


def _run_aircrack(cap_file: str, wordlist: str, bssid: str | None,
                  run, clock) -> CrackResult:
    cmd = ["aircrack-ng", "-w", wordlist]
    if bssid:
        cmd += ["-b", bssid.upper()]
    cmd.append(cap_file)
    start = clock()
    try:
        proc = run(cmd, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "aircrack-ng not found — install it with: "
            "sudo apt install aircrack-ng"
        ) from exc
    elapsed = clock() - start
    outcome = parse_aircrack_result((proc.stdout or "") + (proc.stderr or ""))
    return CrackResult(
        cap_file=cap_file, wordlist=wordlist, found=outcome.found,
        password=outcome.password, method="aircrack-ng",
        elapsed_seconds=elapsed, keys_per_sec=outcome.keys_per_sec,
    )


def _run_hashcat(cap_file: str, wordlist: str, run, clock) -> CrackResult | None:
    """Hashcat route; returns None if conversion fails (fall back)."""
    hash_file = cap_file + ".22000"
    try:
        conv = run(["hcxpcapngtool", "-o", hash_file, cap_file],
                   capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if conv.returncode != 0 or not os.path.exists(hash_file):
        return None
    start = clock()
    run(["hashcat", "-m", "22000", hash_file, wordlist, "--quiet"],
        capture_output=True, text=True)
    elapsed = clock() - start
    show = run(["hashcat", "-m", "22000", hash_file, "--show"],
               capture_output=True, text=True)
    password = parse_hashcat_show(show.stdout or "")
    return CrackResult(
        cap_file=cap_file, wordlist=wordlist, found=password is not None,
        password=password, method="hashcat (mode 22000)",
        elapsed_seconds=elapsed, keys_per_sec=None,
    )


def run_crack(cap_file: str, wordlist: str, *, bssid: str | None = None,
              prefer_hashcat: bool = True, run=subprocess.run,
              which=shutil.which, clock=time.monotonic) -> CrackResult:
    """Crack ``cap_file`` against ``wordlist``.

    Uses the hashcat 22000 route when both optional tools are
    present and conversion succeeds; otherwise aircrack-ng.
    ``run``/``which``/``clock`` are injectable for tests.
    """
    if prefer_hashcat and which("hashcat") and which("hcxpcapngtool"):
        result = _run_hashcat(cap_file, wordlist, run, clock)
        if result is not None:
            return result
    return _run_aircrack(cap_file, wordlist, bssid, run, clock)
