"""Combined audit report (``report`` subcommand).

Takes the JSON results produced by ``capture``, ``crack`` and
``assess`` (any subset) and writes ``report.md`` + ``report.json``
with the verdict and concrete remediation steps.

Note: when the password was recovered, it appears in the report —
that is the point of a self-audit — so treat report files as
sensitive and keep them private.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from wifiguard.safety import LEGAL_REMINDER


def remediation_steps(report: dict) -> list[str]:
    """Concrete fixes derived from whatever results are present."""
    steps: list[str] = []
    crack = report.get("crack") or {}
    assess = report.get("assess") or {}
    capture = report.get("capture") or {}

    if crack.get("found"):
        steps.append(
            "CHANGE THE WIFI PASSWORD NOW — it was recovered from a "
            "captured handshake with a standard wordlist, so any "
            "attacker in range can do the same."
        )
        steps.append(
            "Use a new password of at least 16 characters: 3 random "
            "words plus a number and a symbol is easy to type and "
            "hard to crack."
        )
    elif assess.get("verdict") in ("Critical", "Weak"):
        steps.append(
            f"The password strength verdict is {assess['verdict']} — "
            "replace it with a 16+ character passphrase (3 random "
            "words + number + symbol)."
        )
    if capture and not capture.get("handshake_found"):
        steps.append(
            "The handshake was not captured in this run, so the "
            "crack result is inconclusive — re-run the capture while "
            "a device reconnects to the network."
        )
    if crack and not crack.get("found"):
        steps.append(
            "The password was not in the wordlist tried. That means "
            "'not in this list', not 'uncrackable' — a bigger list or "
            "a GPU rig may still find it if it is short or patterned."
        )
    steps.append("Prefer WPA3 (or WPA2/WPA3 mixed mode) if the router "
                 "offers it; WPA3-SAE is not susceptible to this "
                 "offline handshake-cracking method.")
    steps.append("Disable WPS on the router — it is a separate, "
                 "well-known weak point.")
    steps.append("Update the router firmware and change the router "
                 "admin password from its default.")
    return steps


def build_report(*, capture: dict | None = None,
                 crack: dict | None = None,
                 assess: dict | None = None,
                 generated_at: str | None = None) -> dict:
    report = {
        "tool": "wifiguard",
        "generated_at": generated_at
        or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "capture": capture,
        "crack": crack,
        "assess": assess,
    }
    report["remediation"] = remediation_steps(report)
    return report


def render_report_md(report: dict) -> str:
    lines = [
        "# WiFiGuard — WiFi Password Security Audit",
        "",
        f"Generated: {report['generated_at']}",
        "",
        LEGAL_REMINDER,
        "",
    ]
    capture = report.get("capture")
    if capture:
        lines += [
            "## Handshake capture",
            "",
            f"- Network (BSSID): {capture.get('bssid')}",
            f"- Channel: {capture.get('channel')}",
            f"- Capture file: {capture.get('cap_file')}",
            f"- Handshake captured: "
            f"{'YES' if capture.get('handshake_found') else 'NO'} "
            f"({capture.get('handshake_count', 0)} handshake(s))",
            f"- Deauth frames sent: {capture.get('deauth_sent', 0)}",
            "",
        ]
    crack = report.get("crack")
    if crack:
        lines += [
            "## Password recovery attempt",
            "",
            f"- Engine: {crack.get('method')}",
            f"- Wordlist: {crack.get('wordlist')}",
            f"- Time taken: {crack.get('elapsed_seconds')}s",
        ]
        if crack.get("keys_per_sec"):
            lines.append(f"- Speed: {crack['keys_per_sec']} keys/sec")
        if crack.get("found"):
            lines.append(f"- Result: **PASSWORD FOUND: "
                         f"{crack.get('password')}**")
        else:
            lines.append("- Result: not found in this wordlist "
                         "(this does NOT mean uncrackable)")
        lines.append("")
    assess = report.get("assess")
    if assess:
        lines += [
            "## Password strength",
            "",
            f"- Verdict: **{assess.get('verdict')}** "
            f"(score {assess.get('score')}/100)",
            f"- Length: {assess.get('length')} characters, "
            f"classes: {', '.join(assess.get('classes_present') or [])}",
            f"- Estimated offline crack time: "
            f"{assess.get('estimated_crack_time')} "
            f"(at an assumed {assess.get('rate_assumption_guesses_per_second')} "
            "guesses/sec for WPA2 — an estimate, not a measurement)",
        ]
        if assess.get("in_wordlist"):
            lines.append("- The password appears in a known wordlist.")
        if assess.get("issues"):
            lines.append("- Issues:")
            for issue in assess["issues"]:
                lines.append(f"  - {issue}")
        lines.append("")
    lines += ["## What to do", ""]
    for i, step in enumerate(report.get("remediation") or [], 1):
        lines.append(f"{i}. {step}")
    lines.append("")
    return "\n".join(lines)


def write_reports(report: dict, out_dir: str) -> tuple[str, str]:
    """Write report.md and report.json into ``out_dir``."""
    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, "report.md")
    json_path = os.path.join(out_dir, "report.json")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_report_md(report))
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return md_path, json_path
