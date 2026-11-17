"""Command-line interface for wifiguard.

Examples:
    wifiguard check
    wifiguard scan --interface wlan0mon --duration 20
    wifiguard capture --bssid 8C:42:6D:6A:2F:70 --channel 6 \
        --interface wlan0mon --i-own-this-network
    wifiguard crack capture-01.cap --wordlist rockyou.txt \
        --i-own-this-network
    wifiguard assess --wordlist rockyou.txt
    wifiguard report --capture-json cap.json --crack-json crack.json \
        --assess-json assess.json --out-dir ./audit

Safety: ``capture`` and ``crack`` refuse to run without the explicit
``--i-own-this-network`` flag. Every run prints a one-line legal
reminder. See wifiguard.safety for the enforced limits.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from wifiguard.capture import run_capture
from wifiguard.crack import run_crack
from wifiguard.envcheck import check_environment, format_env_report
from wifiguard.report import build_report, write_reports
from wifiguard.safety import (
    LEGAL_REMINDER,
    MAX_DEAUTH,
    ownership_refusal,
    validate_deauth,
)
from wifiguard.scanner import run_scan
from wifiguard.scanparse import format_scan_table
from wifiguard.strength import assess_password, load_wordlist


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifiguard",
        description="WiFi password security self-audit for your OWN "
                    "network: capture the handshake, test it against "
                    "a wordlist, get a plain-language verdict.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="verify OS, tools, interfaces, "
                                 "monitor-mode capability")

    p_scan = sub.add_parser("scan", help="list nearby access points "
                                         "(passive, time-bounded)")
    p_scan.add_argument("--interface", required=True,
                        help="monitor-mode interface, e.g. wlan0mon")
    p_scan.add_argument("--duration", type=int, default=20,
                        help="seconds to listen (default 20, max 600)")
    p_scan.add_argument("--json-out", default=None,
                        help="also write the scan result as JSON here")

    p_cap = sub.add_parser("capture", help="capture the WPA handshake "
                                           "of YOUR network")
    p_cap.add_argument("--bssid", required=True, help="target AP MAC")
    p_cap.add_argument("--channel", type=int, required=True)
    p_cap.add_argument("--interface", required=True,
                       help="monitor-mode interface, e.g. wlan0mon")
    p_cap.add_argument("--output", default="wifiguard-capture",
                       help="output file prefix (default wifiguard-capture)")
    p_cap.add_argument("--duration", type=int, default=120,
                       help="max seconds to capture (default 120, max 3600)")
    p_cap.add_argument("--deauth", type=int, default=0,
                       help="deauth frames to send to prompt a reconnect "
                            f"(default 0 = passive only, max {MAX_DEAUTH})")
    p_cap.add_argument("--client", default=None,
                       help="optionally target one of your own device MACs")
    p_cap.add_argument("--i-own-this-network", action="store_true",
                       help="REQUIRED: confirm this is your network or "
                            "you are authorized to test it")
    p_cap.add_argument("--json-out", default=None)

    p_crack = sub.add_parser("crack", help="crack a captured handshake "
                                           "against a wordlist")
    p_crack.add_argument("cap", help="capture file (.cap)")
    p_crack.add_argument("--wordlist", required=True)
    p_crack.add_argument("--bssid", default=None,
                         help="target network inside a multi-network cap")
    p_crack.add_argument("--no-hashcat", action="store_true",
                         help="use aircrack-ng even if hashcat is present")
    p_crack.add_argument("--i-own-this-network", action="store_true",
                         help="REQUIRED: confirm the capture is from "
                              "your network")
    p_crack.add_argument("--json-out", default=None)

    p_assess = sub.add_parser("assess", help="assess a password's "
                                             "strength (no tools needed)")
    p_assess.add_argument("--password", default=None,
                          help="password to assess (default: prompt "
                               "without echo)")
    p_assess.add_argument("--wordlist", default=None,
                          help="optional wordlist file to check "
                               "membership against")
    p_assess.add_argument("--json-out", default=None)

    p_report = sub.add_parser("report", help="combine result JSONs "
                                             "into report.md + report.json")
    p_report.add_argument("--capture-json", default=None)
    p_report.add_argument("--crack-json", default=None)
    p_report.add_argument("--assess-json", default=None)
    p_report.add_argument("--out-dir", default=".",
                          help="where to write report.md/report.json")

    return parser


def _write_json(path: str | None, data: dict) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)


def _load_json(path: str | None) -> dict | None:
    if path is None:
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _warn_if_not_root(action: str) -> None:
    try:
        if os.geteuid() != 0:
            print(f"warning: {action} usually needs root — re-run with "
                  "sudo if it fails.", file=sys.stderr)
    except AttributeError:
        pass


def _cmd_check() -> int:
    report = check_environment()
    print(format_env_report(report))
    return 0 if not report.missing_required else 1


def _cmd_scan(args) -> int:
    _warn_if_not_root("scan")
    result = run_scan(args.interface, duration=args.duration)
    print(format_scan_table(result))
    if args.json_out:
        data = {
            "aps": [
                {**{k: v for k, v in vars(ap).items() if k != "clients"},
                 "clients": [vars(s) for s in ap.clients]}
                for ap in result.aps
            ],
            "stations": [vars(s) for s in result.stations],
        }
        _write_json(args.json_out, data)
    return 0


def _cmd_capture(args) -> int:
    if not args.i_own_this_network:
        print(ownership_refusal("capture a handshake"), file=sys.stderr)
        return 2
    try:
        validate_deauth(args.deauth)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _warn_if_not_root("capture")
    result = run_capture(
        bssid=args.bssid, channel=args.channel, interface=args.interface,
        output_prefix=args.output, duration=args.duration,
        deauth=args.deauth, client=args.client,
    )
    print(f"Capture file: {result.cap_file}")
    if result.handshake_found:
        print(f"Handshake CAPTURED ({result.handshake_count}) — "
              "now run: wifiguard crack "
              f"{result.cap_file} --wordlist <wordlist> "
              "--i-own-this-network")
    else:
        print("No handshake captured. Tips: wait for a device to "
              "reconnect, move closer, or re-run with a small "
              "--deauth burst against your own device.")
    _write_json(args.json_out, result.to_dict())
    return 0


def _cmd_crack(args) -> int:
    if not args.i_own_this_network:
        print(ownership_refusal("crack a capture"), file=sys.stderr)
        return 2
    result = run_crack(args.cap, args.wordlist, bssid=args.bssid,
                       prefer_hashcat=not args.no_hashcat)
    print(f"Engine: {result.method}   Time: {result.elapsed_seconds:.1f}s")
    if result.keys_per_sec:
        print(f"Speed: {result.keys_per_sec:.0f} keys/sec")
    if result.found:
        print(f"PASSWORD FOUND: {result.password}")
        print("Verdict: CRITICAL — this password is recoverable by "
              "anyone in range with this wordlist. Change it now.")
    else:
        print("Password NOT in this wordlist. That means 'not in "
              "this list', not 'uncrackable' — try `wifiguard assess` "
              "for a strength estimate.")
    _write_json(args.json_out, result.to_dict())
    return 0


def _cmd_assess(args) -> int:
    password = args.password
    if password is None:
        password = getpass.getpass("WiFi password to assess: ")
    wordlist = load_wordlist(args.wordlist) if args.wordlist else None
    result = assess_password(password, wordlist)
    print(f"Verdict: {result.verdict}  (score {result.score}/100)")
    print(f"Length: {result.length}   Classes: "
          f"{', '.join(result.classes_present) or 'none'}")
    print(f"Estimated offline crack time: {result.estimated_crack_time} "
          "(estimate at an assumed 2,000,000 guesses/sec for WPA2 on a "
          "high-end GPU rig)")
    if result.in_wordlist:
        print("This password appears in the wordlist you provided.")
    if result.issues:
        print("Issues:")
        for issue in result.issues:
            print(f"  - {issue}")
    print("Advice:")
    for suggestion in result.suggestions:
        print(f"  - {suggestion}")
    _write_json(args.json_out, result.to_dict())
    return 0


def _cmd_report(args) -> int:
    if not (args.capture_json or args.crack_json or args.assess_json):
        print("error: give at least one of --capture-json, "
              "--crack-json, --assess-json", file=sys.stderr)
        return 2
    report = build_report(
        capture=_load_json(args.capture_json),
        crack=_load_json(args.crack_json),
        assess=_load_json(args.assess_json),
    )
    md_path, json_path = write_reports(report, args.out_dir)
    print(f"Wrote {md_path} and {json_path}")
    print("Note: if the password was recovered it appears in the "
          "report — keep these files private.")
    return 0


def main(argv: list[str] | None = None) -> int:
    print(LEGAL_REMINDER, file=sys.stderr)
    args = build_parser().parse_args(argv)
    try:
        if args.command == "check":
            return _cmd_check()
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "capture":
            return _cmd_capture(args)
        if args.command == "crack":
            return _cmd_crack(args)
        if args.command == "assess":
            return _cmd_assess(args)
        if args.command == "report":
            return _cmd_report(args)
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2  # unreachable: argparse enforces a command


if __name__ == "__main__":
    raise SystemExit(main())
