import json

from wifiguard.report import build_report, render_report_md, write_reports
from wifiguard.strength import assess_password

CAPTURE = {
    "bssid": "8C:42:6D:6A:2F:70", "channel": 6, "interface": "wlan0mon",
    "cap_file": "wifiguard-capture-01.cap", "handshake_found": True,
    "handshake_count": 1, "deauth_sent": 0, "duration_seconds": 120,
}
CRACK_FOUND = {
    "cap_file": "wifiguard-capture-01.cap", "wordlist": "rockyou.txt",
    "found": True, "password": "HomeWiFi2024", "method": "aircrack-ng",
    "elapsed_seconds": 7.5, "keys_per_sec": 16384.0,
}
CRACK_NOT_FOUND = {**CRACK_FOUND, "found": False, "password": None}


def test_report_with_cracked_password():
    report = build_report(capture=CAPTURE, crack=CRACK_FOUND,
                          assess=assess_password("HomeWiFi2024").to_dict(),
                          generated_at="2026-11-17T00:00:00+00:00")
    md = render_report_md(report)
    assert "PASSWORD FOUND: HomeWiFi2024" in md
    assert "CHANGE THE WIFI PASSWORD NOW" in md
    assert "Handshake captured: YES" in md
    assert report["remediation"]


def test_report_not_found_is_honest():
    report = build_report(capture=CAPTURE, crack=CRACK_NOT_FOUND,
                          generated_at="2026-11-17T00:00:00+00:00")
    md = render_report_md(report)
    assert "not found in this wordlist" in md
    assert "not 'uncrackable'" in md
    assert "PASSWORD FOUND" not in md


def test_report_no_handshake_is_inconclusive():
    capture = {**CAPTURE, "handshake_found": False, "handshake_count": 0}
    report = build_report(capture=capture, crack=CRACK_NOT_FOUND,
                          generated_at="2026-11-17T00:00:00+00:00")
    md = render_report_md(report)
    assert "inconclusive" in md


def test_report_always_has_baseline_advice():
    report = build_report(assess=assess_password("whatever!Pass9").to_dict(),
                          generated_at="2026-11-17T00:00:00+00:00")
    joined = " ".join(report["remediation"])
    assert "WPA3" in joined
    assert "WPS" in joined


def test_write_reports(tmp_path):
    report = build_report(capture=CAPTURE, crack=CRACK_FOUND,
                          generated_at="2026-11-17T00:00:00+00:00")
    md_path, json_path = write_reports(report, str(tmp_path))
    with open(json_path) as fh:
        loaded = json.load(fh)
    assert loaded["crack"]["password"] == "HomeWiFi2024"
    assert "WiFiGuard" in open(md_path).read()
