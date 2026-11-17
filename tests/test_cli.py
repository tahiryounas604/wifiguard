import json

import wifiguard.cli as cli
from wifiguard.capture import CaptureResult
from wifiguard.crack import CrackResult
from wifiguard.envcheck import EnvReport, ToolInfo
from wifiguard.scanparse import parse_airodump_csv
from tests.conftest import AIRODUMP_CSV

CAPTURE_ARGS = ["capture", "--bssid", "8C:42:6D:6A:2F:70",
                "--channel", "6", "--interface", "wlan0mon"]


def test_capture_refused_without_ownership_flag(capsys):
    rc = cli.main(CAPTURE_ARGS)
    assert rc == 2
    err = capsys.readouterr().err
    assert "--i-own-this-network" in err
    assert "refusing" in err


def test_crack_refused_without_ownership_flag(capsys):
    rc = cli.main(["crack", "cap-01.cap", "--wordlist", "rockyou.txt"])
    assert rc == 2
    assert "--i-own-this-network" in capsys.readouterr().err


def test_capture_deauth_over_cap_refused(capsys):
    rc = cli.main(CAPTURE_ARGS + ["--i-own-this-network", "--deauth", "99"])
    assert rc == 2
    assert "safety cap" in capsys.readouterr().err


def test_capture_happy_path(monkeypatch, capsys):
    def fake_capture(**kwargs):
        assert kwargs["deauth"] == 0
        return CaptureResult(
            bssid=kwargs["bssid"], channel=6, interface="wlan0mon",
            cap_file="wifiguard-capture-01.cap", handshake_found=True,
            handshake_count=1, deauth_sent=0, duration_seconds=120)

    monkeypatch.setattr(cli, "run_capture", fake_capture)
    rc = cli.main(CAPTURE_ARGS + ["--i-own-this-network"])
    assert rc == 0
    assert "Handshake CAPTURED" in capsys.readouterr().out


def test_crack_happy_path(monkeypatch, capsys):
    def fake_crack(cap, wordlist, **kwargs):
        return CrackResult(cap_file=cap, wordlist=wordlist, found=True,
                           password="HomeWiFi2024", method="aircrack-ng",
                           elapsed_seconds=7.5, keys_per_sec=16384.0)

    monkeypatch.setattr(cli, "run_crack", fake_crack)
    rc = cli.main(["crack", "cap-01.cap", "--wordlist", "rockyou.txt",
                   "--i-own-this-network"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PASSWORD FOUND: HomeWiFi2024" in out
    assert "CRITICAL" in out


def test_assess_command(capsys):
    rc = cli.main(["assess", "--password", "password123"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Critical" in captured.out
    assert "only audit networks you own" in captured.err  # legal reminder


def test_assess_json_out(tmp_path, capsys):
    out = tmp_path / "assess.json"
    rc = cli.main(["assess", "--password", "Giraffe!Lantern#42River",
                   "--json-out", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["verdict"] == "Strong"


def test_check_command_ok_and_missing(monkeypatch, capsys):
    ok_report = EnvReport(os_name="linux", is_linux=True, is_root=True,
                          tools=[], interfaces=[], monitor_capable=True)
    monkeypatch.setattr(cli, "check_environment", lambda: ok_report)
    assert cli.main(["check"]) == 0

    missing_report = EnvReport(
        os_name="linux", is_linux=True, is_root=False,
        tools=[ToolInfo("aircrack-ng", None, True, "aircrack-ng")],
        interfaces=[], monitor_capable=None)
    monkeypatch.setattr(cli, "check_environment", lambda: missing_report)
    assert cli.main(["check"]) == 1
    capsys.readouterr()


def test_scan_command(monkeypatch, capsys):
    monkeypatch.setattr(
        cli, "run_scan",
        lambda interface, duration=20: parse_airodump_csv(AIRODUMP_CSV))
    rc = cli.main(["scan", "--interface", "wlan0mon"])
    assert rc == 0
    assert "HomeWiFi" in capsys.readouterr().out


def test_report_command(tmp_path, capsys):
    crack = {"cap_file": "c.cap", "wordlist": "rockyou.txt", "found": True,
             "password": "HomeWiFi2024", "method": "aircrack-ng",
             "elapsed_seconds": 7.5, "keys_per_sec": 16384.0}
    crack_path = tmp_path / "crack.json"
    crack_path.write_text(json.dumps(crack))
    rc = cli.main(["report", "--crack-json", str(crack_path),
                   "--out-dir", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.json").exists()
    assert "PASSWORD FOUND" in (tmp_path / "report.md").read_text()


def test_report_requires_at_least_one_input(capsys):
    rc = cli.main(["report"])
    assert rc == 2
    assert "at least one" in capsys.readouterr().err
