from wifiguard.crack import (
    parse_aircrack_result,
    parse_hashcat_show,
    parse_hashcat_status,
    run_crack,
)
from tests.conftest import (
    AIRCRACK_KEY_FOUND,
    AIRCRACK_KEY_NOT_FOUND,
    HASHCAT_SHOW,
)


def test_parse_key_found():
    outcome = parse_aircrack_result(AIRCRACK_KEY_FOUND)
    assert outcome.found is True
    assert outcome.password == "HomeWiFi2024"
    assert outcome.keys_per_sec == 16384.00
    assert outcome.keys_tested == 114688


def test_parse_key_found_with_ansi_redraws():
    # Real aircrack-ng TTY output (regression: live run 2026-11-17):
    # ANSI cursor moves + screen redraws repeat fragments of the
    # KEY FOUND line; the extracted password must stay clean.
    raw = (
        "[00:00:00] 5/10 keys tested (200.00 k/s)\r\n"
        "\x1b[8;28H\x1b[2KKEY FOUND! [ biscotte ]\n"
        "\x1b[11B\x1b[8;28H\x1b[2KKEY FOUND! [ biscotte ]\n"
        "Master Key     : 00 11 22 33\n"
    )
    outcome = parse_aircrack_result(raw)
    assert outcome.found is True
    assert outcome.password == "biscotte"
    assert outcome.keys_tested == 5


def test_parse_key_not_found():
    outcome = parse_aircrack_result(AIRCRACK_KEY_NOT_FOUND)
    assert outcome.found is False
    assert outcome.password is None
    assert outcome.keys_tested == 98304


def test_parse_empty_output():
    outcome = parse_aircrack_result("")
    assert outcome.found is False
    assert outcome.keys_per_sec is None


def test_parse_hashcat_show():
    assert parse_hashcat_show(HASHCAT_SHOW) == "HomeWiFi2024"
    assert parse_hashcat_show("") is None
    assert parse_hashcat_show("Session..........: hashcat\n") is None


def test_parse_hashcat_status():
    assert parse_hashcat_status("Status...........: Cracked\n") is True
    assert parse_hashcat_status("Recovered........: 1/1 (100.00%)\n") is True
    assert parse_hashcat_status("Status...........: Exhausted\n") is False


def test_run_crack_aircrack_route(completed):
    def fake_run(cmd, **kwargs):
        assert cmd[0] == "aircrack-ng"
        assert "rockyou.txt" in cmd
        return completed(AIRCRACK_KEY_FOUND)

    times = iter([100.0, 107.5])
    result = run_crack("cap-01.cap", "rockyou.txt", run=fake_run,
                       which=lambda name: None,
                       clock=lambda: next(times))
    assert result.found is True
    assert result.password == "HomeWiFi2024"
    assert result.method == "aircrack-ng"
    assert result.elapsed_seconds == 7.5


def test_run_crack_not_found(completed):
    result = run_crack("cap-01.cap", "small.txt",
                       run=lambda cmd, **kw: completed(AIRCRACK_KEY_NOT_FOUND),
                       which=lambda name: None, clock=lambda: 0.0)
    assert result.found is False
    assert result.password is None


def test_run_crack_hashcat_route(tmp_path, completed):
    cap = tmp_path / "cap-01.cap"
    cap.write_bytes(b"fake")
    hash_file = str(cap) + ".22000"
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd[0])
        if cmd[0] == "hcxpcapngtool":
            with open(hash_file, "w") as fh:
                fh.write("WPA*01*deadbeef\n")
            return completed("", returncode=0)
        if cmd[0] == "hashcat" and "--show" in cmd:
            return completed(HASHCAT_SHOW)
        return completed("")

    result = run_crack(str(cap), "rockyou.txt", run=fake_run,
                       which=lambda name: "/usr/bin/" + name,
                       clock=lambda: 0.0)
    assert result.found is True
    assert result.password == "HomeWiFi2024"
    assert result.method == "hashcat (mode 22000)"
    assert calls[0] == "hcxpcapngtool"


def test_run_crack_hashcat_conversion_failure_falls_back(tmp_path, completed):
    def fake_run(cmd, **kwargs):
        if cmd[0] == "hcxpcapngtool":
            return completed("", returncode=1)
        return completed(AIRCRACK_KEY_NOT_FOUND)

    result = run_crack("cap-01.cap", "rockyou.txt", run=fake_run,
                       which=lambda name: "/usr/bin/" + name,
                       clock=lambda: 0.0)
    assert result.method == "aircrack-ng"
    assert result.found is False
