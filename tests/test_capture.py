import pytest

from wifiguard.capture import (
    check_handshake,
    parse_handshake_count,
    parse_handshakes,
    run_capture,
)
from wifiguard.safety import MAX_DEAUTH, validate_deauth
from tests.conftest import AIRCRACK_NO_HANDSHAKE, AIRCRACK_ONE_HANDSHAKE


def test_parse_handshakes_map():
    counts = parse_handshakes(AIRCRACK_ONE_HANDSHAKE)
    assert counts == {"8C:42:6D:6A:2F:70": 1, "00:11:22:33:44:55": 0}


def test_parse_handshake_count_for_bssid():
    assert parse_handshake_count(
        AIRCRACK_ONE_HANDSHAKE, "8c:42:6d:6a:2f:70") == 1
    assert parse_handshake_count(
        AIRCRACK_ONE_HANDSHAKE, "00:11:22:33:44:55") == 0
    assert parse_handshake_count(AIRCRACK_ONE_HANDSHAKE, "FF:FF:FF:FF:FF:FF") == 0


def test_parse_handshake_count_max_and_none():
    assert parse_handshake_count(AIRCRACK_ONE_HANDSHAKE) == 1
    assert parse_handshake_count(AIRCRACK_NO_HANDSHAKE) == 0
    assert parse_handshake_count("no useful output") == 0


def test_check_handshake_uses_aircrack(completed):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return completed(AIRCRACK_ONE_HANDSHAKE)

    assert check_handshake("cap-01.cap", "8C:42:6D:6A:2F:70",
                           run=fake_run) == 1
    assert calls[0][0] == "aircrack-ng"


def test_check_handshake_missing_tool():
    def missing(cmd, **kwargs):
        raise FileNotFoundError("no such file")

    with pytest.raises(RuntimeError, match="apt install aircrack-ng"):
        check_handshake("cap-01.cap", run=missing)


def test_validate_deauth_cap():
    assert validate_deauth(0) == 0
    assert validate_deauth(MAX_DEAUTH) == MAX_DEAUTH
    with pytest.raises(ValueError, match="safety cap"):
        validate_deauth(MAX_DEAUTH + 1)
    with pytest.raises(ValueError):
        validate_deauth(-1)


class _FakeProc:
    def __init__(self):
        self.terminated = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):  # pragma: no cover
        pass


def test_run_capture_finds_handshake(tmp_path, completed):
    prefix = str(tmp_path / "cap")
    cap_file = f"{prefix}-01.cap"
    run_cmds = []

    def fake_popen(cmd, **kwargs):
        # airodump-ng "writes" its capture file
        with open(cap_file, "wb") as fh:
            fh.write(b"fake")
        return _FakeProc()

    def fake_run(cmd, **kwargs):
        run_cmds.append(cmd)
        return completed(AIRCRACK_ONE_HANDSHAKE)

    result = run_capture(
        bssid="8C:42:6D:6A:2F:70", channel=6, interface="wlan0mon",
        output_prefix=prefix, duration=10,
        popen=fake_popen, run=fake_run, sleep=lambda s: None,
    )
    assert result.handshake_found is True
    assert result.handshake_count == 1
    assert result.cap_file == cap_file
    assert result.deauth_sent == 0
    assert run_cmds[0][0] == "aircrack-ng"


def test_run_capture_deauth_targets_only_named_bssid(tmp_path, completed):
    prefix = str(tmp_path / "cap")
    cap_file = f"{prefix}-01.cap"
    run_cmds = []

    def fake_popen(cmd, **kwargs):
        with open(cap_file, "wb") as fh:
            fh.write(b"fake")
        return _FakeProc()

    def fake_run(cmd, **kwargs):
        run_cmds.append(cmd)
        return completed(AIRCRACK_NO_HANDSHAKE)

    result = run_capture(
        bssid="8C:42:6D:6A:2F:70", channel=6, interface="wlan0mon",
        output_prefix=prefix, duration=10, deauth=10,
        client="11:22:33:44:55:66",
        popen=fake_popen, run=fake_run, sleep=lambda s: None,
    )
    deauth_cmd = run_cmds[0]
    assert deauth_cmd[0] == "aireplay-ng"
    assert deauth_cmd[deauth_cmd.index("--deauth") + 1] == "10"
    assert deauth_cmd[deauth_cmd.index("-a") + 1] == "8C:42:6D:6A:2F:70"
    assert deauth_cmd[deauth_cmd.index("-c") + 1] == "11:22:33:44:55:66"
    assert result.deauth_sent == 10
    assert result.handshake_found is False


def test_run_capture_rejects_overcap_deauth(tmp_path):
    with pytest.raises(ValueError, match="safety cap"):
        run_capture(
            bssid="8C:42:6D:6A:2F:70", channel=6, interface="wlan0mon",
            output_prefix=str(tmp_path / "cap"), duration=10,
            deauth=MAX_DEAUTH + 1, sleep=lambda s: None,
        )


def test_run_capture_rejects_unbounded_duration(tmp_path):
    with pytest.raises(ValueError, match="exceeds the cap"):
        run_capture(
            bssid="8C:42:6D:6A:2F:70", channel=6, interface="wlan0mon",
            output_prefix=str(tmp_path / "cap"), duration=99999,
            sleep=lambda s: None,
        )
