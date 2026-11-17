import pytest

from wifiguard.scanner import run_scan
from tests.conftest import AIRODUMP_CSV


class _FakeProc:
    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0

    def kill(self):  # pragma: no cover
        pass


def test_run_scan_parses_output(tmp_path):
    def fake_popen(cmd, **kwargs):
        base = cmd[cmd.index("-w") + 1]
        with open(f"{base}-01.csv", "w") as fh:
            fh.write(AIRODUMP_CSV)
        return _FakeProc()

    result = run_scan("wlan0mon", duration=5, workdir=str(tmp_path),
                      popen=fake_popen, sleep=lambda s: None)
    assert len(result.aps) == 3
    assert result.aps[0].essid == "HomeWiFi"


def test_run_scan_missing_tool(tmp_path):
    def missing(cmd, **kwargs):
        raise FileNotFoundError("nope")

    with pytest.raises(RuntimeError, match="apt install aircrack-ng"):
        run_scan("wlan0mon", duration=5, workdir=str(tmp_path),
                 popen=missing, sleep=lambda s: None)


def test_run_scan_rejects_unbounded_duration(tmp_path):
    with pytest.raises(ValueError, match="exceeds the cap"):
        run_scan("wlan0mon", duration=99999, workdir=str(tmp_path),
                 sleep=lambda s: None)
