from wifiguard.envcheck import (
    check_environment,
    format_env_report,
    parse_ip_link_names,
    parse_iw_dev,
    parse_iw_list_monitor,
)
from tests.conftest import IW_DEV, IW_LIST_MONITOR, IW_LIST_NO_MONITOR


def test_parse_iw_dev():
    interfaces = parse_iw_dev(IW_DEV)
    assert len(interfaces) == 1
    assert interfaces[0].name == "wlan0"
    assert interfaces[0].wireless is True
    assert interfaces[0].mode == "managed"


def test_parse_ip_link_names():
    text = ("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
            "2: eth0: <BROADCAST> mtu 1500\n"
            "3: wlan0: <BROADCAST> mtu 1500\n")
    assert parse_ip_link_names(text) == ["lo", "eth0", "wlan0"]


def test_parse_iw_list_monitor():
    assert parse_iw_list_monitor(IW_LIST_MONITOR) is True
    assert parse_iw_list_monitor(IW_LIST_NO_MONITOR) is False
    assert parse_iw_list_monitor("no sections here") is None


def _fake_which(present):
    return lambda name: f"/usr/bin/{name}" if name in present else None


def test_check_environment_all_present(completed):
    present = {"airmon-ng", "airodump-ng", "aircrack-ng", "aireplay-ng",
               "iw", "ip"}

    def fake_run(argv, **kwargs):
        if argv[:2] == ["iw", "dev"]:
            return completed(IW_DEV)
        if argv[:2] == ["iw", "list"]:
            return completed(IW_LIST_MONITOR)
        return completed("")

    report = check_environment(which=_fake_which(present), run=fake_run)
    assert report.missing_required == []
    assert report.monitor_capable is True
    assert [i.name for i in report.interfaces] == ["wlan0"]


def test_check_environment_missing_tools(completed):
    report = check_environment(which=_fake_which(set()),
                               run=lambda argv, **kw: completed(""))
    missing = {t.name for t in report.missing_required}
    assert {"airmon-ng", "airodump-ng", "aircrack-ng"} <= missing
    # optional tools are not "required missing"
    assert "hashcat" not in missing
    text = format_env_report(report)
    assert "sudo apt install aircrack-ng" in text
    assert "MISSING (required)" in text


def test_check_environment_monitor_unknown(completed):
    present = {"airmon-ng", "airodump-ng", "aircrack-ng", "aireplay-ng"}

    def fake_run(argv, **kwargs):
        return completed("")

    report = check_environment(which=_fake_which(present), run=fake_run)
    assert report.monitor_capable is None
    assert "unknown" in format_env_report(report)
