from wifiguard.scanparse import format_scan_table, parse_airodump_csv


def test_parses_all_aps(airodump_csv):
    result = parse_airodump_csv(airodump_csv)
    assert len(result.aps) == 3
    assert [ap.bssid for ap in result.aps] == [
        "8C:42:6D:6A:2F:70", "00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF",
    ]


def test_ap_fields(airodump_csv):
    ap = parse_airodump_csv(airodump_csv).aps[0]
    assert ap.essid == "HomeWiFi"
    assert ap.hidden is False
    assert ap.channel == 6
    assert ap.privacy == "WPA2"
    assert ap.cipher == "CCMP"
    assert ap.authentication == "PSK"
    assert ap.power == -38
    assert ap.beacons == 120
    assert ap.ivs == 45


def test_hidden_essid(airodump_csv):
    ap = parse_airodump_csv(airodump_csv).aps[1]
    assert ap.essid == ""
    assert ap.hidden is True


def test_essid_with_comma(airodump_csv):
    ap = parse_airodump_csv(airodump_csv).aps[2]
    assert ap.essid == "Cafe, Free WiFi"
    assert ap.privacy == "WPA3"


def test_stations_parsed_and_attached(airodump_csv):
    result = parse_airodump_csv(airodump_csv)
    assert len(result.stations) == 2
    home = result.aps[0]
    assert len(home.clients) == 1
    assert home.clients[0].mac == "11:22:33:44:55:66"
    assert home.clients[0].packets == 25


def test_unassociated_station(airodump_csv):
    result = parse_airodump_csv(airodump_csv)
    station = result.stations[1]
    assert station.bssid == "(not associated)"
    assert station.probed_essids == ["CoffeeShop_Guest", "OfficeNet"]
    # not attached to any AP
    assert all(len(ap.clients) == 0 for ap in result.aps[1:])


def test_empty_and_garbage_input():
    assert parse_airodump_csv("").aps == []
    result = parse_airodump_csv("not,a,real\nfile,at,all\n")
    assert result.aps == []
    assert result.stations == []


def test_table_format(airodump_csv):
    table = format_scan_table(parse_airodump_csv(airodump_csv))
    assert "HomeWiFi" in table
    assert "<hidden>" in table
    assert "8C:42:6D:6A:2F:70" in table
    assert "3 access point(s), 2 station(s)" in table
