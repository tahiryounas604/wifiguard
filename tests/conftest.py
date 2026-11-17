import subprocess

import pytest

# A realistic airodump-ng CSV: a normal AP, a hidden-ESSID AP, an AP
# whose ESSID contains a comma, a station section with an associated
# and an unassociated station.
AIRODUMP_CSV = """\
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
8C:42:6D:6A:2F:70, 2026-11-17 10:00:01, 2026-11-17 10:00:21, 6, 130, WPA2, CCMP, PSK, -38, 120, 45, 0.0.0.0, 8, HomeWiFi, \r
00:11:22:33:44:55, 2026-11-17 10:00:02, 2026-11-17 10:00:21, 11, 54, WPA2, CCMP, PSK, -70, 98, 0, 0.0.0.0, 10, , \r
AA:BB:CC:DD:EE:FF, 2026-11-17 10:00:03, 2026-11-17 10:00:21, 1, 270, WPA3, SAE, SAE, -55, 87, 12, 0.0.0.0, 13, Cafe, Free WiFi, \r

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2026-11-17 10:00:05, 2026-11-17 10:00:20, -40, 25, 8C:42:6D:6A:2F:70, HomeWiFi
77:88:99:AA:BB:CC, 2026-11-17 10:00:06, 2026-11-17 10:00:20, -60, 3, (not associated), CoffeeShop_Guest, OfficeNet
"""

AIRCRACK_ONE_HANDSHAKE = """\
Opening wifiguard-capture-01.cap
Read 15234 packets.

   #  BSSID              ESSID                     Encryption

   1  8C:42:6D:6A:2F:70  HomeWiFi                  WPA (1 handshake)
   2  00:11:22:33:44:55  OtherNet                  WPA (0 handshake)

Choosing first network as target.
"""

AIRCRACK_NO_HANDSHAKE = """\
Opening wifiguard-capture-01.cap
Read 812 packets.

   #  BSSID              ESSID                     Encryption

   1  8C:42:6D:6A:2F:70  HomeWiFi                  WPA (0 handshake)
"""

AIRCRACK_KEY_FOUND = """\
                               Aircrack-ng 1.7

      [00:00:07] 114688/999999 keys tested (16384.00 k/s)

      Time left: --

                           KEY FOUND! [ HomeWiFi2024 ]

      Master Key     : 5A 3C 91 0B 77 E2 10 4D 8F A6 C3 29 51 D8 0E B4
"""

AIRCRACK_KEY_NOT_FOUND = """\
                               Aircrack-ng 1.7

      [00:00:12] 98304/98304 keys tested (8192.50 k/s)

                           KEY NOT FOUND
"""

HASHCAT_SHOW = (
    "WPA*01*4d4fe7aac3a2e83f66d713cdf271c0af*8c426d6a2f70*"
    "aabbccddeeff*486f6d6557694669***:HomeWiFi2024\n"
)

IW_DEV = """\
phy#0
\tInterface wlan0
\t\tifindex 3
\t\twdev 0x1
\t\taddr 8c:42:6d:6a:2f:71
\t\ttype managed
\t\twiphy 0
"""

IW_LIST_MONITOR = """\
Wiphy phy0
\tSupported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * AP
\t\t * monitor
\t\t * P2P-client
"""

IW_LIST_NO_MONITOR = """\
Wiphy phy0
\tSupported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * AP
"""


@pytest.fixture()
def airodump_csv() -> str:
    return AIRODUMP_CSV


@pytest.fixture()
def completed():
    """Factory for fake subprocess.CompletedProcess results."""
    def _make(stdout: str = "", returncode: int = 0):
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr="")
    return _make
