"""Safety gates and legal reminders — enforced in code, not just docs.

wifiguard audits the security of a WiFi network by capturing its
WPA/WPA2 handshake and trying to crack it. Those are dual-use
operations, so the tool hard-codes the guard rails here:

- ``capture`` and ``crack`` refuse to run unless the user passes the
  explicit ``--i-own-this-network`` ownership flag.
- Deauthentication (an active, disruptive technique) is opt-in,
  capped at :data:`MAX_DEAUTH` frames, and can only target the access
  point the user named — plus optionally one client MAC the user
  supplies for their own device.
- Captures are always time-bounded (:data:`MAX_CAPTURE_SECONDS`,
  :data:`MAX_SCAN_SECONDS`); nothing runs indefinitely.
- There is deliberately no WPS, evil-twin, or PMKID functionality.
"""
from __future__ import annotations

LEGAL_REMINDER = (
    "Legal reminder: only audit networks you own or are explicitly "
    "authorized to test."
)

OWNERSHIP_FLAG = "--i-own-this-network"

MAX_DEAUTH = 50
MAX_CAPTURE_SECONDS = 3600
MAX_SCAN_SECONDS = 600


def ownership_refusal(action: str) -> str:
    """Message shown when capture/crack is attempted without the flag."""
    return (
        f"error: refusing to {action} without {OWNERSHIP_FLAG}. "
        "wifiguard only audits networks you own or are authorized to "
        "test; re-run with the flag to confirm this is your network."
    )


def validate_deauth(count: int) -> int:
    """Return ``count`` if it is a permitted deauth burst size.

    Raises:
        ValueError: if the count is negative or above the hard cap.
    """
    if count < 0:
        raise ValueError("deauth count cannot be negative")
    if count > MAX_DEAUTH:
        raise ValueError(
            f"deauth count {count} exceeds the safety cap of "
            f"{MAX_DEAUTH}. wifiguard will not send larger bursts."
        )
    return count


def validate_duration(seconds: int, maximum: int, what: str) -> int:
    """Bound a run duration so no operation runs indefinitely."""
    if seconds <= 0:
        raise ValueError(f"{what} duration must be positive")
    if seconds > maximum:
        raise ValueError(
            f"{what} duration {seconds}s exceeds the cap of {maximum}s"
        )
    return seconds
