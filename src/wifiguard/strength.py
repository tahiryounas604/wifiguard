"""Password strength assessment — pure logic, no external tools.

The assessor scores a WiFi password the way an offline attacker
would see it: raw search space (length × character classes), minus
penalties for the patterns real cracking rigs try first — dictionary
words (including leetspeak spellings), wordlist membership, keyboard
walks, repeated characters, and year suffixes.

Crack-time estimates assume a stated rate (see
:data:`WPA_GUESSES_PER_SECOND`) and are labelled estimates everywhere
they are shown: real rigs vary by orders of magnitude.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

# Stated assumption: a high-end GPU rig cracks WPA2 (PBKDF2-HMAC-SHA1,
# 4096 iterations) at roughly 2 million guesses per second. Labelled
# an estimate in all output.
WPA_GUESSES_PER_SECOND = 2_000_000

_LEET = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s",
})

# Base words that make a password weak no matter what is glued around
# them. Checked after leetspeak normalisation and after stripping
# leading/trailing digits and symbols ("p4kistan123" -> "pakistan").
COMMON_WORDS = {
    "password", "passwd", "letmein", "welcome", "admin", "administrator",
    "qwerty", "iloveyou", "sunshine", "dragon", "monkey", "master",
    "secret", "login", "wifi", "wireless", "internet", "router",
    "home", "house", "family", "computer", "laptop", "samsung",
    "iphone", "android", "hello", "pakistan", "india", "cricket",
    "football", "princess", "superman", "batman", "pokemon", "naruto",
    "changeme", "default", "guest", "user", "test", "love", "god",
    "sex", "starwars", "matrix", "windows", "google", "facebook",
}

KEYBOARD_WALKS = (
    "qwertyuiop", "poiuytrewq", "asdfghjkl", "lkjhgfdsa",
    "zxcvbnm", "mnbvcxz", "1234567890", "0987654321",
    "qazwsx", "1qaz2wsx", "qwerty", "asdfgh", "zxcvbn",
)

_YEAR_RE = re.compile(r"(19|20)\d{2}\D{0,3}$")
_REPEAT_RE = re.compile(r"(.)\1\1")
_PHONE_RE = re.compile(r"^\+?\d[\d\s-]{5,}\d$")


@dataclass
class Assessment:
    length: int
    charset_size: int
    classes_present: list[str]
    entropy_bits: float
    in_wordlist: bool
    common_pattern: bool
    score: int  # 0..100
    verdict: str  # Critical / Weak / Fair / Strong
    estimated_crack_seconds: float
    estimated_crack_time: str
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "length": self.length,
            "charset_size": self.charset_size,
            "classes_present": list(self.classes_present),
            "entropy_bits": round(self.entropy_bits, 1),
            "in_wordlist": self.in_wordlist,
            "common_pattern": self.common_pattern,
            "score": self.score,
            "verdict": self.verdict,
            "estimated_crack_seconds": self.estimated_crack_seconds,
            "estimated_crack_time": self.estimated_crack_time,
            "rate_assumption_guesses_per_second": WPA_GUESSES_PER_SECOND,
            "issues": list(self.issues),
            "suggestions": list(self.suggestions),
        }


def load_wordlist(path: str) -> set[str]:
    """Load a wordlist file into a set (exact + lower-cased entries)."""
    words: set[str] = set()
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            word = line.rstrip("\n").rstrip("\r")
            if word:
                words.add(word)
                words.add(word.lower())
    return words


def format_duration(seconds: float) -> str:
    """Human-readable duration for a crack-time estimate."""
    if seconds < 1:
        return "less than a second"
    if seconds < 2:
        return "about a second"
    if seconds < 60:
        return f"about {seconds:.0f} seconds"
    if seconds < 3600:
        return f"about {seconds / 60:.0f} minutes"
    if seconds < 86400:
        return f"about {seconds / 3600:.0f} hours"
    if seconds < 31_557_600:
        return f"about {seconds / 86400:.0f} days"
    years = seconds / 31_557_600
    if years > 1e15:
        return f"about {years:.1e} years"
    return f"about {years:,.0f} years"


def _classes(password: str) -> tuple[list[str], int]:
    classes: list[str] = []
    size = 0
    if any(c.islower() for c in password):
        classes.append("lowercase")
        size += 26
    if any(c.isupper() for c in password):
        classes.append("uppercase")
        size += 26
    if any(c.isdigit() for c in password):
        classes.append("digits")
        size += 10
    if any(c == " " for c in password):
        classes.append("space")
        size += 1
    if any(not c.isalnum() and c != " " for c in password):
        classes.append("symbols")
        size += 33
    return classes, size


def _common_base(password: str) -> str | None:
    """Return the common dictionary word this password is built on.

    Two normalisations are tried, because leetspeak digits sit both
    inside words ("p4kistan") and glued onto the ends ("password123",
    where translating first would turn the tail into letters):
    strip-then-translate and translate-then-strip.
    """
    lowered = password.lower()
    candidates = {
        re.sub(r"^[^a-z]+|[^a-z]+$", "", lowered).translate(_LEET),
        re.sub(r"^[^a-z]+|[^a-z]+$", "", lowered.translate(_LEET)),
    }
    for base in candidates:
        if base in COMMON_WORDS:
            return base
    return None


def _has_keyboard_walk(password: str) -> bool:
    lowered = password.lower()
    return any(
        walk[i:i + 4] in lowered
        for walk in KEYBOARD_WALKS
        for i in range(len(walk) - 3)
    )


def assess_password(password: str, wordlist=None) -> Assessment:
    """Score ``password`` and return a full :class:`Assessment`.

    ``wordlist`` is an optional set of known passwords (see
    :func:`load_wordlist`); membership is an automatic Critical.
    """
    issues: list[str] = []
    suggestions: list[str] = []
    classes, charset_size = _classes(password)
    length = len(password)
    entropy = length * math.log2(charset_size) if charset_size else 0.0

    in_wordlist = bool(wordlist) and (
        password in wordlist or password.lower() in wordlist
    )
    base = _common_base(password)
    common = base is not None
    digits_only = length > 0 and password.isdigit()
    phone_like = digits_only or bool(_PHONE_RE.match(password))
    walk = _has_keyboard_walk(password)
    repeat = bool(_REPEAT_RE.search(password))
    year = bool(_YEAR_RE.search(password))

    if in_wordlist:
        issues.append("This password appears in a known wordlist — "
                      "it is among the first guesses any cracker tries.")
    if common:
        issues.append(f"Built on the common word '{base}' — dictionary "
                      "attacks try such words with digits/symbols added.")
    if digits_only:
        issues.append("Digits only — the search space is tiny and "
                      "number-only lists are tried early.")
    if phone_like and not digits_only:
        issues.append("Looks like a phone number — phone numbers are "
                      "public knowledge and are tried as passwords.")
    if phone_like and digits_only and length <= 13:
        issues.append("Length and shape match a mobile phone number, "
                      "a very common WiFi password choice.")
    if walk:
        issues.append("Contains a keyboard walk (e.g. qwerty / 12345) — "
                      "a standard pattern in rule-based attacks.")
    if repeat:
        issues.append("Contains repeated characters, which rule-based "
                      "attacks model cheaply.")
    if year:
        issues.append("Ends with a year — years are appended by "
                      "cracking rules automatically.")
    if length < 8:
        issues.append("Shorter than the WPA minimum of 8 characters "
                      "is impossible, but anything under 12 falls "
                      "quickly to offline attack.")
    elif length < 16:
        issues.append("Under 16 characters — length is the cheapest "
                      "strength there is.")
    if len(classes) < 3:
        issues.append("Uses fewer than 3 character classes.")

    # --- scoring -------------------------------------------------
    if in_wordlist or common:
        score = 5
        verdict = "Critical"
        estimated_seconds = 1.0  # dictionary attacks hit this at once
    else:
        score = int(round(min(100.0, entropy * 1.4)))
        if digits_only:
            score -= 20
        if phone_like:
            score -= 25
        if walk:
            score -= 30
        if repeat:
            score -= 10
        if year:
            score -= 10
        if len(classes) < 2:
            score -= 10
        score = max(0, min(100, score))
        if score < 20:
            verdict = "Critical"
        elif score < 40:
            verdict = "Weak"
        elif score < 65:
            verdict = "Fair"
        else:
            verdict = "Strong"
        if entropy < 28:
            verdict = "Critical"
        search_space = float(charset_size) ** length if charset_size else 0.0
        estimated_seconds = search_space / 2 / WPA_GUESSES_PER_SECOND

    # --- advice --------------------------------------------------
    if verdict in ("Critical", "Weak"):
        suggestions.append(
            "Change this password. Use at least 16 characters — "
            "for example 3 random words plus a number and a symbol "
            "(e.g. 'lantern-river-42-giraffe!')."
        )
    if length < 16:
        suggestions.append("Make it at least 16 characters long; "
                           "length beats clever substitutions.")
    if common or in_wordlist:
        suggestions.append("Never build a WiFi password on a single "
                           "dictionary word, a name, or a phone number.")
    if len(classes) < 3:
        suggestions.append("Mix lowercase, uppercase, digits and "
                           "symbols — or use a multi-word passphrase.")
    if not suggestions:
        suggestions.append("Good password. Keep it unique to this "
                           "network and change it if it is ever shared "
                           "beyond your household.")

    return Assessment(
        length=length,
        charset_size=charset_size,
        classes_present=classes,
        entropy_bits=entropy,
        in_wordlist=in_wordlist,
        common_pattern=common,
        score=score,
        verdict=verdict,
        estimated_crack_seconds=estimated_seconds,
        estimated_crack_time=format_duration(estimated_seconds),
        issues=issues,
        suggestions=suggestions,
    )
