from wifiguard.strength import (
    assess_password,
    format_duration,
    load_wordlist,
)


def test_common_passwords_are_critical():
    for pw in ("password123", "pakistan123", "Password1", "qwerty123"):
        result = assess_password(pw)
        assert result.verdict == "Critical", pw
        assert result.common_pattern is True, pw


def test_leetspeak_common_word_is_critical():
    result = assess_password("p4k157an99")
    assert result.verdict == "Critical"
    assert result.common_pattern is True


def test_phone_number_is_critical():
    result = assess_password("03001234567")
    assert result.verdict == "Critical"
    assert any("phone" in issue.lower() or "Digits only" in issue
               for issue in result.issues)


def test_wordlist_membership_is_critical(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("letmein1\nXk9-unusual-phrase\npassword\n")
    words = load_wordlist(str(wl))
    result = assess_password("Xk9-unusual-phrase", words)
    assert result.in_wordlist is True
    assert result.verdict == "Critical"
    assert result.estimated_crack_seconds <= 1.0


def test_strong_passphrases():
    for pw in ("Giraffe!Lantern#42River", "correct horse battery staple",
               "Tr7$kQ9!mZ2#xW8p-Long"):
        result = assess_password(pw)
        assert result.verdict == "Strong", pw
        assert result.score >= 65, pw


def test_short_password_weak_or_worse():
    result = assess_password("abc12345")
    assert result.verdict in ("Critical", "Weak")


def test_keyboard_walk_penalty():
    result = assess_password("Xqwerty99!zz")
    assert any("keyboard walk" in issue for issue in result.issues)


def test_year_suffix_flagged():
    result = assess_password("BlueSkyTree2024")
    assert any("year" in issue for issue in result.issues)


def test_classes_and_charset():
    result = assess_password("Abc123!xyz")
    assert set(result.classes_present) == {
        "lowercase", "uppercase", "digits", "symbols"}
    assert result.charset_size == 95
    assert result.length == 10


def test_crack_time_estimate_uses_stated_rate():
    # 10 digits: space 10^10, half on average, at 2,000,000 guesses/s
    result = assess_password("5820471936")
    expected = (10 ** 10) / 2 / 2_000_000
    assert result.estimated_crack_seconds == expected


def test_suggestions_for_weak_password():
    result = assess_password("password123")
    joined = " ".join(result.suggestions)
    assert "16" in joined


def test_format_duration():
    assert format_duration(0.5) == "less than a second"
    assert "seconds" in format_duration(30)
    assert "minutes" in format_duration(600)
    assert "hours" in format_duration(7200)
    assert "days" in format_duration(172800)
    assert "years" in format_duration(31_557_600 * 5)


def test_to_dict_is_json_friendly():
    data = assess_password("SomePass!234").to_dict()
    assert data["verdict"] in ("Critical", "Weak", "Fair", "Strong")
    assert data["rate_assumption_guesses_per_second"] == 2_000_000
