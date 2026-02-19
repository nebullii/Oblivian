from oblivian.redaction import redact


def test_no_patterns_passthrough():
    assert redact("hello sk-ABC123", []) == "hello sk-ABC123"


def test_redacts_openai_key():
    result = redact("token=sk-ABCDEF1234567890", [r"sk-[A-Za-z0-9]{10,}"])
    assert "[REDACTED]" in result
    assert "sk-ABCDEF" not in result


def test_multiple_patterns():
    result = redact("key=AKIAIOSFODNN7EXAMPLE pw=sk-abc1234567890", [
        r"AKIA[A-Z0-9]{16}",
        r"sk-[A-Za-z0-9]{10,}",
    ])
    assert result.count("[REDACTED]") == 2


def test_no_match_unchanged():
    assert redact("nothing sensitive here", [r"sk-[A-Za-z0-9]{10,}"]) == "nothing sensitive here"


def test_case_insensitive():
    result = redact("Bearer SK-ABCDEF1234567890", [r"sk-[A-Za-z0-9]{10,}"])
    assert "[REDACTED]" in result
