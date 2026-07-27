"""Output sanitising.

Everything here operates on text produced by a program that talked to a device
on the network. Both are outside our control, so the failure cases matter: a
missed secret is written to the audit log permanently, and a missed control
sequence reaches a terminal or a browser.
"""

from __future__ import annotations

import pytest

from app.core.redaction import (
    MASK,
    mask_secrets,
    redact_values,
    sanitize,
    strip_control_characters,
    truncate,
)


class TestControlCharacters:
    def test_ansi_colour_codes_are_removed(self) -> None:
        assert strip_control_characters("\x1b[31mred\x1b[0m") == "red"

    def test_cursor_and_screen_sequences_are_removed(self) -> None:
        assert strip_control_characters("a\x1b[2J\x1b[Hb") == "ab"

    def test_osc_sequences_are_removed(self) -> None:
        """These can retitle a terminal window, so they are not cosmetic."""
        assert strip_control_characters("\x1b]0;new title\x07text") == "text"

    def test_carriage_returns_are_removed(self) -> None:
        """A CR lets later output overwrite earlier output, which can be used to
        hide a line from someone reading the log."""
        assert "\r" not in strip_control_characters("real output\rfake output")

    def test_tabs_and_newlines_are_kept(self) -> None:
        assert strip_control_characters("a\tb\nc") == "a\tb\nc"

    @pytest.mark.parametrize("char", ["\x00", "\x07", "\x08", "\x1f", "\x7f"])
    def test_other_control_characters_are_removed(self, char: str) -> None:
        assert strip_control_characters(f"a{char}b") == "ab"

    def test_ordinary_text_is_untouched(self) -> None:
        text = "PING 10.0.0.1: 56 data bytes\n64 bytes: icmp_seq=0 time=0.5 ms"
        assert strip_control_characters(text) == text


class TestSecretMasking:
    @pytest.mark.parametrize(
        "line",
        [
            "password: hunter2",
            "PASSWORD=hunter2",
            "passwd: hunter2",
            "secret = abc123xyz",
            "api_key: sk-1234567890",
            "API-KEY=sk-1234567890",
            "token: eyJhbGciOiJIUzI1NiJ9",
            "Authorization: Bearer eyJhbGci",
        ],
    )
    def test_credential_shaped_lines_are_masked(self, line: str) -> None:
        masked = mask_secrets(line)
        assert MASK in masked
        for secret in ("hunter2", "abc123xyz", "sk-1234567890", "eyJhbGci"):
            assert secret not in masked

    def test_a_private_key_block_is_removed_entirely(self) -> None:
        text = (
            "before\n-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\nafter"
        )
        masked = mask_secrets(text)
        assert "b3BlbnNzaC1rZXktdjEAAAAA" not in masked
        assert "BEGIN OPENSSH PRIVATE KEY" not in masked
        assert "before" in masked and "after" in masked

    def test_a_public_key_blob_is_masked(self) -> None:
        text = "ssh-ed25519 " + "A" * 60 + " netops@console"
        assert "A" * 60 not in mask_secrets(text)

    def test_ordinary_output_is_not_mangled(self) -> None:
        text = "22/tcp open ssh OpenSSH 9.2p1\n443/tcp open https nginx"
        assert mask_secrets(text) == text


class TestExactRedaction:
    def test_a_known_secret_value_is_removed(self) -> None:
        result = redact_values("connecting with s3cret-value now", ["s3cret-value"])
        assert "s3cret-value" not in result
        assert MASK in result

    def test_every_occurrence_is_removed(self) -> None:
        assert "abcd" not in redact_values("abcd and abcd again", ["abcd"])

    @pytest.mark.parametrize("short", ["a", "ab", "abc", ""])
    def test_very_short_values_are_skipped(self, short: str) -> None:
        """Masking every occurrence of a two-character value would destroy the
        output without protecting anything meaningful."""
        text = "a quick brown fox abc"
        assert redact_values(text, [short]) == text


class TestTruncation:
    def test_short_text_is_untouched(self) -> None:
        text, was_truncated = truncate("short", max_bytes=1000)
        assert text == "short"
        assert was_truncated is False

    def test_long_text_is_cut_and_marked(self) -> None:
        text, was_truncated = truncate("x" * 5000, max_bytes=100)
        assert was_truncated is True
        assert "truncated" in text

    def test_multibyte_text_is_cut_on_a_character_boundary(self) -> None:
        """Slicing bytes blindly produces invalid UTF-8, which then fails to
        store or render."""
        text, was_truncated = truncate("é" * 500, max_bytes=101)
        assert was_truncated is True
        text.encode("utf-8")  # must not raise

    def test_the_limit_is_measured_in_bytes(self) -> None:
        _, was_truncated = truncate("é" * 100, max_bytes=50)
        assert was_truncated is True


class TestPipeline:
    def test_all_three_stages_apply(self) -> None:
        raw = "\x1b[31mERROR\x1b[0m password: hunter2\n" + "x" * 1000
        cleaned, was_truncated = sanitize(raw, max_bytes=200)

        assert "\x1b" not in cleaned
        assert "hunter2" not in cleaned
        assert was_truncated is True

    def test_control_characters_cannot_hide_a_secret_from_the_masker(self) -> None:
        """Stripping runs first for exactly this reason: an escape sequence
        inserted mid-word would otherwise break the pattern match."""
        cleaned, _ = sanitize("pass\x1b[0mword: hunter2")
        assert "hunter2" not in cleaned

    def test_supplied_secret_values_are_removed(self) -> None:
        cleaned, _ = sanitize("token is my-real-token here", secret_values=["my-real-token"])
        assert "my-real-token" not in cleaned

    def test_empty_input_is_handled(self) -> None:
        assert sanitize("") == ("", False)
