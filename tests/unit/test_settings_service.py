from __future__ import annotations

import pytest

from app.core.validation import ValidationError
from app.modules.settings.service import _bounded_int, parse_cidr_list


class TestParseCidrList:
    def test_accepts_newline_and_comma_separated_input(self) -> None:
        assert parse_cidr_list("10.0.0.0/8\n192.168.0.0/16") == ["10.0.0.0/8", "192.168.0.0/16"]
        assert parse_cidr_list("10.0.0.0/8, 192.168.0.0/16") == ["10.0.0.0/8", "192.168.0.0/16"]

    def test_ignores_blank_lines_and_whitespace(self) -> None:
        assert parse_cidr_list("\n  10.0.0.0/8  \n\n") == ["10.0.0.0/8"]

    def test_deduplicates_while_preserving_order(self) -> None:
        assert parse_cidr_list("10.0.0.0/8\n192.168.0.0/16\n10.0.0.0/8") == [
            "10.0.0.0/8",
            "192.168.0.0/16",
        ]

    def test_requires_at_least_one_entry(self) -> None:
        """An empty allowlist would either block everything or, worse, be read
        somewhere as 'no restriction'."""
        with pytest.raises(ValidationError, match="At least one"):
            parse_cidr_list("   \n  ")

    def test_one_bad_entry_rejects_the_whole_save(self) -> None:
        """A partially applied allowlist is worse than a rejected one: the
        operator would believe a range is covered when it is not."""
        with pytest.raises(ValidationError):
            parse_cidr_list("10.0.0.0/8\n8.8.8.0/24\n192.168.0.0/16")

    @pytest.mark.parametrize("bad", ["127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/0", "1.1.1.0/24"])
    def test_rejects_reserved_and_public_ranges(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            parse_cidr_list(bad)


class TestBoundedInt:
    def test_accepts_a_value_in_range(self) -> None:
        assert _bounded_int("512", label="X", minimum=1, maximum=1024) == 512

    @pytest.mark.parametrize("bad", ["0", "1025", "-5"])
    def test_rejects_out_of_range(self, bad: str) -> None:
        with pytest.raises(ValidationError, match="between"):
            _bounded_int(bad, label="X", minimum=1, maximum=1024)

    @pytest.mark.parametrize("bad", ["", "many", "10; rm -rf /", "1e3"])
    def test_rejects_non_numeric(self, bad: str) -> None:
        with pytest.raises(ValidationError, match="whole number"):
            _bounded_int(bad, label="X", minimum=1, maximum=1024)

    def test_the_ceiling_stops_a_limit_being_disabled_via_the_form(self) -> None:
        """The scan cap is a safety control. It must not be removable by typing
        a very large number into it."""
        with pytest.raises(ValidationError):
            _bounded_int("99999999", label="Maximum scan hosts", minimum=1, maximum=65536)
