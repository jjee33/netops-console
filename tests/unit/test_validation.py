"""Validation is where a bug becomes a vulnerability, so the rejection cases
matter more than the acceptance cases.
"""

from __future__ import annotations

import ipaddress

import pytest

from app.core.validation import (
    ValidationError,
    parse_ipv4,
    parse_ipv4_network,
    validate_allowed_cidr,
    validate_hostname,
    validate_port,
    validate_scan_target,
)

ALLOWED = [ipaddress.IPv4Network("192.168.0.0/16"), ipaddress.IPv4Network("10.0.0.0/8")]


class TestParseAddress:
    def test_accepts_ipv4(self) -> None:
        assert parse_ipv4("192.168.1.10") == ipaddress.IPv4Address("192.168.1.10")

    def test_rejects_ipv6_explicitly(self) -> None:
        """Out of scope for v0.1 — passing it through would mean unvalidated
        addresses reaching the network layer."""
        with pytest.raises(ValidationError, match="IPv6"):
            parse_ipv4("2001:db8::1")

    @pytest.mark.parametrize(
        "bad", ["", "   ", "999.1.1.1", "192.168.1", "192.168.1.1.1", "hostname", "1e2.3.4.5"]
    )
    def test_rejects_malformed(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            parse_ipv4(bad)

    def test_rejects_octal_style_ambiguity(self) -> None:
        """'0177.0.0.1' is loopback to some parsers and invalid to others.
        Python's ipaddress rejects it; asserting that keeps the guarantee."""
        with pytest.raises(ValidationError):
            parse_ipv4("0177.0.0.1")


class TestParseNetwork:
    def test_accepts_cidr(self) -> None:
        assert parse_ipv4_network("192.168.1.0/24") == ipaddress.IPv4Network("192.168.1.0/24")

    def test_requires_a_prefix(self) -> None:
        with pytest.raises(ValidationError, match="prefix length"):
            parse_ipv4_network("192.168.1.0")

    def test_host_bits_set_suggests_the_correction(self) -> None:
        """Almost always a typo. Silently normalising hides it from the operator."""
        with pytest.raises(ValidationError, match=r"Did you mean 192\.168\.1\.0/24"):
            parse_ipv4_network("192.168.1.5/24")


class TestAllowedCidr:
    @pytest.mark.parametrize(
        "value", ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24"]
    )
    def test_accepts_private_ranges(self, value: str) -> None:
        assert validate_allowed_cidr(value)

    @pytest.mark.parametrize(
        "value",
        [
            "127.0.0.0/8",  # loopback — the app scanning itself
            "169.254.0.0/16",  # link-local, contains cloud metadata
            "169.254.169.254/32",  # the metadata endpoint itself
            "224.0.0.0/4",  # multicast
            "0.0.0.0/0",  # everything
        ],
    )
    def test_rejects_reserved_ranges(self, value: str) -> None:
        with pytest.raises(ValidationError):
            validate_allowed_cidr(value)

    @pytest.mark.parametrize("value", ["8.8.8.0/24", "1.1.1.1/32", "203.0.113.0/24"])
    def test_rejects_public_ranges(self, value: str) -> None:
        """The premise is a private management network. Scanning the public
        internet is not a feature to be configured, it is a mistake."""
        with pytest.raises(ValidationError, match="not a private range"):
            validate_allowed_cidr(value)

    def test_rejects_a_supernet_that_swallows_public_space(self) -> None:
        with pytest.raises(ValidationError):
            validate_allowed_cidr("10.0.0.0/4")


class TestScanTarget:
    def test_accepts_a_subnet_of_the_allowlist(self) -> None:
        assert validate_scan_target("192.168.1.0/24", ALLOWED, 1024)

    def test_rejects_a_network_outside_the_allowlist(self) -> None:
        with pytest.raises(ValidationError, match="outside the configured"):
            validate_scan_target("172.16.0.0/24", ALLOWED, 1024)

    def test_rejects_a_range_larger_than_the_cap(self) -> None:
        with pytest.raises(ValidationError, match="above the limit"):
            validate_scan_target("10.0.0.0/8", ALLOWED, 1024)

    def test_a_slash_22_is_exactly_at_the_default_cap(self) -> None:
        assert validate_scan_target("10.1.0.0/22", ALLOWED, 1024)

    def test_out_of_scope_beats_too_large_in_the_error_message(self) -> None:
        """Both are true for this input; the operator needs the actionable one."""
        with pytest.raises(ValidationError, match="outside the configured"):
            validate_scan_target("8.0.0.0/8", ALLOWED, 1024)


class TestHostname:
    @pytest.mark.parametrize("value", ["router", "nas.lan", "switch-01.example.com", "A.B.C"])
    def test_accepts_valid_names(self, value: str) -> None:
        assert validate_hostname(value) == value.lower().rstrip(".")

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "-leading.hyphen",
            "trailing-.hyphen",
            "under_score.lan",
            "has space.lan",
            "semi;colon.lan",
            "$(id).lan",
            "back`tick`.lan",
            "new\nline.lan",
            "a" * 64 + ".lan",
        ],
    )
    def test_rejects_invalid_and_injection_shaped_names(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            validate_hostname(bad)

    def test_rejects_overlong_names(self) -> None:
        with pytest.raises(ValidationError, match="exceeds"):
            validate_hostname(".".join(["abc"] * 100))


class TestPort:
    @pytest.mark.parametrize("value", [1, 22, "443", 65535])
    def test_accepts_valid_ports(self, value: int | str) -> None:
        assert validate_port(value) == int(value)

    @pytest.mark.parametrize("bad", [0, -1, 65536, "http", "", "22; id", None])
    def test_rejects_invalid_ports(self, bad: object) -> None:
        with pytest.raises(ValidationError):
            validate_port(bad)  # type: ignore[arg-type]
