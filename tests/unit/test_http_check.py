"""HTTP check target validation — the SSRF surface.

Every other diagnostic targets an address discovery already found inside an
allowed range. This one takes a host and asks the server to connect to it, so
the validation here is what stands between an operator's device page and an
arbitrary outbound request.

The distinction that matters: validating a *name* proves nothing, because a name
resolves to an address and the address is what gets connected to.
"""

from __future__ import annotations

import ipaddress
from unittest.mock import patch

import pytest

from app.core.validation import ValidationError
from app.modules.diagnostics.http_check import validate_target

ALLOWED = [ipaddress.IPv4Network("10.0.0.0/8"), ipaddress.IPv4Network("192.168.0.0/16")]


def _resolves_to(*addresses: str):
    """Patch resolution so a name can be made to answer with anything."""
    return patch(
        "app.modules.diagnostics.http_check._resolve",
        return_value=[ipaddress.IPv4Address(a) for a in addresses],
    )


class TestLiteralAddresses:
    def test_an_allowed_address_passes(self) -> None:
        address, port = validate_target("10.0.30.1", 443, "https", ALLOWED)
        assert str(address) == "10.0.30.1"
        assert port == 443

    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",  # the app reaching itself
            "169.254.169.254",  # cloud metadata, the classic SSRF prize
            "169.254.1.1",  # link-local
            "224.0.0.1",  # multicast
        ],
    )
    def test_reserved_addresses_are_refused(self, address: str) -> None:
        with pytest.raises(ValidationError, match="reserved range"):
            validate_target(address, 80, "http", ALLOWED)

    @pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "203.0.113.5"])
    def test_public_addresses_are_refused(self, address: str) -> None:
        with pytest.raises(ValidationError, match="outside the configured"):
            validate_target(address, 80, "http", ALLOWED)

    def test_an_address_outside_the_allowlist_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="outside the configured"):
            validate_target("172.16.5.5", 80, "http", ALLOWED)


class TestNameResolution:
    def test_a_name_resolving_inside_the_allowlist_passes(self) -> None:
        with _resolves_to("10.0.30.5"):
            address, _ = validate_target("nas.lan", 80, "http", ALLOWED)
        assert str(address) == "10.0.30.5"

    def test_a_name_resolving_to_metadata_is_refused(self) -> None:
        """The whole reason resolution happens here. The name looks harmless;
        the address is the attack."""
        with _resolves_to("169.254.169.254"), pytest.raises(ValidationError, match="reserved"):
            validate_target("harmless.lan", 80, "http", ALLOWED)

    def test_a_name_resolving_to_a_public_address_is_refused(self) -> None:
        with _resolves_to("8.8.8.8"), pytest.raises(ValidationError, match="outside"):
            validate_target("exfil.example.com", 80, "http", ALLOWED)

    def test_every_resolved_address_must_pass_not_just_the_first(self) -> None:
        """A round-robin name answering with one allowed and one public address
        must not become reachable by retrying."""
        with _resolves_to("10.0.30.5", "8.8.8.8"), pytest.raises(ValidationError):
            validate_target("split.lan", 80, "http", ALLOWED)

    def test_the_order_of_a_mixed_answer_does_not_matter(self) -> None:
        with _resolves_to("8.8.8.8", "10.0.30.5"), pytest.raises(ValidationError):
            validate_target("split.lan", 80, "http", ALLOWED)

    def test_a_name_that_does_not_resolve_is_refused(self) -> None:
        with (
            patch(
                "app.modules.diagnostics.http_check._resolve",
                side_effect=ValidationError("'nope.lan' did not resolve."),
            ),
            pytest.raises(ValidationError, match="did not resolve"),
        ):
            validate_target("nope.lan", 80, "http", ALLOWED)


class TestSchemeAndPort:
    @pytest.mark.parametrize("scheme", ["file", "gopher", "ftp", "javascript", "data", ""])
    def test_only_http_and_https_are_accepted(self, scheme: str) -> None:
        with pytest.raises(ValidationError, match="not a supported scheme"):
            validate_target("10.0.30.1", 80, scheme, ALLOWED)

    @pytest.mark.parametrize("scheme", ["http", "https"])
    def test_both_web_schemes_pass(self, scheme: str) -> None:
        assert validate_target("10.0.30.1", 8080, scheme, ALLOWED)

    @pytest.mark.parametrize("port", [0, -1, 65536, "http", "", "22; id"])
    def test_invalid_ports_are_refused(self, port: object) -> None:
        with pytest.raises(ValidationError):
            validate_target("10.0.30.1", port, "http", ALLOWED)  # type: ignore[arg-type]


class TestHostnameShape:
    @pytest.mark.parametrize(
        "host", ["has space.lan", "semi;colon.lan", "$(id).lan", "back`tick`.lan", "a\nb.lan"]
    )
    def test_injection_shaped_hostnames_are_refused_before_resolution(self, host: str) -> None:
        with pytest.raises(ValidationError):
            validate_target(host, 80, "http", ALLOWED)

    def test_an_empty_allowlist_permits_nothing(self) -> None:
        """Fails closed. An empty allowlist must never read as 'no restriction'."""
        with pytest.raises(ValidationError):
            validate_target("10.0.30.1", 80, "http", [])
