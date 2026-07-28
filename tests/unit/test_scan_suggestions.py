"""Suggested scan targets.

These exist because the form previously defaulted to the first configured
allowed range, which is normally a supernet like 10.0.0.0/8 — sixteen million
addresses against a cap of 1024. The default value could never succeed, so the
first thing every operator saw was a validation error on a field they had not
touched. Anything offered as a suggestion must therefore be genuinely scannable.
"""

from __future__ import annotations

import ipaddress
from typing import ClassVar

import pytest

from app.modules.discovery.service import parse_local_networks

IP_OUTPUT = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 10.0.10.5/24 brd 10.0.10.255 scope global eth0\\       valid_lft forever
3: eth0.20    inet 10.0.20.5/24 brd 10.0.20.255 scope global eth0.20\\       valid_lft forever
4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever
"""


class TestParseLocalNetworks:
    def test_extracts_the_network_for_each_interface(self) -> None:
        networks = [str(n) for n in parse_local_networks(IP_OUTPUT)]
        assert "10.0.10.0/24" in networks
        assert "10.0.20.0/24" in networks
        assert "172.17.0.0/16" in networks

    def test_the_interface_address_becomes_its_network(self) -> None:
        """`10.0.10.5/24` describes the host, not the range to scan."""
        assert ipaddress.IPv4Network("10.0.10.0/24") in parse_local_networks(IP_OUTPUT)

    def test_loopback_is_excluded(self) -> None:
        assert all(not n.is_loopback for n in parse_local_networks(IP_OUTPUT))

    def test_duplicates_are_collapsed(self) -> None:
        doubled = IP_OUTPUT + "5: eth1    inet 10.0.10.9/24 scope global eth1\\  valid_lft forever"
        networks = [str(n) for n in parse_local_networks(doubled)]
        assert networks.count("10.0.10.0/24") == 1

    @pytest.mark.parametrize(
        "line",
        [
            "",
            "garbage",
            "2: eth0    inet",
            "2: eth0    inet not-an-address/24 scope global",
            "2: eth0    inet6 fe80::1/64 scope link",
        ],
    )
    def test_unparseable_lines_are_skipped_without_raising(self, line: str) -> None:
        """A page that renders is worth more than a complete suggestion list."""
        assert parse_local_networks(line) == []

    def test_ipv6_is_ignored(self) -> None:
        mixed = IP_OUTPUT + "2: eth0    inet6 2001:db8::1/64 scope global"
        assert all(isinstance(n, ipaddress.IPv4Network) for n in parse_local_networks(mixed))


class TestFiltering:
    """The filtering logic that makes a suggestion safe to offer."""

    ALLOWED: ClassVar[list[ipaddress.IPv4Network]] = [ipaddress.IPv4Network("10.0.0.0/8")]

    def _filter(self, max_hosts: int) -> list[str]:
        return [
            str(network)
            for network in parse_local_networks(IP_OUTPUT)
            if network.num_addresses <= max_hosts
            and any(network.subnet_of(entry) for entry in self.ALLOWED)
        ]

    def test_only_networks_inside_the_allowlist_are_offered(self) -> None:
        suggested = self._filter(1024)
        assert "10.0.10.0/24" in suggested
        # Inside the container's own bridge range, but outside what the operator
        # said this instance may touch.
        assert "172.17.0.0/16" not in suggested

    def test_networks_above_the_host_cap_are_offered(self) -> None:
        assert self._filter(1024) == ["10.0.10.0/24", "10.0.20.0/24"]

    def test_a_tiny_cap_offers_nothing_rather_than_something_that_fails(self) -> None:
        assert self._filter(16) == []
