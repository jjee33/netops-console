"""nmap XML parsing.

The fixtures deliberately contain the awkward real cases rather than a clean
scan: hosts with no MAC, no hostname, no ports, combined port states, IPv6
addresses, and a host that is down. Every one occurs in a normal scan.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.modules.discovery.parser import ScanParseError, parse_scan

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def typical() -> str:
    return (FIXTURES / "nmap_typical.xml").read_text()


@pytest.fixture
def edge_cases() -> str:
    return (FIXTURES / "nmap_edge_cases.xml").read_text()


class TestTypicalScan:
    def test_finds_every_host_including_the_down_one(self, typical: str) -> None:
        scan = parse_scan(typical)
        assert len(scan.hosts) == 4
        assert len(scan.up_hosts) == 3

    def test_reads_runstats(self, typical: str) -> None:
        scan = parse_scan(typical)
        assert scan.hosts_up == 3
        assert scan.hosts_total == 4

    def test_extracts_mac_and_vendor(self, typical: str) -> None:
        router = parse_scan(typical).hosts[0]
        assert router.ip_address == "192.168.1.1"
        assert router.mac_address == "aa:bb:cc:11:22:33"
        assert router.vendor == "Ubiquiti Inc"

    def test_mac_is_normalised_to_lowercase(self, typical: str) -> None:
        """Dedup keys on the MAC, so formatting differences between sources
        would otherwise create duplicate devices."""
        for host in parse_scan(typical).hosts:
            if host.mac_address:
                assert host.mac_address == host.mac_address.lower()

    def test_a_host_with_no_reverse_dns_still_parses(self, typical: str) -> None:
        nas = parse_scan(typical).hosts[1]
        assert nas.ip_address == "192.168.1.20"
        assert nas.hostname is None
        assert nas.vendor == "Synology Incorporated"

    def test_a_host_with_no_mac_is_kept(self, typical: str) -> None:
        """Anything across a router has no visible MAC. Dropping it would make
        routed devices invisible."""
        printer = parse_scan(typical).hosts[2]
        assert printer.ip_address == "192.168.1.50"
        assert printer.mac_address is None
        assert printer.hostname == "printer.lan"

    def test_down_hosts_are_marked_not_dropped(self, typical: str) -> None:
        down = parse_scan(typical).hosts[3]
        assert down.ip_address == "192.168.1.99"
        assert down.is_up is False

    def test_ports_and_services(self, typical: str) -> None:
        router = parse_scan(typical).hosts[0]
        assert len(router.ports) == 3

        ssh = next(p for p in router.ports if p.port == 22)
        assert (ssh.protocol, ssh.state, ssh.service) == ("tcp", "open", "ssh")

        filtered = next(p for p in router.ports if p.port == 8080)
        assert filtered.state == "filtered"
        assert filtered.service is None

    def test_combined_port_state_takes_the_first_value(self, typical: str) -> None:
        """nmap emits 'open|filtered' for unanswered UDP."""
        snmp = parse_scan(typical).hosts[2].ports[0]
        assert snmp.port == 161
        assert snmp.protocol == "udp"
        assert snmp.state == "open"


class TestEdgeCases:
    def test_a_host_with_no_ports_element(self, edge_cases: str) -> None:
        host = parse_scan(edge_cases).hosts[0]
        assert host.ip_address == "10.0.0.5"
        assert host.ports == []
        assert host.vendor is None

    def test_ipv6_address_does_not_displace_the_ipv4_one(self, edge_cases: str) -> None:
        host = parse_scan(edge_cases).hosts[1]
        assert host.ip_address == "10.0.0.6"

    def test_ipv6_only_hosts_are_skipped(self, edge_cases: str) -> None:
        """Out of scope for v0.1 — a host with nothing this version can address
        should not become a device row with an empty IP."""
        addresses = [host.ip_address for host in parse_scan(edge_cases).hosts]
        assert all(":" not in address for address in addresses)
        assert "fe80::dead:beef" not in addresses

    def test_the_first_hostname_wins(self, edge_cases: str) -> None:
        host = next(h for h in parse_scan(edge_cases).hosts if h.ip_address == "10.0.0.7")
        assert host.hostname == "first.lan"

    def test_an_empty_hostnames_element_is_fine(self, edge_cases: str) -> None:
        host = next(h for h in parse_scan(edge_cases).hosts if h.ip_address == "10.0.0.8")
        assert host.hostname is None

    def test_malformed_ports_are_dropped_without_failing_the_scan(self, edge_cases: str) -> None:
        """One bad port entry must not discard an otherwise good scan."""
        host = next(h for h in parse_scan(edge_cases).hosts if h.ip_address == "10.0.0.9")
        ports = {(p.port, p.protocol): p for p in host.ports}

        assert (0, "tcp") not in ports
        assert (99999, "tcp") not in ports
        assert (80, "sctp") not in ports

        assert ports[(80, "tcp")].state == "filtered"  # unrecognised state
        assert ports[(443, "tcp")].state == "closed"  # no <state> element

    def test_a_script_payload_in_a_hostname_is_preserved_as_data(self, edge_cases: str) -> None:
        """Kept verbatim here and escaped at render time. Sanitising on the way
        in would hide from the operator what the device actually reported."""
        host = next(h for h in parse_scan(edge_cases).hosts if h.ip_address == "10.0.0.10")
        assert host.hostname == "<script>alert(1)</script>"


class TestMalformedInput:
    @pytest.mark.parametrize("bad", ["", "   ", "not xml at all", "<unclosed>"])
    def test_unusable_input_raises(self, bad: str) -> None:
        with pytest.raises(ScanParseError):
            parse_scan(bad)

    def test_wrong_root_element_is_rejected(self) -> None:
        with pytest.raises(ScanParseError, match="nmaprun"):
            parse_scan("<?xml version='1.0'?><something/>")

    def test_an_empty_scan_is_valid(self) -> None:
        scan = parse_scan(
            "<?xml version='1.0'?><nmaprun><runstats>"
            "<hosts up='0' down='256' total='256'/></runstats></nmaprun>"
        )
        assert scan.hosts == []
        assert scan.hosts_total == 256

    def test_entity_expansion_is_refused(self) -> None:
        """defusedxml is why. A billion-laughs payload must not be expanded."""
        payload = """<?xml version="1.0"?>
        <!DOCTYPE nmaprun [
          <!ENTITY a "aaaaaaaaaa">
          <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
          <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
        ]>
        <nmaprun><host><address addr="&c;" addrtype="ipv4"/></host></nmaprun>"""
        with pytest.raises(ScanParseError):
            parse_scan(payload)

    def test_external_entities_are_refused(self) -> None:
        payload = """<?xml version="1.0"?>
        <!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <nmaprun><host><address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>"""
        with pytest.raises(ScanParseError):
            parse_scan(payload)
