"""Diagnostic argv builders and output parsing.

The builders are hardcoded and take at most two bounded numbers, which is what
makes them the safest execution surface in the application. These tests exist to
keep that true — a builder that ever interpolates user text into a flag is a
command injection, and the bounds are what stop a diagnostic outliving its
timeout.
"""

from __future__ import annotations

import pytest

from app.modules.diagnostics import builders
from app.modules.diagnostics.parsers import parse_ping, summarise_ping

PING_OUTPUT = """\
PING 10.0.30.1 (10.0.30.1) 56(84) bytes of data.
64 bytes from 10.0.30.1: icmp_seq=1 ttl=64 time=0.312 ms
64 bytes from 10.0.30.1: icmp_seq=2 ttl=64 time=0.489 ms

--- 10.0.30.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 0.312/0.400/0.489/0.088 ms
"""

PING_LOSS = """\
PING 10.0.30.99 (10.0.30.99) 56(84) bytes of data.

--- 10.0.30.99 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3070ms
"""


class TestClamping:
    @pytest.mark.parametrize(
        ("given", "expected"),
        [(None, 4), (1, 1), (20, 20), (0, 1), (-5, 1), (999, 20), (10, 10)],
    )
    def test_ping_count_is_forced_into_range(self, given: int | None, expected: int) -> None:
        """The bound is what matters, not which side of it the value landed on —
        an out-of-range number has no security consequence, an unbounded one
        outlives the timeout."""
        command = builders.ping("10.0.0.1", given)
        assert command.arguments[command.arguments.index("-c") + 1] == str(expected)

    @pytest.mark.parametrize(("given", "expected"), [(None, 15), (1, 1), (99, 30), (0, 1)])
    def test_traceroute_hops_are_forced_into_range(self, given: int | None, expected: int) -> None:
        command = builders.traceroute("10.0.0.1", given)
        assert command.arguments[command.arguments.index("-m") + 1] == str(expected)

    def test_the_timeout_always_exceeds_the_tool_deadline(self) -> None:
        """The engine timeout is a backstop for a misbehaving tool, not the
        normal path — if it fires first, every long ping looks like a failure."""
        for count in (1, 4, 20):
            command = builders.ping("10.0.0.1", count)
            deadline = int(command.arguments[command.arguments.index("-w") + 1])
            assert command.timeout > deadline


class TestArgumentSafety:
    @pytest.mark.parametrize(
        "builder",
        [
            lambda t: builders.ping(t),
            lambda t: builders.traceroute(t),
            lambda t: builders.reverse_dns(t),
            lambda t: builders.service_scan(t),
            lambda t: builders.arp_neighbour(t),
            lambda t: builders.dns_lookup(t),
            lambda t: builders.tcp_check(t, 22),
        ],
    )
    def test_the_target_is_a_single_trailing_argument(self, builder) -> None:
        """Never spliced into another argument, so it cannot become a flag."""
        command = builder("10.0.30.1")
        assert command.arguments.count("10.0.30.1") == 1

    @pytest.mark.parametrize(
        "hostile",
        ["; id", "$(id)", "`id`", "10.0.0.1 -oN /tmp/x", "--script=http-vuln", "-oN/tmp/x"],
    )
    def test_hostile_targets_stay_one_opaque_argument(self, hostile: str) -> None:
        """Callers validate before reaching here; this asserts the builder does
        not additionally split or interpret. There is no shell, so a literal is
        inert — but it must stay a single literal."""
        command = builders.ping(hostile)
        assert hostile in command.arguments
        assert command.arguments.count(hostile) == 1

    def test_every_argument_is_a_string(self) -> None:
        command = builders.tcp_check("10.0.0.1", 8080)
        assert all(isinstance(argument, str) for argument in command.arguments)

    def test_name_resolution_is_disabled_where_it_would_mislead(self) -> None:
        """ping and traceroute measure reachability. Leaving DNS on makes a
        resolver outage look like a network fault."""
        assert "-n" in builders.ping("10.0.0.1").arguments
        assert "-n" in builders.traceroute("10.0.0.1").arguments

    def test_the_service_scan_is_bounded_to_a_short_port_list(self) -> None:
        command = builders.service_scan("10.0.0.1")
        ports = command.arguments[command.arguments.index("-p") + 1]
        assert len(ports.split(",")) <= 12
        assert "--host-timeout" in command.arguments

    def test_the_tcp_test_uses_a_plain_connect(self) -> None:
        """-sT needs no privilege and cannot be mistaken for a stealth scan."""
        assert "-sT" in builders.tcp_check("10.0.0.1", 22).arguments


class TestPingParsing:
    def test_extracts_latency_and_loss(self) -> None:
        latency, loss = parse_ping(PING_OUTPUT)
        assert latency == 0.400
        assert loss == 0.0

    def test_total_loss(self) -> None:
        latency, loss = parse_ping(PING_LOSS)
        assert latency is None
        assert loss == 100.0

    def test_falls_back_to_averaging_individual_replies(self) -> None:
        """Some ping builds omit the rtt summary line entirely."""
        latency, _ = parse_ping("64 bytes: time=1.0 ms\n64 bytes: time=3.0 ms")
        assert latency == 2.0

    @pytest.mark.parametrize("junk", ["", "no numbers here", "garbage output"])
    def test_unparseable_output_yields_no_numbers_rather_than_raising(self, junk: str) -> None:
        assert parse_ping(junk) == (None, None)

    def test_summary_text(self) -> None:
        assert summarise_ping(None, 100.0) == "No reply"
        assert "0.4 ms average" in summarise_ping(0.4, 0.0)
        assert summarise_ping(None, None) == "Completed"
