"""Comparing observations and turning them into a readable timeline.

The rules under test are the ones that keep history honest: unchecked ports are
never compared, an absent observation is never diffed against, and a scan that
saw nothing new adds no entry.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.models import DiscoveryObservation, DiscoveryRun
from app.models.change import CHANGE_KINDS
from app.modules.history.changes import CHANGE_LABELS, describe_changes
from app.modules.history.service import describe_ports, diff_observations, scan_events

START = datetime(2026, 10, 1, tzinfo=UTC)


def obs(
    run_id: int,
    *,
    present: bool = True,
    ip: str = "10.0.0.5",
    mac: str | None = "aa:bb:cc:00:00:01",
    hostname: str | None = "nas.lan",
    vendor: str | None = None,
    ports: list[dict[str, Any]] | None = None,
) -> DiscoveryObservation:
    return DiscoveryObservation(
        run_id=run_id,
        device_id=1,
        present=present,
        ip_address=ip,
        mac_address=mac,
        hostname=hostname,
        vendor=vendor,
        ports=ports,
        observed_at=START + timedelta(days=run_id),
    )


def p(port: int, service: str | None = None) -> dict[str, Any]:
    return {"port": port, "protocol": "tcp", "service": service}


RUNS = {i: DiscoveryRun(id=i, subnet="10.0.0.0/24", username_snapshot="admin") for i in range(1, 9)}


class TestDiff:
    def test_field_and_port_changes_are_reported(self) -> None:
        diff = diff_observations(
            obs(1, ports=[p(22, "ssh"), p(80)]),
            obs(2, ip="10.0.0.9", ports=[p(22, "ssh"), p(443, "https")]),
        )
        assert diff.changed
        assert diff.lines() == [
            "IP address: 10.0.0.5 → 10.0.0.9",
            "Newly open: 443/tcp (https)",
            "No longer open: 80/tcp",
        ]

    def test_ports_are_not_compared_when_either_side_did_not_check(self) -> None:
        diff = diff_observations(obs(1, ports=[p(22)]), obs(2, ports=None))
        assert not diff.ports_compared
        assert not diff.changed, "unchecked ports must not read as closed"

    def test_a_name_that_stopped_resolving_is_a_change(self) -> None:
        diff = diff_observations(obs(1), obs(2, hostname=None))
        assert diff.lines() == ["Hostname: nas.lan → not reported"]

    def test_empty_string_and_none_are_the_same(self) -> None:
        assert not diff_observations(obs(1, vendor=""), obs(2, vendor=None)).changed

    def test_ports_sort_numerically(self) -> None:
        diff = diff_observations(obs(1, ports=[]), obs(2, ports=[p(8080), p(22), p(443)]))
        assert diff.opened == ["22/tcp", "443/tcp", "8080/tcp"]


class TestDescribePorts:
    def test_three_distinct_states(self) -> None:
        assert describe_ports(None) == "ports not checked"
        assert describe_ports([]) == "no open ports found"
        assert describe_ports([p(22, "ssh")]) == "open: 22/tcp (ssh)"


class TestScanEvents:
    def test_identical_scans_add_no_events_but_count_as_coverage(self) -> None:
        events, coverage = scan_events([obs(1), obs(2), obs(3)], RUNS)
        assert [event.title for event in events] == ["First recorded by scan #1 of 10.0.0.0/24"]
        assert (coverage.scans, coverage.answered, coverage.last_present) == (3, 3, True)

    def test_going_quiet_is_reported_once(self) -> None:
        events, coverage = scan_events(
            [obs(1), obs(2, present=False), obs(3, present=False), obs(4)], RUNS
        )
        titles = [event.title for event in events]
        assert titles == [
            "First recorded by scan #1 of 10.0.0.0/24",
            "Did not answer scan #2 of 10.0.0.0/24",
            "Answered again in scan #4 of 10.0.0.0/24",
        ]
        assert events[-1].details == ["Nothing differs from when it was last seen."]
        assert coverage.answered == 2

    def test_return_is_diffed_against_the_last_present_observation(self) -> None:
        """The absent row carries stale device values; diffing against it
        would hide a change that happened while the device was away."""
        events, _ = scan_events(
            [obs(1), obs(2, present=False, ip="10.0.0.5"), obs(3, ip="10.0.0.40")], RUNS
        )
        assert events[-1].details == ["IP address: 10.0.0.5 → 10.0.0.40"]

    def test_port_comparison_gap_is_stated(self) -> None:
        events, _ = scan_events([obs(1, ports=[p(22)]), obs(2, ports=None, ip="10.0.0.6")], RUNS)
        assert "Ports not compared" in events[-1].details[-1]

    def test_a_first_absent_observation_is_reported(self) -> None:
        events, coverage = scan_events([obs(1, present=False)], RUNS)
        assert events[0].tone == "warn"
        assert coverage.answered == 0

    def test_events_link_to_the_scan_report(self) -> None:
        events, _ = scan_events([obs(5)], RUNS)
        assert events[0].link == "/discovery/runs/5/report"

    def test_no_observations(self) -> None:
        events, coverage = scan_events([], RUNS)
        assert events == []
        assert coverage.last_run_id is None


class TestChangeDescriptions:
    def test_every_change_kind_has_a_label(self) -> None:
        assert set(CHANGE_LABELS) == set(CHANGE_KINDS)

    def test_nothing_changed(self) -> None:
        assert describe_changes({"name": "a"}, {"name": "a"}) is None

    def test_long_values_are_truncated(self) -> None:
        detail = describe_changes({"name": None}, {"name": "y" * 300}) or ""
        assert len(detail) < 120
        assert detail.endswith("…”")
