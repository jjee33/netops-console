"""Rule-based explanations for check and scan results.

All outputs here are synthetic, written in the format each tool produces. The
cases that matter most are the ones where status alone is misleading: an empty
``dig`` answer and a closed port both exit 0.
"""

from __future__ import annotations

import pytest

from app.models import DiagnosticResult, DiscoveryObservation, DiscoveryRun
from app.modules.diagnostics.explain import explain_diagnostic
from app.modules.discovery.explain import explain_run


def result(
    kind: str,
    status: str,
    output: str = "",
    *,
    loss: float | None = None,
    target: str = "10.0.0.5",
    exit_code: int | None = None,
) -> DiagnosticResult:
    return DiagnosticResult(
        type=kind,
        status=status,
        output=output,
        packet_loss_pct=loss,
        target=target,
        exit_code=exit_code,
    )


PING_UNREACHABLE = """PING 10.0.0.5 (10.0.0.5) 56(84) bytes of data.
From 10.0.0.2 icmp_seq=1 Destination Host Unreachable

--- 10.0.0.5 ping statistics ---
4 packets transmitted, 0 received, +4 errors, 100% packet loss, time 3060ms
"""

PING_SILENT = """PING 10.0.0.5 (10.0.0.5) 56(84) bytes of data.

--- 10.0.0.5 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3070ms
"""


class TestPing:
    def test_unreachable_points_at_layer_two(self) -> None:
        explanation = explain_diagnostic(result("ping", "failed", PING_UNREACHABLE, loss=100))
        assert explanation
        assert "Destination Host Unreachable" in (explanation.evidence or "")

    def test_silent_loss_suggests_icmp_filtering_and_an_arp_check(self) -> None:
        explanation = explain_diagnostic(result("ping", "failed", PING_SILENT, loss=100))
        assert explanation
        assert any("ICMP" in cause for cause in explanation.causes)
        assert any("ARP entry" in step for step in explanation.next_steps)

    def test_partial_loss(self) -> None:
        explanation = explain_diagnostic(result("ping", "success", "...", loss=25))
        assert explanation and "25%" in explanation.headline

    def test_clean_success_needs_no_explanation(self) -> None:
        assert explain_diagnostic(result("ping", "success", "...", loss=0)) is None

    def test_missing_capability(self) -> None:
        explanation = explain_diagnostic(
            result("ping", "failed", "ping: socket: Operation not permitted")
        )
        assert explanation and "raw packets" in explanation.headline


class TestStatusCodesThatLie:
    def test_empty_forward_lookup_is_explained(self) -> None:
        explanation = explain_diagnostic(result("dns", "success", "(no output)"))
        assert explanation and "does not resolve" in explanation.headline

    def test_empty_reverse_lookup_is_explained_as_common(self) -> None:
        explanation = explain_diagnostic(result("rdns", "success", ""))
        assert explanation and "PTR" in explanation.headline

    @pytest.mark.parametrize(
        ("state", "phrase"), [("closed", "nothing is listening"), ("filtered", "No answer")]
    )
    def test_tcp_port_state(self, state: str, phrase: str) -> None:
        output = f"PORT   STATE  SERVICE\n22/tcp {state} ssh\n"
        explanation = explain_diagnostic(result("tcp", "success", output))
        assert explanation and phrase in explanation.headline

    def test_open_port_needs_no_explanation(self) -> None:
        assert explain_diagnostic(result("tcp", "success", "22/tcp open  ssh\n")) is None

    def test_empty_arp_table(self) -> None:
        explanation = explain_diagnostic(result("arp", "success", "(no output)"))
        assert explanation and "No neighbour table entry" in explanation.headline

    def test_failed_arp_state(self) -> None:
        explanation = explain_diagnostic(result("arp", "success", "10.0.0.5 dev eth0  FAILED"))
        assert explanation and "nothing answered" in explanation.headline

    def test_reachable_arp_needs_no_explanation(self) -> None:
        output = "10.0.0.5 dev eth0 lladdr aa:bb:cc:00:00:01 REACHABLE"
        assert explain_diagnostic(result("arp", "success", output)) is None


class TestTraceroute:
    def test_unreached_target(self) -> None:
        output = "traceroute to 10.0.0.5\n 1  10.0.0.1  0.4 ms\n 2  *\n 3  *\n"
        explanation = explain_diagnostic(result("traceroute", "success", output))
        assert explanation and "did not reach" in explanation.headline

    def test_reached_target(self) -> None:
        output = "traceroute to 10.0.0.5\n 1  10.0.0.1  0.4 ms\n 2  10.0.0.5  0.9 ms\n"
        assert explain_diagnostic(result("traceroute", "success", output)) is None

    def test_prohibited(self) -> None:
        output = " 1  10.0.0.1  0.4 ms !X\n"
        explanation = explain_diagnostic(result("traceroute", "success", output))
        assert explanation and "rejected" in explanation.headline


class TestHttp:
    @pytest.mark.parametrize(
        ("output", "phrase"),
        [
            ("ConnectError: [Errno 111] Connection refused", "refused"),
            ("ConnectError: [SSL: WRONG_VERSION_NUMBER] wrong version number", "plain-HTTP"),
            ("RemoteProtocolError: Server disconnected without sending a response.", "closed"),
            ("No response from https://10.0.0.5:443/ within 10s.", "timed out"),
            ("https://10.0.0.5:443/\nstatus:       401 Unauthorized\n", "requires login"),
            ("http://10.0.0.5:80/\nstatus:       503 Service Unavailable\n", "error (503)"),
        ],
    )
    def test_common_outcomes(self, output: str, phrase: str) -> None:
        explanation = explain_diagnostic(result("http_check", "failed", output))
        assert explanation and phrase in explanation.headline


class TestRefusalsAndCapacity:
    def test_out_of_scope_device_points_at_settings(self) -> None:
        output = "10.9.0.5 is outside the currently allowed ranges. Add its range in Settings."
        explanation = explain_diagnostic(result("ping", "rejected", output))
        assert explanation and any("Settings" in step for step in explanation.next_steps)

    def test_busy(self) -> None:
        explanation = explain_diagnostic(result("ping", "busy", "All execution slots are in use."))
        assert explanation and "slot" in explanation.headline

    def test_unrecognised_failure_still_says_something(self) -> None:
        explanation = explain_diagnostic(result("service_scan", "failed", "odd", exit_code=3))
        assert explanation and explanation.evidence == "Exit code 3."


def run(status: str, summary: str = "", found: int = 0) -> DiscoveryRun:
    return DiscoveryRun(
        id=1, subnet="10.0.0.0/24", status=status, output_summary=summary, devices_found=found
    )


def present(ip: str, mac: str | None) -> DiscoveryObservation:
    return DiscoveryObservation(run_id=1, present=True, ip_address=ip, mac_address=mac)


class TestRunExplanations:
    def test_capability_failure(self) -> None:
        explanation = explain_run(run("failed", "dnet: Failed to open device eth0\nQUITTING!"), [])
        assert explanation and "raw packets" in explanation.headline

    def test_timeout_suggests_a_smaller_range(self) -> None:
        explanation = explain_run(run("timeout", "Scan exceeded 300s."), [])
        assert explanation and any("smaller range" in s for s in explanation.next_steps)

    def test_interrupted(self) -> None:
        explanation = explain_run(run("failed", "Interrupted — the application restarted"), [])
        assert explanation and "restarted" in explanation.headline

    def test_nothing_answered(self) -> None:
        explanation = explain_run(run("success", "0 host(s) responded; 0 new."), [])
        assert explanation and "nothing answered" in explanation.headline

    def test_no_mac_addresses_flags_bridge_networking(self) -> None:
        """The silent failure the README warns about: a scan that succeeds
        with every MAC column empty."""
        rows = [present("10.0.0.1", None), present("10.0.0.2", None)]
        explanation = explain_run(run("success", found=2), rows)
        assert explanation and "MAC" in explanation.headline
        assert any("host networking" in cause for cause in explanation.causes)

    def test_healthy_scan_needs_no_explanation(self) -> None:
        rows = [present("10.0.0.1", "aa:bb:cc:00:00:01"), present("10.0.0.2", None)]
        assert explain_run(run("success", found=2), rows) is None

    def test_running_scan_is_not_explained(self) -> None:
        assert explain_run(run("running"), []) is None
