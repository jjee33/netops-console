"""The ExecutionEngine — the single path through which every command runs.

Nothing else in this application may call ``subprocess``, ``os.system``, or
``asyncio.create_subprocess_*``. That rule is what makes the following
guarantees true everywhere rather than in most places:

* no shell, ever — argv arrays only, so metacharacters in a parameter are inert
* only allowlisted, absolute-path binaries
* a hard timeout on every run
* the whole **process group** is killed on timeout, not just the direct child
* output is size-capped, control-stripped, and secret-masked before it is
  stored or shown
* concurrency is bounded, and the permit is always returned

A second call site elsewhere would silently opt out of all of it, which is why
``ruff``'s subprocess rules are enabled globally and suppressed only here.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
import signal
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final

from app.core.redaction import DEFAULT_MAX_BYTES, sanitize

logger = logging.getLogger("netops.execution")


class ExecutionStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    REJECTED = "rejected"
    BUSY = "busy"


# Only these programs may ever be executed. Resolved to absolute paths at
# startup; anything not here is refused before a process is spawned. Adding an
# entry is a security decision, not a convenience — a shell or an interpreter
# here would defeat the entire argv discipline.
ALLOWED_BINARIES: Final = frozenset(
    {
        "nmap",
        "ping",
        "traceroute",
        "dig",
        "host",
        "ip",
        "arp",
    }
)

# Never executable, even if something adds them to the set above by mistake.
# Each one runs arbitrary commands by design.
_FORBIDDEN_NAMES: Final = frozenset(
    {
        "sh", "bash", "zsh", "dash", "ksh", "csh", "fish",
        "python", "python3", "perl", "ruby", "node", "php",
        "awk", "gawk", "find", "xargs", "env", "eval", "sudo", "su",
        "vi", "vim", "less", "more", "man", "docker", "kubectl",
    }
)  # fmt: skip

DEFAULT_TIMEOUT: Final = 30.0
MAX_TIMEOUT: Final = 600.0

# Grace period between SIGTERM and SIGKILL for a timed-out process group.
_KILL_GRACE: Final = 2.0


class ExecutionRejected(Exception):
    """The command was refused before anything was spawned."""


class ExecutionBusy(Exception):
    """No capacity. Raised rather than queueing, so the caller can say so."""


@dataclass(frozen=True)
class ExecutionResult:
    status: ExecutionStatus
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool = False
    argv: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status is ExecutionStatus.SUCCESS


def resolve_binary(name: str) -> str:
    """Resolve a program name to an absolute path, or refuse.

    Refuses anything not in the allowlist, anything on the forbidden list, and
    anything that looks like a path rather than a bare program name — a caller
    passing ``../../bin/sh`` must not reach ``shutil.which``.
    """
    if not name or "/" in name or "\\" in name or name != name.strip():
        raise ExecutionRejected(f"{name!r} is not a bare program name.")

    if name in _FORBIDDEN_NAMES:
        raise ExecutionRejected(f"{name!r} can execute arbitrary commands and is never allowed.")

    if name not in ALLOWED_BINARIES:
        raise ExecutionRejected(f"{name!r} is not an allowed program.")

    path = shutil.which(name)
    if path is None:
        raise ExecutionRejected(f"{name!r} is not installed in this image.")

    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise ExecutionRejected(f"{name!r} did not resolve to a file.")

    return str(resolved)


def build_argv(program: str, arguments: list[str]) -> list[str]:
    """Assemble an argv list, validating the program and every argument.

    Each argument becomes exactly one argv element. No argument is ever parsed,
    split, or interpolated, so shell metacharacters inside one are passed to the
    program as literal text — there is no shell to interpret them.
    """
    argv = [resolve_binary(program)]

    for argument in arguments:
        if not isinstance(argument, str):
            raise ExecutionRejected(f"argument {argument!r} is not a string.")
        if "\x00" in argument:
            # A NUL truncates the string at the execve boundary, so what the
            # kernel receives would differ from what was validated.
            raise ExecutionRejected("arguments must not contain NUL bytes.")
        argv.append(argument)

    return argv


class ExecutionEngine:
    """Runs commands under concurrency, timeout, and output limits."""

    def __init__(
        self,
        max_concurrent: int = 4,
        max_discovery_concurrent: int = 1,
        max_output_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrent)
        # Discovery gets its own, lower limit: a scan is far heavier than a
        # ping, and one runaway scan should not consume the whole budget.
        self._discovery_semaphore = asyncio.Semaphore(max_discovery_concurrent)
        self._max_output_bytes = max_output_bytes

    async def run(
        self,
        program: str,
        arguments: list[str],
        *,
        # A `timeout` parameter rather than letting callers wrap this in
        # `asyncio.timeout`: cancelling the coroutine would abandon the child
        # process, not kill it. Expiry here means killing the whole process
        # group, which only this function is positioned to do.
        timeout: float = DEFAULT_TIMEOUT,  # noqa: ASYNC109
        discovery: bool = False,
        secret_values: list[str] | None = None,
    ) -> ExecutionResult:
        argv = build_argv(program, arguments)

        if timeout <= 0 or timeout > MAX_TIMEOUT:
            raise ExecutionRejected(f"timeout must be between 0 and {MAX_TIMEOUT} seconds.")

        semaphore = self._discovery_semaphore if discovery else self._semaphore

        # Fail fast rather than queueing. An operator waiting on a page needs
        # "busy, try again" far more than an unbounded wait.
        if semaphore.locked():
            raise ExecutionBusy("All execution slots are in use. Try again shortly.")

        await semaphore.acquire()
        try:
            return await self._spawn(argv, timeout, secret_values)
        finally:
            # In `finally` without exception: a permit leaked on an error path
            # is permanent, and enough of them stop the application executing
            # anything at all.
            semaphore.release()

    async def _spawn(
        self,
        argv: list[str],
        timeout: float,  # noqa: ASYNC109 - see run()
        secret_values: list[str] | None,
    ) -> ExecutionResult:
        started = time.monotonic()
        logger.info("exec: %s", " ".join(argv))

        process = await asyncio.create_subprocess_exec(
            # Not a shell, and argv[0] is an allowlisted absolute path resolved
            # by resolve_binary. This is the one permitted spawn in the
            # codebase — see the module docstring before adding another.
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # New session makes the child a process-group leader, which is what
            # allows killing its children too. traceroute and continuous ping
            # spawn helpers that outlive a plain process.kill().
            start_new_session=True,
        )

        status = ExecutionStatus.SUCCESS
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except TimeoutError:
            status = ExecutionStatus.TIMEOUT
            stdout, stderr = await self._terminate(process)
            logger.warning("timeout after %.1fs: %s", timeout, argv[0])

        duration_ms = int((time.monotonic() - started) * 1000)

        clean_out, out_truncated = sanitize(
            stdout.decode("utf-8", errors="replace"),
            max_bytes=self._max_output_bytes,
            secret_values=secret_values,
        )
        clean_err, err_truncated = sanitize(
            stderr.decode("utf-8", errors="replace"),
            max_bytes=self._max_output_bytes,
            secret_values=secret_values,
        )

        if status is not ExecutionStatus.TIMEOUT:
            status = ExecutionStatus.SUCCESS if process.returncode == 0 else ExecutionStatus.FAILED

        return ExecutionResult(
            status=status,
            exit_code=process.returncode,
            stdout=clean_out,
            stderr=clean_err,
            duration_ms=duration_ms,
            truncated=out_truncated or err_truncated,
            argv=argv,
        )

    @staticmethod
    async def _terminate(process: asyncio.subprocess.Process) -> tuple[bytes, bytes]:
        """Kill the timed-out process group, politely then not.

        ``killpg`` rather than ``process.kill()``: the latter signals only the
        direct child and leaves its children holding sockets and file
        descriptors, which is how a timeout turns into an orphan leak.
        """
        if process.returncode is not None:
            return b"", b""

        try:
            group = os.getpgid(process.pid)
        except ProcessLookupError:
            return b"", b""

        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(group, signal.SIGTERM)

        try:
            return await asyncio.wait_for(process.communicate(), timeout=_KILL_GRACE)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(group, signal.SIGKILL)
            with contextlib.suppress(TimeoutError):
                return await asyncio.wait_for(process.communicate(), timeout=_KILL_GRACE)
        return b"", b""


_engine: ExecutionEngine | None = None


def get_engine() -> ExecutionEngine:
    global _engine
    if _engine is None:
        from app.core.config import get_settings

        settings = get_settings()
        _engine = ExecutionEngine(
            max_concurrent=settings.max_concurrent_executions,
            max_discovery_concurrent=settings.max_concurrent_scans,
        )
    return _engine


def reset_engine() -> None:
    """Drop the cached engine. For tests and settings changes."""
    global _engine
    _engine = None
