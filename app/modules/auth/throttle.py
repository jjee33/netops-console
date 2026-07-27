"""Per-IP login rate limiting.

In-process state, which is correct here rather than a compromise: the
application already refuses to start with more than one worker, so there is
exactly one copy. A Redis dependency for a single-operator tool would be
infrastructure with no corresponding benefit.

This complements the per-account lockout in the database. Both are needed —
account lockout alone lets an attacker spray one attempt each across many
usernames, and IP limiting alone does nothing against a distributed attempt at
one known account.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Final

# A human typing a password wrong gets nowhere near this. A script does.
MAX_ATTEMPTS_PER_IP: Final = 10
WINDOW_SECONDS: Final = 300.0

# Stop the dict growing without bound if someone cycles source addresses.
MAX_TRACKED_IPS: Final = 10_000


@dataclass
class _Bucket:
    attempts: list[float] = field(default_factory=list)


class LoginThrottle:
    def __init__(
        self,
        max_attempts: int = MAX_ATTEMPTS_PER_IP,
        window_seconds: float = WINDOW_SECONDS,
    ) -> None:
        self._max_attempts = max_attempts
        self._window = window_seconds
        self._buckets: dict[str, _Bucket] = defaultdict(_Bucket)

    def _prune(self, bucket: _Bucket, now: float) -> None:
        cutoff = now - self._window
        bucket.attempts = [t for t in bucket.attempts if t > cutoff]

    def is_limited(self, ip: str, *, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        bucket = self._buckets.get(ip)
        if bucket is None:
            return False
        self._prune(bucket, now)
        return len(bucket.attempts) >= self._max_attempts

    def record_failure(self, ip: str, *, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now

        # Evict wholesale rather than LRU: this is a defensive cap, not a cache,
        # and the window means everything expires within minutes anyway.
        if len(self._buckets) >= MAX_TRACKED_IPS and ip not in self._buckets:
            self._buckets.clear()

        bucket = self._buckets[ip]
        self._prune(bucket, now)
        bucket.attempts.append(now)

    def reset(self, ip: str) -> None:
        """Clear on success, so one bad day does not lock out a real operator."""
        self._buckets.pop(ip, None)

    def retry_after(self, ip: str, *, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        bucket = self._buckets.get(ip)
        if bucket is None or not bucket.attempts:
            return 0
        self._prune(bucket, now)
        if len(bucket.attempts) < self._max_attempts:
            return 0
        return max(1, int(self._window - (now - min(bucket.attempts))))


login_throttle = LoginThrottle()
