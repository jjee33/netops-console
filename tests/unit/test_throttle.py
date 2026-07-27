from __future__ import annotations

from app.modules.auth.throttle import LoginThrottle


class TestLoginThrottle:
    def test_allows_traffic_below_the_limit(self) -> None:
        throttle = LoginThrottle(max_attempts=3, window_seconds=60)
        for _ in range(2):
            throttle.record_failure("10.0.0.1", now=100.0)
        assert throttle.is_limited("10.0.0.1", now=100.0) is False

    def test_blocks_at_the_limit(self) -> None:
        throttle = LoginThrottle(max_attempts=3, window_seconds=60)
        for _ in range(3):
            throttle.record_failure("10.0.0.1", now=100.0)
        assert throttle.is_limited("10.0.0.1", now=100.0) is True

    def test_the_window_slides(self) -> None:
        throttle = LoginThrottle(max_attempts=3, window_seconds=60)
        for _ in range(3):
            throttle.record_failure("10.0.0.1", now=100.0)

        assert throttle.is_limited("10.0.0.1", now=159.0) is True
        assert throttle.is_limited("10.0.0.1", now=161.0) is False

    def test_addresses_are_tracked_independently(self) -> None:
        """Otherwise one noisy source locks out every other operator."""
        throttle = LoginThrottle(max_attempts=2, window_seconds=60)
        throttle.record_failure("10.0.0.1", now=1.0)
        throttle.record_failure("10.0.0.1", now=2.0)

        assert throttle.is_limited("10.0.0.1", now=3.0) is True
        assert throttle.is_limited("10.0.0.2", now=3.0) is False

    def test_success_clears_the_counter(self) -> None:
        """A real operator who mistypes several times then succeeds should not
        stay throttled."""
        throttle = LoginThrottle(max_attempts=3, window_seconds=60)
        for _ in range(3):
            throttle.record_failure("10.0.0.1", now=1.0)
        throttle.reset("10.0.0.1")
        assert throttle.is_limited("10.0.0.1", now=2.0) is False

    def test_retry_after_counts_down(self) -> None:
        throttle = LoginThrottle(max_attempts=2, window_seconds=60)
        throttle.record_failure("10.0.0.1", now=100.0)
        throttle.record_failure("10.0.0.1", now=100.0)

        assert throttle.retry_after("10.0.0.1", now=100.0) == 60
        assert throttle.retry_after("10.0.0.1", now=130.0) == 30

    def test_retry_after_is_zero_when_not_limited(self) -> None:
        throttle = LoginThrottle(max_attempts=3, window_seconds=60)
        assert throttle.retry_after("10.0.0.9", now=1.0) == 0

    def test_tracking_is_bounded(self) -> None:
        """Cycling source addresses must not grow the map without limit."""
        throttle = LoginThrottle(max_attempts=2, window_seconds=60)
        for index in range(12_000):
            throttle.record_failure(f"10.1.{index // 256}.{index % 256}", now=1.0)
        assert len(throttle._buckets) <= 10_000
