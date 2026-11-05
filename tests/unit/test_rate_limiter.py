"""Tests for the sliding-window rate limiter."""
from datetime import datetime, timedelta

from siem.alerting.rate_limiter import SlidingWindowRateLimiter

T0 = datetime(2026, 10, 17, 10, 0, 0)


def test_allows_up_to_max():
    rl = SlidingWindowRateLimiter(3, window_seconds=60)
    assert rl.allow(T0) is True
    assert rl.allow(T0) is True
    assert rl.allow(T0) is True
    assert rl.allow(T0) is False


def test_window_slides():
    rl = SlidingWindowRateLimiter(2, window_seconds=60)
    rl.allow(T0)
    rl.allow(T0)
    assert rl.allow(T0) is False
    # after the window passes, capacity is restored
    assert rl.allow(T0 + timedelta(seconds=61)) is True


def test_remaining():
    rl = SlidingWindowRateLimiter(3, window_seconds=60)
    assert rl.remaining(T0) == 3
    rl.allow(T0)
    assert rl.remaining(T0) == 2


def test_reset():
    rl = SlidingWindowRateLimiter(1, window_seconds=60)
    assert rl.allow(T0) is True
    assert rl.allow(T0) is False
    rl.reset()
    assert rl.allow(T0) is True
