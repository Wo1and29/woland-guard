"""Tests for the process-local agent request limiter."""

from woland_guard_control_plane.application.rate_limit import AgentRateLimiter


def test_rate_limiter_is_keyed_by_agent_and_recovers_after_window() -> None:
    """Each public ID has an independent bounded window."""

    current_time = 100.0

    def clock() -> float:
        return current_time

    limiter = AgentRateLimiter(max_requests=1, window_seconds=10, clock=clock)

    assert limiter.consume("agent-a") is None
    assert limiter.consume("agent-a") == 10
    assert limiter.consume("agent-b") is None

    current_time = 111.0
    assert limiter.consume("agent-a") is None


def test_rate_limiter_reset_clears_all_keys() -> None:
    """Reset removes the current process-local counters."""

    limiter = AgentRateLimiter(max_requests=1, window_seconds=60)
    assert limiter.consume("agent") is None
    assert limiter.consume("agent") is not None

    limiter.reset()

    assert limiter.consume("agent") is None
