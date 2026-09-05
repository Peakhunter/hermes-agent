"""Tests for staged inactivity timeout in gateway agent runs.

Tests cover:
- Warning fires once when inactivity reaches gateway_timeout_warning threshold
- Warning does not fire when gateway_timeout is 0 (unlimited)
- Warning fires only once per run, not on every poll
- Full timeout still fires at gateway_timeout threshold
- Warning respects HERMES_AGENT_TIMEOUT_WARNING env var
- Warning disabled when gateway_timeout_warning is 0
"""

import concurrent.futures
import os
import sys
import time
from pathlib import Path

from gateway.run import (
    _SuspendAwareInactivityWindow,
    _build_gateway_inactivity_timeout_message,
)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class FakeAgent:
    """Mock agent with controllable activity summary for timeout tests."""

    def __init__(self, idle_seconds=0.0, activity_desc="tool_call",
                 current_tool=None, api_call_count=5, max_iterations=90):
        self._idle_seconds = idle_seconds
        self._activity_desc = activity_desc
        self._current_tool = current_tool
        self._api_call_count = api_call_count
        self._max_iterations = max_iterations
        self._interrupted = False
        self._interrupt_msg = None

    def get_activity_summary(self):
        return {
            "last_activity_ts": time.time() - self._idle_seconds,
            "last_activity_desc": self._activity_desc,
            "seconds_since_activity": self._idle_seconds,
            "current_tool": self._current_tool,
            "api_call_count": self._api_call_count,
            "max_iterations": self._max_iterations,
        }

    def interrupt(self, msg):
        self._interrupted = True
        self._interrupt_msg = msg

    def run_conversation(self, prompt):
        return {"final_response": "Done", "messages": []}


class SlowFakeAgent(FakeAgent):
    """Agent that runs for a while, then goes idle."""

    def __init__(self, run_duration=0.5, idle_after=None, **kwargs):
        super().__init__(**kwargs)
        self._run_duration = run_duration
        self._idle_after = idle_after
        self._start_time = None

    def get_activity_summary(self):
        summary = super().get_activity_summary()
        if self._idle_after is not None and self._start_time:
            elapsed = time.time() - self._start_time
            if elapsed > self._idle_after:
                idle_time = elapsed - self._idle_after
                summary["seconds_since_activity"] = idle_time
                summary["last_activity_desc"] = "api_call_streaming"
            else:
                summary["seconds_since_activity"] = 0.0
        return summary

    def run_conversation(self, prompt):
        self._start_time = time.time()
        time.sleep(self._run_duration)
        return {"final_response": "Completed after work", "messages": []}


class TestStagedInactivityWarning:
    """Test the staged inactivity warning before full timeout."""

    def test_warning_fires_once_before_timeout(self):
        """Warning fires when inactivity reaches warning threshold."""
        agent = SlowFakeAgent(
            run_duration=0.6,
            idle_after=0.05,
            activity_desc="api_call_streaming",
        )

        _agent_timeout = 20.0
        _agent_warning = 0.15
        _POLL_INTERVAL = 0.05

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = pool.submit(agent.run_conversation, "test prompt")
        _inactivity_timeout = False
        _warning_fired = False
        _warning_send_count = 0

        while True:
            done, _ = concurrent.futures.wait({future}, timeout=_POLL_INTERVAL)
            if done:
                result = future.result()
                break
            _idle_secs = 0.0
            if hasattr(agent, "get_activity_summary"):
                try:
                    _act = agent.get_activity_summary()
                    _idle_secs = _act.get("seconds_since_activity", 0.0)
                except Exception:
                    pass
            if (not _warning_fired and _agent_warning > 0
                    and _idle_secs >= _agent_warning):
                _warning_fired = True
                _warning_send_count += 1
            if _idle_secs >= _agent_timeout:
                _inactivity_timeout = True
                break

        pool.shutdown(wait=False, cancel_futures=True)

        assert _warning_fired
        assert _warning_send_count == 1
        assert not _inactivity_timeout



    def test_full_timeout_still_fires_after_warning(self):
        """Full timeout fires even after warning was sent."""
        agent = SlowFakeAgent(
            run_duration=5.0,
            idle_after=0.05,
            activity_desc="waiting for provider response (streaming)",
        )

        _agent_timeout = 0.4
        _agent_warning = 0.15
        _POLL_INTERVAL = 0.05

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = pool.submit(agent.run_conversation, "test")
        _inactivity_timeout = False
        _warning_fired = False

        while True:
            done, _ = concurrent.futures.wait({future}, timeout=_POLL_INTERVAL)
            if done:
                future.result()
                break
            _idle_secs = 0.0
            if hasattr(agent, "get_activity_summary"):
                try:
                    _act = agent.get_activity_summary()
                    _idle_secs = _act.get("seconds_since_activity", 0.0)
                except Exception:
                    pass
            if (not _warning_fired and _agent_warning > 0
                    and _idle_secs >= _agent_warning):
                _warning_fired = True
            if _idle_secs >= _agent_timeout:
                _inactivity_timeout = True
                break

        pool.shutdown(wait=False, cancel_futures=True)
        assert _warning_fired
        assert _inactivity_timeout


class TestSleepAwareTimeoutDiagnostics:
    def test_suspend_gap_resets_active_runtime_inactivity(self):
        window = _SuspendAwareInactivityWindow(wall_time=100.0, monotonic_time=50.0)

        assert window.observe(wall_time=31190.0, monotonic_time=52.0) == 31088.0
        assert window.effective_idle_seconds(31090.0, monotonic_time=52.0) == 0.0
        assert window.effective_idle_seconds(31210.0, monotonic_time=72.0) == 20.0

    def test_normal_scheduler_delay_is_not_system_suspension(self):
        window = _SuspendAwareInactivityWindow(wall_time=100.0, monotonic_time=50.0)

        assert window.observe(wall_time=110.0, monotonic_time=60.0) == 0.0
        assert window.effective_idle_seconds(10.0, monotonic_time=60.0) == 10.0

    def test_activity_after_wake_clears_suspension_attribution(self):
        window = _SuspendAwareInactivityWindow(wall_time=100.0, monotonic_time=50.0)
        window.observe(wall_time=31190.0, monotonic_time=52.0)

        window.observe_activity(last_activity_at=31191.0)

        assert window.suspension_gap_seconds == 0.0
        assert window.effective_idle_seconds(1800.0, monotonic_time=1852.0) == 1800.0

    def test_timeout_message_reports_measured_idle_not_threshold(self):
        message = _build_gateway_inactivity_timeout_message(
            {
                "last_activity_desc": "starting API call #10",
                "seconds_since_activity": 31088.0,
                "api_call_count": 10,
                "max_iterations": 90,
            },
            timeout=1800.0,
        )

        assert "8h 38m" in message
        assert "30 min inactivity limit" in message
        assert "Agent inactive for 30 min" not in message

    def test_sleep_recovery_does_not_recommend_raising_timeout(self):
        message = _build_gateway_inactivity_timeout_message(
            {
                "last_activity_desc": "starting API call #10",
                "seconds_since_activity": 32888.0,
                "api_call_count": 10,
                "max_iterations": 90,
            },
            timeout=1800.0,
            suspension_gap_seconds=31088.0,
            active_idle_seconds=1800.0,
        )

        assert "system sleep or hibernation" in message
        assert "interrupted" in message
        assert "increase the limit" not in message
        assert "gateway_timeout" not in message





