#!/usr/bin/env python3
"""
Unified Gateway (UGW) Health Check
====================================
Standalone script — no dependency on the hermes agent codebase.

Reads ~/.hermes/gateway_state.json and reports the gateway health status.

Exit codes:
  0 = running (healthy)
  1 = critical / not running
  2 = degraded (warning)

Install:
  cp ugw-health-check.py ~/.hermes/scripts/ugw-health-check.py
  chmod +x ~/.hermes/scripts/ugw-health-check.py
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


_HERMES_HOME = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
_STATE_FILE = _HERMES_HOME / "gateway_state.json"

# Valid gateway_state values as defined in gateway/status.py
_HEALTHY_STATES = {"running"}
_DEGRADED_STATES = {"degraded"}
# Everything else (starting, draining, stopped, startup_failed) is CRITICAL


def _read_state() -> dict | None:
    """Read and parse gateway_state.json, returning None on any failure."""
    if not _STATE_FILE.exists():
        return None
    try:
        raw = _STATE_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _format_uptime(start_time: int | None) -> str:
    """Return a human-readable uptime string, or 'unknown' if unavailable."""
    if start_time is None:
        return "unknown"
    # start_time is a kernel clock-tick value from /proc/<pid>/stat — not a
    # Unix timestamp. We cannot convert it to a wall-clock duration without
    # knowing the boot time, so we fall back to the file's updated_at field
    # (which is a real ISO timestamp) for a rough "last updated" indicator.
    return f"start_time tick={start_time}"


def _format_uptime_from_updated(updated_at: str | None) -> str:
    """Return a human-readable age from an ISO timestamp string."""
    if not updated_at:
        return "unknown"
    try:
        dt = datetime.fromisoformat(updated_at)
        age_s = int((datetime.now(timezone.utc) - dt).total_seconds())
        if age_s < 0:
            age_s = 0
        hours, rem = divmod(age_s, 3600)
        minutes, seconds = divmod(rem, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    except (ValueError, TypeError):
        return "unknown"


def _format_platforms(platforms: dict) -> str:
    """Return a compact platform summary string."""
    if not platforms:
        return "(none)"
    parts = []
    for name, info in platforms.items():
        state = info.get("state", "unknown")
        parts.append(f"{name}:{state}")
    return ", ".join(parts)


def main() -> int:
    data = _read_state()

    if data is None:
        print("Unified Gateway CRITICAL")
        print(f"Status: CRITICAL (gateway_state_check: state file not found or unreadable)")
        print(f"State file: {_STATE_FILE}")
        return 1

    gateway_state = data.get("gateway_state", "unknown")
    pid = data.get("pid")
    active_agents = data.get("active_agents", 0)
    platforms = data.get("platforms", {})
    start_time = data.get("start_time")
    updated_at = data.get("updated_at")
    exit_reason = data.get("exit_reason")

    platform_summary = _format_platforms(platforms)
    uptime = _format_uptime_from_updated(updated_at)

    if gateway_state in _HEALTHY_STATES:
        print("Unified Gateway OK")
        print(f"Status: RUNNING (report_type: gateway_state_check)")
        print(f"Active agents: {active_agents}")
        print(f"Platforms: {platform_summary}")
        print(f"PID: {pid} | Last updated: {uptime} ago")
        return 0

    elif gateway_state in _DEGRADED_STATES:
        print("Unified Gateway DEGRADED")
        print(f"Status: DEGRADED (gateway_state: {gateway_state})")
        print(f"Active agents: {active_agents}")
        print(f"Platforms: {platform_summary}")
        print(f"PID: {pid} | Last updated: {uptime} ago")
        if exit_reason:
            print(f"Exit reason: {exit_reason}")
        return 2

    else:
        print("Unified Gateway CRITICAL")
        print(f"Status: CRITICAL (gateway_state: {gateway_state})")
        if exit_reason:
            print(f"Exit reason: {exit_reason}")
        print(f"PID: {pid} | Last updated: {uptime} ago")
        print(f"Platforms: {platform_summary}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
