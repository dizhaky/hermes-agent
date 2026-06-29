---
name: ugw-health-check
description: Checks whether the Hermes Unified Gateway process is healthy by reading ~/.hermes/gateway_state.json and verifying the recorded PID is alive. Detects stale state files left by SIGKILL or OOM kills.
version: 1.0.0
platforms: [linux, macos]
metadata:
  hermes:
    tags: [devops, gateway, health, monitoring, ops]
    related_skills: []
---

# UGW Health Check

Standalone script that reports the health status of the Hermes Unified Gateway process.

## What it checks

1. Reads `~/.hermes/gateway_state.json` (or `$HERMES_HOME/gateway_state.json`)
2. Verifies the `gateway_state` field (`running`, `degraded`, etc.)
3. Checks that the recorded PID is still alive via `os.kill(pid, 0)` — catches stale state files left by SIGKILL or OOM kills

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Gateway is running and healthy |
| 1 | CRITICAL — not running, stale state, or state file missing |
| 2 | DEGRADED — running with warnings |

## Usage

```bash
# Run directly
python3 ugw-health-check.py

# Install to scripts directory
cp ugw-health-check.py ~/.hermes/scripts/ugw-health-check.py
chmod +x ~/.hermes/scripts/ugw-health-check.py
~/.hermes/scripts/ugw-health-check.py
```

## Requirements

- Python 3.9+
- No external dependencies — uses only the standard library

## Example output

```
Unified Gateway OK
Status: RUNNING (report_type: gateway_state_check)
Active agents: 2
Platforms: slack:connected, telegram:connected
PID: 12345 | Last updated: 5s ago
```

```
Unified Gateway CRITICAL
Status: CRITICAL (process dead — stale state file, PID 12345 not running)
Last updated: 2m 30s ago
Platforms: slack:connected
```
