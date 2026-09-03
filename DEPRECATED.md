# Deprecated for Dan's fleet

**Status:** this fork is no longer part of Dan Izhaky's agent fleet, as of 2026-09-03.

This says nothing about [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent)
upstream, which is a live open-source project. It is a statement about `dizhaky/hermes-agent`
only: the gateway, cron fleet and skill-sync arms that used to run against this fork are
retired, and nothing in Dan's infrastructure reads from it any more.

## For agents and automation

Do not sync into this repository. In particular:

- `bin/sync-skills` in [dizhaky/dotfiles](https://github.com/dizhaky/dotfiles) used to copy the
  canonical portable skills from `.claude/skills/` into a hermes-agent checkout. That arm is
  disabled; `HERMES_AGENT_DIR` is ignored unless `SYNC_SKILLS_ALLOW_HERMES=1` is set explicitly.
- Do not open PRs here to keep `.claude/skills/` in step with dotfiles. The last such sync was
  [#221](https://github.com/dizhaky/hermes-agent/pull/221) (`0713858`), which merged on
  2026-09-03 shortly *after* the deprecation, from a session that did not have the decision.
  It was left in place rather than reverted — a frozen repo's contents do not matter — but it
  should be the last one.

## What was retired

The Hermes gateway and cron fleet ran only on mfc1 (`hermes-gateway.service`), with the Macs as
tunnel clients. Related tracking: DAN-3253 (canceled — the sync it describes shipped as #221 but
is no longer wanted).

dotfiles still carries a `hermes/` skill mirror, the `books-health-loop` cron doc and related
config. Removing those is decommission work that has not been scheduled.
