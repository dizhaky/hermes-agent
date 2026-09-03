---
name: temporal-facts
description: >-
  [AUTO] Use when a fact changes, a correction arrives, or when writing
  to Memory Gateway / vault CRM — close the old version with a start/end
  and a source receipt instead of overwriting in place. Do not install
  Utopia; this is the fleet write rule.
---

# Temporal facts

Memory Gateway is present-tense (Neo4j + Qdrant). It has no rewind.
Git history on the vault is the real timeline. Still: **never silently
overwrite a living fact.** Close it, then open the new one, and point
both at the sentence they came from.

Related REF (do not install): [Utopia](https://github.com/deeplethe/utopia)
(bitemporal graph, one Rust binary + Postgres, v0.1).

## Receipt on every write

Every Gateway write includes:

- `valid_from:` ISO date (when it became true, or when we learned it)
- `valid_until:` ISO date or `open`
- `source:` URL, note path, quote, or message — the sentence it came from
- MCP `provenance` field set to that same source when the tool accepts it

A fact without a source is a rumor. Do not store rumors.

## Close, don't overwrite

Stable title stays the same (`PREF:: …`, `DECISION:: …`, `PROJ:: …`).

1. **Search** by that title first.
2. **Unchanged** → no-op.
3. **New** → `write` with `valid_from`, `valid_until: open`, `source`.
4. **Changed** → `write` a CLOSED copy of the old body
   (`valid_until:` today, same source plus `closed_because:`), then
   `update` the live `memory_id` with the new body, new `valid_from`,
   and the new source. Do not `delete`.
5. **CANON** → never delete; never overwrite without the closed copy.

Vault CRM (`People/`, `Companies/`): append a dated log line. Do not
rewrite history in place. One phone key. No concatenated dates.

## What this is not

Do not stand up Utopia, a second Postgres, or a second knowledge plane.
Do not restore LiteLLM or the OpenRouter key.
