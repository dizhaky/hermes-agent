---
name: harness-engineering
description: >-
  [AUTO] Use when an agent fails, loops, forgets decisions, uses the wrong
  tool, skips verification, or when standing up / scoring any agent setup.
  Improve the environment around the model (contract, map, tools, durable
  state, sensors, permissions, traces) instead of swapping the prompt or
  model first. Applies to every bot.
---

# Harness engineering

When an agent fails, do **not** start by changing the prompt, swapping the
model, or widening the context window. Inspect the system around the model.

The model only reasons and proposes. The **harness** decides what it can
see, what it can touch, what survives a session, what counts as evidence,
and when the run must stop.

Prompt engineering improves the instruction.
Harness engineering improves the conditions under which the instruction
is executed.

Source: [rari, Harness Engineering](https://x.com/i/article/2093441687989186560)
(2026-08-29). Also [OpenAI](https://openai.com/index/harness-engineering/)
and [Anthropic](https://www.anthropic.com/engineering/harness-design-long-running-apps).

## Seven jobs

1. **Contract** — before acting, bound the ask: goal, inputs, output,
   constraints, done-when. Stops silent redefinition of success.
2. **Map** — a small root guide that says where to look. Load detail only
   when the current task needs it. A giant dump consumes context.
3. **Tools** — every tool has a purpose, predictable output, explicit
   failure state, and a permission boundary. Bad tools make the model guess.
4. **Durable state** — decisions, artifacts, failures, and open risks live
   outside the chat. The next session inherits state, not a retelling.
5. **Sensors before autonomy** — tests, linters, logs, screenshots, schema
   checks. The model makes an artifact; the environment produces evidence;
   the harness decides if that is enough to continue.
6. **Permissions outside the model** — the model recommends; the harness
   authorizes. Do not let the same system invent, approve, and execute an
   expensive or irreversible action.
7. **Traces and local recovery** — every run leaves a readable trail.
   Failure upgrades a guide, test, tool, or policy — not only this output.

## Encode rules twice

First as guidance the agent can understand. Then as a mechanical check it
cannot bypass. The guide explains why. The check enforces the boundary.

## Loop

`keep trying until it works` is not a control system. A useful loop has
evidence, a retry cap, a budget, and an escalation path. The model repairs
the local gap. The harness decides whether another attempt is allowed.

## Change receipt

When a run finishes, keep a compact receipt: context sources, tools used,
tests, retries, cost, accepted artifact, rollback point. Do not keep only
the final output.

## Temporal facts (receipt + when)

Load skill `temporal-facts`. Close the old version; do not overwrite.
Every Gateway write carries `valid_from` / `valid_until` and a source
receipt. Related REF (do not install):
[Utopia](https://github.com/deeplethe/utopia).

## Failure → infrastructure

| Class | Harness change |
|---|---|
| Missing context | Add a map or retrieval rule |
| Wrong tool | Improve tool description or routing |
| Bad output | Add a validator or stronger contract |
| Repeated loop | Add a retry cap and escalation |
| Unsafe action | Add a permission gate |
| Lost decision | Store it in durable state |
| Unknown failure | Add tracing and evidence capture |

## Checklist (before trusting real work)

- [ ] Success defined before execution
- [ ] Agent can find the right project knowledge without loading everything
- [ ] Every tool has a contract and a failure state
- [ ] Execution isolated from production where possible
- [ ] Important decisions stored outside the conversation
- [ ] Risky transitions have evidence
- [ ] Irreversible actions protected by approval
- [ ] Every loop has a retry cap and budget
- [ ] Run can resume after interruption
- [ ] Tool calls and state changes are explainable
- [ ] Failure updates a guide, test, tool, or policy
- [ ] Final artifact can be rolled back

If several answers are no, a stronger model only makes the failure more
expensive.

## Fleet score (Dan, 2026-09-03)

Score the live Grok / Claude / Codex / Cursor setup, not the wish list.

| Job | Score | Notes |
|---|---|---|
| Contract | 6/10 | `unlazy` / `GATES.md` on substantial work; not every ask gets done-when |
| Map | 8/10 | `AGENTS.md`, vault folder map, skill routing |
| Tools | 7/10 | MCP + Auto-review; some tools fail opaquely (OpenRouter 401 as "ingest failed") |
| Durable state | 8/10 | Vault + Memory Gateway; chat is not SoT |
| Sensors | 6/10 | CI, health listener; Mac disk-audit fixture flood is noise |
| Permissions | 8/10 | Auto-review, never send without draft, don't restore OpenRouter |
| Traces | 5/10 | Daily ops diary, merge-only vault; per-run change receipts are weak |

Gaps to close: per-run change receipts; more rules as checks not prose;
Mac Pro not always on local-exec; Mac `kb-daemon` still pointed at
disabled OpenRouter (mfc1 is on Ollama Cloud GLM 5.2).

Do not restore LiteLLM or the OpenRouter key. Do not treat Air vault-git
or Air disk as in-scope.
