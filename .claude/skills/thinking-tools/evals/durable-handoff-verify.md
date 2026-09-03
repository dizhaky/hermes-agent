# Eval cases (moved from SKILL.md)

## Verify it works
- Scripted 3-step task: checkpoint after step 1, kill the session; in a fresh
  session, resume must reconstruct the goal, mark step 1 done, and start step 2
  without redoing step 1.
- Checkpoint twice → one record updated, not two (idempotency).
- Feed a checkpoint with a falsely-marked-done item → resume catches it at the
  verify step.
- Schema lint: the written record parses back into all required fields.
