# Eval cases (moved from SKILL.md)

## Verify it works
- Feed a decaying log `(5,4,2,1,0,0)` → STOP fires at the second zero / rolling
  crossing.
- Feed a steady-high log → CONTINUE.
- Feed all-zeros → FIX-GENERATOR, not STOP.
- Override the threshold → the new threshold is respected.

