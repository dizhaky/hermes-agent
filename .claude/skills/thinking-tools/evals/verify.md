# Eval cases (moved from SKILL.md)

## Verify it works
- Rigged matrix where B dominates on every criterion → B wins regardless of
  weights.
- Near-tie case → sensitivity reports a small flip-point and the verdict says
  "near-tie".
- Change weights after scoring → the skill refuses / re-scores clean.
- Transitive tournament (A>B>C) → A wins the bracket.
- Arithmetic audit: weighted totals recompute by hand.
