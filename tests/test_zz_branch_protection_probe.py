"""THROWAWAY — branch-protection probe. DO NOT MERGE.

This file exists only to make CI red on a short-lived pull request, so that the
PR's ``mergeable_state`` can distinguish ``blocked`` (the ``All required checks
pass`` aggregator IS a required status check) from ``unstable`` (it is not).

It has no purpose in this repository. It is deleted along with its branch as
soon as the reading is taken. If you are reading this on ``main``, the teardown
failed — delete the file.

Raises AssertionError directly rather than using ``assert False`` so it fails
the test lane without also tripping a lint rule the auto-fix bot might rewrite.
"""


def test_deliberate_failure_for_branch_protection_probe() -> None:
    raise AssertionError(
        "deliberate failure — branch-protection probe; see module docstring"
    )
