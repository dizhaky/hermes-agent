"""Regression tests for StepFun region inference (CodeQL
``py/incomplete-url-substring-sanitization``).

``_infer_stepfun_region`` used ``if "api.stepfun.com" in normalized``, so a
lookalike host such as ``api.stepfun.com.example.net`` inferred ``china``. It
now parses the host and compares it exactly.
"""

import pytest

from hermes_cli.main import _infer_stepfun_region


class TestStepFunRegionInference:
    """Host is matched exactly, not by substring."""

    def test_real_china_endpoint(self):
        assert _infer_stepfun_region("https://api.stepfun.com/step_plan/v1") == "china"

    def test_real_international_endpoint(self):
        assert (
            _infer_stepfun_region("https://api.stepfun.ai/step_plan/v1") == "international"
        )

    @pytest.mark.parametrize(
        "url",
        [
            "https://api.stepfun.com.example.net/step_plan/v1",
            "https://evil.example/?next=https://api.stepfun.com/step_plan/v1",
            "https://api.stepfun.com.evil.example/v1",
        ],
    )
    def test_lookalike_hosts_are_not_china(self, url):
        assert _infer_stepfun_region(url) == "international"

    @pytest.mark.parametrize("url", ["", None, "   "])
    def test_empty_input_defaults_to_international(self, url):
        assert _infer_stepfun_region(url) == "international"

    def test_bare_host_without_scheme(self):
        assert _infer_stepfun_region("api.stepfun.com") == "china"

    def test_trailing_dot_host_is_normalized(self):
        assert _infer_stepfun_region("https://api.stepfun.com./v1") == "china"

    @pytest.mark.parametrize("url", ["https://[foo", "https://[::1", "http://["])
    def test_malformed_netloc_does_not_raise(self, url):
        """Inference must stay total — the caller shows a picker afterwards.

        `urlparse(...).hostname` raises ValueError on a malformed netloc, and
        these values arrive unvalidated from STEPFUN_BASE_URL / model.base_url.
        The substring implementation this replaced never raised.
        """
        assert _infer_stepfun_region(url) == "international"
