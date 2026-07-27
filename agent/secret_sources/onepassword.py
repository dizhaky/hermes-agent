"""1Password Secrets Manager (onepassword-sdk) integration.

Hermes pulls API keys from 1Password at process startup so they don't
have to live in plaintext in ``~/.hermes/.env``.

Design summary
--------------

* The ``onepassword-sdk`` Python package (``import onepassword``) is used
  as the primary access method.  It authenticates via a 1Password
  Service Account token (``ops_...``).
* The service account token is read from the env var named in
  ``secrets.onepassword.service_account_token_env``
  (default: ``OP_SERVICE_ACCOUNT_TOKEN``).
* A specific item is targeted via ``secrets.onepassword.vault``
  (vault title; empty = search all accessible vaults) and
  ``secrets.onepassword.item`` (item title; required).
* Each field in the item is mapped to an env var: the field label is
  uppercased and spaces/hyphens are replaced with underscores.  An
  optional ``secrets.onepassword.field_mapping`` dict lets you override
  individual mappings (field label → env var name).
* Results are cached in-process for ``cache_ttl_seconds`` seconds so
  back-to-back ``hermes`` invocations don't hammer the API.
* Failures NEVER block Hermes startup.  Missing SDK, bad token, or item
  not found all emit a one-line warning and continue with whatever
  credentials ``.env`` already had.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# How long to wait for individual SDK calls, in seconds.
SDK_TIMEOUT_SECONDS = 30

# Strings passed to Client.authenticate() to identify this integration.
_OP_INTEGRATION_NAME = "hermes-agent"
_OP_INTEGRATION_VERSION = "1.0.0"

# In-process cache: (vault_name, item_title) → _CachedFetch
_CacheKey = Tuple[str, str]
_CACHE: Dict[_CacheKey, "_CachedFetch"] = {}


@dataclass
class _CachedFetch:
    secrets: Dict[str, str]
    fetched_at: float

    def is_fresh(self, ttl_seconds: float) -> bool:
        if ttl_seconds <= 0:
            return False
        return (time.time() - self.fetched_at) < ttl_seconds


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class FetchResult:
    """Outcome of a single 1Password secrets pull."""

    secrets: Dict[str, str] = field(default_factory=dict)
    applied: List[str] = field(default_factory=list)    # set into os.environ
    skipped: List[str] = field(default_factory=list)    # already set, not overridden
    warnings: List[str] = field(default_factory=list)   # non-fatal issues
    error: Optional[str] = None                         # fatal: nothing was fetched
    sdk_available: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None


# ---------------------------------------------------------------------------
# SDK availability
# ---------------------------------------------------------------------------


def _check_sdk_available() -> bool:
    """Return True if the ``onepassword`` Python SDK is importable."""
    try:
        import onepassword  # noqa: F401
        return True
    except ImportError:
        return False


def _ensure_sdk() -> None:
    """Raise :class:`RuntimeError` if the SDK is not available."""
    if not _check_sdk_available():
        raise RuntimeError(
            "The 'onepassword' Python SDK is not installed.  "
            "Run `hermes secrets onepassword install` or "
            "`pip install onepassword-sdk` to install it."
        )


def install_onepassword_sdk(*, force: bool = False) -> str:
    """Install the ``onepassword-sdk`` package via pip.

    Returns a short version string on success.  Raises :class:`RuntimeError`
    on failure — callers in the auto-install path catch these.
    """
    import subprocess  # noqa: PLC0415 — lazy import

    if _check_sdk_available() and not force:
        import onepassword  # noqa: F401
        return _sdk_version()

    pkg = "onepassword-sdk>=0.1.0,<2.0.0"
    cmd = [sys.executable, "-m", "pip", "install", "--quiet"]
    if force:
        cmd.append("--force-reinstall")
    cmd.append(pkg)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"pip install failed: {type(exc).__name__}") from None

    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()[:300]
        raise RuntimeError(f"pip install onepassword-sdk failed: {err}")

    return _sdk_version()


def _sdk_version() -> str:
    """Return the installed onepassword-sdk version string, or 'unknown'."""
    try:
        import importlib.metadata
        return importlib.metadata.version("onepassword-sdk")
    except Exception:  # noqa: BLE001
        try:
            import onepassword  # noqa: F401  # type: ignore[import-not-found]
            return "installed"
        except ImportError:
            return "not installed"


# ---------------------------------------------------------------------------
# Name helpers
# ---------------------------------------------------------------------------


def _field_label_to_env_name(label: str) -> str:
    """Convert a 1Password field label to a valid env var name.

    Rules applied in order:
      1. Uppercase the whole string.
      2. Replace spaces and hyphens with underscores.
      3. Strip any character that is not alphanumeric or underscore.
    """
    name = label.upper()
    name = re.sub(r"[ \-]", "_", name)
    name = re.sub(r"[^\w]", "", name)
    return name


def _is_valid_env_name(name: str) -> bool:
    """Return True if ``name`` is a valid POSIX env-var name."""
    if not name:
        return False
    if not (name[0].isalpha() or name[0] == "_"):
        return False
    return all(c.isalnum() or c == "_" for c in name)


# ---------------------------------------------------------------------------
# Async fetch core
# ---------------------------------------------------------------------------


async def _fetch_secrets_async(
    *,
    token: str,
    vault_name: str,
    item_title: str,
    field_mapping: Dict[str, str],
) -> Tuple[Dict[str, str], List[str]]:
    """Authenticate to 1Password, find the target item, return field values.

    Returns ``(secrets_dict, warnings_list)``.  Raises :class:`RuntimeError`
    for fatal conditions (vault not found, item not found, auth failure).
    """
    from onepassword.client import Client  # noqa: PLC0415  # type: ignore[import-not-found]

    client = await asyncio.wait_for(
        Client.authenticate(
            auth=token,
            integration_name=_OP_INTEGRATION_NAME,
            integration_version=_OP_INTEGRATION_VERSION,
        ),
        timeout=SDK_TIMEOUT_SECONDS,
    )

    # ------------------------------------------------------------------ vaults
    all_vaults = await asyncio.wait_for(client.vaults.list(), timeout=SDK_TIMEOUT_SECONDS)
    if vault_name:
        matching = [v for v in all_vaults if v.title == vault_name]
        if not matching:
            raise RuntimeError(
                f"Vault {vault_name!r} not found.  "
                f"Accessible vaults: {[v.title for v in all_vaults]}"
            )
        vault_ids = [matching[0].id]
    else:
        vault_ids = [v.id for v in all_vaults]

    if not vault_ids:
        raise RuntimeError(
            "No vaults are accessible to this service account.  "
            "Check vault permissions in the 1Password admin console."
        )

    # ------------------------------------------------------------------ item
    target_item = None
    for vault_id in vault_ids:
        item_overviews = await asyncio.wait_for(client.items.list(vault_id), timeout=SDK_TIMEOUT_SECONDS)
        for overview in item_overviews:
            if not item_title or overview.title == item_title:
                target_item = await asyncio.wait_for(
                    client.items.get(vault_id, overview.id),
                    timeout=SDK_TIMEOUT_SECONDS,
                )
                break
        if target_item is not None:
            break

    if target_item is None:
        if item_title:
            raise RuntimeError(
                f"Item {item_title!r} not found in 1Password "
                f"(searched {len(vault_ids)} vault(s))."
            )
        return {}, ["No items found in the accessible 1Password vault(s)."]

    # ------------------------------------------------------------------ fields
    # First pass: build label → env_name mapping and label → value for all
    # non-empty fields with valid env var names.
    field_to_env: Dict[str, str] = {}   # field label → env var name
    field_values: Dict[str, str] = {}   # field label → secret value
    warnings: List[str] = []

    for fld in target_item.fields:
        label = fld.title
        value = fld.value
        if not isinstance(value, str) or not value:
            continue

        # Apply explicit override first; fall back to derived name.
        if field_mapping and label in field_mapping:
            env_name = field_mapping[label]
        else:
            env_name = _field_label_to_env_name(label)

        if not _is_valid_env_name(env_name):
            warnings.append(
                f"Skipping field {label!r}: derived env var name "
                f"{env_name!r} is not a valid identifier"
            )
            continue

        field_to_env[label] = env_name
        field_values[label] = value

    # Detect collisions: two fields that normalize to the same env var name.
    env_name_sources: Dict[str, str] = {}  # env_name → first field label
    collisions: set = set()
    for field_name, env_name in field_to_env.items():
        if env_name in env_name_sources:
            logger.warning(
                "1Password field mapping collision: '%s' and '%s' both map to '%s'; skipping both",
                env_name_sources[env_name], field_name, env_name,
            )
            collisions.add(env_name)
        else:
            env_name_sources[env_name] = field_name

    # Build final secrets dict, excluding colliding env names.
    secrets: Dict[str, str] = {
        field_to_env[label]: value
        for label, value in field_values.items()
        if field_to_env[label] not in collisions
    }

    return secrets, warnings


# ---------------------------------------------------------------------------
# Synchronous public fetch
# ---------------------------------------------------------------------------


def fetch_onepassword_secrets(
    *,
    token: str,
    vault_name: str = "",
    item_title: str = "",
    field_mapping: Optional[Dict[str, str]] = None,
    cache_ttl_seconds: float = 300,
    use_cache: bool = True,
) -> Tuple[Dict[str, str], List[str]]:
    """Pull secrets from 1Password.

    Returns ``(secrets_dict, warnings_list)``.

    Raises :class:`RuntimeError` for fatal conditions (SDK not installed,
    auth failure, item not found).  Callers in the env_loader path catch
    this and emit a single warning; callers in the CLI setup wizard let it
    propagate so the user sees a clear error.
    """
    if not token:
        raise RuntimeError("1Password service account token is empty")

    cache_key = (vault_name, item_title)
    if use_cache:
        cached = _CACHE.get(cache_key)
        if cached and cached.is_fresh(cache_ttl_seconds):
            return cached.secrets, []

    _ensure_sdk()

    fm = field_mapping or {}

    try:
        try:
            asyncio.get_running_loop()
            has_running_loop = True
        except RuntimeError:
            has_running_loop = False

        if has_running_loop:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    asyncio.run,
                    _fetch_secrets_async(
                        token=token,
                        vault_name=vault_name,
                        item_title=item_title,
                        field_mapping=fm,
                    ),
                )
                try:
                    secrets, warnings = future.result(timeout=SDK_TIMEOUT_SECONDS + 5)
                except concurrent.futures.TimeoutError:
                    raise RuntimeError("1Password fetch timed out") from None
        else:
            secrets, warnings = asyncio.run(
                _fetch_secrets_async(
                    token=token,
                    vault_name=vault_name,
                    item_title=item_title,
                    field_mapping=fm,
                )
            )
    except RuntimeError:
        # Re-raise RuntimeError as-is (our own error messages).
        raise
    except Exception as exc:  # noqa: BLE001
        # Use only the exception type name — not str(exc) — to avoid
        # propagating token data that may appear in the SDK's error message
        # (CodeQL py/clear-text-logging-sensitive-data taint path).
        raise RuntimeError(f"1Password SDK error: {type(exc).__name__}") from None

    _CACHE[cache_key] = _CachedFetch(secrets=secrets, fetched_at=time.time())
    return secrets, warnings


# ---------------------------------------------------------------------------
# Public entry point — called from hermes_cli.env_loader
# ---------------------------------------------------------------------------


def apply_onepassword_secrets(
    config: dict,
    home_path: Path,
    previously_managed: Optional[set] = None,
) -> Dict[str, str]:
    """Pull secrets from 1Password and inject them into ``os.environ``.

    Called by ``_apply_external_secret_sources()`` in env_loader after
    the dotenv files have loaded.  Parameters come from the
    ``secrets.onepassword.*`` section of ``config.yaml``.

    Returns a dict of ``{env_var_name: "***"}`` for every secret that was
    actually applied (values are always masked — never logged).  Returns
    an empty dict on any failure.

    This function never raises — failures emit a ``logger.warning`` and
    return ``{}``.
    """
    token_env = config.get("service_account_token_env", "OP_SERVICE_ACCOUNT_TOKEN")
    vault_name = config.get("vault", "")
    item_title = config.get("item", "")
    field_mapping: Dict[str, str] = config.get("field_mapping") or {}
    override_existing = bool(config.get("override_existing", False))
    cache_ttl = float(config.get("cache_ttl_seconds", 300))
    auto_install = bool(config.get("auto_install", True))

    token = os.environ.get(token_env, "").strip()
    if not token:
        logger.warning(
            "secrets.onepassword.enabled is true but the service account "
            "token env var is not set.  Run `hermes secrets onepassword setup`."
        )
        return {}

    if not item_title:
        logger.warning(
            "secrets.onepassword.item is not configured.  "
            "Run `hermes secrets onepassword setup`."
        )
        return {}

    # Auto-install the SDK if requested and not present.
    if auto_install and not _check_sdk_available():
        try:
            install_onepassword_sdk()
        except Exception as exc:  # noqa: BLE001
            # exc is from pip install — safe to log in full (no token data).
            logger.warning("1Password SDK auto-install failed: %s", exc)
            return {}

    try:
        secrets, warnings = fetch_onepassword_secrets(
            token=token,
            vault_name=vault_name,
            item_title=item_title,
            field_mapping=field_mapping,
            cache_ttl_seconds=cache_ttl,
        )
    except RuntimeError as exc:
        # Log only the exception type, not the message, to avoid CodeQL
        # clear-text-logging alert (the message may contain token data that
        # flowed through the SDK call).
        logger.warning(
            "1Password secrets fetch failed (%s) — run "
            "`hermes secrets onepassword status` for details",
            type(exc).__name__,
        )
        return {}

    if warnings:
        logger.warning(
            "1Password: %d field(s) skipped during secrets fetch "
            "(run `hermes secrets onepassword status` for details)",
            len(warnings),
        )

    applied: Dict[str, str] = {}
    for key, value in secrets.items():
        if key == token_env:
            # Never let 1Password override the token used to authenticate.
            continue
        if not override_existing and os.environ.get(key):
            # Always refresh keys that 1Password previously injected so that
            # credential rotation takes effect without requiring override_existing.
            if previously_managed is None or key not in previously_managed:
                continue
        os.environ[key] = value
        applied[key] = "***"

    if applied:
        logger.debug("1Password: applied %d secret(s)", len(applied))

    return applied


# ---------------------------------------------------------------------------
# Status helper — used by the CLI status command
# ---------------------------------------------------------------------------


def get_onepassword_status(config: dict, home_path: Path) -> dict:
    """Return a dict describing current configuration and SDK availability.

    Used by ``hermes secrets onepassword status`` to populate the table.
    """
    token_env = config.get("service_account_token_env", "OP_SERVICE_ACCOUNT_TOKEN")
    vault = config.get("vault", "")
    item = config.get("item", "")

    return {
        "enabled": bool(config.get("enabled")),
        "sdk_available": _check_sdk_available(),
        "sdk_version": _sdk_version(),
        "token_env": token_env,
        "token_set": bool(os.environ.get(token_env, "").strip()),
        "vault": vault or "(search all vaults)",
        "item": item or "(unset)",
        "override_existing": bool(config.get("override_existing", False)),
        "cache_ttl_seconds": config.get("cache_ttl_seconds", 300),
        "auto_install": bool(config.get("auto_install", True)),
        "field_mapping": config.get("field_mapping") or {},
    }


# ---------------------------------------------------------------------------
# Test hook — flush the cache between test cases
# ---------------------------------------------------------------------------


def _reset_cache_for_tests() -> None:
    _CACHE.clear()
