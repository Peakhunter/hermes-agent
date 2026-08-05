"""
Buzz Platform Adapter for Hermes Agent.

A plugin-based gateway adapter that connects to a Buzz community relay
(Block's open-source human+agent collaboration platform, built on the
Nostr protocol) and relays messages to/from the Hermes agent.

The adapter does not speak Nostr itself — it shells out to the ``buzz``
CLI binary ("JSON in, JSON out") via ``asyncio.create_subprocess_exec``.
Inbound delivery uses a poll loop (the CLI is request/response); see the
"Known limitations" note in the platform docs.

Configuration in config.yaml::

    gateway:
      platforms:
        buzz:
          enabled: true
          extra:
            relay_url: https://mycommunity.communities.buzz.xyz
            channels:                  # channel UUIDs to watch (empty = all joined)
              - ccc2bc1a-7a82-5a8f-8c4e-57a070cbe7cd
            home_channel: ccc2bc1a-7a82-5a8f-8c4e-57a070cbe7cd
            poll_interval: 4           # seconds between poll sweeps
            activity_owner_pubkey: ""  # owner npub/hex for encrypted activity
            cli_path: ""               # path to the buzz binary (default: PATH, then ~/bin/buzz)
            credentials_file: ""       # JSON file holding the nsec (fallback for BUZZ_PRIVATE_KEY)
            allowed_users: []          # secure default: deny unless allow_all_users is true

Or via environment variables (overrides config.yaml):
    BUZZ_RELAY_URL, BUZZ_CHANNELS, BUZZ_HOME_CHANNEL, BUZZ_POLL_INTERVAL,
    BUZZ_CLI_PATH, BUZZ_CREDENTIALS_FILE, BUZZ_ALLOWED_USERS,
    BUZZ_ALLOW_ALL_USERS

The only secret is BUZZ_PRIVATE_KEY (nsec or hex) — it belongs in
``~/.hermes/.env``.  It is passed to the CLI via the subprocess
environment and is never logged.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from agent.secret_scope import UnscopedSecretError as _UnscopedSecretError
from agent.secret_scope import get_secret as _scoped_get_secret


def _get_scoped_secret(name, default=None):
    """Scope-aware credential read with the default-profile startup fallback.

    Secondary profiles construct their adapters under a profile secret
    scope -- the scope is authoritative and a scoped miss returns ``default``
    (no cross-profile borrow from ``os.environ``, which may hold another
    profile's value). The DEFAULT profile's adapter constructs and sends
    *unscoped* under multiplexing, where a bare ``get_secret`` would raise
    ``UnscopedSecretError`` and crash this path; there ``os.environ`` is that
    profile's own value, so fall back to it. Same pattern as the Slack
    ``SLACK_APP_TOKEN`` read (#59739) and
    ``gateway/platforms/whatsapp_common.py::_get_wsecret``.
    """
    try:
        val = _scoped_get_secret(name, default)
    except _UnscopedSecretError:
        val = os.getenv(name)
    return val if val is not None else default


logger = logging.getLogger(__name__)

from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
    cache_image_from_bytes,
    validate_inbound_media_size,
)
from gateway.config import Platform


# Buzz chat messages are Nostr kind 9 events.  ``buzz messages get`` also
# returns housekeeping kinds (joins, canvas updates, …) — only kind 9 is
# dispatched to the agent.
_CHAT_KIND = 9
# How many events to request per poll / seed call.
_FETCH_LIMIT = 50
# Bound on the per-channel de-dupe set (events, not bytes).
_SEEN_CAP = 500
# Re-run DM discovery (``dms list`` plus the channels-list fallback) every
# N poll sweeps to pick up conversations opened mid-run.
_DM_DISCOVERY_EVERY = 5

_DEFAULT_POLL_INTERVAL = 4.0
_MIN_POLL_INTERVAL = 1.0
_CLI_TIMEOUT = 30.0

_BUZZ_MARKDOWN_IMAGE_RE = re.compile(r"!\[[^\]\r\n]*\]\((https?://[^)\s]+)\)")
_BUZZ_MEDIA_IMAGE_PATH_RE = re.compile(
    r"/media/([0-9a-f]{64})\.(png|jpe?g|gif|webp|bmp)",
    re.IGNORECASE,
)
_BUZZ_IMAGE_MIME = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
    "bmp": "image/bmp",
}
_MAX_BUZZ_IMAGES_PER_MESSAGE = 4

# WebSocket transport (NIP-42 authenticated Nostr subscription).
# kind 44100 is Buzz's channel-membership event — used for live DM discovery.
_WS_AUTH_TIMEOUT = 20.0
_WS_MAX_MESSAGE_BYTES = 2_000_000
_WS_MEMBERSHIP_KIND = 44100
_WS_MEMBERSHIP_SUB_ID = "hermes-buzz-membership"
_ACTIVITY_QUEUE_SIZE = 256
_ACTIVITY_SEND_TIMEOUT = 2.0
_ACTIVITY_ACK_TIMEOUT = 30.0
_ACTIVITY_PENDING_CAP = 1024
_ACTIVITY_TERMINAL_REPLAY_CAP = 256
_ACTIVITY_TERMINAL_KINDS = frozenset({"turn_completed", "turn_error"})

_FALSE_VALUES = frozenset({"false", "0", "no", "off"})
_YAML_BRIDGE_MARKER_PREFIX = "_HERMES_YAML_BRIDGED_"

# Where to look for a credentials JSON (keys: nsec / private_key_hex) when
# BUZZ_PRIVATE_KEY is not set.  Module-level so tests can point it at a tmpdir.
_DEFAULT_CREDENTIALS_DIR = Path("~/.config/buzz").expanduser()


def _load_nostr_auth():
    """Import the sibling nostr_auth module in a loader-agnostic way.

    The adapter is imported both as a package module
    (``plugins.platforms.buzz.adapter``) and as a bare single-file module by
    the test plugin loader, where relative imports have no parent package.
    """
    try:
        from . import nostr_auth  # type: ignore[no-redef]

        return nostr_auth
    except ImportError:
        import importlib.util

        path = Path(__file__).with_name("nostr_auth.py")
        spec = importlib.util.spec_from_file_location("plugin_adapter_buzz_nostr_auth", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


# ---------------------------------------------------------------------------
# bech32 (BIP-173) helpers — used to convert between npub and hex pubkeys so
# mention detection and allow-lists accept either form.  Pure stdlib.
# ---------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: List[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def hex_to_npub(pubkey_hex: str) -> Optional[str]:
    """Encode a 64-char hex pubkey as an ``npub1…`` bech32 string."""
    try:
        raw = bytes.fromhex(pubkey_hex)
    except ValueError:
        return None
    if len(raw) != 32:
        return None
    data = _convertbits(raw, 8, 5)
    if data is None:
        return None
    values = _bech32_hrp_expand("npub") + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return "npub1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)


def npub_to_hex(npub: str) -> Optional[str]:
    """Decode an ``npub1…`` bech32 string to a 64-char hex pubkey."""
    npub = npub.strip().lower()
    if not npub.startswith("npub1"):
        return None
    data_part = npub[len("npub1"):]
    try:
        data = [_BECH32_CHARSET.index(c) for c in data_part]
    except ValueError:
        return None
    if _bech32_polymod(_bech32_hrp_expand("npub") + data) != 1:
        return None
    decoded = _convertbits(data[:-6], 5, 8, pad=False)
    if decoded is None or len(decoded) != 32:
        return None
    return bytes(decoded).hex()


def normalize_user_ref(ref: str) -> Optional[str]:
    """Normalize a user reference (hex pubkey or npub) to lowercase hex."""
    ref = (ref or "").strip().lower()
    if not ref:
        return None
    if ref.startswith("npub1"):
        return npub_to_hex(ref)
    if re.fullmatch(r"[0-9a-f]{64}", ref):
        return ref
    return None


# Backward-compatible private alias for existing plugin imports.
_normalize_user_ref = normalize_user_ref


# ---------------------------------------------------------------------------
# buzz-cli invocation helpers
# ---------------------------------------------------------------------------

_MEMBER_MENTION_ERROR_RE = re.compile(
    r"mention '(@.+?)' (?:does not match a current channel member|is ambiguous)",
    re.IGNORECASE,
)
_MAX_MENTIONS_ERROR = "too many unique message mentions"
_OUTBOUND_MENTION_RE = re.compile(r"(?<![\w@])@(?=[^\s@])")
_MENTION_FALLBACK_MAX_RETRIES = 3


def _unresolved_mention_fallback(content: str, error: str) -> Optional[str]:
    """Return readable text after a Buzz outbound mention-validation error."""
    error = error or ""
    match = _MEMBER_MENTION_ERROR_RE.search(error)
    if match:
        mention = match.group(1)
        fallback = re.sub(
            rf"(?<![\w@]){re.escape(mention)}",
            mention[1:],
            content or "",
            flags=re.IGNORECASE,
        )
    elif _MAX_MENTIONS_ERROR in error.lower():
        fallback = _OUTBOUND_MENTION_RE.sub("", content or "")
    else:
        return None
    return fallback if fallback != content else None

def _resolve_cli_path(configured: str = "") -> str:
    """Resolve the buzz CLI binary path portably.

    Order: explicit config value → ``buzz`` on PATH → ``~/bin/buzz``.
    Returns "" when nothing is found so callers can raise a config error.
    """
    if configured:
        p = Path(configured).expanduser()
        return str(p) if p.is_file() else ""
    found = shutil.which("buzz")
    if found:
        return found
    fallback = Path.home() / "bin" / "buzz"
    return str(fallback) if fallback.is_file() else ""


def _resolve_private_key(extra: Optional[dict] = None) -> str:
    """Resolve the Nostr private key: env first, then a credentials JSON.

    NEVER log the return value.
    """
    key = _get_scoped_secret("BUZZ_PRIVATE_KEY", "").strip()
    if key:
        return key
    configured = os.getenv("BUZZ_CREDENTIALS_FILE", "").strip() or (extra or {}).get("credentials_file", "")
    if configured:
        candidates = [Path(configured).expanduser()]
    else:
        try:
            candidates = sorted(_DEFAULT_CREDENTIALS_DIR.glob("*credentials*.json"))
        except OSError:
            candidates = []
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        for field in ("nsec", "private_key_hex", "private_key"):
            value = data.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


async def _exec_buzz(
    cli_path: str,
    args: List[str],
    *,
    relay_url: str,
    private_key: str,
    input_text: Optional[str] = None,
    timeout: float = _CLI_TIMEOUT,
) -> Tuple[int, str, str]:
    """Run the buzz CLI with an argument list (never a shell) and return
    ``(returncode, stdout, stderr)``.

    The private key travels via the subprocess environment only — it never
    appears in argv, so process listings and error logs stay clean.
    """
    env = os.environ.copy()
    env["BUZZ_RELAY_URL"] = relay_url
    env["BUZZ_PRIVATE_KEY"] = private_key
    proc = await asyncio.create_subprocess_exec(
        cli_path,
        *args,
        stdin=asyncio.subprocess.PIPE if input_text is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input_text.encode("utf-8") if input_text is not None else None),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, "", json.dumps({"error": "timeout", "message": f"buzz {args[0] if args else ''} timed out after {timeout}s"})
    return (
        proc.returncode if proc.returncode is not None else 4,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


def _cli_error_message(stderr: str, returncode: int) -> str:
    """Extract the human-readable message from the CLI's JSON error contract.

    stderr is ``{"error": "<category>", "message": "<detail>"}`` on failure;
    fall back to the raw (stripped) stderr when it isn't JSON.
    """
    text = (stderr or "").strip()
    try:
        data = json.loads(text)
        if isinstance(data, dict) and data.get("message"):
            return f"{data.get('error', 'error')}: {data['message']} (exit {returncode})"
    except ValueError:
        pass
    return text or f"buzz CLI failed with exit code {returncode}"


def _parse_json_list(stdout: str) -> List[dict]:
    """Parse CLI stdout expected to be a JSON array of objects."""
    try:
        data = json.loads(stdout or "[]")
    except ValueError:
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _event_reply_target(event: dict) -> str:
    """Return the thread anchor referenced by a Buzz chat event."""
    tags = event.get("tags")
    if not isinstance(tags, list):
        return ""
    root_target = ""
    reply_target = ""
    for tag in tags:
        if not isinstance(tag, list) or len(tag) < 2 or tag[0] != "e":
            continue
        target = str(tag[1] or "")
        marker = str(tag[3] or "") if len(tag) > 3 else ""
        if marker == "root":
            root_target = target
        elif marker == "reply" or not marker:
            reply_target = target
    return root_target or reply_target


def _config_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() not in _FALSE_VALUES


def _bridge_yaml_env(env_name: str, value: Any) -> None:
    """Seed an env var while retaining whether YAML, not the operator, owns it."""
    marker = f"{_YAML_BRIDGE_MARKER_PREFIX}{env_name}"
    current = os.getenv(env_name)
    if current is None or os.getenv(marker) == current:
        bridged = str(value).lower()
        os.environ[env_name] = bridged
        os.environ[marker] = bridged


_RUNTIME_AUTHORIZATION_POLICY_CACHE: Dict[str, dict] = {}


def _copy_authorization_policy(policy: dict) -> dict:
    copied = dict(policy)
    if isinstance(copied.get("allowed_users"), list):
        copied["allowed_users"] = list(copied["allowed_users"])
    return copied


def _load_runtime_authorization_config(profile: Optional[str] = None) -> dict:
    """Resolve the live, profile-scoped Buzz access policy from config.yaml."""
    from hermes_cli.config import _expand_env_vars, read_user_config_raw
    from hermes_cli.managed_scope import apply_managed_overlay

    cache_key = profile or "default"

    try:
        if profile:
            from hermes_cli.profiles import get_profile_dir
            from hermes_constants import (
                reset_hermes_home_override,
                set_hermes_home_override,
            )

            token = set_hermes_home_override(str(get_profile_dir(profile)))
            try:
                config = read_user_config_raw()
            finally:
                reset_hermes_home_override(token)
        else:
            config = read_user_config_raw()
        # This policy is presence-sensitive: merged defaults would make an
        # absent key indistinguishable from an explicit deny. Expand user refs
        # and apply the administrator overlay without merging DEFAULT_CONFIG.
        expanded = _expand_env_vars(config)
        config = apply_managed_overlay(
            expanded if isinstance(expanded, dict) else {}
        )
    except Exception:
        logger.warning(
            "Buzz: retaining last valid runtime authorization policy",
            exc_info=True,
        )
        return _copy_authorization_policy(
            _RUNTIME_AUTHORIZATION_POLICY_CACHE.get(cache_key, {})
        )
    merged: Dict[str, Any] = {}

    def _merge(candidate: Any) -> None:
        if not isinstance(candidate, dict):
            return
        merged.update(
            {
                key: value
                for key, value in candidate.items()
                if key
                not in {"enabled", "token", "home_channel", "home_channels", "extra"}
            }
        )
        extra = candidate.get("extra")
        if isinstance(extra, dict):
            merged.update(extra)

    if isinstance(config, dict):
        gateway = config.get("gateway")
        gateway_platforms = (
            gateway.get("platforms") if isinstance(gateway, dict) else None
        )
        if isinstance(gateway_platforms, dict):
            _merge(gateway_platforms.get("buzz"))

        platforms = config.get("platforms")
        if isinstance(platforms, dict):
            _merge(platforms.get("buzz"))

        if isinstance(gateway, dict):
            _merge(gateway.get("buzz"))
        _merge(config.get("buzz"))

    policy: dict = {}
    if "allowed_users" in merged:
        raw_allowed = merged["allowed_users"]
        if isinstance(raw_allowed, str):
            raw_allowed = raw_allowed.split(",")
        if not isinstance(raw_allowed, (list, tuple)):
            raw_allowed = []
        policy["allowed_users"] = [
            normalized
            for entry in raw_allowed
            if isinstance(entry, str)
            and (normalized := _normalize_user_ref(entry))
        ]
    if "allow_all_users" in merged:
        policy["allow_all_users"] = merged["allow_all_users"]
    _RUNTIME_AUTHORIZATION_POLICY_CACHE[cache_key] = _copy_authorization_policy(
        policy
    )
    return _copy_authorization_policy(policy)


# ---------------------------------------------------------------------------
# Buzz Adapter
# ---------------------------------------------------------------------------

class BuzzAdapter(BasePlatformAdapter):
    """Poll-based Buzz adapter implementing the BasePlatformAdapter interface.

    Instantiated by the adapter_factory passed to register_platform().
    """

    def __init__(self, config, **kwargs):
        platform = Platform("buzz")
        super().__init__(config=config, platform=platform)

        extra = getattr(config, "extra", {}) or {}
        self._extra = extra

        # Connection settings (env vars override config.yaml)
        self.relay_url = (os.getenv("BUZZ_RELAY_URL") or extra.get("relay_url", "")).strip()
        self.cli_path = _resolve_cli_path(
            os.getenv("BUZZ_CLI_PATH", "").strip() or str(extra.get("cli_path", "") or "")
        )

        # Channels to watch: env csv > extra list/csv; empty = all joined channels
        raw_channels = os.getenv("BUZZ_CHANNELS") or extra.get("channels", [])
        if isinstance(raw_channels, str):
            raw_channels = raw_channels.split(",")
        self.channels: List[str] = [c.strip() for c in raw_channels if isinstance(c, str) and c.strip()]

        self.home_channel = (os.getenv("BUZZ_HOME_CHANNEL") or str(extra.get("home_channel", "") or "")).strip()

        try:
            interval = float(os.getenv("BUZZ_POLL_INTERVAL") or extra.get("poll_interval", _DEFAULT_POLL_INTERVAL))
        except (TypeError, ValueError):
            interval = _DEFAULT_POLL_INTERVAL
        self.poll_interval = max(_MIN_POLL_INTERVAL, interval)

        # Whether channel messages must @mention the agent to get a response.
        # Defaults to True (respond only when addressed). Set False to make the
        # agent respond to every message in a watched channel. DMs always
        # dispatch regardless. Env (BUZZ_REQUIRE_MENTION) overrides config.yaml.
        _rm_raw = os.getenv("BUZZ_REQUIRE_MENTION")
        if _rm_raw is None:
            _rm_cfg = extra.get("require_mention", True)
        else:
            _rm_cfg = _rm_raw
        self.require_mention = _config_bool(_rm_cfg)

        # Keep the historical strict behavior by default: replies in shared
        # channel threads must continue mentioning the agent. When disabled,
        # a thread remains addressed after the agent has replied once.
        _trm_raw = os.getenv("BUZZ_THREAD_REQUIRE_MENTION")
        if _trm_raw is None:
            _trm_cfg = extra.get("thread_require_mention", True)
        else:
            _trm_cfg = _trm_raw
        self.thread_require_mention = _config_bool(_trm_cfg)
        self._mention_config_signature: Optional[Tuple[int, int]] = None

        # Inbound transport: "auto" (WebSocket with poll fallback, default),
        # "websocket" (require WS; fail connect when it can't authenticate),
        # or "poll" (CLI polling only). Env (BUZZ_TRANSPORT) overrides
        # config.yaml.
        _transport = (
            os.getenv("BUZZ_TRANSPORT") or str(extra.get("transport", "auto") or "auto")
        ).strip().lower()
        self.transport = _transport if _transport in ("auto", "websocket", "poll") else "auto"

        # Optional native Gateway activity observer. The owner pubkey is a
        # routing/encryption setting (not a secret); an empty value keeps the
        # observer disabled without changing normal Buzz chat delivery.
        _activity_owner = str(extra.get("activity_owner_pubkey", "") or "").strip()
        self.activity_owner_pubkey = (
            _normalize_user_ref(_activity_owner) if _activity_owner else ""
        )
        if _activity_owner and not self.activity_owner_pubkey:
            raise ValueError(
                "Buzz activity_owner_pubkey must be a valid x-only secp256k1 "
                "public key encoded as 64 hex characters or npub"
            )
        if self.activity_owner_pubkey:
            try:
                self.activity_owner_pubkey = (
                    _load_nostr_auth().validate_x_only_public_key(
                        self.activity_owner_pubkey
                    )
                )
            except ValueError as exc:
                raise ValueError(
                    "Buzz activity_owner_pubkey must be a valid x-only "
                    "secp256k1 public key encoded as 64 hex characters or npub"
                ) from exc

        # Secret — resolved lazily (never at import/registration time and
        # never logged).  connect() re-resolves it to fail fast with a clear
        # error when it is missing.
        self._private_key: str = ""

        # Identity — filled in by connect() from ``buzz users get``
        self._self_pubkey: str = ""
        self._self_npub: str = ""
        self._display_name: str = ""

        # Runtime state
        self._poll_task: Optional[asyncio.Task] = None
        self._ws_task: Optional[asyncio.Task] = None
        self._ws_ready: Optional[asyncio.Event] = None
        self._ws_active = False  # True while the WS loop owns inbound delivery
        self._ws_connection: Any = None
        self._activity_seq = 0
        self._activity_ws_generation = 0
        self._activity_pending_event_ids: OrderedDict[
            str, tuple[int, asyncio.TimerHandle]
        ] = OrderedDict()
        self._activity_pending_terminal_payloads: OrderedDict[
            str, Dict[str, Any]
        ] = OrderedDict()
        self._activity_queue: asyncio.Queue = asyncio.Queue(maxsize=_ACTIVITY_QUEUE_SIZE)
        self._activity_sender_task: Optional[asyncio.Task] = None
        self._activity_terminal_replay: OrderedDict[str, Dict[str, Any]] = (
            OrderedDict()
        )
        self._membership_since = 0
        self._lock_key: Optional[str] = None
        # channel_id -> {"chat_type", "last_ts", "seen": OrderedDict[event_id, None]}
        self._channel_state: Dict[str, dict] = {}
        self._channel_names: Dict[str, str] = {}
        # channel_id -> raw ``channels list`` entry; drives DM-vs-channel
        # classification (see _may_reclassify_as_dm).
        self._channel_meta: Dict[str, dict] = {}
        self._user_names: Dict[str, str] = {}
        self._poll_count = 0

    @property
    def name(self) -> str:
        return "Buzz"

    # ── buzz-cli plumbing ─────────────────────────────────────────────────

    async def _run_cli(self, args: List[str], *, input_text: Optional[str] = None) -> Tuple[int, str, str]:
        if not self._private_key:
            self._private_key = _resolve_private_key(self._extra)
        return await _exec_buzz(
            self.cli_path,
            args,
            relay_url=self.relay_url,
            private_key=self._private_key,
            input_text=input_text,
        )

    # ── Connection lifecycle ──────────────────────────────────────────────

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        """Verify relay credentials, seed high-water marks, start polling."""
        if not self.relay_url:
            logger.error("Buzz: relay URL must be configured")
            self._set_fatal_error("config_missing", "BUZZ_RELAY_URL must be set", retryable=False)
            return False
        if not self.cli_path:
            logger.error("Buzz: buzz CLI binary not found (set BUZZ_CLI_PATH or put 'buzz' on PATH)")
            self._set_fatal_error("cli_missing", "buzz CLI binary not found", retryable=False)
            return False
        self._private_key = _resolve_private_key(self._extra)
        if not self._private_key:
            logger.error("Buzz: no private key (set BUZZ_PRIVATE_KEY or a credentials file)")
            self._set_fatal_error("config_missing", "BUZZ_PRIVATE_KEY must be set", retryable=False)
            return False

        # Learn our own identity: pubkey drives self-echo suppression and
        # display name drives channel mention gating.
        code, out, err = await self._run_cli(["users", "get"])
        if code != 0:
            message = _cli_error_message(err, code)
            logger.error("Buzz: failed to fetch own profile from %s — %s", self.relay_url, message)
            self._set_fatal_error("connect_failed", message, retryable=code == 2)
            return False
        profiles = _parse_json_list(out)
        if not profiles or not profiles[0].get("pubkey"):
            logger.error("Buzz: 'users get' returned no profile — is the key a member of this community?")
            self._set_fatal_error("connect_failed", "buzz users get returned no profile", retryable=True)
            return False
        self._self_pubkey = str(profiles[0]["pubkey"]).lower()
        self._display_name = str(profiles[0].get("display_name") or "").strip()
        self._self_npub = hex_to_npub(self._self_pubkey) or ""

        # Prevent two profiles from driving the same Buzz identity on the
        # same relay (duplicate replies, split de-dupe state). Mirrors the
        # IRC adapter's scoped-lock pattern.
        try:
            from gateway.status import acquire_scoped_lock

            lock_key = f"{self.relay_url}:{self._self_pubkey}"
            if not acquire_scoped_lock("buzz", lock_key):
                logger.error(
                    "Buzz: identity %s… on %s already in use by another profile",
                    self._self_pubkey[:8],
                    self.relay_url,
                )
                self._set_fatal_error(
                    "lock_conflict", "Buzz identity in use by another profile", retryable=False
                )
                return False
            self._lock_key = lock_key
        except ImportError:
            self._lock_key = None  # status module not available (e.g. tests)

        # Start the membership cursor before taking the joined-channel
        # snapshot. A join racing with startup is then present either in the
        # snapshot or in the membership subscription's inclusive overlap.
        if self.transport in ("auto", "websocket"):
            self._membership_since = int(time.time())

        # Map channel ids to names and pick the watch set.
        code, out, err = await self._run_cli(["channels", "list", "--member"])
        if code != 0:
            message = _cli_error_message(err, code)
            logger.error("Buzz: failed to list channels — %s", message)
            self._set_fatal_error("connect_failed", message, retryable=code == 2)
            return False
        listed = _parse_json_list(out)
        self._channel_names = {
            str(ch.get("channel_id")): str(ch.get("name") or ch.get("channel_id"))
            for ch in listed
            if ch.get("channel_id")
        }
        for ch in listed:
            if ch.get("channel_id"):
                self._channel_meta[str(ch["channel_id"])] = ch
        watch = self.channels or list(self._channel_names)
        if not watch:
            logger.error("Buzz: no channels to watch (configure BUZZ_CHANNELS or join a channel)")
            self._set_fatal_error("config_missing", "no Buzz channels to watch", retryable=False)
            return False

        # Seed high-water marks from the newest events so a (re)start never
        # replays channel history into the agent.
        for channel_id in watch:
            await self._seed_channel(channel_id, chat_type="group")
        await self._discover_dms(seed=True)

        # Inbound transport: prefer the NIP-42-authenticated WebSocket
        # subscription (push, near-zero latency); fall back to CLI polling
        # when the WS can't be established (transport="auto") or when the
        # user pinned transport="poll".
        transport_used = "poll"
        if self.transport in ("auto", "websocket"):
            if await self._start_websocket():
                transport_used = "websocket"
            elif self.transport == "websocket":
                self._set_fatal_error(
                    "ws_auth_failed",
                    "Buzz WebSocket transport did not authenticate (transport=websocket)",
                    retryable=True,
                )
                await self.disconnect()
                return False
        if transport_used == "poll":
            self._poll_task = asyncio.create_task(self._poll_loop())
        self._mark_connected()
        logger.info(
            "Buzz: connected to %s as %s, watching %d channel(s) via %s%s",
            self.relay_url,
            self._display_name or self._self_npub[:16],
            len(self._channel_state),
            transport_used,
            "" if transport_used == "websocket" else f", poll interval {self.poll_interval:.1f}s",
        )
        return True

    async def disconnect(self) -> None:
        """Stop the inbound transport and drop runtime state."""
        self._mark_disconnected()
        lock_key = getattr(self, "_lock_key", None)
        if lock_key:
            try:
                from gateway.status import release_scoped_lock

                release_scoped_lock("buzz", lock_key)
            except Exception:
                pass
            self._lock_key = None
        self._ws_active = False
        self._ws_connection = None
        if self._ws_task and not self._ws_task.done():
            self._ws_task.cancel()
            try:
                await self._ws_task
            except asyncio.CancelledError:
                pass
        self._ws_task = None
        await self._reset_activity_transport()
        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        self._poll_task = None
        self._channel_state = {}
        self._poll_count = 0

    # ── Sending ───────────────────────────────────────────────────────────

    @staticmethod
    def _remember_agent_thread_ids(state: dict, *event_ids: str) -> None:
        active = state.setdefault("agent_thread_ids", OrderedDict())
        for event_id in event_ids:
            if event_id:
                active[str(event_id)] = None
                active.move_to_end(str(event_id))
        while len(active) > _SEEN_CAP:
            active.popitem(last=False)

    @staticmethod
    def _remember_thread_root(state: dict, event_id: str, reply_target: str) -> None:
        if not event_id or not reply_target:
            return
        roots = state.setdefault("thread_roots", OrderedDict())
        root = reply_target
        visited = set()
        while root in roots and root not in visited:
            visited.add(root)
            root = roots[root]
        roots[str(event_id)] = str(root)
        roots.move_to_end(str(event_id))
        while len(roots) > _SEEN_CAP:
            roots.popitem(last=False)

    @staticmethod
    def _resolve_thread_root(state: dict, event_id: str) -> str:
        roots = state.get("thread_roots", {})
        root = str(event_id)
        visited = set()
        while root in roots and root not in visited:
            visited.add(root)
            root = str(roots[root])
        return root

    def _remember_event_thread_root(self, state: dict, event: dict) -> None:
        self._remember_thread_root(
            state,
            str(event.get("id") or ""),
            _event_reply_target(event),
        )

    def _remember_agent_thread_event(self, state: dict, event: dict) -> None:
        if str(event.get("pubkey") or "").lower() != self._self_pubkey:
            return
        event_id = str(event.get("id") or "")
        reply_target = _event_reply_target(event)
        if reply_target:
            root = self._resolve_thread_root(state, reply_target)
            self._remember_agent_thread_ids(state, root, event_id)
        else:
            # A user can start a thread by replying to one of the agent's
            # top-level events, so that event is itself a participated root.
            self._remember_agent_thread_ids(state, event_id)

    @staticmethod
    def _remember_pending_thread_event(state: dict, event: dict) -> None:
        event_id = str(event.get("id") or "")
        if not event_id:
            return
        pending = state.setdefault("pending_thread_events", OrderedDict())
        pending[event_id] = event
        pending.move_to_end(event_id)
        while len(pending) > _SEEN_CAP:
            pending.popitem(last=False)

    async def _retry_pending_thread_events(self, channel_id: str, state: dict) -> None:
        pending = state.get("pending_thread_events", {})
        active = state.get("agent_thread_ids", {})
        for event_id, event in list(pending.items()):
            reply_target = _event_reply_target(event)
            if not reply_target:
                pending.pop(event_id, None)
                continue
            root = self._resolve_thread_root(state, reply_target)
            if root not in active:
                continue
            pending.pop(event_id, None)
            state["seen"].pop(event_id, None)
            await self._handle_event(channel_id, state, event)
    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        if not content:
            return SendResult(success=False, error="Empty message")
        args = ["messages", "send", "--channel", str(chat_id), "--content", "-"]
        reply_target = reply_to or (metadata or {}).get("thread_id")
        state = self._channel_state.get(str(chat_id))
        if reply_target and state is not None:
            reply_target = self._resolve_thread_root(state, str(reply_target))
        if reply_target:
            args += ["--reply-to", str(reply_target)]
        send_content = content
        code, out, err = await self._run_cli(args, input_text=send_content)
        for _ in range(_MENTION_FALLBACK_MAX_RETRIES):
            fallback = (
                _unresolved_mention_fallback(send_content, err)
                if code != 0
                else None
            )
            if fallback is None:
                break
            logger.warning("Buzz: unresolved outbound mention; retrying as readable text")
            send_content = fallback
            code, out, err = await self._run_cli(args, input_text=send_content)
        if code != 0:
            return SendResult(
                success=False,
                error=_cli_error_message(err, code),
                retryable=code == 2,
            )
        try:
            data = json.loads(out or "{}")
        except ValueError:
            data = {}
        event_id = data.get("event_id")
        accepted = bool(data.get("accepted", True))
        if event_id and accepted:
            # Belt-and-braces echo suppression: the poll loop already skips
            # our own pubkey, but marking the id seen makes de-dupe explicit.
            self._mark_seen(str(chat_id), str(event_id))
            if state is not None:
                # Any accepted outbound event can become a thread root when a
                # user replies to it later, even when this send was top-level.
                if reply_target:
                    self._remember_thread_root(
                        state, str(event_id), str(reply_target)
                    )
                    self._remember_agent_thread_ids(
                        state, str(reply_target), str(event_id)
                    )
                else:
                    self._remember_agent_thread_ids(state, str(event_id))
        return SendResult(
            success=accepted,
            message_id=str(event_id) if event_id else None,
            raw_response=data,
        )

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        """Buzz has no typing indicator API — no-op."""
        pass

    def _enqueue_activity(
        self,
        kind: str,
        *,
        channel_id: Optional[str],
        session_id: Optional[str],
        turn_id: Optional[str],
        payload: Optional[Dict[str, Any]] = None,
        started_at: Optional[str] = None,
    ) -> bool:
        """Non-blocking, fail-open enqueue of one encrypted observer frame."""

        if not self.activity_owner_pubkey:
            return False
        self._activity_seq += 1
        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
        observer_payload: Dict[str, Any] = {
            "seq": self._activity_seq,
            "timestamp": timestamp,
            "kind": str(kind),
            "agentIndex": None,
            "channelId": str(channel_id) if channel_id is not None else None,
            "sessionId": str(session_id) if session_id is not None else None,
            "turnId": str(turn_id) if turn_id is not None else None,
            "payload": payload or {},
        }
        if started_at is not None:
            observer_payload["startedAt"] = str(started_at)
        websocket = self._ws_connection
        if not self._ws_active or websocket is None:
            return self._cache_terminal_activity(observer_payload)
        try:
            self._activity_queue.put_nowait(
                (self._activity_ws_generation, observer_payload)
            )
        except asyncio.QueueFull:
            if self._cache_terminal_activity(observer_payload):
                return True
            logger.debug("Buzz: observer activity queue full; dropping frame")
            return False
        if self._activity_sender_task is None or self._activity_sender_task.done():
            self._activity_sender_task = asyncio.create_task(self._activity_sender_loop())
        return True

    def _cache_terminal_activity(self, observer_payload: Dict[str, Any]) -> bool:
        """Retain only the latest terminal frame per turn across reconnects."""

        if str(observer_payload.get("kind") or "") not in _ACTIVITY_TERMINAL_KINDS:
            return False
        replay_key = str(
            observer_payload.get("turnId")
            or observer_payload.get("sessionId")
            or observer_payload.get("seq")
        )
        self._activity_terminal_replay[replay_key] = observer_payload
        self._activity_terminal_replay.move_to_end(replay_key)
        while len(self._activity_terminal_replay) > _ACTIVITY_TERMINAL_REPLAY_CAP:
            self._activity_terminal_replay.popitem(last=False)
        return True

    def _replay_terminal_activity(self) -> None:
        """Move bounded terminal frames onto the current WebSocket generation."""

        if not self._ws_active or self._ws_connection is None:
            return
        while self._activity_terminal_replay and not self._activity_queue.full():
            _, observer_payload = self._activity_terminal_replay.popitem(last=False)
            self._activity_queue.put_nowait(
                (self._activity_ws_generation, observer_payload)
            )
        if (
            not self._activity_queue.empty()
            and (
                self._activity_sender_task is None
                or self._activity_sender_task.done()
            )
        ):
            self._activity_sender_task = asyncio.create_task(
                self._activity_sender_loop()
            )

    async def publish_activity(
        self,
        kind: str,
        *,
        channel_id: Optional[str],
        session_id: Optional[str],
        turn_id: Optional[str],
        payload: Optional[Dict[str, Any]] = None,
        started_at: Optional[str] = None,
    ) -> bool:
        """Compatibility wrapper for direct adapter callers and focused tests."""

        return self._enqueue_activity(
            kind,
            channel_id=channel_id,
            session_id=session_id,
            turn_id=turn_id,
            payload=payload,
            started_at=started_at,
        )

    def _drop_activity_ack(self, event_id: str) -> bool:
        event_id = str(event_id)
        pending = self._activity_pending_event_ids.pop(event_id, None)
        self._activity_pending_terminal_payloads.pop(event_id, None)
        if pending is None:
            return False
        pending[1].cancel()
        return True

    def _expire_activity_ack(self, event_id: str, generation: int) -> None:
        event_id = str(event_id)
        pending = self._activity_pending_event_ids.get(event_id)
        if pending is None or pending[0] != generation:
            return
        self._activity_pending_event_ids.pop(event_id, None)
        self._activity_pending_terminal_payloads.pop(event_id, None)
        logger.debug("Buzz: observer activity ACK timed out")

    def _track_activity_ack(
        self,
        event_id: str,
        generation: int,
        observer_payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._drop_activity_ack(event_id)
        handle = asyncio.get_running_loop().call_later(
            _ACTIVITY_ACK_TIMEOUT,
            self._expire_activity_ack,
            str(event_id),
            generation,
        )
        event_id = str(event_id)
        self._activity_pending_event_ids[event_id] = (generation, handle)
        self._activity_pending_event_ids.move_to_end(event_id)
        if (
            observer_payload is not None
            and str(observer_payload.get("kind") or "")
            in _ACTIVITY_TERMINAL_KINDS
        ):
            self._activity_pending_terminal_payloads[event_id] = observer_payload
            self._activity_pending_terminal_payloads.move_to_end(event_id)
        while len(self._activity_pending_event_ids) > _ACTIVITY_PENDING_CAP:
            evicted_id, (_, evicted_handle) = self._activity_pending_event_ids.popitem(
                last=False
            )
            self._activity_pending_terminal_payloads.pop(evicted_id, None)
            evicted_handle.cancel()

    async def _activity_sender_loop(self) -> None:
        """Encrypt and send queued observer frames without blocking Gateway turns."""
        while True:
            generation, observer_payload = await self._activity_queue.get()
            event_id: Optional[str] = None
            try:
                websocket = self._ws_connection
                if (
                    not self._ws_active
                    or websocket is None
                    or generation != self._activity_ws_generation
                ):
                    self._cache_terminal_activity(observer_payload)
                    continue
                event = await asyncio.to_thread(
                    _load_nostr_auth().build_observer_event,
                    private_key=self._private_key,
                    owner_pubkey=str(self.activity_owner_pubkey),
                    payload=observer_payload,
                )
                if (
                    not self._ws_active
                    or websocket is not self._ws_connection
                    or generation != self._activity_ws_generation
                ):
                    self._cache_terminal_activity(observer_payload)
                    continue
                event_id = str(event["id"])
                # Track before send so a very fast relay OK cannot race ahead
                # of correlation state installation.
                self._track_activity_ack(event_id, generation, observer_payload)
                raw = json.dumps(["EVENT", event], separators=(",", ":"))
                await asyncio.wait_for(websocket.send(raw), timeout=_ACTIVITY_SEND_TIMEOUT)
            except asyncio.CancelledError:
                if event_id is not None:
                    self._drop_activity_ack(event_id)
                self._cache_terminal_activity(observer_payload)
                raise
            except Exception:
                if event_id is not None:
                    self._drop_activity_ack(event_id)
                self._cache_terminal_activity(observer_payload)
                logger.debug("Buzz: observer activity publication failed", exc_info=True)
            finally:
                self._activity_queue.task_done()
                # If a terminal frame was retained because the queue was full
                # or its old generation became stale, refill from the bounded
                # replay cache as capacity becomes available.
                self._replay_terminal_activity()

    async def _reset_activity_transport(self) -> None:
        """Invalidate one WebSocket generation and drop all of its activity."""
        self._activity_ws_generation += 1
        task = self._activity_sender_task
        self._activity_sender_task = None
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        while True:
            try:
                queued = self._activity_queue.get_nowait()
                if isinstance(queued, tuple) and len(queued) == 2:
                    self._cache_terminal_activity(queued[1])
                self._activity_queue.task_done()
            except asyncio.QueueEmpty:
                break
        for event_id in list(self._activity_pending_event_ids):
            payload = self._activity_pending_terminal_payloads.get(event_id)
            if payload is not None:
                self._cache_terminal_activity(payload)
            self._drop_activity_ack(event_id)

    async def send_reaction(self, chat_id: str, message_id: str, emoji: str) -> bool:
        """Add a reaction to a message via buzz-cli.

        Returns True on success, False on failure. Errors are logged but not
        raised — reactions are best-effort and should never block the main
        message flow.
        """
        if not self.cli_path or not emoji or not message_id:
            return False
        # buzz-cli: `reactions add --event <64-char hex event id> --emoji <e>`.
        # The event id IS the message_id we recorded on dispatch; channel is
        # not a parameter to this subcommand.
        args = [
            "reactions", "add",
            "--event", str(message_id),
            "--emoji", emoji,
        ]
        code, _out, err = await self._run_cli(args)
        if code != 0:
            logger.debug(
                "Buzz: reaction add failed for message %s in %s — %s",
                message_id[:12], chat_id, _cli_error_message(err, code),
            )
            return False
        return True

    async def send_image(
        self,
        chat_id: str,
        image_url: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send an image: local files upload via --file, URLs go as a link."""
        local = Path(image_url).expanduser() if not image_url.startswith(("http://", "https://")) else None
        if local is not None and local.is_file():
            args = [
                "messages", "send",
                "--channel", str(chat_id),
                "--file", str(local),
                "--content", "-",
            ]
            reply_target = reply_to or (metadata or {}).get("thread_id")
            state = self._channel_state.get(str(chat_id))
            if reply_target and state is not None:
                reply_target = self._resolve_thread_root(state, str(reply_target))
            if reply_target:
                args += ["--reply-to", str(reply_target)]
            send_content = caption or ""
            code, out, err = await self._run_cli(args, input_text=send_content)
            for _ in range(_MENTION_FALLBACK_MAX_RETRIES):
                fallback = (
                    _unresolved_mention_fallback(send_content, err)
                    if code != 0
                    else None
                )
                if fallback is None:
                    break
                logger.warning(
                    "Buzz: unresolved outbound caption mention; retrying as readable text"
                )
                send_content = fallback
                code, out, err = await self._run_cli(args, input_text=send_content)
            if code != 0:
                return SendResult(success=False, error=_cli_error_message(err, code), retryable=code == 2)
            try:
                data = json.loads(out or "{}")
            except ValueError:
                data = {}
            event_id = data.get("event_id")
            accepted = bool(data.get("accepted", True))
            if event_id and accepted:
                self._mark_seen(str(chat_id), str(event_id))
                if state is not None:
                    if reply_target:
                        self._remember_thread_root(
                            state, str(event_id), str(reply_target)
                        )
                        self._remember_agent_thread_ids(
                            state, str(reply_target), str(event_id)
                        )
                    else:
                        self._remember_agent_thread_ids(state, str(event_id))
            return SendResult(
                success=accepted,
                message_id=str(event_id) if event_id else None,
                raw_response=data,
            )
        # Markdown renders in Buzz, so a URL arrives as a clickable image link.
        text = f"{caption}\n{image_url}" if caption else image_url
        return await self.send(chat_id, text, reply_to=reply_to, metadata=metadata)

    async def send_image_file(
        self,
        chat_id: str,
        image_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """Upload a local image through Buzz's native ``--file`` path."""
        return await self.send_image(
            chat_id=chat_id,
            image_url=image_path,
            caption=caption,
            reply_to=reply_to,
            metadata=metadata,
        )

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        chat_id = str(chat_id)
        state = self._channel_state.get(chat_id)
        chat_type = state["chat_type"] if state else "group"
        name = self._channel_names.get(chat_id)
        if name is None and self.cli_path:
            code, out, _err = await self._run_cli(["channels", "get", "--channel", chat_id])
            if code == 0:
                try:
                    data = json.loads(out or "{}")
                    if isinstance(data, dict) and data.get("name"):
                        name = str(data["name"])
                        self._channel_names[chat_id] = name
                except ValueError:
                    pass
        return {"name": name or chat_id, "type": chat_type, "chat_id": chat_id}

    # ── Inbound: WebSocket transport (NIP-42 authenticated) ──────────────
    #
    # Push transport contributed in PR #73636 by @ScaleLeanChris, adapted to
    # dispatch through the same _handle_event() machinery as the poll loop so
    # de-dupe, mention gating, DM latching, and the allow-list behave
    # identically on both transports.

    def _websocket_url(self) -> str:
        parsed = urlsplit(self.relay_url.strip())
        scheme = {"http": "ws", "https": "wss"}.get(parsed.scheme, parsed.scheme)
        if scheme not in ("ws", "wss") or not parsed.netloc:
            raise ValueError("Buzz relay URL must use http(s) or ws(s)")
        return urlunsplit((scheme, parsed.netloc, parsed.path or "", parsed.query, ""))

    async def _start_websocket(self) -> bool:
        """Start the WS loop; True when it authenticates within the timeout."""
        try:
            import websockets  # noqa: F401  (availability probe)

            self._websocket_url()
        except Exception as e:
            logger.info("Buzz: WebSocket transport unavailable (%s); falling back to polling", e)
            return False
        self._ws_ready = asyncio.Event()
        if not self._membership_since:
            self._membership_since = int(time.time())
        self._ws_task = asyncio.create_task(self._websocket_loop())
        try:
            await asyncio.wait_for(self._ws_ready.wait(), timeout=_WS_AUTH_TIMEOUT + 5)
        except (asyncio.TimeoutError, TimeoutError):
            logger.warning("Buzz: WebSocket did not authenticate in time")
            self._ws_active = False
            if self._ws_task and not self._ws_task.done():
                self._ws_task.cancel()
                try:
                    await self._ws_task
                except asyncio.CancelledError:
                    pass
            self._ws_task = None
            return False
        return True

    async def _authenticate_websocket(self, websocket) -> None:
        """NIP-42: wait for the relay's AUTH challenge, answer with a signed
        kind-22242 event (plus the optional NIP-OA owner-attestation tag from
        BUZZ_AUTH_TAG), and wait for the OK acknowledgment."""
        build_auth_event = _load_nostr_auth().build_auth_event

        raw = await asyncio.wait_for(websocket.recv(), timeout=_WS_AUTH_TIMEOUT)
        message = json.loads(raw)
        if not isinstance(message, list) or len(message) < 2 or message[0] != "AUTH":
            raise ConnectionError("Buzz relay did not send a NIP-42 AUTH challenge")
        event = build_auth_event(
            private_key=self._private_key,
            challenge=str(message[1]),
            relay_url=self._websocket_url(),
            auth_tag_json=os.getenv("BUZZ_AUTH_TAG", ""),
        )
        await websocket.send(json.dumps(["AUTH", event], separators=(",", ":")))
        while True:
            raw = await asyncio.wait_for(websocket.recv(), timeout=_WS_AUTH_TIMEOUT)
            response = json.loads(raw)
            if not isinstance(response, list) or not response:
                continue
            if response[0] == "OK" and len(response) >= 4 and response[1] == event["id"]:
                if response[2] is True:
                    return
                raise ConnectionError(f"Buzz WebSocket AUTH rejected: {response[3]}")
            if response[0] in ("NOTICE", "CLOSED"):
                detail = response[-1] if len(response) > 1 else "authentication failed"
                raise ConnectionError(f"Buzz WebSocket AUTH failed: {detail}")

    async def _send_channel_subscription(self, websocket, subscription_id: str, channel_id: str) -> None:
        state = self._channel_state.get(channel_id) or {}
        since = max(int(state.get("last_ts") or time.time()) - 1, 0)
        request = [
            "REQ",
            subscription_id,
            {"kinds": [_CHAT_KIND], "#h": [channel_id], "since": since},
        ]
        await websocket.send(json.dumps(request, separators=(",", ":")))

    async def _subscribe_websocket(self, websocket) -> Dict[str, Optional[str]]:
        """Subscribe to every watched conversation plus membership events
        (kind 44100 p-tagged to us) for live DM discovery."""
        subscriptions: Dict[str, Optional[str]] = {}
        for index, channel_id in enumerate(list(self._channel_state)):
            subscription_id = f"hermes-buzz-{index}"
            subscriptions[subscription_id] = channel_id
            await self._send_channel_subscription(websocket, subscription_id, channel_id)
        if self._self_pubkey:
            request = [
                "REQ",
                _WS_MEMBERSHIP_SUB_ID,
                {
                    "kinds": [_WS_MEMBERSHIP_KIND],
                    "#p": [self._self_pubkey],
                    "since": max(self._membership_since - 1, 0),
                },
            ]
            await websocket.send(json.dumps(request, separators=(",", ":")))
            subscriptions[_WS_MEMBERSHIP_SUB_ID] = None
        return subscriptions

    async def _handle_membership_event(self, websocket, subscriptions: Dict[str, Optional[str]], event: dict) -> None:
        """Rediscover and subscribe after a membership event p-tagged to us."""
        event_since = max(int(event.get("created_at") or 0), 0)
        before = set(self._channel_state)
        if not await self._discover_joined_channels(since=event_since):
            raise ConnectionError("Buzz joined-channel discovery failed")
        self._membership_since = max(self._membership_since, event_since)
        await self._discover_dms(seed=False)
        for channel_id in self._channel_state:
            if channel_id in before:
                continue
            subscription_id = f"hermes-buzz-dm-{len(subscriptions)}"
            subscriptions[subscription_id] = channel_id
            await self._send_channel_subscription(websocket, subscription_id, channel_id)
            logger.info("Buzz: subscribed to new conversation %s", channel_id)

    def _handle_activity_ack(self, message: list) -> bool:
        """Correlate an observer EVENT acknowledgment and surface rejection."""
        if len(message) < 3 or message[0] != "OK":
            return False
        event_id = str(message[1])
        if not self._drop_activity_ack(event_id):
            return False
        if message[2] is not True:
            detail = str(message[3]) if len(message) > 3 else "relay rejected event"
            logger.warning("Buzz: observer activity rejected by relay: %s", detail)
        return True

    async def _websocket_loop(self) -> None:
        """Persistent authenticated subscription with bounded reconnect
        backoff. Events route through _handle_event() — identical semantics
        to the poll loop. On reconnect, per-channel `since` filters resume
        from the last observed timestamps (same-second overlap de-duped by
        event id)."""
        import websockets

        backoff = 1.0
        try:
            while True:
                try:
                    async with websockets.connect(
                        self._websocket_url(),
                        open_timeout=_WS_AUTH_TIMEOUT,
                        close_timeout=5,
                        ping_interval=20,
                        ping_timeout=20,
                        max_size=_WS_MAX_MESSAGE_BYTES,
                    ) as websocket:
                        await self._authenticate_websocket(websocket)
                        self._activity_ws_generation += 1
                        self._ws_connection = websocket
                        subscriptions = await self._subscribe_websocket(websocket)
                        self._ws_active = True
                        self._replay_terminal_activity()
                        if self._ws_ready is not None:
                            self._ws_ready.set()
                        backoff = 1.0
                        async for raw in websocket:
                            try:
                                message = json.loads(raw)
                            except (ValueError, TypeError):
                                logger.warning("Buzz: ignoring malformed WebSocket frame")
                                continue
                            if not isinstance(message, list) or not message:
                                continue
                            if message[0] == "EVENT" and len(message) >= 3:
                                subscription_id = str(message[1])
                                event = message[2]
                                if not isinstance(event, dict):
                                    continue
                                if subscription_id == _WS_MEMBERSHIP_SUB_ID:
                                    await self._handle_membership_event(websocket, subscriptions, event)
                                    continue
                                channel_id = subscriptions.get(subscription_id)
                                state = self._channel_state.get(channel_id or "")
                                if channel_id and state is not None:
                                    await self._handle_event(channel_id, state, event)
                                    self._trim_seen(state)
                            elif message[0] == "OK":
                                self._handle_activity_ack(message)
                            elif message[0] == "CLOSED":
                                detail = message[-1] if len(message) > 2 else "subscription closed"
                                raise ConnectionError(str(detail))
                            elif message[0] == "NOTICE":
                                logger.warning("Buzz: relay notice: %s", message[-1])
                    self._ws_active = False
                    self._ws_connection = None
                    await self._reset_activity_transport()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self._ws_active = False
                    self._ws_connection = None
                    await self._reset_activity_transport()
                    logger.warning("Buzz: WebSocket disconnected; retrying in %.1fs: %s", backoff, e)
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 30.0)
        finally:
            self._ws_active = False
            self._ws_connection = None
            await self._reset_activity_transport()

    # ── Inbound polling ───────────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        """Poll every watched channel for new events until cancelled."""
        try:
            while True:
                await asyncio.sleep(self.poll_interval)
                self._poll_count += 1
                try:
                    if self._poll_count % _DM_DISCOVERY_EVERY == 0:
                        await self._discover_dms(seed=False)
                    for channel_id in list(self._channel_state):
                        await self._poll_channel(channel_id)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.warning("Buzz: poll sweep failed", exc_info=True)
        except asyncio.CancelledError:
            raise

    async def _seed_channel(self, channel_id: str, chat_type: str) -> None:
        """Initialize a channel's high-water mark from its newest events."""
        state = {"chat_type": chat_type, "last_ts": 0, "seen": OrderedDict()}
        self._channel_state[channel_id] = state
        code, out, err = await self._run_cli(
            ["messages", "get", "--channel", channel_id, "--limit", str(_FETCH_LIMIT)]
        )
        if code != 0:
            logger.warning(
                "Buzz: could not seed channel %s — %s", channel_id, _cli_error_message(err, code)
            )
            # Fall back to "now" so a transiently unreadable channel does not
            # replay its whole history once it becomes readable.
            state["last_ts"] = int(time.time())
            return
        for event in _parse_json_list(out):
            event_id = event.get("id")
            created_at = int(event.get("created_at") or 0)
            if event_id:
                state["seen"][str(event_id)] = None
            state["last_ts"] = max(state["last_ts"], created_at)
            # History is never dispatched, but it still classifies: a DM that
            # leaked in via ``channels list`` latches to chat_type="dm" here,
            # so it bypasses the mention gate from the very first poll.
            self._maybe_latch_dm(channel_id, state, event)
            self._remember_event_thread_root(state, event)
            self._remember_agent_thread_event(state, event)
        self._trim_seen(state)

    async def _discover_joined_channels(self, *, since: int) -> bool:
        """Watch newly joined channels when no explicit allowlist is set."""
        if self.channels:
            return True
        code, out, err = await self._run_cli(["channels", "list", "--member"])
        if code != 0:
            logger.warning(
                "Buzz: failed to rediscover joined channels — %s",
                _cli_error_message(err, code),
            )
            return False
        for channel in _parse_json_list(out):
            channel_id = str(channel.get("channel_id") or "")
            if not channel_id:
                continue
            self._channel_meta[channel_id] = channel
            self._channel_names[channel_id] = str(channel.get("name") or channel_id)
            if channel_id in self._channel_state:
                continue
            self._channel_state[channel_id] = {
                "chat_type": "group",
                "last_ts": max(int(since), 0),
                "seen": OrderedDict(),
            }
        return True

    async def _discover_dms(self, *, seed: bool) -> None:
        """Watch DM conversations.  New ones found mid-run dispatch from their
        beginning (a fresh conversation has no history worth suppressing);
        ones present at startup are seeded like channels.

        ``dms list`` is only a best-effort source: on some hosted relays it
        returns ``[]`` even when DM conversations exist (#68871).  Those DMs
        DO surface in ``channels list`` as entries named "DM" with an empty
        description, so that listing is scanned as a fallback.  Fallback
        finds are watched as ``group`` and latch to ``dm`` via p-tag
        detection (_is_direct_message_event) rather than trusting the name
        alone to unlock the mention-free DM path.
        """
        code, out, _err = await self._run_cli(["dms", "list"])
        if code == 0:
            for dm in _parse_json_list(out):
                dm_id = str(dm.get("dm_id") or "")
                if not dm_id or dm_id in self._channel_state:
                    continue
                if seed:
                    await self._seed_channel(dm_id, chat_type="dm")
                else:
                    self._channel_state[dm_id] = {"chat_type": "dm", "last_ts": 0, "seen": OrderedDict()}
                self._channel_names.setdefault(dm_id, "DM")

        code, out, _err = await self._run_cli(["channels", "list"])
        if code != 0:
            return
        for ch in _parse_json_list(out):
            ch_id = str(ch.get("channel_id") or "")
            if not ch_id:
                continue
            self._channel_meta[ch_id] = ch
            self._channel_names.setdefault(ch_id, str(ch.get("name") or ch_id))
            if ch_id in self._channel_state or not self._may_reclassify_as_dm(ch_id):
                continue
            if seed:
                await self._seed_channel(ch_id, chat_type="group")
            else:
                self._channel_state[ch_id] = {"chat_type": "group", "last_ts": 0, "seen": OrderedDict()}

    async def _poll_channel(self, channel_id: str) -> None:
        state = self._channel_state.get(channel_id)
        if state is None:
            return
        args = ["messages", "get", "--channel", channel_id, "--limit", str(_FETCH_LIMIT)]
        if state["last_ts"]:
            # Nostr `since` is inclusive: same-second events are re-fetched
            # and de-duped by id below.
            args += ["--since", str(state["last_ts"])]
        code, out, err = await self._run_cli(args)
        if code != 0:
            logger.debug(
                "Buzz: poll of channel %s failed — %s", channel_id, _cli_error_message(err, code)
            )
            return
        for event in _parse_json_list(out):
            await self._handle_event(channel_id, state, event)
        self._trim_seen(state)

    async def _handle_event(self, channel_id: str, state: dict, event: dict) -> None:
        """De-dupe, filter, and dispatch a single ``messages get`` event."""
        self._refresh_mention_policy()
        event_id = str(event.get("id") or "")
        created_at = int(event.get("created_at") or 0)
        if not event_id or event_id in state["seen"]:
            return
        state["seen"][event_id] = None
        state["last_ts"] = max(state["last_ts"], created_at)

        if int(event.get("kind") or 0) != _CHAT_KIND:
            return
        pubkey = str(event.get("pubkey") or "").lower()
        content = event.get("content")
        if not pubkey or not isinstance(content, str) or not content.strip():
            return

        # Reconstruct active thread participation from echoed outbound events.
        # This runs before self-echo suppression because those events are the
        # durable source used to restore thread behavior after a restart.
        self._remember_event_thread_root(state, event)
        self._remember_agent_thread_event(state, event)

        # Suppress self-echo: never dispatch our own messages back to the agent.
        if pubkey == self._self_pubkey:
            await self._retry_pending_thread_events(channel_id, state)
            return

        # Reject unauthorized senders before any authenticated media fetch or
        # profile lookup. This mirrors the gateway's live authorization policy
        # while keeping protected relay resources inaccessible to rejected input.
        if not self._should_ack_sender(pubkey):
            return

        # Reclassify a leaked DM before gating so its first un-mentioned
        # message both latches the conversation and dispatches.
        self._maybe_latch_dm(channel_id, state, event)

        is_dm = state["chat_type"] == "dm"
        reply_target = _event_reply_target(event)
        thread_root = (
            self._resolve_thread_root(state, reply_target) if reply_target else ""
        )
        in_agent_thread = bool(
            reply_target
            and thread_root in state.get("agent_thread_ids", {})
        )
        # Top-level and thread mention gates are independent, matching Slack:
        # thread_require_mention can keep replies gated even when top-level
        # channel messages are free-response. DMs always dispatch.
        if not is_dm and not self._is_mentioned(content):
            if reply_target and self.thread_require_mention:
                return
            if self.require_mention and not in_agent_thread:
                if reply_target:
                    self._remember_pending_thread_event(state, event)
                return
        # Strip a leading @mention so slash commands (@Chip /whoami ->
        # /whoami) and clean prompts are recognized. DM messages often still
        # open with "@Chip" even though no mention is required there, so the
        # strip applies to both chat types.
        dispatch_text = self._strip_mention(content)

        dispatch_text, media_urls, media_types = await self._ingest_buzz_images(
            dispatch_text
        )

        await self._dispatch_message(
            text=dispatch_text,
            chat_id=channel_id,
            chat_type="dm" if is_dm else "group",
            user_id=pubkey,
            user_name=await self._resolve_user_name(pubkey),
            message_id=event_id,
            created_at=created_at,
            thread_id=reply_target,
            message_type=MessageType.PHOTO if media_urls else MessageType.TEXT,
            media_urls=media_urls,
            media_types=media_types,
        )

    def _refresh_mention_policy(self) -> None:
        """Apply saved Buzz mention settings without restarting the gateway."""
        try:
            from hermes_cli.config import get_config_path, read_user_config_raw

            path = get_config_path()
            stat = path.stat()
            signature = (stat.st_mtime_ns, stat.st_size)
            if signature == self._mention_config_signature:
                return
            raw = read_user_config_raw(path)
            buzz = raw.get("buzz", {}) if isinstance(raw, dict) else {}
            extra = buzz.get("extra", buzz) if isinstance(buzz, dict) else {}
            if not isinstance(extra, dict):
                extra = {}

            for key, env_name, attr in (
                ("require_mention", "BUZZ_REQUIRE_MENTION", "require_mention"),
                (
                    "thread_require_mention",
                    "BUZZ_THREAD_REQUIRE_MENTION",
                    "thread_require_mention",
                ),
            ):
                marker = f"{_YAML_BRIDGE_MARKER_PREFIX}{env_name}"
                explicit_env = os.getenv(env_name)
                if explicit_env is not None and os.getenv(marker) != explicit_env:
                    value = explicit_env
                elif key in extra:
                    value = extra[key]
                    _bridge_yaml_env(env_name, value)
                else:
                    continue
                setattr(self, attr, _config_bool(value))
            self._mention_config_signature = signature
        except Exception:
            logger.debug("Buzz: could not refresh mention policy", exc_info=True)

    def _buzz_image_metadata(self, url: str) -> Optional[Tuple[str, str, str]]:
        """Return ``(sha256, extension, MIME)`` for this relay's image URL."""
        relay = urlsplit(self.relay_url)
        candidate = urlsplit(url)
        if (
            candidate.scheme.lower() != relay.scheme.lower()
            or candidate.netloc.lower() != relay.netloc.lower()
            or candidate.username is not None
            or candidate.password is not None
            or candidate.query
            or candidate.fragment
        ):
            return None
        match = _BUZZ_MEDIA_IMAGE_PATH_RE.fullmatch(candidate.path)
        if match is None:
            return None
        digest, extension = match.groups()
        extension = extension.lower()
        return digest.lower(), f".{extension}", _BUZZ_IMAGE_MIME[extension]

    @staticmethod
    def _buzz_image_removal_span(
        text: str, span: Tuple[int, int]
    ) -> Tuple[int, int]:
        """Expand standalone image markup to its line without touching neighbours."""
        start, end = span
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", end)
        if line_end < 0:
            line_end = len(text)
        if text[line_start:start].strip() or text[end:line_end].strip():
            return span
        if line_end < len(text):
            return line_start, line_end + 1
        if line_start > 0:
            return line_start - 1, line_end
        return line_start, line_end

    async def _ingest_buzz_images(self, text: str) -> Tuple[str, List[str], List[str]]:
        """Authenticated-download protected Buzz Markdown images for vision."""
        media_urls: List[str] = []
        media_types: List[str] = []
        consumed_spans: List[Tuple[int, int]] = []
        download_attempts = 0

        for match in _BUZZ_MARKDOWN_IMAGE_RE.finditer(text):
            url = match.group(1)
            metadata = self._buzz_image_metadata(url)
            if metadata is None:
                continue
            if download_attempts >= _MAX_BUZZ_IMAGES_PER_MESSAGE:
                break
            download_attempts += 1
            expected_digest, extension, mime = metadata
            fd, temporary_path = tempfile.mkstemp(
                prefix="hermes_buzz_media_", suffix=extension
            )
            os.close(fd)
            try:
                code, _out, _err = await self._run_cli(
                    ["media", "get", url, "--output", temporary_path]
                )
                if code != 0:
                    logger.warning(
                        "Buzz: authenticated inbound image download failed (exit %d)",
                        code,
                    )
                    continue
                path = Path(temporary_path)
                validate_inbound_media_size(path.stat().st_size, media_type="image")
                data = path.read_bytes()
                if hashlib.sha256(data).hexdigest() != expected_digest:
                    logger.warning("Buzz: inbound image hash did not match its media URL")
                    continue
                cached_path = cache_image_from_bytes(data, ext=extension)
                os.chmod(cached_path, 0o600)
                media_urls.append(cached_path)
                media_types.append(mime)
                consumed_spans.append(
                    self._buzz_image_removal_span(text, match.span())
                )
            except (OSError, ValueError):
                logger.warning("Buzz: could not cache authenticated inbound image", exc_info=True)
            finally:
                try:
                    Path(temporary_path).unlink()
                except OSError:
                    pass

        merged_spans: List[List[int]] = []
        for start, end in sorted(consumed_spans):
            if merged_spans and start <= merged_spans[-1][1]:
                merged_spans[-1][1] = max(merged_spans[-1][1], end)
            else:
                merged_spans.append([start, end])
        for start, end in reversed(merged_spans):
            text = text[:start] + text[end:]
        return text, media_urls, media_types

    # ── DM classification (issue #68871) ──────────────────────────────────
    #
    # ``buzz dms list`` returns [] on some hosted relays even when DM
    # conversations exist, so DMs leak in via ``channels list`` and get
    # watched as chat_type="group" — which wrongly puts them behind the
    # channel mention gate.  Classification therefore keys off the Nostr
    # tags of the messages themselves.  Observed on a live hosted relay:
    #
    #   * every message another user sends IN A DM carries a structural
    #     ["p", <our pubkey>] tag, even when the text never mentions us
    #     (recipient addressing);
    #   * in a real channel, a ["p", <our pubkey>] tag appears only when the
    #     text visibly @mentions us (typed mention, with or without a reply
    #     ["e", ...] tag) — never on plain broadcasts.
    #
    # So "p-tagged to self WITHOUT a visible mention in the content" is the
    # DM discriminator: in a channel that combination does not occur, and a
    # channel reply/mention that p-tags us is excluded because the mention
    # is right there in the text.  As a second, independent guard, a
    # conversation whose ``channels list`` metadata looks like a real
    # community channel (real name / non-empty description) is never
    # reclassified at all, whereas relay-materialized DMs are always named
    # "DM" with an empty description.  Nothing is lost while unlatched: a
    # DM message that DOES mention us dispatches through the mention gate
    # anyway, so the latch flips exactly on the first message that needs it.

    def _may_reclassify_as_dm(self, channel_id: str) -> bool:
        """True when the conversation's metadata does not rule out a DM.

        Known real community channels (real name or non-empty description in
        ``channels list``) must never turn into DMs just because a message
        p-tags us.  A conversation with no metadata at all is trusted only
        when the user did not explicitly configure it as a watched channel.
        """
        meta = self._channel_meta.get(channel_id)
        if meta is None:
            return channel_id not in self.channels
        name = str(meta.get("name") or "").strip()
        description = str(meta.get("description") or "").strip()
        return name == "DM" and not description

    def _is_direct_message_event(self, channel_id: str, event: dict) -> bool:
        """True when ``event`` is shaped like a direct message to us: a chat
        message from another user, p-tagged to our pubkey, whose content does
        NOT visibly mention us — i.e. the p-tag is structural DM addressing,
        not the artifact of a typed @mention (see block comment above)."""
        if not self._self_pubkey or not self._may_reclassify_as_dm(channel_id):
            return False
        if int(event.get("kind") or 0) != _CHAT_KIND:
            return False
        pubkey = str(event.get("pubkey") or "").lower()
        if not pubkey or pubkey == self._self_pubkey:
            return False
        tags = event.get("tags")
        if not isinstance(tags, list):
            return False
        p_tagged_to_self = any(
            isinstance(tag, (list, tuple))
            and len(tag) > 1
            and tag[0] == "p"
            and str(tag[1]).lower() == self._self_pubkey
            for tag in tags
        )
        if not p_tagged_to_self:
            return False
        content = event.get("content")
        return isinstance(content, str) and not self._is_mentioned(content)

    def _maybe_latch_dm(self, channel_id: str, state: dict, event: dict) -> None:
        """Latch a group conversation to chat_type="dm" once any direct
        message is seen; the classification then sticks so subsequent
        un-mentioned messages in the conversation dispatch too."""
        if state["chat_type"] == "dm" or not self._is_direct_message_event(channel_id, event):
            return
        state["chat_type"] = "dm"
        self._channel_names.setdefault(channel_id, "DM")
        logger.info("Buzz: conversation %s reclassified as DM (message p-tagged to self)", channel_id)

    def _is_mentioned(self, content: str) -> bool:
        """True when content explicitly addresses this agent.

        Buzz's native ``@display-name`` mention produces a structural ``p`` tag.
        Requiring the ``@`` here also prevents paths and identifiers such as
        ``/projects/chip-server`` from being mistaken for mentions. Exact npub
        and hexadecimal identities remain explicit addressing forms.
        """
        lowered = content.lower()
        if self._self_pubkey and self._self_pubkey in lowered:
            return True
        if self._self_npub and self._self_npub in lowered:
            return True
        if self._display_name:
            pattern = rf"(?<!\w)@{re.escape(self._display_name.lower())}(?!\w)"
            if re.search(pattern, lowered):
                return True
        return False

    def _strip_mention(self, content: str) -> str:
        """Remove a leading @mention of this agent so the remaining text can be
        recognized as a slash command or clean prompt.

        Mirrors the Discord adapter, which strips its own ``<@id>`` mention
        before dispatch. Without this a channel message like ``@Chip /whoami``
        arrives with a leading ``@Chip``; the gateway's ``is_command()`` checks
        ``text.lstrip().startswith("/")`` and never fires the command. Only a
        LEADING mention is stripped (case-insensitive); mentions mid-sentence
        are left intact so normal prose is unaffected.
        """
        text = content.strip()
        candidates = []
        if self._display_name:
            candidates.append(re.escape(self._display_name))
        if self._self_npub:
            candidates.append(re.escape(self._self_npub))
        if self._self_pubkey:
            candidates.append(re.escape(self._self_pubkey))
        if not candidates:
            return text
        # Optional leading '@', one of the identity forms, optional trailing
        # ':' or ',' and surrounding whitespace.
        pattern = rf"^@?(?:{'|'.join(candidates)})[\s:,]*"
        stripped = re.sub(pattern, "", text, count=1, flags=re.IGNORECASE)
        return stripped.strip()

    async def _resolve_user_name(self, pubkey: str) -> str:
        """Resolve a pubkey to a display name (cached; falls back to npub prefix).

        Failures are cached too (negative caching): without it, every message
        from a profile-less pubkey re-runs ``users get`` each poll sweep,
        which amplifies badly when several adapter instances poll in one
        process.
        """
        cached = self._user_names.get(pubkey)
        if cached is not None:
            return cached
        name = ""
        code, out, _err = await self._run_cli(["users", "get", "--pubkey", pubkey])
        if code == 0:
            profiles = _parse_json_list(out)
            if profiles:
                name = str(profiles[0].get("display_name") or "").strip()
        if not name:
            name = (hex_to_npub(pubkey) or pubkey)[:16]
        self._user_names[pubkey] = name
        return name

    @staticmethod
    def _trim_seen(state: dict) -> None:
        seen = state["seen"]
        while len(seen) > _SEEN_CAP:
            seen.popitem(last=False)

    def _mark_seen(self, channel_id: str, event_id: str) -> None:
        state = self._channel_state.get(channel_id)
        if state is not None:
            state["seen"][event_id] = None
            self._trim_seen(state)

    @staticmethod
    def _should_ack_sender(user_id: str, profile: Optional[str] = None) -> bool:
        """Return whether the live Buzz policy admits a cosmetic acknowledgement."""
        sender = _normalize_user_ref(user_id)

        def explicit_value(name: str) -> Tuple[bool, str]:
            from agent.secret_scope import current_secret_scope, is_multiplex_active

            scope = current_secret_scope()
            if scope is not None and name in scope:
                value = scope.get(name)
                return True, "" if value is None else str(value)
            if is_multiplex_active():
                return False, ""
            if name in os.environ:
                return True, os.environ.get(name, "")
            return False, ""

        policy = _load_runtime_authorization_config(profile)

        allow_all_present, allow_all_value = explicit_value(
            "BUZZ_ALLOW_ALL_USERS"
        )
        if not allow_all_present and "allow_all_users" in policy:
            allow_all_value = str(policy["allow_all_users"])
        if allow_all_value.strip().lower() in {"true", "1", "yes"}:
            return True

        allowed_present, allowed_value = explicit_value("BUZZ_ALLOWED_USERS")
        if allowed_present:
            allowed = {
                normalized
                for raw in allowed_value.split(",")
                if (normalized := _normalize_user_ref(raw))
            }
        else:
            allowed = set(policy.get("allowed_users", []))
        return bool(sender and sender in allowed)

    async def _dispatch_message(
        self,
        text: str,
        chat_id: str,
        chat_type: str,
        user_id: str,
        user_name: str,
        message_id: str,
        created_at: int,
        thread_id: Optional[str] = None,
        message_type: MessageType = MessageType.TEXT,
        media_urls: Optional[List[str]] = None,
        media_types: Optional[List[str]] = None,
    ) -> None:
        """Build a MessageEvent and hand it to the base class handler."""
        if not self._message_handler:
            return

        # Buzz channel replies are flat under the initiating event. Treat a
        # top-level channel event as its own root so the initiating command and
        # later replies resolve to one thread-scoped gateway session. DMs keep
        # their existing conversation-wide session semantics.
        effective_thread_id = thread_id or (
            message_id if chat_type == "group" else None
        )
        source = self.build_source(
            chat_id=chat_id,
            chat_name=self._channel_names.get(chat_id, chat_id),
            chat_type=chat_type,
            user_id=user_id,
            user_name=user_name,
            thread_id=effective_thread_id,
        )

        event = MessageEvent(
            text=text,
            message_type=message_type,
            source=source,
            message_id=message_id,
            timestamp=datetime.fromtimestamp(created_at) if created_at else datetime.now(),
            media_urls=media_urls or [],
            media_types=media_types or [],
        )

        await self.handle_message(event)
        
        # Acknowledgements are cosmetic only; central authorization remains
        # the enforcement point. Keep unauthorized traffic silent.
        if self._should_ack_sender(user_id, getattr(source, "profile", None)):
            try:
                await self.send_reaction(chat_id, message_id, "👀")
            except Exception:
                logger.debug(
                    "Buzz: reaction failed for message %s",
                    message_id[:12],
                    exc_info=True,
                )

    def on_turn_lifecycle(self, event: Any) -> bool:
        """Translate a neutral Gateway event into encrypted Buzz activity."""
        return _handle_gateway_turn_lifecycle(event=event, route=self)


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------

def check_requirements() -> bool:
    """Check if Buzz is configured: a relay URL plus a resolvable key."""
    if not os.getenv("BUZZ_RELAY_URL", "").strip():
        return False
    return bool(_resolve_private_key())


def validate_config(config) -> bool:
    """Validate that the platform config has enough info to connect."""
    extra = getattr(config, "extra", {}) or {}
    relay = os.getenv("BUZZ_RELAY_URL") or extra.get("relay_url", "")
    return bool(relay and _resolve_private_key(extra))


def is_connected(config) -> bool:
    """Check whether Buzz is configured (env or config.yaml)."""
    return validate_config(config)


def _apply_yaml_config(yaml_cfg: dict, buzz_cfg: dict) -> Optional[dict]:
    """Translate ``config.yaml`` ``buzz.extra`` keys into ``BUZZ_*`` env vars.

    Implements the ``apply_yaml_config_fn`` contract.  ``check_requirements``
    and the adapter's connect path read configuration from the environment, so
    a config.yaml-only setup (no ``BUZZ_*`` env vars beyond the secret) would
    otherwise fail the ``check_fn`` gate and be silently skipped at gateway
    startup.  This hook bridges the ``extra`` block into env, mirroring the
    Slack/Telegram pattern.  Env vars win over YAML — every assignment is
    guarded by ``not os.getenv(...)`` so explicit env overrides survive a
    config.yaml update.  ``BUZZ_PRIVATE_KEY`` is a secret and stays in ``.env``;
    it is never sourced from config.yaml here.
    """
    extra = buzz_cfg.get("extra", buzz_cfg) or {}
    if not isinstance(extra, dict):
        return None
    _str_keys = {
        "relay_url": "BUZZ_RELAY_URL",
        "cli_path": "BUZZ_CLI_PATH",
        "home_channel": "BUZZ_HOME_CHANNEL",
        "transport": "BUZZ_TRANSPORT",
    }
    for src, env in _str_keys.items():
        val = extra.get(src)
        if val and not os.getenv(env):
            os.environ[env] = str(val)
    interval = extra.get("poll_interval")
    if interval is not None and not os.getenv("BUZZ_POLL_INTERVAL"):
        os.environ["BUZZ_POLL_INTERVAL"] = str(interval)
    channels = extra.get("channels")
    if channels is not None and not os.getenv("BUZZ_CHANNELS"):
        if isinstance(channels, (list, tuple)):
            channels = ",".join(str(c) for c in channels)
        os.environ["BUZZ_CHANNELS"] = str(channels)
    if "require_mention" in extra:
        _bridge_yaml_env("BUZZ_REQUIRE_MENTION", extra["require_mention"])
    if "thread_require_mention" in extra:
        _bridge_yaml_env(
            "BUZZ_THREAD_REQUIRE_MENTION", extra["thread_require_mention"]
        )
    return None


def _env_enablement() -> Optional[dict]:
    """Seed ``PlatformConfig.extra`` from env vars during gateway config load.

    Called BEFORE adapter construction so env-only setups show up in
    ``hermes gateway status`` and ``get_connected_platforms()``.  Returns
    ``None`` when Buzz isn't minimally configured.

    The special ``home_channel`` key is handled by the core hook — it becomes
    a proper ``HomeChannel`` on the ``PlatformConfig``.
    """
    relay = os.getenv("BUZZ_RELAY_URL", "").strip()
    if not relay or not _resolve_private_key():
        return None
    seed: dict = {"relay_url": relay}
    channels = os.getenv("BUZZ_CHANNELS", "").strip()
    if channels:
        seed["channels"] = [c.strip() for c in channels.split(",") if c.strip()]
    interval = os.getenv("BUZZ_POLL_INTERVAL", "").strip()
    if interval:
        try:
            seed["poll_interval"] = float(interval)
        except ValueError:
            pass
    cli_path = os.getenv("BUZZ_CLI_PATH", "").strip()
    if cli_path:
        seed["cli_path"] = cli_path
    # Home channel for deliver=buzz cron jobs; defaults to the first watched
    # channel so env-only setups get a sensible target without extra config.
    home = os.getenv("BUZZ_HOME_CHANNEL", "").strip() or (seed.get("channels") or [""])[0]
    if home:
        seed["home_channel"] = {
            "chat_id": home,
            "name": os.getenv("BUZZ_HOME_CHANNEL_NAME", home),
        }
    return seed


async def _standalone_send(
    pconfig,
    chat_id: str,
    message: str,
    *,
    thread_id: Optional[str] = None,
    media_files: Optional[List[str]] = None,
    force_document: bool = False,
) -> Dict[str, Any]:
    """One-shot send without a live adapter (out-of-process cron delivery).

    Used by ``tools/send_message_tool`` when ``hermes cron`` runs separately
    from the gateway process.  Without this hook, ``deliver=buzz`` cron jobs
    fail with ``No live adapter for platform 'buzz'``.
    """
    extra = getattr(pconfig, "extra", {}) or {}
    relay = (os.getenv("BUZZ_RELAY_URL") or extra.get("relay_url", "")).strip()
    private_key = _resolve_private_key(extra)
    cli_path = _resolve_cli_path(
        os.getenv("BUZZ_CLI_PATH", "").strip() or str(extra.get("cli_path", "") or "")
    )
    if not relay or not private_key:
        return {"error": "Buzz standalone send: BUZZ_RELAY_URL and BUZZ_PRIVATE_KEY must be configured"}
    if not cli_path:
        return {"error": "Buzz standalone send: buzz CLI binary not found"}
    target = (chat_id or "").strip() or (os.getenv("BUZZ_HOME_CHANNEL") or str(extra.get("home_channel", "") or "")).strip()
    if not target:
        return {"error": "Buzz standalone send: no target channel (set BUZZ_HOME_CHANNEL)"}

    args = ["messages", "send", "--channel", target, "--content", "-"]
    if thread_id:
        args += ["--reply-to", str(thread_id)]
    for path in media_files or []:
        args += ["--file", str(path)]
    try:
        send_content = message
        code, out, err = await _exec_buzz(
            cli_path,
            args,
            relay_url=relay,
            private_key=private_key,
            input_text=send_content,
        )
        for _ in range(_MENTION_FALLBACK_MAX_RETRIES):
            fallback = (
                _unresolved_mention_fallback(send_content, err)
                if code != 0
                else None
            )
            if fallback is None:
                break
            logger.warning(
                "Buzz: unresolved standalone mention; retrying as readable text"
            )
            send_content = fallback
            code, out, err = await _exec_buzz(
                cli_path,
                args,
                relay_url=relay,
                private_key=private_key,
                input_text=send_content,
            )
    except asyncio.CancelledError:
        raise
    except OSError as e:
        return {"error": f"Buzz standalone send failed to launch CLI: {e}"}
    if code != 0:
        return {"error": f"Buzz standalone send failed: {_cli_error_message(err, code)}"}
    try:
        data = json.loads(out or "{}")
    except ValueError:
        data = {}
    return {"success": True, "message_id": str(data.get("event_id") or "")}


def interactive_setup() -> None:
    """Interactive ``hermes gateway setup`` flow for the Buzz platform.

    Lazy-imports ``hermes_cli.setup`` helpers so the plugin stays importable
    in non-CLI contexts (gateway runtime, tests).
    """
    from hermes_cli.setup import (
        prompt,
        prompt_yes_no,
        save_env_value,
        get_env_value,
        print_header,
        print_info,
        print_warning,
        print_success,
    )

    print_header("Buzz")
    existing_relay = get_env_value("BUZZ_RELAY_URL")
    if existing_relay:
        print_info(f"Buzz: already configured (relay: {existing_relay})")
        if not prompt_yes_no("Reconfigure Buzz?", False):
            return

    print_info("Connect Hermes to a Buzz community (Block's Nostr-based human+agent platform).")
    print_info("   Requires the buzz CLI binary and a Nostr key that is a community member.")
    print()

    relay = prompt(
        "Relay URL (e.g. https://mycommunity.communities.buzz.xyz)",
        default=existing_relay or "",
    )
    if not relay:
        print_warning("Relay URL is required — skipping Buzz setup")
        return
    save_env_value("BUZZ_RELAY_URL", relay.strip())

    key = prompt("Nostr private key (nsec or hex; leave blank to keep current)", password=True)
    if key:
        save_env_value("BUZZ_PRIVATE_KEY", key.strip())
    elif not _resolve_private_key():
        print_warning("No private key configured — set BUZZ_PRIVATE_KEY before starting the gateway")

    channels = prompt(
        "Channel UUIDs to watch (comma-separated, empty = all joined channels)",
        default=get_env_value("BUZZ_CHANNELS") or "",
    )
    if channels:
        save_env_value("BUZZ_CHANNELS", channels.replace(" ", ""))

    home = prompt(
        "Home channel UUID for cron/notification delivery (optional)",
        default=get_env_value("BUZZ_HOME_CHANNEL") or "",
    )
    if home:
        save_env_value("BUZZ_HOME_CHANNEL", home.strip())

    print()
    print_info("🔒 Access control: restrict who can talk to the agent")
    allow_all = prompt_yes_no("Allow all community members to talk to the agent?", False)
    if allow_all:
        save_env_value("BUZZ_ALLOW_ALL_USERS", "true")
        save_env_value("BUZZ_ALLOWED_USERS", "")
        print_warning("⚠️  Open access — anyone in the community can command the agent.")
    else:
        save_env_value("BUZZ_ALLOW_ALL_USERS", "false")
        allowed = prompt(
            "Allowed users (comma-separated npubs or hex pubkeys, empty to deny everyone)",
            default=get_env_value("BUZZ_ALLOWED_USERS") or "",
        )
        save_env_value("BUZZ_ALLOWED_USERS", allowed.replace(" ", "") if allowed else "")

    print()
    print_success("Buzz configuration saved to ~/.hermes/.env")
    print_info("Restart the gateway for changes to take effect: hermes gateway restart")


def _handle_gateway_turn_lifecycle(*, event, route=None, **_kwargs):
    """Translate neutral Gateway lifecycle metadata into Buzz observer frames."""

    if not isinstance(route, BuzzAdapter) or not route.activity_owner_pubkey:
        return False

    phase = getattr(event, "phase", "")
    payload: Dict[str, Any]
    kind: str
    if phase == "turn_started":
        triggering_id = str(getattr(event, "triggering_event_id", "") or "")
        payload = {
            "source": "channel",
            "triggeringEventIds": (
                [triggering_id]
                if re.fullmatch(r"[0-9a-fA-F]{64}", triggering_id)
                else []
            ),
        }
        kind = "turn_started"
    elif phase == "session_resolved":
        payload = {
            "sessionId": str(getattr(event, "session_id", "") or ""),
            "isNewSession": bool(getattr(event, "is_new_session", False)),
        }
        kind = "session_resolved"
    elif phase == "turn_liveness":
        payload = {}
        kind = "turn_liveness"
    elif phase in {"tool_started", "tool_finished"}:
        status = str(getattr(event, "tool_status", "") or "")
        payload = {
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": str(getattr(event, "session_id", "") or ""),
                "update": {
                    "sessionUpdate": (
                        "tool_call" if phase == "tool_started" else "tool_call_update"
                    ),
                    "toolCallId": str(getattr(event, "tool_call_id", "") or ""),
                    "title": str(getattr(event, "tool_name", "") or ""),
                    "toolName": str(getattr(event, "tool_name", "") or ""),
                    "status": status,
                    "rawInput": {},
                },
            },
        }
        kind = "acp_read"
    elif phase == "turn_finished":
        outcome = str(getattr(event, "outcome", None) or "failed")
        if outcome == "success":
            kind = "turn_completed"
            payload = {}
        else:
            kind = "turn_error"
            payload = {"status": outcome}
    else:
        return False

    try:
        return route._enqueue_activity(
            kind,
            channel_id=getattr(event, "channel_id", None),
            session_id=getattr(event, "session_id", None),
            turn_id=getattr(event, "turn_id", None),
            started_at=getattr(event, "started_at", None),
            payload=payload,
        )
    except Exception:
        logger.debug("Buzz: Gateway lifecycle translation failed open", exc_info=True)
        return False


def register(ctx):
    """Plugin entry point: called by the Hermes plugin system."""
    ctx.register_platform(
        name="buzz",
        label="Buzz",
        adapter_factory=lambda cfg: BuzzAdapter(cfg),
        check_fn=check_requirements,
        validate_config=validate_config,
        is_connected=is_connected,
        required_env=["BUZZ_RELAY_URL", "BUZZ_PRIVATE_KEY"],
        install_hint="Requires the buzz CLI binary (https://github.com/block/buzz) on PATH or at BUZZ_CLI_PATH",
        setup_fn=interactive_setup,
        # Env-driven auto-configuration: seeds PlatformConfig.extra with
        # relay/channels/poll interval + home_channel so env-only setups show
        # up in gateway status without instantiating the adapter.
        env_enablement_fn=_env_enablement,
        # Bridge config.yaml buzz.extra -> BUZZ_* env vars so check_fn and the
        # env-driven connect path work for config.yaml-only setups (secret stays
        # in .env). Without this the check_fn gate skips Buzz at startup.
        apply_yaml_config_fn=_apply_yaml_config,
        # Cron home-channel delivery support (deliver=buzz).
        cron_deliver_env_var="BUZZ_HOME_CHANNEL",
        # Out-of-process cron delivery.  Without this hook, deliver=buzz
        # cron jobs fail with "No live adapter" when cron runs separately
        # from the gateway.
        standalone_sender_fn=_standalone_send,
        # Auth env vars and live config resolver for central authorization.
        allowed_users_env="BUZZ_ALLOWED_USERS",
        allow_all_env="BUZZ_ALLOW_ALL_USERS",
        authorization_config_fn=_load_runtime_authorization_config,
        authorization_user_normalizer=_normalize_user_ref,
        # Display
        emoji="🐝",
        # Buzz identities are pubkeys, not phone numbers
        pii_safe=False,
        allow_update_command=True,
        # LLM guidance
        platform_hint=(
            "You are collaborating in a Buzz workspace (Block's Nostr-based "
            "human+agent platform). Markdown IS supported. Users address you "
            "by @-mentioning your name or npub in channels; direct messages "
            "reach you without a mention. Keep responses conversational."
        ),
    )
