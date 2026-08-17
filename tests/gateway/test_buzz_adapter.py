"""Tests for the Buzz platform adapter plugin."""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import pytest
from unittest.mock import AsyncMock, MagicMock

from gateway.session import build_session_key
from tests.gateway._plugin_adapter_loader import load_plugin_adapter

# Load plugins/platforms/buzz/adapter.py under a unique module name
# (plugin_adapter_buzz) so it cannot collide with other plugin adapters
# loaded by sibling tests in the same xdist worker.
_buzz_mod = load_plugin_adapter("buzz")

BuzzAdapter = _buzz_mod.BuzzAdapter
hex_to_npub = _buzz_mod.hex_to_npub
npub_to_hex = _buzz_mod.npub_to_hex
_normalize_user_ref = _buzz_mod._normalize_user_ref
_cli_error_message = _buzz_mod._cli_error_message
_resolve_private_key = _buzz_mod._resolve_private_key
check_requirements = _buzz_mod.check_requirements
validate_config = _buzz_mod.validate_config
register = _buzz_mod.register
_env_enablement = _buzz_mod._env_enablement
_apply_yaml_config = _buzz_mod._apply_yaml_config
_standalone_send = _buzz_mod._standalone_send

# Real key pair (Chip's public identity — public information, not a secret)
SELF_PUBKEY = "9fd5c7ba6d3ef224da78f541e0fcb9c50f72cc63edb19aae76ac6a0474dfa860"
SELF_NPUB = "npub1nl2u0wnd8mezfknc74q7pl9ec58h9nrrakce4tnk434qgaxl4psqe5twr6"
OTHER_PUBKEY = "a" * 64
CHANNEL = "ccc2bc1a-7a82-5a8f-8c4e-57a070cbe7cd"
# Real DM conversation as materialized by a hosted relay: `dms list` returns
# [] for it (#68871) while `channels list` shows it as name "DM", empty
# description, indistinguishable from a channel except via message p-tags.
DM_CHANNEL = "6468cc16-a114-4f23-8b8c-02c1655cbf6b"

_ENV_VARS = (
    "BUZZ_RELAY_URL",
    "BUZZ_PRIVATE_KEY",
    "BUZZ_CHANNELS",
    "BUZZ_HOME_CHANNEL",
    "BUZZ_ALLOWED_USERS",
    "BUZZ_ALLOW_ALL_USERS",
    "BUZZ_REQUIRE_MENTION",
    "BUZZ_POLL_INTERVAL",
    "BUZZ_CLI_PATH",
    "BUZZ_CREDENTIALS_FILE",
    "BUZZ_REQUIRE_MENTION",
    "BUZZ_THREAD_REQUIRE_MENTION",
    "_HERMES_YAML_BRIDGED_BUZZ_REQUIRE_MENTION",
    "_HERMES_YAML_BRIDGED_BUZZ_THREAD_REQUIRE_MENTION",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    """Keep tests hermetic: no ambient Buzz env vars or real credentials."""
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(_buzz_mod, "_DEFAULT_CREDENTIALS_DIR", tmp_path / "no-creds")
    yield


def _event(event_id, pubkey=OTHER_PUBKEY, content="hello", created_at=1000, kind=9):
    return {
        "id": event_id,
        "pubkey": pubkey,
        "content": content,
        "created_at": created_at,
        "kind": kind,
        "tags": [["h", CHANNEL]],
    }


def _make_adapter(extra=None):
    from gateway.config import PlatformConfig

    cfg = PlatformConfig(enabled=True, extra={"relay_url": "https://test.relay", **(extra or {})})
    adapter = BuzzAdapter(cfg)
    adapter._self_pubkey = SELF_PUBKEY
    adapter._self_npub = SELF_NPUB
    adapter._display_name = "Chip"
    adapter._private_key = "nsec1test"
    # Polling/routing/media tests exercise behavior independently of cosmetic
    # acknowledgement authorization. Security tests restore the real method.
    adapter._should_ack_sender = lambda *_args, **_kwargs: True
    return adapter


class _ScriptedCli:
    """Fake ``_run_cli`` that routes on the buzz subcommand and records calls."""

    def __init__(self):
        self.responses = {}  # (group, cmd) -> list of (code, stdout, stderr)
        self.calls = []

    def script(self, group, cmd, payload, code=0, stderr=""):
        stdout = payload if isinstance(payload, str) else json.dumps(payload)
        self.responses.setdefault((group, cmd), []).append((code, stdout, stderr))

    async def __call__(self, args, *, input_text=None):
        self.calls.append((list(args), input_text))
        queue = self.responses.get((args[0], args[1]), [])
        if len(queue) > 1:
            return queue.pop(0)
        if queue:
            return queue[0]
        return 0, "[]", ""


# ── bech32 / identity helpers ─────────────────────────────────────────────


class TestBech32Helpers:

    def test_hex_to_npub_known_pair(self):
        assert hex_to_npub(SELF_PUBKEY) == SELF_NPUB

    def test_npub_to_hex_known_pair(self):
        assert npub_to_hex(SELF_NPUB) == SELF_PUBKEY


# ── Adapter init / config precedence ──────────────────────────────────────


class TestBuzzAdapterInit:


    def test_init_from_config_extra(self):
        from gateway.config import PlatformConfig
        cfg = PlatformConfig(
            enabled=True,
            extra={
                "relay_url": "https://cfg.relay",
                "channels": ["ccc"],
                "poll_interval": 2,
                "home_channel": "ccc",
            },
        )
        adapter = BuzzAdapter(cfg)
        assert adapter.relay_url == "https://cfg.relay"
        assert adapter.channels == ["ccc"]
        assert adapter.poll_interval == 2.0
        assert adapter.home_channel == "ccc"

    def test_outbound_mention_pubkeys_reject_casefold_collisions(self):
        from gateway.config import PlatformConfig

        cfg = PlatformConfig(
            enabled=True,
            extra={
                "relay_url": "https://cfg.relay",
                "outbound_mention_pubkeys": {
                    "Agent": OTHER_PUBKEY,
                    "agent": SELF_PUBKEY,
                },
            },
        )

        with pytest.raises(ValueError, match="duplicate display name"):
            BuzzAdapter(cfg)

    def test_validate_config_rejects_invalid_outbound_mention_mapping(
        self, monkeypatch
    ):
        from gateway.config import PlatformConfig

        monkeypatch.setenv("BUZZ_PRIVATE_KEY", "nsec1test")
        cfg = PlatformConfig(
            enabled=True,
            extra={
                "relay_url": "https://cfg.relay",
                "outbound_mention_pubkeys": "not-a-mapping",
            },
        )

        assert validate_config(cfg) is False

    def test_env_overrides_config(self, monkeypatch):
        monkeypatch.setenv("BUZZ_RELAY_URL", "https://env.relay")
        from gateway.config import PlatformConfig
        adapter = BuzzAdapter(PlatformConfig(enabled=True, extra={"relay_url": "https://cfg.relay"}))
        assert adapter.relay_url == "https://env.relay"

    def test_runtime_authorization_config_normalizes_buzz_identities(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        (tmp_path / "config.yaml").write_text(
            "buzz:\n"
            "  extra:\n"
            f"    allowed_users: [{SELF_NPUB}, {OTHER_PUBKEY.upper()}]\n"
            "    allow_all_users: false\n",
            encoding="utf-8",
        )

        policy = _buzz_mod._load_runtime_authorization_config()

        assert policy == {
            "allowed_users": [SELF_PUBKEY, OTHER_PUBKEY],
            "allow_all_users": False,
        }

    def test_runtime_authorization_config_supports_gateway_buzz_path(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        (tmp_path / "config.yaml").write_text(
            "gateway:\n"
            "  buzz:\n"
            "    extra:\n"
            f"      allowed_users: [{SELF_NPUB}]\n"
            "      allow_all_users: true\n",
            encoding="utf-8",
        )

        assert _buzz_mod._load_runtime_authorization_config() == {
            "allowed_users": [SELF_PUBKEY],
            "allow_all_users": True,
        }

    def test_runtime_authorization_config_uses_canonical_gateway_platform(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        (tmp_path / "config.yaml").write_text(
            "gateway:\n"
            "  platforms:\n"
            "    buzz:\n"
            "      extra:\n"
            f"        allowed_users: [{OTHER_PUBKEY}]\n"
            "        allow_all_users: false\n"
            "  buzz:\n"
            "    extra:\n"
            "      allow_all_users: true\n"
            "platforms:\n"
            "  buzz:\n"
            "    extra:\n"
            "      allow_all_users: true\n"
            "buzz:\n"
            "  extra:\n"
            f"    allowed_users: [{SELF_NPUB}]\n"
            "    allow_all_users: true\n",
            encoding="utf-8",
        )

        assert _buzz_mod._load_runtime_authorization_config() == {
            "allowed_users": [OTHER_PUBKEY],
            "allow_all_users": False,
        }

    def test_runtime_authorization_config_retains_last_valid_policy(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "buzz:\n"
            "  extra:\n"
            f"    allowed_users: [{SELF_NPUB}]\n",
            encoding="utf-8",
        )
        expected = {"allowed_users": [SELF_PUBKEY]}
        assert _buzz_mod._load_runtime_authorization_config() == expected

        config_path.write_text("buzz: [not: valid", encoding="utf-8")

        assert _buzz_mod._load_runtime_authorization_config() == expected

        config_path.write_text(
            "buzz:\n"
            "  extra:\n"
            f"    allowed_users: [{OTHER_PUBKEY}]\n",
            encoding="utf-8",
        )
        assert _buzz_mod._load_runtime_authorization_config() == {
            "allowed_users": [OTHER_PUBKEY]
        }

        config_path.write_text("buzz:\n  extra: {}\n", encoding="utf-8")
        assert _buzz_mod._load_runtime_authorization_config() == {}

        config_path.unlink()
        assert _buzz_mod._load_runtime_authorization_config() == {}

    def test_runtime_authorization_config_honors_managed_overlay(
        self, monkeypatch, tmp_path
    ):
        from hermes_cli import managed_scope

        home = tmp_path / "home"
        managed = tmp_path / "managed"
        home.mkdir()
        managed.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(home))
        monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
        (home / "config.yaml").write_text(
            "buzz:\n"
            "  extra:\n"
            f"    allowed_users: [{OTHER_PUBKEY}]\n"
            "    allow_all_users: true\n",
            encoding="utf-8",
        )
        (managed / "config.yaml").write_text(
            "buzz:\n"
            "  extra:\n"
            f"    allowed_users: [{SELF_NPUB}]\n"
            "    allow_all_users: false\n",
            encoding="utf-8",
        )
        managed_scope.invalidate_managed_cache()

        assert _buzz_mod._load_runtime_authorization_config() == {
            "allowed_users": [SELF_PUBKEY],
            "allow_all_users": False,
        }

    def test_runtime_authorization_config_reads_requested_profile(
        self, monkeypatch, tmp_path
    ):
        from hermes_cli.profiles import get_profile_dir

        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        (tmp_path / "config.yaml").write_text(
            f"buzz:\n  extra:\n    allowed_users: [{OTHER_PUBKEY}]\n",
            encoding="utf-8",
        )
        secondary = get_profile_dir("secondary")
        secondary.mkdir(parents=True)
        (secondary / "config.yaml").write_text(
            f"buzz:\n  extra:\n    allowed_users: [{SELF_NPUB}]\n",
            encoding="utf-8",
        )

        assert _buzz_mod._load_runtime_authorization_config("secondary") == {
            "allowed_users": [SELF_PUBKEY]
        }

    def test_scoped_gateway_loader_seeds_legacy_extra(self, monkeypatch, tmp_path):
        from agent import secret_scope as ss
        from gateway.config import Platform, load_gateway_config

        hermes_home = tmp_path / ".hermes"
        hermes_home.mkdir()
        (hermes_home / "config.yaml").write_text(
            "buzz:\n"
            "  extra:\n"
            "    relay_url: https://profile.relay\n"
            f"    allowed_users:\n      - {SELF_NPUB}\n"
            "    allow_all_users: false\n"
            "    require_mention: false\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        ss.set_multiplex_active(True)
        token = ss.set_secret_scope({})
        try:
            config = load_gateway_config()
        finally:
            ss.reset_secret_scope(token)
            ss.set_multiplex_active(False)

        buzz = config.platforms[Platform("buzz")]
        assert buzz.extra["relay_url"] == "https://profile.relay"
        assert buzz.extra["allowed_users"] == [SELF_NPUB]
        assert buzz.extra["allow_all_users"] is False
        assert buzz.extra["require_mention"] is False
        assert "BUZZ_RELAY_URL" not in os.environ
        assert "BUZZ_ALLOWED_USERS" not in os.environ
        assert "BUZZ_ALLOW_ALL_USERS" not in os.environ

    def test_nested_buzz_config_wins_and_warns_on_legacy_conflict(
        self, monkeypatch, tmp_path, caplog
    ):
        from agent import secret_scope as ss
        from gateway.config import Platform, load_gateway_config

        hermes_home = tmp_path / ".hermes"
        hermes_home.mkdir()
        (hermes_home / "config.yaml").write_text(
            "buzz:\n"
            "  extra:\n"
            "    relay_url: http://legacy.relay\n"
            "gateway:\n"
            "  platforms:\n"
            "    buzz:\n"
            "      enabled: true\n"
            "      extra:\n"
            "        relay_url: https://canonical.relay\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        monkeypatch.setenv("BUZZ_PRIVATE_KEY", "nsec1test")
        ss.set_multiplex_active(True)
        token = ss.set_secret_scope({})
        try:
            config = load_gateway_config()
        finally:
            ss.reset_secret_scope(token)
            ss.set_multiplex_active(False)

        buzz = config.platforms[Platform("buzz")]
        assert buzz.extra["relay_url"] == "https://canonical.relay"
        assert "conflicting legacy top-level buzz config" in caplog.text

    def test_canonical_only_buzz_config_does_not_warn(self, monkeypatch, caplog):
        canonical = {
            "enabled": True,
            "extra": {"relay_url": "https://canonical.relay"},
        }
        monkeypatch.setattr(
            _buzz_mod, "_profile_scoped_config_load", lambda: True
        )

        extra = _buzz_mod._apply_yaml_config(
            {"gateway": {"platforms": {"buzz": canonical}}},
            canonical,
        )

        assert extra["relay_url"] == "https://canonical.relay"
        assert "conflicting legacy" not in caplog.text


# ── CLI error contract ────────────────────────────────────────────────────


class TestCliErrorContract:

    def test_parses_json_error(self):
        msg = _cli_error_message('{"error":"relay_error","message":"boom","retryable":false}', 2)
        assert "relay_error" in msg and "boom" in msg and "exit 2" in msg


# ── Seeding / high-water mark / de-dupe ───────────────────────────────────


class TestPollingDedupe:

    @pytest.fixture
    def adapter(self):
        a = _make_adapter()
        a._dispatched = []

        async def capture(**kwargs):
            a._dispatched.append(kwargs)

        a._dispatch_message = capture
        a._message_handler = AsyncMock()
        return a

    @pytest.mark.asyncio
    async def test_seed_sets_high_water_mark_without_dispatch(self, adapter):
        cli = _ScriptedCli()
        cli.script("messages", "get", [
            _event("e1", content="@Chip old history", created_at=100),
            _event("e2", content="@Chip newer history", created_at=200),
        ])
        adapter._run_cli = cli
        await adapter._seed_channel(CHANNEL, chat_type="group")

        state = adapter._channel_state[CHANNEL]
        assert state["last_ts"] == 200
        assert set(state["seen"]) == {"e1", "e2"}
        # Seeding must never replay history into the agent
        assert adapter._dispatched == []

    @pytest.mark.asyncio
    async def test_new_event_dispatched_once(self, adapter):
        cli = _ScriptedCli()
        cli.script("messages", "get", [_event("e1", content="@Chip hi", created_at=100)])
        adapter._run_cli = cli
        await adapter._seed_channel(CHANNEL, chat_type="group")

        # Poll 1: seeded event + a genuinely new mention
        cli.responses.clear()
        cli.script("messages", "get", [
            _event("e1", content="@Chip hi", created_at=100),
            _event("e2", content="hey @Chip, ping", created_at=150),
        ])
        await adapter._poll_channel(CHANNEL)
        assert [d["message_id"] for d in adapter._dispatched] == ["e2"]
        assert adapter._dispatched[0]["text"] == "hey @Chip, ping"
        assert adapter._channel_state[CHANNEL]["last_ts"] == 150

        # Poll 2: identical response — the seen-id set must de-dupe
        await adapter._poll_channel(CHANNEL)
        assert len(adapter._dispatched) == 1


# ── Mention gating / DMs / authorization ──────────────────────────────────


class TestMentionGating:

    def test_live_refresh_reads_canonical_dashboard_controls(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.delenv("BUZZ_REQUIRE_MENTION", raising=False)
        monkeypatch.delenv("BUZZ_THREAD_REQUIRE_MENTION", raising=False)
        monkeypatch.delenv(
            "_HERMES_YAML_BRIDGE_BUZZ_REQUIRE_MENTION", raising=False
        )
        monkeypatch.delenv(
            "_HERMES_YAML_BRIDGE_BUZZ_THREAD_REQUIRE_MENTION", raising=False
        )
        (tmp_path / "config.yaml").write_text(
            "gateway:\n"
            "  platforms:\n"
            "    buzz:\n"
            "      extra:\n"
            "        require_mention: false\n"
            "        thread_require_mention: false\n",
            encoding="utf-8",
        )
        adapter = _make_adapter(
            {"require_mention": True, "thread_require_mention": True}
        )

        adapter._refresh_mention_policy()

        assert adapter.require_mention is False
        assert adapter.thread_require_mention is False

    @pytest.fixture
    def adapter(self):
        a = _make_adapter()
        a._dispatched = []

        async def capture(**kwargs):
            a._dispatched.append(kwargs)

        a._dispatch_message = capture
        a._message_handler = AsyncMock()
        a._channel_state[CHANNEL] = {"chat_type": "group", "last_ts": 0, "seen": {}}
        return a

    async def _poll_with(self, adapter, *events):
        cli = _ScriptedCli()
        cli.script("messages", "get", list(events))
        adapter._run_cli = cli
        await adapter._poll_channel(CHANNEL)

    @pytest.mark.asyncio
    async def test_unaddressed_channel_message_ignored(self, adapter):
        await self._poll_with(adapter, _event("e1", content="just chatting", created_at=10))
        assert adapter._dispatched == []

    @pytest.mark.asyncio
    async def test_display_name_inside_repository_path_is_not_a_mention(self, adapter):
        await self._poll_with(
            adapter,
            _event(
                "e1",
                content="Did you update /projects/chip-server-buzz-recovery?",
                created_at=10,
            ),
        )

        assert adapter._dispatched == []

    @pytest.mark.asyncio
    async def test_unmentioned_followup_dispatches_after_agent_replies_when_thread_mentions_disabled(self):
        adapter = _make_adapter({"thread_require_mention": False})
        adapter._dispatched = []

        async def capture(**kwargs):
            adapter._dispatched.append(kwargs)

        adapter._dispatch_message = capture
        adapter._message_handler = AsyncMock()
        adapter._channel_state[CHANNEL] = {
            "chat_type": "group", "last_ts": 0, "seen": {},
        }

        await self._poll_with(
            adapter,
            _tagged_event(
                "root", CHANNEL, content="@Chip does it work?", created_at=10,
            ),
        )

        cli = _ScriptedCli()
        cli.script(
            "messages", "send",
            {"accepted": True, "event_id": "agent", "message": ""},
        )
        adapter._run_cli = cli
        await adapter.send(CHANNEL, "Yes.", reply_to="root")

        await self._poll_with(
            adapter,
            _tagged_event(
                "followup", CHANNEL, content="Tell me more", created_at=12,
                reply_to="root",
            ),
        )

        assert [d["message_id"] for d in adapter._dispatched] == ["root", "followup"]

    @pytest.mark.asyncio
    async def test_unmentioned_reply_to_agent_authored_root_is_dispatched(self):
        adapter = _make_adapter({"thread_require_mention": False})
        adapter._dispatched = []

        async def capture(**kwargs):
            adapter._dispatched.append(kwargs)

        adapter._dispatch_message = capture
        adapter._message_handler = AsyncMock()
        adapter._channel_state[CHANNEL] = {
            "chat_type": "group",
            "last_ts": 0,
            "seen": {},
        }
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "agent-root", "message": ""},
        )
        adapter._run_cli = cli
        await adapter.send(CHANNEL, "Recovery status")

        await self._poll_with(
            adapter,
            _tagged_event(
                "followup",
                CHANNEL,
                content="What should we do?",
                created_at=12,
                reply_to="agent-root",
            ),
        )

        assert [d["message_id"] for d in adapter._dispatched] == ["followup"]

    @pytest.mark.asyncio
    async def test_agent_authored_root_is_restored_from_self_echo(self, adapter):
        adapter.thread_require_mention = False

        await self._poll_with(
            adapter,
            _tagged_event(
                "agent-root",
                CHANNEL,
                pubkey=SELF_PUBKEY,
                content="Recovery status",
                created_at=11,
            ),
            _tagged_event(
                "followup",
                CHANNEL,
                content="What should we do?",
                created_at=12,
                reply_to="agent-root",
            ),
        )

        assert [d["message_id"] for d in adapter._dispatched] == ["followup"]

    @pytest.mark.asyncio
    async def test_nested_unmentioned_followup_stays_in_agent_thread(self):
        adapter = _make_adapter({"thread_require_mention": False})
        adapter._dispatched = []

        async def capture(**kwargs):
            adapter._dispatched.append(kwargs)

        adapter._dispatch_message = capture
        adapter._message_handler = AsyncMock()
        adapter._channel_state[CHANNEL] = {
            "chat_type": "group", "last_ts": 0, "seen": {},
        }
        cli = _ScriptedCli()
        cli.script(
            "messages", "send",
            {"accepted": True, "event_id": "agent", "message": ""},
        )
        adapter._run_cli = cli
        await adapter.send(CHANNEL, "Yes.", reply_to="root")

        await self._poll_with(
            adapter,
            _tagged_event(
                "first-followup", CHANNEL, content="Tell me more", created_at=12,
                reply_to="root",
            ),
            _tagged_event(
                "nested-followup", CHANNEL, content="More detail", created_at=13,
                reply_to="first-followup",
            ),
        )

        assert [d["message_id"] for d in adapter._dispatched] == [
            "first-followup",
            "nested-followup",
        ]

    @pytest.mark.asyncio
    async def test_thread_mention_gate_still_applies_when_top_level_mentions_disabled(
        self,
    ):
        adapter = _make_adapter(
            {"require_mention": False, "thread_require_mention": True}
        )
        adapter._dispatched = []

        async def capture(**kwargs):
            adapter._dispatched.append(kwargs)

        adapter._dispatch_message = capture
        adapter._message_handler = AsyncMock()
        adapter._channel_state[CHANNEL] = {
            "chat_type": "group", "last_ts": 0, "seen": {},
        }

        await self._poll_with(
            adapter,
            _tagged_event("root", CHANNEL, content="Top level", created_at=10),
            _tagged_event(
                "reply", CHANNEL, content="Thread reply", created_at=11,
                reply_to="root",
            ),
        )

        assert [d["message_id"] for d in adapter._dispatched] == ["root"]

    @pytest.mark.asyncio
    async def test_saved_mention_settings_apply_without_adapter_restart(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        _apply_yaml_config(
            {}, {"extra": {"require_mention": True, "thread_require_mention": False}}
        )
        adapter = _make_adapter()
        adapter._dispatched = []

        async def capture(**kwargs):
            adapter._dispatched.append(kwargs)

        adapter._dispatch_message = capture
        adapter._message_handler = AsyncMock()
        adapter._channel_state[CHANNEL] = {
            "chat_type": "group",
            "last_ts": 0,
            "seen": {},
            "agent_thread_ids": {"root": None},
        }
        (tmp_path / "config.yaml").write_text(
            "buzz:\n"
            "  extra:\n"
            "    require_mention: false\n"
            "    thread_require_mention: true\n",
            encoding="utf-8",
        )

        await self._poll_with(
            adapter,
            _tagged_event(
                "top-level", CHANNEL, content="No mention needed", created_at=11,
            ),
            _tagged_event(
                "followup", CHANNEL, content="Tell me more", created_at=12,
                reply_to="root",
            ),
        )

        assert [d["message_id"] for d in adapter._dispatched] == ["top-level"]

    def test_malformed_saved_config_preserves_working_mention_policy(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        adapter = _make_adapter(
            {"require_mention": False, "thread_require_mention": False}
        )
        (tmp_path / "config.yaml").write_text(
            "buzz: [unterminated\n",
            encoding="utf-8",
        )

        adapter._refresh_mention_policy()

        assert adapter.require_mention is False
        assert adapter.thread_require_mention is False

    def test_missing_saved_settings_preserve_working_mention_policy(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        adapter = _make_adapter(
            {"require_mention": False, "thread_require_mention": False}
        )
        (tmp_path / "config.yaml").write_text(
            "buzz:\n  extra: {}\n",
            encoding="utf-8",
        )

        adapter._refresh_mention_policy()

        assert adapter.require_mention is False
        assert adapter.thread_require_mention is False

    def test_explicit_env_overrides_saved_mention_policy(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv("BUZZ_REQUIRE_MENTION", "false")
        monkeypatch.setenv("BUZZ_THREAD_REQUIRE_MENTION", "false")
        adapter = _make_adapter()
        (tmp_path / "config.yaml").write_text(
            "buzz:\n"
            "  extra:\n"
            "    require_mention: true\n"
            "    thread_require_mention: true\n",
            encoding="utf-8",
        )

        adapter._refresh_mention_policy()

        assert adapter.require_mention is False
        assert adapter.thread_require_mention is False

    def test_runtime_env_replacement_takes_ownership_from_yaml(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        _apply_yaml_config(
            {}, {"extra": {"require_mention": False, "thread_require_mention": False}}
        )
        adapter = _make_adapter()
        monkeypatch.setenv("BUZZ_REQUIRE_MENTION", "true")
        (tmp_path / "config.yaml").write_text(
            "buzz:\n  extra:\n    require_mention: false\n",
            encoding="utf-8",
        )

        adapter._refresh_mention_policy()

        assert adapter.require_mention is True

    @pytest.mark.asyncio
    async def test_seeded_agent_reply_restores_thread_followups_after_restart(self):
        adapter = _make_adapter({"thread_require_mention": False})
        adapter._dispatched = []

        async def capture(**kwargs):
            adapter._dispatched.append(kwargs)

        adapter._dispatch_message = capture
        adapter._message_handler = AsyncMock()
        cli = _ScriptedCli()
        cli.script(
            "messages", "get",
            [
                _tagged_event(
                    "root", CHANNEL, content="@Chip does it work?", created_at=10,
                ),
                _tagged_event(
                    "agent", CHANNEL, content="Yes.", pubkey=SELF_PUBKEY,
                    created_at=11, reply_to="root",
                ),
            ],
        )
        adapter._run_cli = cli
        await adapter._seed_channel(CHANNEL, chat_type="group")

        await self._poll_with(
            adapter,
            _tagged_event(
                "followup", CHANNEL, content="Tell me more", created_at=12,
                reply_to="root",
            ),
        )

        assert [d["message_id"] for d in adapter._dispatched] == ["followup"]

    @pytest.mark.asyncio
    async def test_seeded_agent_authored_root_restores_followups_after_restart(self):
        adapter = _make_adapter({"thread_require_mention": False})
        adapter._dispatched = []

        async def capture(**kwargs):
            adapter._dispatched.append(kwargs)

        adapter._dispatch_message = capture
        adapter._message_handler = AsyncMock()
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "get",
            [
                _tagged_event(
                    "agent-root",
                    CHANNEL,
                    content="Recovery status",
                    pubkey=SELF_PUBKEY,
                    created_at=11,
                ),
            ],
        )
        adapter._run_cli = cli
        await adapter._seed_channel(CHANNEL, chat_type="group")

        await self._poll_with(
            adapter,
            _tagged_event(
                "followup",
                CHANNEL,
                content="What should we do?",
                created_at=12,
                reply_to="agent-root",
            ),
        )

        assert [d["message_id"] for d in adapter._dispatched] == ["followup"]

    @pytest.mark.asyncio
    async def test_early_followup_retries_after_agent_echo_arrives(self):
        adapter = _make_adapter({"thread_require_mention": False})
        adapter._dispatched = []

        async def capture(**kwargs):
            adapter._dispatched.append(kwargs)

        adapter._dispatch_message = capture
        adapter._message_handler = AsyncMock()
        adapter._channel_state[CHANNEL] = {
            "chat_type": "group", "last_ts": 0, "seen": {},
        }

        await self._poll_with(
            adapter,
            _tagged_event(
                "followup", CHANNEL, content="Tell me more", created_at=12,
                reply_to="root",
            ),
            _tagged_event(
                "agent", CHANNEL, content="Yes.", pubkey=SELF_PUBKEY,
                created_at=11, reply_to="root",
            ),
        )

        assert [d["message_id"] for d in adapter._dispatched] == ["followup"]
        assert adapter._channel_state[CHANNEL].get("pending_thread_events") == {}

    @pytest.mark.asyncio
    async def test_rejected_agent_reply_does_not_open_thread_for_followups(self):
        adapter = _make_adapter({"thread_require_mention": False})
        adapter._dispatched = []

        async def capture(**kwargs):
            adapter._dispatched.append(kwargs)

        adapter._dispatch_message = capture
        adapter._message_handler = AsyncMock()
        adapter._channel_state[CHANNEL] = {
            "chat_type": "group", "last_ts": 0, "seen": {},
        }

        cli = _ScriptedCli()
        cli.script(
            "messages", "send",
            {"accepted": False, "event_id": "agent", "message": "rejected"},
        )
        adapter._run_cli = cli
        result = await adapter.send(CHANNEL, "No.", reply_to="root")
        assert result.success is False

        await self._poll_with(
            adapter,
            _tagged_event(
                "followup", CHANNEL, content="Tell me more", created_at=12,
                reply_to="root",
            ),
        )

        assert adapter._dispatched == []

    @pytest.mark.asyncio
    async def test_agent_reply_targets_thread_root_instead_of_latest_nested_reply(self):
        adapter = _make_adapter({"require_mention": False})
        adapter._dispatched = []

        async def capture(**kwargs):
            adapter._dispatched.append(kwargs)

        adapter._dispatch_message = capture
        adapter._message_handler = AsyncMock()
        adapter._channel_state[CHANNEL] = {
            "chat_type": "group", "last_ts": 0, "seen": {},
        }

        await self._poll_with(
            adapter,
            _tagged_event("root", CHANNEL, content="Start", created_at=10),
            _tagged_event(
                "first-reply", CHANNEL, content="First", created_at=11,
                reply_to="root",
            ),
            _tagged_event(
                "nested-reply", CHANNEL, content="Nested", created_at=12,
                reply_to="first-reply",
            ),
        )

        cli = _ScriptedCli()
        cli.script(
            "messages", "send",
            {"accepted": True, "event_id": "agent", "message": ""},
        )
        adapter._run_cli = cli
        await adapter.send(CHANNEL, "Reply.", reply_to="nested-reply")

        assert cli.calls[-1][0][-2:] == ["--reply-to", "root"]

    @pytest.mark.asyncio
    async def test_name_mention_dispatched(self, adapter):
        await self._poll_with(adapter, _event("e1", content="hey @Chip can you help?", created_at=10))
        assert len(adapter._dispatched) == 1

    @pytest.mark.asyncio
    async def test_reply_root_propagates_to_dispatched_thread_id(self, adapter):
        root_id = "f" * 64
        await self._poll_with(
            adapter,
            _tagged_event(
                "e1",
                CHANNEL,
                content="@Chip same-thread answer",
                created_at=10,
                reply_to=root_id,
            ),
        )

        assert adapter._dispatched[0]["thread_id"] == root_id

    @pytest.mark.parametrize(
        ("content", "expected"),
        [
            ("hey @cHiP can you help?", True),
            ("Chip, can you help?", False),
            (f"nostr:{SELF_NPUB} hello", True),
            (f"identity {SELF_PUBKEY.upper()}", True),
        ],
    )
    def test_explicit_mention_contract(self, adapter, content, expected):
        assert adapter._is_mentioned(content) is expected

    @pytest.mark.asyncio
    async def test_protected_buzz_markdown_image_is_downloaded_for_vision(
        self, adapter, monkeypatch, tmp_path
    ):
        image_bytes = b"\x89PNG\r\n\x1a\nprotected-image"
        image_hash = hashlib.sha256(image_bytes).hexdigest()
        image_url = f"https://test.relay/media/{image_hash}.png"
        event = _event(
            "e1",
            content=f"@Chip what does this show?\n![image]({image_url})",
            created_at=10,
        )
        monkeypatch.setenv("IMAGE_CACHE_DIR", str(tmp_path / "images"))

        cli = _ScriptedCli()
        cli.script("messages", "get", [event])

        async def run_cli(args, *, input_text=None):
            cli.calls.append((list(args), input_text))
            if args[:2] == ["media", "get"]:
                output = Path(args[args.index("--output") + 1])
                output.write_bytes(image_bytes)
                return 0, "", ""
            queue = cli.responses.get((args[0], args[1]), [])
            return queue[0] if queue else (0, "[]", "")

        adapter._run_cli = run_cli
        await adapter._poll_channel(CHANNEL)

        dispatched = adapter._dispatched[0]
        assert dispatched["message_type"] is _buzz_mod.MessageType.PHOTO
        assert dispatched["media_types"] == ["image/png"]
        assert len(dispatched["media_urls"]) == 1
        cached_image = Path(dispatched["media_urls"][0])
        assert cached_image.read_bytes() == image_bytes
        if not sys.platform.startswith("win"):
            assert stat.S_IMODE(cached_image.stat().st_mode) == 0o600
        assert dispatched["text"] == "what does this show?"
        assert any(call[0][:3] == ["media", "get", image_url] for call in cli.calls)

    @pytest.mark.asyncio
    async def test_retryable_media_failure_is_retried_before_preserving_link(
        self, adapter, monkeypatch, tmp_path
    ):
        image_bytes = b"\x89PNG\r\n\x1a\nprotected-image-after-retry"
        image_hash = hashlib.sha256(image_bytes).hexdigest()
        image_url = f"https://test.relay/media/{image_hash}.png"
        monkeypatch.setenv("IMAGE_CACHE_DIR", str(tmp_path / "images"))
        monkeypatch.setattr(
            _buzz_mod, "_BUZZ_MEDIA_RETRY_DELAYS", (0,), raising=False
        )
        attempts = 0

        async def run_cli(args, *, input_text=None):
            nonlocal attempts
            assert args[:3] == ["media", "get", image_url]
            attempts += 1
            if attempts == 1:
                return (
                    4,
                    "",
                    '{"error":"server_error","message":"media unavailable",'
                    '"retryable":true}',
                )
            output = Path(args[args.index("--output") + 1])
            output.write_bytes(image_bytes)
            return 0, "", ""

        adapter._run_cli = run_cli
        text = f"inspect this\n![image]({image_url})"
        result_text, media_urls, media_types = await adapter._ingest_buzz_images(text)

        assert attempts == 2
        assert image_url not in result_text
        assert len(media_urls) == 1
        assert Path(media_urls[0]).read_bytes() == image_bytes
        assert media_types == ["image/png"]

    @pytest.mark.asyncio
    async def test_text_without_buzz_images_is_preserved_byte_for_byte(self, adapter):
        original = (
            "line one\n\n\n\nline two\n\n"
            "```\ncode\n\n\n\nstill code\n```\n\ntrailing   \n"
        )

        text, media_urls, media_types = await adapter._ingest_buzz_images(original)

        assert text == original
        assert media_urls == []
        assert media_types == []

    @pytest.mark.asyncio
    async def test_external_images_do_not_consume_buzz_download_cap(
        self, adapter, monkeypatch, tmp_path
    ):
        image_bytes = b"\x89PNG\r\n\x1a\nprotected-after-external-links"
        image_hash = hashlib.sha256(image_bytes).hexdigest()
        buzz_url = f"https://test.relay/media/{image_hash}.png"
        external = "\n".join(
            f"![external](https://example.invalid/media/{index}.png)"
            for index in range(_buzz_mod._MAX_BUZZ_IMAGES_PER_MESSAGE)
        )
        text = f"{external}\n![buzz]({buzz_url})"
        monkeypatch.setenv("IMAGE_CACHE_DIR", str(tmp_path / "images"))

        cli = _ScriptedCli()

        async def run_cli(args, *, input_text=None):
            cli.calls.append((list(args), input_text))
            output = Path(args[args.index("--output") + 1])
            output.write_bytes(image_bytes)
            return 0, "", ""

        adapter._run_cli = run_cli
        result_text, media_urls, media_types = await adapter._ingest_buzz_images(text)

        assert len(media_urls) == 1
        assert media_types == ["image/png"]
        assert buzz_url not in result_text
        assert "https://example.invalid/media/0.png" in result_text
        assert [call[0][:3] for call in cli.calls] == [["media", "get", buzz_url]]

    @pytest.mark.asyncio
    async def test_external_markdown_image_is_not_fetched_with_buzz_credentials(self, adapter):
        external_url = "https://example.invalid/media/" + ("a" * 64) + ".png"
        await self._poll_with(
            adapter,
            _event(
                "e1",
                content=f"@Chip inspect this\n![image]({external_url})",
                created_at=10,
            ),
        )

        dispatched = adapter._dispatched[0]
        assert dispatched["media_urls"] == []
        assert external_url in dispatched["text"]
        assert all(call[0][:2] != ["media", "get"] for call in adapter._run_cli.calls)

    @pytest.mark.asyncio
    async def test_failed_authenticated_image_download_preserves_original_link(self, adapter):
        image_url = "https://test.relay/media/" + ("a" * 64) + ".png"
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "get",
            [
                _event(
                    "e1",
                    content=f"@Chip inspect this\n![image]({image_url})",
                    created_at=10,
                )
            ],
        )
        cli.script("media", "get", "", code=3, stderr='{"error":"auth"}')
        adapter._run_cli = cli

        await adapter._poll_channel(CHANNEL)

        dispatched = adapter._dispatched[0]
        assert dispatched["media_urls"] == []
        assert dispatched["message_type"] is _buzz_mod.MessageType.TEXT
        assert image_url in dispatched["text"]
        assert sum(call[0][:2] == ["media", "get"] for call in cli.calls) == 1

    @pytest.mark.asyncio
    async def test_unauthorized_image_message_is_not_downloaded(self, adapter):
        adapter._should_ack_sender = lambda *_args, **_kwargs: False
        image_url = "https://test.relay/media/" + ("a" * 64) + ".png"
        await self._poll_with(
            adapter,
            _event(
                "e1",
                content=f"@Chip inspect this\n![image]({image_url})",
                created_at=10,
            ),
        )

        assert adapter._dispatched == []
        assert all(call[0][:2] != ["media", "get"] for call in adapter._run_cli.calls)

    @pytest.mark.asyncio
    async def test_top_level_command_confirmation_reply_uses_same_session(self):
        """A reply to a top-level Buzz command must see its pending confirm."""
        from tools import slash_confirm

        adapter = _make_adapter()
        dispatched = []

        async def capture(event):
            dispatched.append(event)

        adapter._message_handler = capture
        # This test exercises Buzz source/thread construction, not BasePlatformAdapter's
        # fire-and-forget task scheduler. Keep dispatch synchronous and deterministic.
        adapter.handle_message = capture
        root_id = "f" * 64
        reply_id = "e" * 64

        await adapter._dispatch_message(
            text="/new",
            chat_id=CHANNEL,
            chat_type="group",
            user_id=OTHER_PUBKEY,
            user_name="tester",
            message_id=root_id,
            created_at=10,
        )
        await adapter._dispatch_message(
            text="/always",
            chat_id=CHANNEL,
            chat_type="group",
            user_id=OTHER_PUBKEY,
            user_name="tester",
            message_id=reply_id,
            created_at=11,
            thread_id=root_id,
        )

        root_key = build_session_key(dispatched[0].source)
        reply_key = build_session_key(dispatched[1].source)
        slash_confirm.clear(root_key)

        async def handler(_choice):
            return "approved"

        try:
            slash_confirm.register(root_key, "confirm-1", "new", handler)
            assert reply_key == root_key
            assert slash_confirm.get_pending(reply_key) is not None
        finally:
            slash_confirm.clear(root_key)
            slash_confirm.clear(reply_key)


    @pytest.mark.asyncio
    async def test_central_authorization_grant_controls_intake(self, adapter):
        adapter._should_ack_sender = lambda *_args, **_kwargs: False
        adapter.set_authorization_check(
            lambda user_id, chat_type=None, chat_id=None: user_id == OTHER_PUBKEY
        )

        await self._poll_with(
            adapter, _event("e1", content="@Chip hello", created_at=10)
        )

        assert [item["message_id"] for item in adapter._dispatched] == ["e1"]


class TestAcknowledgementAuthorization:

    @pytest.mark.asyncio
    async def test_unauthorized_sender_gets_no_seen_reaction(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        (tmp_path / "config.yaml").write_text(
            "buzz:\n"
            "  extra:\n"
            f"    allowed_users: [{SELF_NPUB}]\n"
            "    allow_all_users: false\n",
            encoding="utf-8",
        )
        adapter = _make_adapter()
        adapter._should_ack_sender = BuzzAdapter._should_ack_sender
        adapter._message_handler = AsyncMock()
        adapter.handle_message = AsyncMock()
        adapter.send_reaction = AsyncMock(return_value=True)

        await adapter._dispatch_message(
            text="test",
            chat_id=CHANNEL,
            chat_type="group",
            user_id=OTHER_PUBKEY,
            user_name="Other",
            message_id="e1",
            created_at=10,
        )

        adapter.handle_message.assert_awaited_once()
        adapter.send_reaction.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_allowlisted_sender_keeps_seen_reaction(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        (tmp_path / "config.yaml").write_text(
            "buzz:\n"
            "  extra:\n"
            f"    allowed_users: [{OTHER_PUBKEY.upper()}]\n"
            "    allow_all_users: false\n",
            encoding="utf-8",
        )
        adapter = _make_adapter()
        adapter._should_ack_sender = BuzzAdapter._should_ack_sender
        adapter._message_handler = AsyncMock()
        adapter.handle_message = AsyncMock()
        adapter.send_reaction = AsyncMock(return_value=True)

        await adapter._dispatch_message(
            text="test",
            chat_id=CHANNEL,
            chat_type="group",
            user_id=OTHER_PUBKEY,
            user_name="Other",
            message_id="e1",
            created_at=10,
        )

        adapter.send_reaction.assert_awaited_once_with(CHANNEL, "e1", "👀")

    @pytest.mark.asyncio
    async def test_explicit_env_allowlist_controls_seen_reaction(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv("BUZZ_ALLOWED_USERS", OTHER_PUBKEY.upper())
        (tmp_path / "config.yaml").write_text(
            "buzz:\n  extra:\n    allow_all_users: false\n",
            encoding="utf-8",
        )
        adapter = _make_adapter()
        adapter._should_ack_sender = BuzzAdapter._should_ack_sender
        adapter._message_handler = AsyncMock()
        adapter.handle_message = AsyncMock()
        adapter.send_reaction = AsyncMock(return_value=True)

        await adapter._dispatch_message(
            text="test",
            chat_id=CHANNEL,
            chat_type="group",
            user_id=OTHER_PUBKEY,
            user_name="Other",
            message_id="e1",
            created_at=10,
        )

        adapter.send_reaction.assert_awaited_once_with(CHANNEL, "e1", "👀")

    @pytest.mark.asyncio
    async def test_noncanonical_allow_all_env_does_not_ack_sender(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv("BUZZ_ALLOW_ALL_USERS", "on")
        (tmp_path / "config.yaml").write_text(
            "buzz:\n  extra:\n    allow_all_users: false\n",
            encoding="utf-8",
        )
        adapter = _make_adapter()
        adapter._should_ack_sender = BuzzAdapter._should_ack_sender
        adapter._message_handler = AsyncMock()
        adapter.handle_message = AsyncMock()
        adapter.send_reaction = AsyncMock(return_value=True)

        await adapter._dispatch_message(
            text="test",
            chat_id=CHANNEL,
            chat_type="group",
            user_id=OTHER_PUBKEY,
            user_name="Other",
            message_id="e1",
            created_at=10,
        )

        adapter.handle_message.assert_awaited_once()
        adapter.send_reaction.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_explicit_empty_allowlist_env_keeps_runtime_allow_all_reaction(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv("BUZZ_ALLOWED_USERS", "")
        (tmp_path / "config.yaml").write_text(
            "buzz:\n  extra:\n    allow_all_users: true\n",
            encoding="utf-8",
        )
        adapter = _make_adapter()
        adapter._should_ack_sender = BuzzAdapter._should_ack_sender
        adapter._message_handler = AsyncMock()
        adapter.handle_message = AsyncMock()
        adapter.send_reaction = AsyncMock(return_value=True)

        await adapter._dispatch_message(
            text="test",
            chat_id=CHANNEL,
            chat_type="group",
            user_id=OTHER_PUBKEY,
            user_name="Other",
            message_id="e1",
            created_at=10,
        )

        adapter.send_reaction.assert_awaited_once_with(CHANNEL, "e1", "👀")

    @pytest.mark.asyncio
    async def test_explicit_allow_all_env_keeps_runtime_allowlist_reaction(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv("BUZZ_ALLOW_ALL_USERS", "false")
        (tmp_path / "config.yaml").write_text(
            "buzz:\n"
            "  extra:\n"
            f"    allowed_users: [{OTHER_PUBKEY}]\n",
            encoding="utf-8",
        )
        adapter = _make_adapter()
        adapter._should_ack_sender = BuzzAdapter._should_ack_sender
        adapter._message_handler = AsyncMock()
        adapter.handle_message = AsyncMock()
        adapter.send_reaction = AsyncMock(return_value=True)

        await adapter._dispatch_message(
            text="test",
            chat_id=CHANNEL,
            chat_type="group",
            user_id=OTHER_PUBKEY,
            user_name="Other",
            message_id="e1",
            created_at=10,
        )

        adapter.send_reaction.assert_awaited_once_with(CHANNEL, "e1", "👀")

    @pytest.mark.asyncio
    async def test_multiplex_ack_uses_active_profile_scope(self, monkeypatch, tmp_path):
        from agent import secret_scope

        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv("BUZZ_ALLOW_ALL_USERS", "true")
        (tmp_path / "config.yaml").write_text("buzz:\n  extra: {}\n", encoding="utf-8")
        token = secret_scope.set_secret_scope({"BUZZ_ALLOWED_USERS": SELF_PUBKEY})
        secret_scope.set_multiplex_active(True)
        try:
            adapter = _make_adapter()
            adapter._should_ack_sender = BuzzAdapter._should_ack_sender
            adapter._message_handler = AsyncMock()
            adapter.handle_message = AsyncMock()
            adapter.send_reaction = AsyncMock(return_value=True)

            await adapter._dispatch_message(
                text="test",
                chat_id=CHANNEL,
                chat_type="group",
                user_id=OTHER_PUBKEY,
                user_name="Other",
                message_id="e1",
                created_at=10,
            )

            adapter.handle_message.assert_awaited_once()
            adapter.send_reaction.assert_not_awaited()
        finally:
            secret_scope.reset_secret_scope(token)
            secret_scope.set_multiplex_active(False)


# ── DM classification via p-tags (issue #68871) ──────────────────────────
#
# `buzz dms list` returns [] on some hosted relays, so DM conversations leak
# in via `channels list` and get seeded chat_type="group".  The adapter must
# reclassify them from the Nostr tags of real traffic: DM messages are
# p-tagged to our own pubkey WITHOUT the text mentioning us, while channel
# messages only ever p-tag us when the text visibly @mentions us.


def _tagged_event(event_id, channel, *, content, pubkey=OTHER_PUBKEY,
                  created_at=1000, kind=9, p=None, reply_to=None):
    """Event with the tag shapes observed on a live relay (h/p/e tags)."""
    tags = [["h", channel]]
    if reply_to:
        tags.append(["e", reply_to, "", "reply"])
    if p:
        tags.append(["p", p])
    return {
        "id": event_id,
        "pubkey": pubkey,
        "content": content,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
    }


class TestDmClassification:

    @pytest.fixture
    def adapter(self):
        a = _make_adapter()
        a._dispatched = []

        async def capture(**kwargs):
            a._dispatched.append(kwargs)

        a._dispatch_message = capture
        a._message_handler = AsyncMock()
        # Metadata exactly as `channels list` returns it on the hosted relay.
        a._channel_meta = {
            DM_CHANNEL: {"channel_id": DM_CHANNEL, "name": "DM", "description": ""},
            CHANNEL: {
                "channel_id": CHANNEL,
                "name": "general",
                "description": "General conversation and community updates.",
            },
        }
        a._channel_names = {DM_CHANNEL: "DM", CHANNEL: "general"}
        # Both leaked in as group — the bug under test.
        a._channel_state[DM_CHANNEL] = {"chat_type": "group", "last_ts": 0, "seen": {}}
        a._channel_state[CHANNEL] = {"chat_type": "group", "last_ts": 0, "seen": {}}
        return a

    async def _poll_with(self, adapter, channel, *events):
        cli = _ScriptedCli()
        cli.script("messages", "get", list(events))
        adapter._run_cli = cli
        await adapter._poll_channel(channel)

    @pytest.mark.asyncio
    async def test_unmentioned_ptagged_dm_latches_and_dispatches(self, adapter):
        """The reported bug: a DM without an @mention must dispatch."""
        await self._poll_with(
            adapter, DM_CHANNEL,
            _tagged_event("e1", DM_CHANNEL, content="here's a test message", p=SELF_PUBKEY),
        )
        assert adapter._channel_state[DM_CHANNEL]["chat_type"] == "dm"
        assert [d["message_id"] for d in adapter._dispatched] == ["e1"]
        assert adapter._dispatched[0]["chat_type"] == "dm"


    @pytest.mark.asyncio
    async def test_general_reply_ptagging_self_stays_channel(self, adapter):
        """A #general reply to us p-tags our pubkey (observed live) — that
        must NOT reclassify the channel; mention gating still applies."""
        await self._poll_with(
            adapter, CHANNEL,
            _tagged_event("e1", CHANNEL, content="@chip what's up?",
                          p=SELF_PUBKEY, reply_to="root-event"),
        )
        assert adapter._channel_state[CHANNEL]["chat_type"] == "group"
        # It carried a mention, so it dispatches — but as a group message.
        assert [d["chat_type"] for d in adapter._dispatched] == ["group"]

        # And once the mention is absent, the channel gate drops the message
        # even though the earlier reply p-tagged us.
        await self._poll_with(
            adapter, CHANNEL,
            _tagged_event("e2", CHANNEL, content="thanks everyone", created_at=1001),
        )
        assert len(adapter._dispatched) == 1


    @pytest.mark.asyncio
    async def test_channel_like_metadata_blocks_latch_even_without_mention(self, adapter):
        """Second guard on its own: even a p-tagged, un-mentioned message
        cannot reclassify a conversation whose metadata says real channel."""
        adapter._channel_meta[CHANNEL]["description"] = ""
        adapter._channel_meta[CHANNEL]["name"] = "announcements"
        await self._poll_with(
            adapter, CHANNEL,
            _tagged_event("e1", CHANNEL, content="fyi everyone", p=SELF_PUBKEY),
        )
        assert adapter._channel_state[CHANNEL]["chat_type"] == "group"
        assert adapter._dispatched == []


    @pytest.mark.asyncio
    async def test_dm_shaped_channel_discovered_when_dms_list_empty(self):
        """Fallback discovery: with `dms list` broken (returns []), a
        DM-shaped `channels list` entry gets watched; real channels not
        already watched are left alone."""
        a = _make_adapter()
        cli = _ScriptedCli()
        cli.script("dms", "list", [])
        cli.script("channels", "list", [
            {"channel_id": DM_CHANNEL, "name": "DM", "description": "", "created_at": 1},
            {"channel_id": CHANNEL, "name": "general",
             "description": "General conversation and community updates.", "created_at": 2},
        ])
        a._run_cli = cli
        await a._discover_dms(seed=False)
        # Watched as group; the p-tag latch flips it on the first real DM.
        assert a._channel_state[DM_CHANNEL]["chat_type"] == "group"
        assert a._may_reclassify_as_dm(DM_CHANNEL) is True
        assert CHANNEL not in a._channel_state
        assert a._may_reclassify_as_dm(CHANNEL) is False


# ── Dynamic joined-channel discovery ─────────────────────────────────────


class TestChannelDiscovery:
    @pytest.mark.asyncio
    async def test_authoritative_reconciliation_reports_name_change(self):
        adapter = _make_adapter()
        adapter._channel_state = {
            CHANNEL: {"chat_type": "group", "last_ts": 1, "seen": {}},
        }
        adapter._channel_names = {CHANNEL: "old name"}
        adapter._run_cli = AsyncMock(return_value=(0, json.dumps([
            {"channel_id": CHANNEL, "name": "new name"},
        ]), ""))

        assert await adapter._discover_joined_channels(since=9) is True
        assert adapter._channel_names[CHANNEL] == "new name"

    @pytest.mark.asyncio
    async def test_authoritative_reconciliation_removes_departed_group_but_preserves_dm(self):
        adapter = _make_adapter()
        adapter.cli_path = "/fake/buzz"
        departed = "12c81eb7-3a12-47c1-b8af-c66f1c74ca8b"
        dm = "4764ae67-7cd8-4f3e-967d-7dd93986b11a"
        adapter._channel_state = {
            CHANNEL: {"chat_type": "group", "last_ts": 1, "seen": {}},
            departed: {"chat_type": "group", "last_ts": 1, "seen": {}},
            dm: {"chat_type": "dm", "last_ts": 1, "seen": {}},
        }
        adapter._channel_names = {CHANNEL: "kept", departed: "gone", dm: "dm"}
        adapter._run_cli = AsyncMock(return_value=(0, json.dumps([
            {"channel_id": CHANNEL, "name": "kept"},
        ]), ""))

        assert await adapter._discover_joined_channels(since=9) is True
        assert set(adapter._channel_state) == {CHANNEL, dm}
        assert departed not in adapter._channel_names
        assert departed not in adapter._directory_content()["channel_ids"]

    @pytest.mark.asyncio
    async def test_removal_event_closes_subscription_and_reprojects_directory(self):
        adapter = _make_adapter()
        departed = "12c81eb7-3a12-47c1-b8af-c66f1c74ca8b"
        adapter._channel_state = {
            CHANNEL: {"chat_type": "group", "last_ts": 1, "seen": {}},
            departed: {"chat_type": "group", "last_ts": 1, "seen": {}},
        }
        adapter._discover_joined_channels = AsyncMock(side_effect=lambda **_: adapter._channel_state.pop(departed) is not None)
        adapter._discover_dms = AsyncMock()
        adapter._publish_directory_websocket = AsyncMock()
        websocket = AsyncMock()
        subscriptions = {"hermes-buzz-0": CHANNEL, "hermes-buzz-1": departed}

        await adapter._handle_membership_event(
            websocket, subscriptions, {"kind": 44101, "created_at": 10}
        )

        assert departed not in subscriptions.values()
        assert json.loads(websocket.send.await_args_list[0].args[0]) == ["CLOSE", "hermes-buzz-1"]
        adapter._publish_directory_websocket.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_explicit_channels_are_not_removed_by_authoritative_joined_snapshot(self):
        adapter = _make_adapter({"channels": [CHANNEL]})
        adapter._channel_state = {CHANNEL: {"chat_type": "group", "last_ts": 1, "seen": {}}}
        adapter._run_cli = AsyncMock()
        assert await adapter._discover_joined_channels(since=2) is False
        assert CHANNEL in adapter._channel_state
        adapter._run_cli.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_poll_sweep_does_not_publish_unchanged_successful_projection(self, monkeypatch):
        adapter = _make_adapter({"poll_interval": 0.01})
        adapter._channel_state = {CHANNEL: {"chat_type": "group", "last_ts": 1, "seen": {}}}
        adapter._last_directory_projection = adapter._directory_projection()
        adapter._discover_joined_channels = AsyncMock(return_value=False)
        adapter._discover_dms = AsyncMock()
        adapter._poll_channel = AsyncMock(side_effect=asyncio.CancelledError)
        adapter._publish_directory_fallback = AsyncMock(return_value=True)
        monkeypatch.setattr(_buzz_mod, "_DM_DISCOVERY_EVERY", 1)
        with pytest.raises(asyncio.CancelledError):
            await adapter._poll_loop()
        adapter._discover_joined_channels.assert_awaited_once()
        adapter._publish_directory_fallback.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("last_projection", ["previous", None])
    async def test_poll_sweep_publishes_changed_state_or_retries_prior_failure(
        self, monkeypatch, last_projection
    ):
        adapter = _make_adapter({"poll_interval": 0.01})
        adapter._channel_state = {CHANNEL: {"chat_type": "group", "last_ts": 1, "seen": {}}}
        adapter._last_directory_projection = last_projection
        adapter._discover_joined_channels = AsyncMock(return_value=last_projection == "previous")
        adapter._discover_dms = AsyncMock()
        adapter._poll_channel = AsyncMock(side_effect=asyncio.CancelledError)
        adapter._publish_directory_fallback = AsyncMock(return_value=True)
        monkeypatch.setattr(_buzz_mod, "_DM_DISCOVERY_EVERY", 1)
        with pytest.raises(asyncio.CancelledError):
            await adapter._poll_loop()
        adapter._publish_directory_fallback.assert_awaited_once()


    @pytest.mark.asyncio
    async def test_connect_lists_only_joined_channels(self, monkeypatch):
        import gateway.status as gateway_status

        monkeypatch.setattr(
            gateway_status, "acquire_scoped_lock", lambda platform, key: True
        )
        monkeypatch.setattr(_buzz_mod, "_resolve_private_key", lambda extra=None: "nsec1test")
        monkeypatch.setattr(_buzz_mod.time, "time", lambda: 1000)
        adapter = _make_adapter()
        adapter.cli_path = "/fake/buzz"
        adapter._start_websocket = AsyncMock(return_value=False)
        adapter._publish_directory_fallback = AsyncMock(return_value=True)
        unjoined_channel = "12c81eb7-3a12-47c1-b8af-c66f1c74ca8b"
        cli = _ScriptedCli()
        cli.script(
            "users", "get",
            [{"pubkey": SELF_PUBKEY, "display_name": "Chip"}],
        )
        cli.script("messages", "get", [])
        cli.script("dms", "list", [])
        membership_cursors = []

        async def run_cli(args, *, input_text=None):
            if args == ["channels", "list", "--member"]:
                membership_cursors.append(adapter._membership_since)
                return 0, json.dumps([
                    {"channel_id": CHANNEL, "name": "general", "description": "General"},
                ]), ""
            if args == ["channels", "list"]:
                return 0, json.dumps([
                    {"channel_id": CHANNEL, "name": "general", "description": "General"},
                    {"channel_id": unjoined_channel, "name": "other", "description": "Other"},
                ]), ""
            return await cli(args, input_text=input_text)

        adapter._run_cli = run_cli

        try:
            assert await adapter.connect() is True
        finally:
            await adapter.disconnect()

        assert membership_cursors == [1000]
        assert unjoined_channel not in adapter._channel_state

    @pytest.mark.asyncio
    async def test_membership_event_subscribes_to_new_joined_channel(self):
        adapter = _make_adapter()
        adapter._channel_state[CHANNEL] = {
            "chat_type": "group", "last_ts": 100, "seen": {},
        }
        new_channel = "4764ae67-7cd8-4f3e-967d-7dd93986b11a"
        cli = _ScriptedCli()
        cli.script("channels", "list", [
            {"channel_id": CHANNEL, "name": "general", "description": "General"},
            {"channel_id": new_channel, "name": "project", "description": "Project"},
        ])
        cli.script("dms", "list", [])
        adapter._run_cli = cli
        adapter._publish_directory_websocket = AsyncMock()
        websocket = AsyncMock()
        subscriptions = {"hermes-buzz-0": CHANNEL}

        await adapter._handle_membership_event(
            websocket,
            subscriptions,
            {
                "created_at": 1234,
                "kind": _buzz_mod._WS_MEMBERSHIP_KIND,
                "tags": [["p", SELF_PUBKEY], ["h", new_channel]],
            },
        )

        assert new_channel in adapter._channel_state
        assert adapter._channel_state[new_channel]["chat_type"] == "group"
        assert adapter._channel_state[new_channel]["last_ts"] == 1234
        assert new_channel in subscriptions.values()
        assert (["channels", "list", "--member"], None) in cli.calls
        request = json.loads(websocket.send.await_args.args[0])
        assert request[2]["#h"] == [new_channel]
        assert request[2]["since"] == 1234
        adapter._publish_directory_websocket.assert_awaited_once_with(websocket)

    @pytest.mark.asyncio
    async def test_membership_event_respects_explicit_channel_allowlist(self):
        adapter = _make_adapter({"channels": [CHANNEL]})
        adapter._channel_state[CHANNEL] = {
            "chat_type": "group", "last_ts": 100, "seen": {},
        }
        new_channel = "4764ae67-7cd8-4f3e-967d-7dd93986b11a"
        cli = _ScriptedCli()
        cli.script("channels", "list", [
            {"channel_id": new_channel, "name": "project", "description": "Project"},
        ])
        cli.script("dms", "list", [])
        adapter._run_cli = cli
        adapter._publish_directory_websocket = AsyncMock()
        websocket = AsyncMock()
        subscriptions = {"hermes-buzz-0": CHANNEL}

        await adapter._handle_membership_event(
            websocket,
            subscriptions,
            {"created_at": 1234, "kind": _buzz_mod._WS_MEMBERSHIP_KIND},
        )

        assert new_channel not in adapter._channel_state
        assert new_channel not in subscriptions.values()
        websocket.send.assert_not_awaited()
        adapter._publish_directory_websocket.assert_awaited_once_with(websocket)

    @pytest.mark.asyncio
    async def test_membership_event_retries_after_joined_channel_discovery_failure(self):
        adapter = _make_adapter()
        adapter._membership_since = 100
        cli = _ScriptedCli()
        cli.script("channels", "list", [], code=2, stderr="temporary failure")
        adapter._run_cli = cli
        websocket = AsyncMock()

        with pytest.raises(ConnectionError, match="joined-channel discovery failed"):
            await adapter._handle_membership_event(
                websocket,
                {"hermes-buzz-0": CHANNEL},
                {"created_at": 1234, "kind": _buzz_mod._WS_MEMBERSHIP_KIND},
            )

        assert adapter._membership_since == 100
        websocket.send.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_removal_reconciliation_subscribes_concurrent_new_join(self, monkeypatch):
        existing_channel = CHANNEL
        removed_channel = "4764ae67-7cd8-4f3e-967d-7dd93986b11a"
        new_channel = "85f52f6f-af83-4a91-bb7a-4e3605cf8e6e"
        monkeypatch.setattr(_buzz_mod.time, "time", lambda: 2000)
        adapter = _make_adapter()
        adapter._membership_since = 100
        adapter._channel_state[existing_channel] = {
            "chat_type": "group", "last_ts": 100, "seen": {},
        }
        adapter._channel_state[removed_channel] = {
            "chat_type": "group", "last_ts": 100, "seen": {},
        }
        cli = _ScriptedCli()
        cli.script("channels", "list", [
            {"channel_id": existing_channel, "name": "general"},
            {"channel_id": new_channel, "name": "new"},
        ])
        cli.script("messages", "get", [])
        adapter._run_cli = cli
        adapter._publish_directory_websocket = AsyncMock()
        websocket = AsyncMock()
        subscriptions = {
            "existing": existing_channel,
            "removed": removed_channel,
            _buzz_mod._WS_MEMBERSHIP_SUB_ID: None,
        }

        await adapter._handle_membership_event(
            websocket,
            subscriptions,
            {
                "created_at": 1500,
                "kind": _buzz_mod._WS_MEMBERSHIP_REMOVED_KIND,
                "tags": [["p", SELF_PUBKEY], ["h", removed_channel]],
            },
        )

        assert removed_channel not in adapter._channel_state
        assert removed_channel not in subscriptions.values()
        assert new_channel in adapter._channel_state
        assert new_channel in subscriptions.values()
        requests = [json.loads(call.args[0]) for call in websocket.send.await_args_list]
        assert ["CLOSE", "removed"] in requests
        new_request = next(
            request
            for request in requests
            if len(request) > 2 and request[2].get("#h") == [new_channel]
        )
        assert new_request[2]["since"] == 2000
        adapter._publish_directory_websocket.assert_awaited_once_with(websocket)

    @pytest.mark.asyncio
    async def test_out_of_order_removals_reconcile_each_authoritative_snapshot(self):
        first_channel = CHANNEL
        second_channel = "4764ae67-7cd8-4f3e-967d-7dd93986b11a"
        adapter = _make_adapter()
        adapter._membership_since = 100
        adapter._channel_state[first_channel] = {
            "chat_type": "group", "last_ts": 100, "seen": {},
        }
        adapter._channel_state[second_channel] = {
            "chat_type": "group", "last_ts": 100, "seen": {},
        }
        cli = _ScriptedCli()
        cli.script("channels", "list", [
            {"channel_id": second_channel, "name": "second"},
        ])
        cli.script("channels", "list", [])
        adapter._run_cli = cli
        adapter._publish_directory_websocket = AsyncMock()
        websocket = AsyncMock()
        subscriptions = {"first": first_channel, "second": second_channel}

        await adapter._handle_membership_event(
            websocket,
            subscriptions,
            {
                "created_at": 1001,
                "kind": _buzz_mod._WS_MEMBERSHIP_REMOVED_KIND,
                "tags": [["p", SELF_PUBKEY], ["h", first_channel]],
            },
        )
        await adapter._handle_membership_event(
            websocket,
            subscriptions,
            {
                "created_at": 1000,
                "kind": _buzz_mod._WS_MEMBERSHIP_REMOVED_KIND,
                "tags": [["p", SELF_PUBKEY], ["h", second_channel]],
            },
        )

        assert adapter._channel_state == {}
        assert subscriptions == {}
        assert adapter._membership_since == 1001
        assert [call[0] for call in cli.calls].count(
            ["channels", "list", "--member"]
        ) == 2
        assert websocket.send.await_count == 2

    @pytest.mark.asyncio
    async def test_membership_removal_preserves_explicit_channel_configuration(self):
        adapter = _make_adapter({"channels": [CHANNEL]})
        adapter._membership_since = 100
        state = {"chat_type": "group", "last_ts": 100, "seen": {}}
        adapter._channel_state[CHANNEL] = state
        adapter._publish_directory_websocket = AsyncMock()
        websocket = AsyncMock()
        subscriptions = {"hermes-buzz-0": CHANNEL}

        await adapter._handle_membership_event(
            websocket,
            subscriptions,
            {
                "created_at": 1234,
                "kind": _buzz_mod._WS_MEMBERSHIP_REMOVED_KIND,
                "tags": [["p", SELF_PUBKEY], ["h", CHANNEL]],
            },
        )

        assert adapter._channel_state[CHANNEL] is state
        assert subscriptions == {"hermes-buzz-0": CHANNEL}
        assert adapter._membership_since == 1234
        websocket.send.assert_not_awaited()
        adapter._publish_directory_websocket.assert_not_awaited()


# ── Sending ───────────────────────────────────────────────────────────────


class TestBuzzAdapterSend:

    @pytest.mark.asyncio
    async def test_send_success_via_stdin(self):
        adapter = _make_adapter()
        adapter._channel_state[CHANNEL] = {"chat_type": "group", "last_ts": 0, "seen": {}}
        cli = _ScriptedCli()
        cli.script("messages", "send", {"accepted": True, "event_id": "evt123", "message": ""})
        adapter._run_cli = cli

        result = await adapter.send(CHANNEL, "hello **markdown**")
        assert result.success is True
        assert result.message_id == "evt123"
        assert len(cli.calls) == 1

        args, stdin_text = cli.calls[0]
        assert args[:2] == ["messages", "send"]
        assert args[args.index("--channel") + 1] == CHANNEL
        # Content travels via stdin (--content -), never argv
        assert args[args.index("--content") + 1] == "-"
        assert stdin_text == "hello **markdown**"
        # Our own event id is marked seen for echo suppression
        assert "evt123" in adapter._channel_state[CHANNEL]["seen"]

    @pytest.mark.asyncio
    async def test_send_metadata_thread_id_uses_reply_to_flag(self):
        adapter = _make_adapter()
        cli = _ScriptedCli()
        cli.script("messages", "send", {"accepted": True, "event_id": "evt124", "message": ""})
        adapter._run_cli = cli

        result = await adapter.send(
            CHANNEL,
            "working",
            metadata={"thread_id": "buzz-event-123"},
        )

        assert result.success is True
        args, _stdin = cli.calls[0]
        assert args[args.index("--reply-to") + 1] == "buzz-event-123"

    @pytest.mark.asyncio
    async def test_send_configured_agent_handoff_uses_exact_pubkey(self):
        adapter = _make_adapter(
            {"outbound_mention_pubkeys": {"CodexTerraM": OTHER_PUBKEY}}
        )
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "evt-agent-handoff", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send(
            CHANNEL,
            "@CodexTerraM — review the clean rebuild.",
            metadata={"thread_id": "thread-root"},
        )

        assert result.success is True
        assert len(cli.calls) == 1
        args, stdin_text = cli.calls[0]
        assert args[args.index("--mention") + 1] == OTHER_PUBKEY
        assert stdin_text == "@CodexTerraM — review the clean rebuild."

    @pytest.mark.asyncio
    async def test_send_uses_casefold_consistently_for_unicode_names(self):
        adapter = _make_adapter(
            {
                "outbound_mention_pubkeys": {
                    "i": OTHER_PUBKEY,
                    "ı": SELF_PUBKEY,
                }
            }
        )
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "evt-unicode-name", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send(CHANNEL, "@ı — review this.")

        assert result.success is True
        args, stdin_text = cli.calls[0]
        mention_values = [
            args[index + 1]
            for index, value in enumerate(args)
            if value == "--mention"
        ]
        assert mention_values == [SELF_PUBKEY]
        assert stdin_text == "@ı — review this."

    @pytest.mark.asyncio
    async def test_send_never_downgrades_configured_agent_handoff(self):
        adapter = _make_adapter(
            {"outbound_mention_pubkeys": {"CodexTerraM": OTHER_PUBKEY}}
        )
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr=(
                "mention '@CodexTerraM' does not match a current channel member"
            ),
        )
        adapter._run_cli = cli

        result = await adapter.send(
            CHANNEL,
            "@CodexTerraM — review the clean rebuild.",
        )

        assert result.success is False
        assert len(cli.calls) == 1
        args, stdin_text = cli.calls[0]
        assert args[args.index("--mention") + 1] == OTHER_PUBKEY
        assert stdin_text == "@CodexTerraM — review the clean rebuild."

    @pytest.mark.asyncio
    async def test_send_configured_handoff_only_protects_its_own_marker(self):
        adapter = _make_adapter(
            {"outbound_mention_pubkeys": {"CodexTerraM": OTHER_PUBKEY}}
        )
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr="mention '@ghost' does not match a current channel member",
        )
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "evt-mixed", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send(
            CHANNEL,
            "@CodexTerraM — ask @ghost to review.",
        )

        assert result.success is True
        assert len(cli.calls) == 2
        first_args, first_text = cli.calls[0]
        second_args, second_text = cli.calls[1]
        assert first_args == second_args
        assert first_args[first_args.index("--mention") + 1] == OTHER_PUBKEY
        assert first_text == "@CodexTerraM — ask @ghost to review."
        assert second_text == "@CodexTerraM — ask ghost to review."

    @pytest.mark.asyncio
    async def test_send_unconfigured_prefix_does_not_strip_configured_handoff(self):
        adapter = _make_adapter(
            {"outbound_mention_pubkeys": {"Ghostly": OTHER_PUBKEY}}
        )
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr="mention '@ghost' does not match a current channel member",
        )
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "evt-prefix", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send(
            CHANNEL,
            "@Ghostly — ask @ghost to review.",
        )

        assert result.success is True
        assert [text for _args, text in cli.calls] == [
            "@Ghostly — ask @ghost to review.",
            "@Ghostly — ask ghost to review.",
        ]

    @pytest.mark.asyncio
    async def test_send_retries_unresolved_mentions_as_readable_text(self):
        adapter = _make_adapter()
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr=(
                "user_error: mention '@teknium1' does not match a current "
                "channel member; retry with --mention <pubkey>"
            ),
        )
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "evt-fallback", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send(
            CHANNEL,
            "Ask @teknium1 and notify @Codex, but keep bob@example.com intact.",
            metadata={"thread_id": "thread-root"},
        )

        assert result.success is True
        assert result.message_id == "evt-fallback"
        assert len(cli.calls) == 2
        first_args, first_text = cli.calls[0]
        fallback_args, fallback_text = cli.calls[1]
        assert first_text == "Ask @teknium1 and notify @Codex, but keep bob@example.com intact."
        assert fallback_text == "Ask teknium1 and notify @Codex, but keep bob@example.com intact."
        assert fallback_args == first_args
        assert fallback_args[fallback_args.index("--reply-to") + 1] == "thread-root"

    @pytest.mark.asyncio
    async def test_send_retries_unicode_unresolved_mention(self):
        adapter = _make_adapter()
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr="mention '@Иван' does not match a current channel member",
        )
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "evt-unicode", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send(CHANNEL, "Ask @Иван Петров to review")

        assert result.success is True
        assert [text for _args, text in cli.calls] == [
            "Ask @Иван Петров to review",
            "Ask Иван Петров to review",
        ]

    @pytest.mark.asyncio
    async def test_send_retries_apostrophe_name(self):
        adapter = _make_adapter()
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr="mention '@O'Brien' does not match a current channel member",
        )
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "evt-apostrophe", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send(CHANNEL, "Ask @O'Brien to review")

        assert result.success is True
        assert [text for _args, text in cli.calls] == [
            "Ask @O'Brien to review",
            "Ask O'Brien to review",
        ]

    @pytest.mark.asyncio
    async def test_send_retries_each_new_unresolved_name_within_cap(self):
        adapter = _make_adapter()
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr="mention '@Ghost One' does not match a current channel member",
        )
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr="mention '@Ghost Two' does not match a current channel member",
        )
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "evt-multiple", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send(CHANNEL, "ping @Ghost One and @Ghost Two")

        assert result.success is True
        assert [text for _args, text in cli.calls] == [
            "ping @Ghost One and @Ghost Two",
            "ping Ghost One and @Ghost Two",
            "ping Ghost One and Ghost Two",
        ]

    @pytest.mark.asyncio
    async def test_send_caps_sequential_mention_fallback_retries(self):
        adapter = _make_adapter()
        cli = _ScriptedCli()
        for name in ("One", "Two", "Three", "Four"):
            cli.script(
                "messages",
                "send",
                "",
                code=1,
                stderr=(
                    f"mention '@Ghost {name}' does not match a current channel member"
                ),
            )
        adapter._run_cli = cli

        result = await adapter.send(
            CHANNEL,
            "ping @Ghost One, @Ghost Two, @Ghost Three, and @Ghost Four",
        )

        assert result.success is False
        assert result.error == (
            "mention '@Ghost Four' does not match a current channel member"
        )
        assert len(cli.calls) == 4

    @pytest.mark.asyncio
    async def test_send_retries_ambiguous_mention_without_silencing_other_mentions(self):
        adapter = _make_adapter()
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr=(
                "mention '@Twin' is ambiguous; candidates: npub1a, npub1b. "
                "Retry with --mention <pubkey>"
            ),
        )
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "evt-ambiguous", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send(CHANNEL, "Ask @Twin and notify @Codex")

        assert result.success is True
        assert cli.calls[1][1] == "Ask Twin and notify @Codex"

    @pytest.mark.asyncio
    async def test_send_retries_max_mentions_with_all_markers_neutralized(self):
        adapter = _make_adapter()
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr="too many unique message mentions (max 2)",
        )
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "evt-max", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send(
            CHANNEL,
            "Ask @Иван, @李明, and @Codex; email bob@example.com",
        )

        assert result.success is True
        assert cli.calls[1][1] == (
            "Ask Иван, 李明, and Codex; email bob@example.com"
        )

    @pytest.mark.asyncio
    async def test_send_does_not_retry_unrelated_failure(self):
        adapter = _make_adapter()
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr="forbidden: sender is not authorized",
        )
        adapter._run_cli = cli

        result = await adapter.send(CHANNEL, "Ask @Codex")

        assert result.success is False
        assert len(cli.calls) == 1

    @pytest.mark.asyncio
    async def test_send_propagates_second_attempt_failure_without_third_attempt(self):
        adapter = _make_adapter()
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr="mention '@ghost' does not match a current channel member",
        )
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr="relay unavailable after fallback",
        )
        adapter._run_cli = cli

        result = await adapter.send(CHANNEL, "Ask @ghost")

        assert result.success is False
        assert result.error == "relay unavailable after fallback"
        assert len(cli.calls) == 2

    @pytest.mark.asyncio
    async def test_send_image_local_file_uses_file_flag(self, tmp_path):
        img = tmp_path / "shot.png"
        img.write_bytes(b"\x89PNG fake")
        adapter = _make_adapter()
        cli = _ScriptedCli()
        cli.script("messages", "send", {"accepted": True, "event_id": "evt126", "message": ""})
        adapter._run_cli = cli
        result = await adapter.send_image(CHANNEL, str(img), caption="screenshot")
        assert result.success is True
        args, _stdin = cli.calls[0]
        assert args[args.index("--file") + 1] == str(img)

    @pytest.mark.asyncio
    async def test_top_level_image_send_opens_active_thread(self, tmp_path):
        img = tmp_path / "shot.png"
        img.write_bytes(b"\x89PNG fake")
        adapter = _make_adapter()
        adapter._channel_state[CHANNEL] = {
            "chat_type": "group",
            "last_ts": 0,
            "seen": {},
        }
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "agent-image-root", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send_image(CHANNEL, str(img), caption="screenshot")

        assert result.success is True
        assert list(adapter._channel_state[CHANNEL]["agent_thread_ids"]) == [
            "agent-image-root"
        ]

    @pytest.mark.asyncio
    async def test_send_image_reply_targets_root_and_opens_active_thread(self, tmp_path):
        img = tmp_path / "shot.png"
        img.write_bytes(b"\x89PNG fake")
        adapter = _make_adapter()
        adapter._channel_state[CHANNEL] = {
            "chat_type": "group",
            "last_ts": 0,
            "seen": {},
            "thread_roots": _buzz_mod.OrderedDict({"nested": "root"}),
        }
        cli = _ScriptedCli()
        cli.script(
            "messages", "send",
            {"accepted": True, "event_id": "agent-image", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send_image(
            CHANNEL, str(img), caption="screenshot", reply_to="nested"
        )

        assert result.success is True
        args, _stdin = cli.calls[0]
        assert args[args.index("--reply-to") + 1] == "root"
        assert list(adapter._channel_state[CHANNEL]["agent_thread_ids"]) == [
            "root",
            "agent-image",
        ]

    @pytest.mark.asyncio
    async def test_send_image_retries_unresolved_caption_mention(self, tmp_path):
        img = tmp_path / "shot.png"
        img.write_bytes(b"\x89PNG fake")
        adapter = _make_adapter()
        cli = _ScriptedCli()
        cli.script(
            "messages",
            "send",
            "",
            code=1,
            stderr="mention '@ghost' does not match a current channel member",
        )
        cli.script(
            "messages",
            "send",
            {"accepted": True, "event_id": "evt-image-fallback", "message": ""},
        )
        adapter._run_cli = cli

        result = await adapter.send_image(
            CHANNEL,
            str(img),
            caption="For @ghost",
            reply_to="thread-root",
        )

        assert result.success is True
        assert [text for _args, text in cli.calls] == ["For @ghost", "For ghost"]
        assert cli.calls[1][0] == cli.calls[0][0]


# ── Lifecycle ─────────────────────────────────────────────────────────────


class TestBuzzAdapterLifecycle:


    @pytest.mark.asyncio
    async def test_disconnect_releases_scoped_lock(self, monkeypatch):
        """The identity lock taken in connect() must be released on disconnect."""
        import gateway.status as gateway_status

        released = []
        monkeypatch.setattr(
            gateway_status,
            "release_scoped_lock",
            lambda platform, key: released.append((platform, key)),
        )
        adapter = _make_adapter()
        adapter._lock_key = "wss://relay.example:" + SELF_PUBKEY
        await adapter.disconnect()
        assert released == [("buzz", "wss://relay.example:" + SELF_PUBKEY)]
        assert adapter._lock_key is None

    @pytest.mark.asyncio
    async def test_connect_fails_when_identity_lock_held(self, monkeypatch):
        """A second profile using the same relay+pubkey must fail fast."""
        import gateway.status as gateway_status

        monkeypatch.setattr(
            gateway_status, "acquire_scoped_lock", lambda platform, key: False
        )
        adapter = _make_adapter()
        adapter.cli_path = "/fake/buzz"
        monkeypatch.setattr(_buzz_mod, "_resolve_private_key", lambda extra=None: "nsec1test")
        cli = _ScriptedCli()
        cli.script(
            "users", "get",
            [{"pubkey": SELF_PUBKEY, "display_name": "Chip"}],
        )
        adapter._run_cli = cli
        assert await adapter.connect() is False
        assert adapter._lock_key is None


# ── Credentials / requirements ────────────────────────────────────────────


class TestCredentialResolution:

    def test_env_key_wins(self, monkeypatch):
        monkeypatch.setenv("BUZZ_PRIVATE_KEY", "nsec1fromenv")
        assert _resolve_private_key() == "nsec1fromenv"

    def test_credentials_file_fallback(self, monkeypatch, tmp_path):
        creds = tmp_path / "agent_credentials.json"
        creds.write_text(json.dumps({"nsec": "nsec1fromfile", "npub": "npub1x"}), encoding="utf-8")
        monkeypatch.setenv("BUZZ_CREDENTIALS_FILE", str(creds))
        assert _resolve_private_key() == "nsec1fromfile"


# ── Env enablement / registration / standalone send ──────────────────────


class TestEnvEnablement:

    def test_returns_none_when_unconfigured(self):
        assert _env_enablement() is None

    def test_yaml_config_bridges_thread_mention_setting(self):
        _apply_yaml_config(
            {},
            {"extra": {"thread_require_mention": False}},
        )

        assert _make_adapter().thread_require_mention is False


class TestBuzzPluginRegistration:

    def test_register_platform_contract(self):
        from gateway.platform_registry import platform_registry

        platform_registry.unregister("buzz")
        ctx = MagicMock()
        register(ctx)
        ctx.register_platform.assert_called_once()
        kwargs = ctx.register_platform.call_args.kwargs
        assert kwargs["name"] == "buzz"
        assert kwargs["cron_deliver_env_var"] == "BUZZ_HOME_CHANNEL"
        assert kwargs["allowed_users_env"] == "BUZZ_ALLOWED_USERS"
        assert kwargs["allow_all_env"] == "BUZZ_ALLOW_ALL_USERS"
        assert callable(kwargs["authorization_config_fn"])
        assert callable(kwargs["authorization_user_normalizer"])
        assert callable(kwargs["standalone_sender_fn"])
        assert callable(kwargs["env_enablement_fn"])
        assert set(kwargs["required_env"]) == {"BUZZ_RELAY_URL", "BUZZ_PRIVATE_KEY"}


class TestStandaloneSend:

    @pytest.mark.asyncio
    async def test_standalone_invalid_outbound_mapping_returns_error(
        self, monkeypatch, tmp_path
    ):
        from gateway.config import PlatformConfig

        fake_cli = tmp_path / "buzz"
        fake_cli.write_text("#!/bin/sh\n", encoding="utf-8")
        monkeypatch.setenv("BUZZ_RELAY_URL", "https://r")
        monkeypatch.setenv("BUZZ_PRIVATE_KEY", "nsec1x")
        monkeypatch.setenv("BUZZ_CLI_PATH", str(fake_cli))

        result = await _standalone_send(
            PlatformConfig(
                enabled=True,
                extra={"outbound_mention_pubkeys": "not-a-mapping"},
            ),
            CHANNEL,
            "hello",
        )

        assert result == {
            "error": "Buzz standalone send: invalid outbound_mention_pubkeys"
        }

    @pytest.mark.asyncio
    async def test_standalone_send_success(self, monkeypatch, tmp_path):
        from gateway.config import PlatformConfig

        fake_cli = tmp_path / "buzz"
        fake_cli.write_text("#!/bin/sh\n", encoding="utf-8")
        monkeypatch.setenv("BUZZ_RELAY_URL", "https://r")
        monkeypatch.setenv("BUZZ_PRIVATE_KEY", "nsec1x")
        monkeypatch.setenv("BUZZ_CLI_PATH", str(fake_cli))

        captured = {}

        async def fake_exec(cli_path, args, *, relay_url, private_key, input_text=None, timeout=30.0):
            captured.update(cli_path=cli_path, args=args, relay_url=relay_url, input_text=input_text)
            return 0, json.dumps({"accepted": True, "event_id": "evt-cron", "message": ""}), ""

        monkeypatch.setattr(_buzz_mod, "_exec_buzz", fake_exec)

        result = await _standalone_send(PlatformConfig(enabled=True, extra={}), CHANNEL, "cron says hi")
        assert result == {"success": True, "message_id": "evt-cron"}
        assert captured["args"][:2] == ["messages", "send"]
        assert captured["input_text"] == "cron says hi"
        # The private key must never be part of argv
        assert all("nsec1x" not in str(a) for a in captured["args"])

    @pytest.mark.asyncio
    async def test_standalone_send_configured_handoff_uses_exact_pubkey(
        self, monkeypatch, tmp_path
    ):
        from gateway.config import PlatformConfig

        fake_cli = tmp_path / "buzz"
        fake_cli.write_text("#!/bin/sh\n", encoding="utf-8")
        monkeypatch.setenv("BUZZ_RELAY_URL", "https://r")
        monkeypatch.setenv("BUZZ_PRIVATE_KEY", "nsec1x")
        monkeypatch.setenv("BUZZ_CLI_PATH", str(fake_cli))
        calls = []

        async def fake_exec(
            cli_path, args, *, relay_url, private_key, input_text=None, timeout=30.0
        ):
            calls.append((list(args), input_text))
            return 0, json.dumps(
                {"accepted": True, "event_id": "evt-cron", "message": ""}
            ), ""

        monkeypatch.setattr(_buzz_mod, "_exec_buzz", fake_exec)

        result = await _standalone_send(
            PlatformConfig(
                enabled=True,
                extra={
                    "outbound_mention_pubkeys": {"CodexTerraM": OTHER_PUBKEY}
                },
            ),
            CHANNEL,
            "@CodexTerraM — review the scheduled result.",
        )

        assert result == {"success": True, "message_id": "evt-cron"}
        args, stdin_text = calls[0]
        assert args[args.index("--mention") + 1] == OTHER_PUBKEY
        assert stdin_text == "@CodexTerraM — review the scheduled result."

    @pytest.mark.asyncio
    async def test_standalone_send_retries_unresolved_mention(self, monkeypatch, tmp_path):
        from gateway.config import PlatformConfig

        fake_cli = tmp_path / "buzz"
        fake_cli.write_text("#!/bin/sh\n", encoding="utf-8")
        monkeypatch.setenv("BUZZ_RELAY_URL", "https://r")
        monkeypatch.setenv("BUZZ_PRIVATE_KEY", "nsec1x")
        monkeypatch.setenv("BUZZ_CLI_PATH", str(fake_cli))
        calls = []

        async def fake_exec(cli_path, args, *, relay_url, private_key, input_text=None, timeout=30.0):
            calls.append((list(args), input_text))
            if len(calls) == 1:
                return 1, "", "mention '@ghost' does not match a current channel member"
            return 0, json.dumps({"accepted": True, "event_id": "evt-cron", "message": ""}), ""

        monkeypatch.setattr(_buzz_mod, "_exec_buzz", fake_exec)

        result = await _standalone_send(
            PlatformConfig(enabled=True, extra={}),
            CHANNEL,
            "Cron asks @ghost",
            thread_id="thread-root",
        )

        assert result == {"success": True, "message_id": "evt-cron"}
        assert [text for _args, text in calls] == ["Cron asks @ghost", "Cron asks ghost"]
        assert calls[1][0] == calls[0][0]

    @pytest.mark.asyncio
    async def test_standalone_configured_handoff_only_protects_its_own_marker(
        self, monkeypatch, tmp_path
    ):
        from gateway.config import PlatformConfig

        fake_cli = tmp_path / "buzz"
        fake_cli.write_text("#!/bin/sh\n", encoding="utf-8")
        monkeypatch.setenv("BUZZ_RELAY_URL", "https://r")
        monkeypatch.setenv("BUZZ_PRIVATE_KEY", "nsec1x")
        monkeypatch.setenv("BUZZ_CLI_PATH", str(fake_cli))
        calls = []

        async def fake_exec(
            cli_path, args, *, relay_url, private_key, input_text=None, timeout=30.0
        ):
            calls.append((list(args), input_text))
            if len(calls) == 1:
                return 1, "", "mention '@ghost' does not match a current channel member"
            return 0, json.dumps(
                {"accepted": True, "event_id": "evt-cron", "message": ""}
            ), ""

        monkeypatch.setattr(_buzz_mod, "_exec_buzz", fake_exec)

        result = await _standalone_send(
            PlatformConfig(
                enabled=True,
                extra={
                    "outbound_mention_pubkeys": {"CodexTerraM": OTHER_PUBKEY}
                },
            ),
            CHANNEL,
            "@CodexTerraM asks @ghost to review",
        )

        assert result == {"success": True, "message_id": "evt-cron"}
        assert [text for _args, text in calls] == [
            "@CodexTerraM asks @ghost to review",
            "@CodexTerraM asks ghost to review",
        ]
        assert calls[1][0] == calls[0][0]
        assert calls[0][0][calls[0][0].index("--mention") + 1] == OTHER_PUBKEY
