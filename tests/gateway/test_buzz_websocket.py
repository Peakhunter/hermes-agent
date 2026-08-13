"""Tests for the Buzz WebSocket transport (NIP-42) and Nostr signing module.

The signing module and WS transport were contributed in PR #73636 by
@ScaleLeanChris and consolidated onto the merged poll-based adapter; these
tests cover the crypto (against the official BIP-340 vector) and the WS
lifecycle as wired into BuzzAdapter.
"""

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from tests.gateway._plugin_adapter_loader import load_plugin_adapter

_buzz_mod = load_plugin_adapter("buzz")
BuzzAdapter = _buzz_mod.BuzzAdapter

import importlib.util as _ilu
from pathlib import Path as _Path

_auth_path = _Path(_buzz_mod.__file__).with_name("nostr_auth.py")
_spec = _ilu.spec_from_file_location("plugin_adapter_buzz_nostr_auth", _auth_path)
nostr_auth = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(nostr_auth)

SELF_PUBKEY = "9fd5c7ba6d3ef224da78f541e0fcb9c50f72cc63edb19aae76ac6a0474dfa860"
# BIP-340 test vector 0 private key
TEST_PRIVATE_KEY = "00" * 31 + "03"
OWNER_PRIVATE_KEY = "00" * 31 + "04"
CHANNEL = "ccc2bc1a-7a82-5a8f-8c4e-57a070cbe7cd"


def _owner_tag(agent_pubkey=None, conditions=""):
    agent_pubkey = agent_pubkey or nostr_auth.public_key_hex(TEST_PRIVATE_KEY)
    message = __import__("hashlib").sha256(
        f"nostr:agent-auth:{agent_pubkey}:{conditions}".encode()
    ).digest()
    return [
        "auth",
        nostr_auth.public_key_hex(OWNER_PRIVATE_KEY),
        conditions,
        nostr_auth.schnorr_sign(
            message, OWNER_PRIVATE_KEY, auxiliary_randomness=bytes(32)
        ).hex(),
    ]


def _make_adapter(extra=None):
    from gateway.config import PlatformConfig

    cfg = PlatformConfig(enabled=True, extra={"relay_url": "https://test.relay", **(extra or {})})
    adapter = BuzzAdapter(cfg)
    adapter._self_pubkey = SELF_PUBKEY
    adapter._private_key = TEST_PRIVATE_KEY
    adapter._display_name = "Chip"
    return adapter


@pytest.fixture(autouse=True)
def _clean_buzz_auth_tag(monkeypatch):
    monkeypatch.delenv("BUZZ_AUTH_TAG", raising=False)


# ── nostr_auth: BIP-340 / NIP-42 ──────────────────────────────────────────


def test_schnorr_sign_matches_official_bip340_vector_zero():
    signature = nostr_auth.schnorr_sign(
        bytes(32), TEST_PRIVATE_KEY, auxiliary_randomness=bytes(32)
    )
    assert nostr_auth.public_key_hex(TEST_PRIVATE_KEY).upper() == (
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    )
    assert signature.hex().upper() == (
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    )


def test_decode_private_key_rejects_bad_input():
    with pytest.raises(ValueError):
        nostr_auth.decode_private_key("not-a-key")
    with pytest.raises(ValueError):
        nostr_auth.decode_private_key("00" * 32)  # zero — outside range
    with pytest.raises(ValueError):
        nostr_auth.decode_private_key("nsec1qqqqqqqq")  # bad checksum/length


def test_build_auth_event_shape_and_owner_tag():
    owner_tag = _owner_tag()
    tag = json.dumps(owner_tag)
    event = nostr_auth.build_auth_event(
        private_key=TEST_PRIVATE_KEY,
        challenge="challenge-1",
        relay_url="wss://relay.example",
        auth_tag_json=tag,
        created_at=1_700_000_000,
        auxiliary_randomness=bytes(32),
    )
    assert event["kind"] == 22242
    assert ["relay", "wss://relay.example"] in event["tags"]
    assert ["challenge", "challenge-1"] in event["tags"]
    assert owner_tag in event["tags"]
    assert len(bytes.fromhex(event["sig"])) == 64
    assert event["pubkey"] == nostr_auth.public_key_hex(TEST_PRIVATE_KEY)


def test_nip44_encrypt_matches_official_vector():
    """Observer payload encryption must be byte-compatible with NIP-44 v2."""
    sender_private_key = "00" * 31 + "01"
    recipient_private_key = "00" * 31 + "02"
    recipient_pubkey = nostr_auth.public_key_hex(recipient_private_key)

    payload = nostr_auth.nip44_encrypt(
        "a",
        private_key=sender_private_key,
        recipient_pubkey=recipient_pubkey,
        nonce=bytes.fromhex("00" * 31 + "01"),
    )

    assert payload == (
        "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtD"
        "KfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+"
        "kF5Vsb"
    )


def test_nip44_encrypt_rejects_non_spec_plaintext_above_65535_bytes():
    with pytest.raises(ValueError, match="1 to 65535 bytes"):
        nostr_auth.nip44_encrypt(
            "a" * 65_536,
            private_key="00" * 31 + "01",
            recipient_pubkey=nostr_auth.public_key_hex("00" * 31 + "02"),
            nonce=bytes(32),
        )


def test_build_observer_event_encrypts_and_signs_nip_ao_shape(monkeypatch):
    owner_private_key = "00" * 31 + "02"
    owner_pubkey = nostr_auth.public_key_hex(owner_private_key)
    captured = {}

    def fake_encrypt(plaintext, **kwargs):
        captured["plaintext"] = plaintext
        captured.update(kwargs)
        return "encrypted-observer-payload"

    monkeypatch.setattr(nostr_auth, "nip44_encrypt", fake_encrypt)
    payload = {
        "seq": 1,
        "timestamp": "2026-08-03T14:00:00.000Z",
        "kind": "turn_started",
        "agentIndex": None,
        "channelId": CHANNEL,
        "sessionId": "session-1",
        "turnId": "turn-1",
        "payload": {"source": "channel"},
    }

    event = nostr_auth.build_observer_event(
        private_key=TEST_PRIVATE_KEY,
        owner_pubkey=owner_pubkey,
        payload=payload,
        created_at=1_700_000_000,
        auxiliary_randomness=bytes(32),
    )

    assert event["kind"] == 24200
    assert event["content"] == "encrypted-observer-payload"
    assert ["p", owner_pubkey] in event["tags"]
    assert ["agent", event["pubkey"]] in event["tags"]
    assert ["frame", "telemetry"] in event["tags"]
    assert json.loads(captured["plaintext"]) == payload
    assert captured["private_key"] == TEST_PRIVATE_KEY
    assert captured["recipient_pubkey"] == owner_pubkey
    assert len(bytes.fromhex(event["sig"])) == 64


# ── Adapter WS wiring ─────────────────────────────────────────────────────


class _FakeWebSocket:
    """Replays a NIP-42 handshake: AUTH challenge, then OK for the reply."""

    def __init__(self):
        self.sent = []

    async def recv(self):
        if self.sent:
            auth_event = self.sent[0][1]
            return json.dumps(["OK", auth_event["id"], True, "authenticated"])
        return json.dumps(["AUTH", "relay-challenge"])

    async def send(self, raw):
        self.sent.append(json.loads(raw))


@pytest.mark.asyncio
async def test_websocket_auth_raises_on_rejection():
    adapter = _make_adapter()

    class RejectingWs(_FakeWebSocket):
        async def recv(self):
            if self.sent:
                auth_event = self.sent[0][1]
                return json.dumps(["OK", auth_event["id"], False, "denied"])
            return json.dumps(["AUTH", "relay-challenge"])

    with pytest.raises(ConnectionError):
        await adapter._authenticate_websocket(RejectingWs())


@pytest.mark.asyncio
async def test_publish_activity_sends_encrypted_observer_event_over_active_websocket():
    owner_private_key = "00" * 31 + "02"
    owner_pubkey = nostr_auth.public_key_hex(owner_private_key)
    adapter = _make_adapter({"activity_owner_pubkey": owner_pubkey})
    websocket = _FakeWebSocket()
    adapter._ws_active = True
    adapter._ws_connection = websocket

    published = await adapter.publish_activity(
        "turn_started",
        channel_id=CHANNEL,
        session_id="session-1",
        turn_id="turn-1",
        started_at="2026-08-03T14:00:00.000Z",
        payload={"source": "channel"},
    )

    assert published is True
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)
    assert len(websocket.sent) == 1
    frame = websocket.sent[0]
    assert frame[0] == "EVENT"
    assert frame[1]["kind"] == 24200
    assert ["p", owner_pubkey] in frame[1]["tags"]
    assert ["agent", frame[1]["pubkey"]] in frame[1]["tags"]
    assert ["frame", "telemetry"] in frame[1]["tags"]
    adapter._activity_sender_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await adapter._activity_sender_task


@pytest.mark.asyncio
async def test_publish_activity_does_not_wait_for_backpressured_websocket():
    owner_pubkey = nostr_auth.public_key_hex("2".zfill(64))
    adapter = _make_adapter(extra={"activity_owner_pubkey": owner_pubkey})

    class _BackpressuredWebSocket:
        async def send(self, _payload):
            await asyncio.Event().wait()

    adapter._ws_connection = _BackpressuredWebSocket()
    adapter._ws_active = True

    published = await asyncio.wait_for(
        adapter.publish_activity(
            "turn_started",
            channel_id="channel-1",
            session_id="session-1",
            turn_id="turn-1",
            payload={},
        ),
        timeout=0.05,
    )

    assert published is True
    assert adapter._activity_sender_task is not None
    adapter._activity_sender_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await adapter._activity_sender_task


def test_activity_owner_pubkey_rejects_malformed_config():
    with pytest.raises(ValueError, match="activity_owner_pubkey"):
        _make_adapter({"activity_owner_pubkey": "not-a-pubkey"})


@pytest.mark.asyncio
async def test_publish_activity_fails_open_when_websocket_send_fails():
    owner_pubkey = nostr_auth.public_key_hex("00" * 31 + "02")
    adapter = _make_adapter({"activity_owner_pubkey": owner_pubkey})

    class BrokenWebSocket:
        async def send(self, raw):
            raise ConnectionError("relay unavailable")

    adapter._ws_active = True
    adapter._ws_connection = BrokenWebSocket()

    assert await adapter.publish_activity(
        "turn_completed",
        channel_id=CHANNEL,
        session_id="session-1",
        turn_id="turn-1",
    ) is True
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)
    assert not adapter._activity_pending_event_ids
    adapter._activity_sender_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await adapter._activity_sender_task


@pytest.mark.asyncio
async def test_observer_relay_rejection_is_correlated_and_logged(caplog):
    owner_pubkey = nostr_auth.public_key_hex("2".zfill(64))
    adapter = _make_adapter(extra={"activity_owner_pubkey": owner_pubkey})
    websocket = _FakeWebSocket()
    adapter._ws_connection = websocket
    adapter._ws_active = True

    assert await adapter.publish_activity(
        "turn_started",
        channel_id="channel-1",
        session_id="session-1",
        turn_id="turn-1",
        started_at="2026-08-03T14:00:00.000Z",
        payload={},
    ) is True
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)
    event_id = websocket.sent[0][1]["id"]
    assert event_id in adapter._activity_pending_event_ids

    with caplog.at_level("WARNING"):
        assert adapter._handle_activity_ack(
            ["OK", event_id, False, "restricted: not authorized"]
        ) is True

    assert event_id not in adapter._activity_pending_event_ids
    assert "restricted: not authorized" in caplog.text
    adapter._activity_sender_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await adapter._activity_sender_task


@pytest.mark.asyncio
async def test_disconnect_drops_stale_activity_queue_and_pending_acks():
    adapter = _make_adapter()
    adapter._track_activity_ack("event-id", adapter._activity_ws_generation)
    _, timer = adapter._activity_pending_event_ids["event-id"]
    adapter._activity_queue.put_nowait({"kind": "turn_liveness"})

    await adapter.disconnect()

    assert adapter._activity_queue.empty()
    assert not adapter._activity_pending_event_ids
    assert timer.cancelled()


@pytest.mark.asyncio
async def test_terminal_during_disconnect_replays_once_after_reconnect(monkeypatch):
    owner_pubkey = nostr_auth.public_key_hex("00" * 31 + "02")
    adapter = _make_adapter({"activity_owner_pubkey": owner_pubkey})
    old_websocket = _FakeWebSocket()
    adapter._ws_active = True
    adapter._ws_connection = old_websocket

    counter = 0

    def build_event(**kwargs):
        nonlocal counter
        counter += 1
        return {
            "id": f"event-{counter}",
            "kind": 24200,
            "payload": kwargs["payload"],
        }

    monkeypatch.setattr(
        _buzz_mod,
        "_load_nostr_auth",
        lambda: SimpleNamespace(build_observer_event=build_event),
    )

    assert adapter._enqueue_activity(
        "turn_started",
        channel_id=CHANNEL,
        session_id="session-1",
        turn_id="turn-1",
    )
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)
    assert [frame[1]["payload"]["kind"] for frame in old_websocket.sent] == [
        "turn_started"
    ]

    adapter._ws_active = False
    adapter._ws_connection = None
    await adapter._reset_activity_transport()
    assert not adapter._enqueue_activity(
        "turn_liveness",
        channel_id=CHANNEL,
        session_id="session-1",
        turn_id="turn-1",
    )
    assert adapter._enqueue_activity(
        "turn_completed",
        channel_id=CHANNEL,
        session_id="session-1",
        turn_id="turn-1",
    )

    new_websocket = _FakeWebSocket()
    adapter._activity_ws_generation += 1
    adapter._ws_connection = new_websocket
    adapter._ws_active = True
    adapter._replay_terminal_activity()
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)

    assert [frame[1]["payload"]["kind"] for frame in new_websocket.sent] == [
        "turn_completed"
    ]
    assert not adapter._activity_terminal_replay
    adapter._replay_terminal_activity()
    await asyncio.sleep(0)
    assert len(new_websocket.sent) == 1
    adapter._activity_sender_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await adapter._activity_sender_task


def test_terminal_replay_is_bounded_and_keeps_latest_turns(monkeypatch):
    owner_pubkey = nostr_auth.public_key_hex("00" * 31 + "02")
    adapter = _make_adapter({"activity_owner_pubkey": owner_pubkey})
    monkeypatch.setattr(_buzz_mod, "_ACTIVITY_TERMINAL_REPLAY_CAP", 2)

    for turn_id in ("turn-1", "turn-2", "turn-3"):
        assert adapter._enqueue_activity(
            "turn_error",
            channel_id=CHANNEL,
            session_id="session-1",
            turn_id=turn_id,
            payload={"status": "failed"},
        )

    assert list(adapter._activity_terminal_replay) == ["turn-2", "turn-3"]


@pytest.mark.asyncio
async def test_unacked_terminal_is_recovered_when_socket_disconnects(monkeypatch):
    owner_pubkey = nostr_auth.public_key_hex("00" * 31 + "02")
    adapter = _make_adapter({"activity_owner_pubkey": owner_pubkey})
    old_websocket = _FakeWebSocket()
    adapter._ws_active = True
    adapter._ws_connection = old_websocket

    counter = 0

    def build_event(**kwargs):
        nonlocal counter
        counter += 1
        return {
            "id": f"event-{counter}",
            "kind": 24200,
            "payload": kwargs["payload"],
        }

    monkeypatch.setattr(
        _buzz_mod,
        "_load_nostr_auth",
        lambda: SimpleNamespace(build_observer_event=build_event),
    )

    assert adapter._enqueue_activity(
        "turn_completed",
        channel_id=CHANNEL,
        session_id="session-1",
        turn_id="turn-1",
    )
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)
    assert "event-1" in adapter._activity_pending_event_ids

    adapter._ws_active = False
    adapter._ws_connection = None
    await adapter._reset_activity_transport()
    assert not adapter._activity_pending_event_ids
    assert list(adapter._activity_terminal_replay) == ["turn-1"]

    new_websocket = _FakeWebSocket()
    adapter._activity_ws_generation += 1
    adapter._ws_connection = new_websocket
    adapter._ws_active = True
    adapter._replay_terminal_activity()
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)

    assert [frame[1]["payload"]["kind"] for frame in new_websocket.sent] == [
        "turn_completed"
    ]
    adapter._activity_sender_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await adapter._activity_sender_task


@pytest.mark.asyncio
async def test_activity_sender_drops_frame_when_websocket_generation_changes(monkeypatch):
    owner_pubkey = nostr_auth.public_key_hex("00" * 31 + "02")
    adapter = _make_adapter({"activity_owner_pubkey": owner_pubkey})
    old_websocket = _FakeWebSocket()
    new_websocket = _FakeWebSocket()
    adapter._ws_active = True
    adapter._ws_connection = old_websocket
    adapter._activity_ws_generation = 1

    def build_during_reconnect(**kwargs):
        adapter._activity_ws_generation = 2
        adapter._ws_connection = new_websocket
        return {"id": "event-id"}

    monkeypatch.setattr(
        _buzz_mod,
        "_load_nostr_auth",
        lambda: SimpleNamespace(build_observer_event=build_during_reconnect),
    )
    adapter._activity_queue.put_nowait((1, {"kind": "turn_liveness"}))
    adapter._activity_sender_task = asyncio.create_task(adapter._activity_sender_loop())

    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)
    adapter._activity_sender_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await adapter._activity_sender_task

    assert old_websocket.sent == []
    assert new_websocket.sent == []
    assert not adapter._activity_pending_event_ids


@pytest.mark.asyncio
async def test_activity_ack_expires_on_deadline_and_late_ack_is_ignored(monkeypatch):
    owner_pubkey = nostr_auth.public_key_hex("00" * 31 + "02")
    adapter = _make_adapter({"activity_owner_pubkey": owner_pubkey})
    websocket = _FakeWebSocket()
    adapter._ws_active = True
    adapter._ws_connection = websocket
    monkeypatch.setattr(_buzz_mod, "_ACTIVITY_ACK_TIMEOUT", 0.01)

    assert await adapter.publish_activity(
        "turn_started",
        channel_id=CHANNEL,
        session_id="session-1",
        turn_id="turn-1",
        payload={},
    )
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)
    event_id = websocket.sent[0][1]["id"]
    assert event_id in adapter._activity_pending_event_ids

    await asyncio.sleep(0.03)
    assert event_id not in adapter._activity_pending_event_ids
    assert adapter._handle_activity_ack(["OK", event_id, True, "late"]) is False

    adapter._activity_sender_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await adapter._activity_sender_task


@pytest.mark.asyncio
async def test_activity_pending_ack_cap_cancels_evicted_deadline(monkeypatch):
    adapter = _make_adapter()
    monkeypatch.setattr(_buzz_mod, "_ACTIVITY_PENDING_CAP", 2)

    adapter._track_activity_ack("first", 1)
    first_timer = adapter._activity_pending_event_ids["first"][1]
    adapter._track_activity_ack("second", 1)
    adapter._track_activity_ack("third", 1)

    assert list(adapter._activity_pending_event_ids) == ["second", "third"]
    assert first_timer.cancelled()
    await adapter._reset_activity_transport()


def test_activity_owner_pubkey_rejects_non_curve_x_coordinate():
    with pytest.raises(ValueError, match="activity_owner_pubkey"):
        _make_adapter({"activity_owner_pubkey": "f" * 64})


def test_activity_owner_pubkey_is_config_only(monkeypatch):
    env_owner = nostr_auth.public_key_hex("00" * 31 + "02")
    monkeypatch.setenv("BUZZ_ACTIVITY_OWNER_PUBKEY", env_owner)

    adapter = _make_adapter()

    assert adapter.activity_owner_pubkey == ""


@pytest.mark.asyncio
async def test_publish_directory_sends_complete_signed_projection_and_requires_matching_ack(
    monkeypatch,
):
    owner_tag = _owner_tag()
    monkeypatch.setenv("BUZZ_AUTH_TAG", json.dumps(owner_tag))
    monkeypatch.setenv("BUZZ_ALLOW_ALL_USERS", "false")
    allowed = {"a" * 64, "d" * 64}
    adapter = _make_adapter({"allowed_users": sorted(allowed)})
    adapter._self_pubkey = nostr_auth.public_key_hex(TEST_PRIVATE_KEY)
    adapter._channel_state = {
        CHANNEL: {"chat_type": "group", "last_ts": 0, "seen": {}},
        "dm-id": {"chat_type": "dm", "last_ts": 0, "seen": {}},
    }
    adapter._channel_names = {CHANNEL: "general", "dm-id": "DM"}

    class DirectoryWebSocket:
        def __init__(self):
            self.sent = []

        async def send(self, raw):
            self.sent.append(json.loads(raw))

        async def recv(self):
            event = self.sent[-1][1]
            return json.dumps(["OK", event["id"], True, "stored"])

    websocket = DirectoryWebSocket()
    await adapter._publish_directory_websocket(websocket)

    frame = websocket.sent[0]
    assert frame[0] == "EVENT"
    event = frame[1]
    assert event["kind"] == 10100
    assert event["pubkey"] == adapter._self_pubkey
    assert owner_tag in event["tags"]
    assert len(bytes.fromhex(event["sig"])) == 64
    content = json.loads(event["content"])
    assert content == {
        "name": "Chip",
        "display_name": "Chip",
        "agent_type": "hermes-gateway",
        "capabilities": ["chat"],
        "status": "online",
        "respond_to": "allowlist",
        "respond_to_allowlist": sorted(allowed),
        "channels": ["general"],
        "channel_ids": [CHANNEL],
        "channel_add_policy": "owner_only",
    }


def test_directory_projection_never_uses_config_only_allow_all(monkeypatch):
    monkeypatch.delenv("BUZZ_ALLOW_ALL_USERS", raising=False)
    monkeypatch.delenv("GATEWAY_ALLOW_ALL_USERS", raising=False)
    adapter = _make_adapter({"allow_all_users": True})
    assert adapter._directory_content()["respond_to"] == "allowlist"
    assert adapter._directory_content()["respond_to_allowlist"] == []


def test_directory_projection_default_deny_is_buzz_picker_compatible(monkeypatch):
    for name in ("BUZZ_ALLOW_ALL_USERS", "GATEWAY_ALLOW_ALL_USERS", "GATEWAY_ALLOWED_USERS"):
        monkeypatch.delenv(name, raising=False)
    content = _make_adapter()._directory_content()
    assert content["status"] == "online"
    assert content["respond_to"] == "allowlist"
    assert content["respond_to_allowlist"] == []


def test_nip_oa_verification_accepts_exact_agent_and_rejects_wrong_agent():
    tag = _owner_tag(conditions="kind=10100&created_at>0")
    assert nostr_auth.verify_auth_tag_for_event(
        tag, nostr_auth.public_key_hex(TEST_PRIVATE_KEY), kind=10100, created_at=1
    )
    with pytest.raises(ValueError):
        nostr_auth.verify_auth_tag_for_event(
            tag, nostr_auth.public_key_hex("00" * 31 + "05"), kind=10100, created_at=1
        )


@pytest.mark.parametrize("conditions", [
    "kind=9",
    "created_at<1",
    "kind=10100&created_at>10&created_at<5",
])
def test_nip_oa_directory_conditions_reject_incompatible_event(conditions):
    with pytest.raises(ValueError, match="condition"):
        nostr_auth.verify_auth_tag_for_event(
            _owner_tag(conditions=conditions),
            nostr_auth.public_key_hex(TEST_PRIVATE_KEY),
            kind=10100,
            created_at=10,
        )


def test_nip_oa_directory_conditions_accept_compatible_kind_and_time():
    tag = _owner_tag(conditions="kind=10100&created_at>9&created_at<11")
    assert nostr_auth.verify_auth_tag_for_event(
        tag, nostr_auth.public_key_hex(TEST_PRIVATE_KEY), kind=10100, created_at=10
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("conditions", [
    "kind=9",
    "created_at<1",
    "kind=10100&created_at>10&created_at<5",
])
async def test_directory_publication_rejects_incompatible_owner_conditions(
    monkeypatch, conditions
):
    monkeypatch.setattr(_buzz_mod.time, "time", lambda: 10)
    monkeypatch.setenv("BUZZ_AUTH_TAG", json.dumps(_owner_tag(conditions=conditions)))
    adapter = _make_adapter()
    adapter._self_pubkey = nostr_auth.public_key_hex(TEST_PRIVATE_KEY)
    with pytest.raises(ValueError, match="condition"):
        await adapter._publish_directory_websocket(AsyncMock())


@pytest.mark.asyncio
async def test_directory_publication_accepts_compatible_owner_conditions(monkeypatch):
    monkeypatch.setattr(_buzz_mod.time, "time", lambda: 10)
    monkeypatch.setenv(
        "BUZZ_AUTH_TAG",
        json.dumps(_owner_tag(conditions="kind=10100&created_at>9&created_at<11")),
    )
    websocket = AsyncMock()
    websocket.recv.side_effect = lambda: json.dumps(
        ["OK", json.loads(websocket.send.await_args.args[0])[1]["id"], True, "stored"]
    )
    adapter = _make_adapter()
    adapter._self_pubkey = nostr_auth.public_key_hex(TEST_PRIVATE_KEY)
    assert await adapter._publish_directory_websocket(websocket) is True


def test_nip_42_auth_event_evaluates_owner_conditions_against_auth_event():
    incompatible = json.dumps(_owner_tag(conditions="kind=10100"))
    with pytest.raises(ValueError, match="condition"):
        nostr_auth.build_auth_event(
            private_key=TEST_PRIVATE_KEY,
            challenge="challenge",
            relay_url="wss://relay.example",
            auth_tag_json=incompatible,
            created_at=10,
        )

    compatible = json.dumps(_owner_tag(conditions="kind=22242&created_at>9&created_at<11"))
    event = nostr_auth.build_auth_event(
        private_key=TEST_PRIVATE_KEY,
        challenge="challenge",
        relay_url="wss://relay.example",
        auth_tag_json=compatible,
        created_at=10,
        auxiliary_randomness=bytes(32),
    )
    assert event["kind"] == 22242
    assert event["created_at"] == 10


@pytest.mark.parametrize("mutator", [
    lambda tag: [tag[0], tag[1].upper(), tag[2], tag[3]],
    lambda tag: [tag[0], tag[1], "kind=010100", tag[3]],
    lambda tag: [tag[0], tag[1], tag[2], "0" * 128],
])
def test_nip_oa_verification_rejects_non_buzz_compatible_tags(mutator):
    with pytest.raises(ValueError):
        nostr_auth.verify_auth_tag(mutator(_owner_tag()), nostr_auth.public_key_hex(TEST_PRIVATE_KEY))


def test_signed_directory_event_deterministic_vector_and_signature():
    event = nostr_auth.build_signed_event(
        private_key=TEST_PRIVATE_KEY, kind=10100, tags=[], content='{"status":"online"}',
        created_at=1_700_000_000, auxiliary_randomness=bytes(32),
    )
    assert event["id"] == "14073c61e18826eb743cbd4928a7ab30df8d1fed53846ef53c9fdeb287f34093"
    assert event["sig"] == (
        "2df61fd0276a03f6b1392a276a0ba40ef98fa9107f19def3263de9016a11fbae"
        "fdfe3ed458c86cdd6e507ed10ce6344390236ac491f1e1ad5fe2037f3ff06c16"
    )
    assert nostr_auth.schnorr_verify(bytes.fromhex(event["id"]), event["pubkey"], event["sig"])


@pytest.mark.asyncio
async def test_joined_channel_reconciliation_refreshes_directory_after_subscription():
    adapter = _make_adapter()
    adapter._channel_state = {
        CHANNEL: {"chat_type": "group", "last_ts": 100, "seen": {}},
    }
    new_channel = "4764ae67-7cd8-4f3e-967d-7dd93986b11a"

    async def discover(*, since):
        adapter._channel_state[new_channel] = {
            "chat_type": "group", "last_ts": since, "seen": {},
        }
        adapter._channel_names[new_channel] = "project"
        return True

    adapter._discover_joined_channels = discover
    adapter._discover_dms = AsyncMock()
    adapter._publish_directory_websocket = AsyncMock()
    websocket = AsyncMock()
    subscriptions = {"hermes-buzz-0": CHANNEL}

    await adapter._handle_membership_event(
        websocket,
        subscriptions,
        {"created_at": 1234, "kind": _buzz_mod._WS_MEMBERSHIP_KIND},
    )

    adapter._publish_directory_websocket.assert_awaited_once_with(websocket)
    assert new_channel in subscriptions.values()


@pytest.mark.asyncio
async def test_poll_transport_uses_bounded_authenticated_websocket_for_directory(monkeypatch):
    adapter = _make_adapter({"transport": "poll"})
    websocket = AsyncMock()
    context = AsyncMock()
    context.__aenter__.return_value = websocket
    connect = MagicMock(return_value=context)
    monkeypatch.setitem(__import__("sys").modules, "websockets", MagicMock(connect=connect))
    adapter._authenticate_websocket = AsyncMock()
    adapter._publish_directory_websocket = AsyncMock()

    assert await adapter._publish_directory_fallback() is True

    adapter._authenticate_websocket.assert_awaited_once_with(websocket)
    adapter._publish_directory_websocket.assert_awaited_once_with(websocket, force=False)
    assert connect.call_args.kwargs["open_timeout"] == _buzz_mod._WS_AUTH_TIMEOUT
    assert connect.call_args.kwargs["max_size"] == _buzz_mod._WS_MAX_MESSAGE_BYTES


@pytest.mark.asyncio
async def test_authentication_has_one_absolute_deadline_and_frame_cap(monkeypatch):
    adapter = _make_adapter()
    monkeypatch.setattr(_buzz_mod, "_WS_AUTH_TIMEOUT", 0.03)
    monkeypatch.setattr(_buzz_mod, "_WS_DEFERRED_FRAME_CAP", 2)

    class DripWs:
        async def recv(self):
            await asyncio.sleep(0.012)
            return json.dumps(["EVENT", "other", {}])
        async def send(self, _raw): pass

    started = asyncio.get_running_loop().time()
    with pytest.raises((TimeoutError, ConnectionError)):
        await adapter._authenticate_websocket(DripWs())
    assert asyncio.get_running_loop().time() - started < 0.08


@pytest.mark.asyncio
async def test_directory_publication_ignores_nonmatching_positive_ack():
    adapter = _make_adapter()

    class WrongThenRejectedWebSocket:
        def __init__(self):
            self.event = None
            self.responses = 0

        async def send(self, raw):
            self.event = json.loads(raw)[1]

        async def recv(self):
            self.responses += 1
            if self.responses == 1:
                return json.dumps(["OK", "0" * 64, True, "stored another event"])
            return json.dumps(["OK", self.event["id"], False, "denied"])

    with pytest.raises(ConnectionError, match="directory publication rejected"):
        await adapter._publish_directory_websocket(WrongThenRejectedWebSocket())


@pytest.mark.asyncio
async def test_directory_ack_wait_defers_interleaved_subscription_frame():
    adapter = _make_adapter()
    interleaved = json.dumps(["EVENT", "hermes-buzz-0", {"id": "message"}])

    class InterleavedWebSocket:
        def __init__(self):
            self.event = None
            self.responses = [interleaved]

        async def send(self, raw):
            self.event = json.loads(raw)[1]

        async def recv(self):
            if self.responses:
                return self.responses.pop(0)
            return json.dumps(["OK", self.event["id"], True, "stored"])

    await adapter._publish_directory_websocket(InterleavedWebSocket())

    assert list(adapter._ws_deferred_frames) == [interleaved]


@pytest.mark.asyncio
async def test_directory_publication_deduplicates_projection_but_republishes_on_reconnect():
    adapter = _make_adapter()

    class AckWs:
        def __init__(self):
            self.events = []

        async def send(self, raw):
            frame = json.loads(raw)
            if frame[0] == "EVENT":
                self.events.append(frame[1])

        async def recv(self):
            return json.dumps(["OK", self.events[-1]["id"], True, "stored"])

    websocket = AckWs()
    assert await adapter._publish_directory_websocket(websocket) is True
    assert await adapter._publish_directory_websocket(websocket) is False
    assert await adapter._publish_directory_websocket(websocket, force=True) is True
    assert len(websocket.events) == 2


@pytest.mark.asyncio
async def test_websocket_startup_wiring_delivers_deferred_frame_exactly_once(monkeypatch):
    adapter = _make_adapter()
    event = {"id": "message", "created_at": 1}
    raw = json.dumps(["EVENT", "hermes-buzz-0", event])
    websocket = AsyncMock()
    websocket.recv.side_effect = asyncio.CancelledError
    context = AsyncMock()
    context.__aenter__.return_value = websocket
    monkeypatch.setitem(
        __import__("sys").modules,
        "websockets",
        MagicMock(connect=MagicMock(return_value=context)),
    )
    order = []
    adapter._authenticate_websocket = AsyncMock(side_effect=lambda _ws: order.append("auth"))

    async def publish(_ws, *, force=False):
        order.append(("publish", force))
        adapter._ws_deferred_frames.append(raw)
        return True

    adapter._publish_directory_websocket = publish
    adapter._subscribe_websocket = AsyncMock(
        side_effect=lambda _ws: order.append("subscribe") or {"hermes-buzz-0": CHANNEL}
    )
    adapter._channel_state = {CHANNEL: {"chat_type": "group", "last_ts": 0, "seen": {}}}
    adapter._handle_event = AsyncMock()

    with pytest.raises(asyncio.CancelledError):
        await adapter._websocket_loop()

    assert order == ["auth", ("publish", True), "subscribe"]
    adapter._handle_event.assert_awaited_once_with(CHANNEL, adapter._channel_state[CHANNEL], event)


def test_directory_projection_never_widens_adapter_allowlist(monkeypatch):
    allowed = "a" * 64
    monkeypatch.setenv("BUZZ_ALLOW_ALL_USERS", "true")
    monkeypatch.setenv("GATEWAY_ALLOW_ALL_USERS", "true")
    adapter = _make_adapter({"allowed_users": [allowed]})

    projection = adapter._directory_content()

    assert projection["respond_to"] == "allowlist"
    assert projection["respond_to_allowlist"] == [allowed]
