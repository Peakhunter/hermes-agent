"""Tests for the Buzz WebSocket transport (NIP-42) and Nostr signing module.

The signing module and WS transport were contributed in PR #73636 by
@ScaleLeanChris and consolidated onto the merged poll-based adapter; these
tests cover the crypto (against the official BIP-340 vector) and the WS
lifecycle as wired into BuzzAdapter.
"""

import asyncio
import json
import sys
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

# BIP-340 test vector 0 private key
TEST_PRIVATE_KEY = "00" * 31 + "03"
SELF_PUBKEY = nostr_auth.public_key_hex(TEST_PRIVATE_KEY)
OWNER_PRIVATE_KEY = "00" * 31 + "04"
CHANNEL = "ccc2bc1a-7a82-5a8f-8c4e-57a070cbe7cd"


@pytest.fixture(autouse=True)
def _clean_transport_override(monkeypatch):
    monkeypatch.delenv("BUZZ_TRANSPORT", raising=False)
    monkeypatch.delenv("BUZZ_AUTH_TAG", raising=False)
    monkeypatch.delenv("BUZZ_CHANNELS", raising=False)


def _make_adapter(extra=None):
    from gateway.config import PlatformConfig

    cfg = PlatformConfig(enabled=True, extra={"relay_url": "https://test.relay", **(extra or {})})
    adapter = BuzzAdapter(cfg)
    adapter._self_pubkey = SELF_PUBKEY
    adapter._private_key = TEST_PRIVATE_KEY
    adapter._display_name = "Chip"
    return adapter


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


def test_signed_directory_event_deterministic_vector_and_signature():
    event = nostr_auth.build_signed_event(
        private_key=TEST_PRIVATE_KEY,
        kind=10100,
        tags=[],
        content='{"status":"online"}',
        created_at=1_700_000_000,
        auxiliary_randomness=bytes(32),
    )
    assert event["id"] == "14073c61e18826eb743cbd4928a7ab30df8d1fed53846ef53c9fdeb287f34093"
    assert event["sig"] == (
        "2df61fd0276a03f6b1392a276a0ba40ef98fa9107f19def3263de9016a11fbae"
        "fdfe3ed458c86cdd6e507ed10ce6344390236ac491f1e1ad5fe2037f3ff06c16"
    )
    assert nostr_auth.schnorr_verify(
        bytes.fromhex(event["id"]), event["pubkey"], event["sig"]
    )


def test_decode_private_key_rejects_bad_input():
    with pytest.raises(ValueError):
        nostr_auth.decode_private_key("not-a-key")
    with pytest.raises(ValueError):
        nostr_auth.decode_private_key("00" * 32)  # zero — outside range
    with pytest.raises(ValueError):
        nostr_auth.decode_private_key("nsec1qqqqqqqq")  # bad checksum/length


def test_nip_oa_verification_accepts_exact_agent_and_rejects_wrong_agent():
    tag = _owner_tag(conditions="kind=10100&created_at>0")
    assert nostr_auth.verify_auth_tag_for_event(
        tag,
        nostr_auth.public_key_hex(TEST_PRIVATE_KEY),
        kind=10100,
        created_at=1,
    )
    with pytest.raises(ValueError):
        nostr_auth.verify_auth_tag_for_event(
            tag,
            nostr_auth.public_key_hex("00" * 31 + "05"),
            kind=10100,
            created_at=1,
        )


@pytest.mark.parametrize(
    "conditions",
    [
        "kind=9",
        "created_at<1",
        "kind=10100&created_at>10&created_at<5",
    ],
)
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
        tag,
        nostr_auth.public_key_hex(TEST_PRIVATE_KEY),
        kind=10100,
        created_at=10,
    )


@pytest.mark.parametrize(
    "conditions",
    [
        "kind=10100 ",
        "kind=10100&",
        "&kind=10100",
        "kind!=10100",
        "kind=010100",
        "kind=65536",
        "created_at<4294967296",
    ],
)
def test_nip_oa_condition_grammar_rejects_noncanonical_forms(conditions):
    with pytest.raises(ValueError):
        nostr_auth.verify_auth_tag_for_event(
            _owner_tag(conditions=conditions),
            nostr_auth.public_key_hex(TEST_PRIVATE_KEY),
            kind=10100,
            created_at=10,
        )


@pytest.mark.parametrize("conditions", ["created_at<10", "created_at>10"])
def test_nip_oa_created_at_boundaries_are_strict(conditions):
    with pytest.raises(ValueError, match="created_at condition"):
        nostr_auth.verify_auth_tag_for_event(
            _owner_tag(conditions=conditions),
            nostr_auth.public_key_hex(TEST_PRIVATE_KEY),
            kind=10100,
            created_at=10,
        )


def test_nip_oa_rejects_self_attestation_and_non_lowercase_keys():
    agent_pubkey = nostr_auth.public_key_hex(TEST_PRIVATE_KEY)
    with pytest.raises(ValueError, match="self-attestation"):
        nostr_auth.verify_auth_tag(
            ["auth", agent_pubkey, "", "0" * 128], agent_pubkey
        )
    with pytest.raises(ValueError, match="invalid label or pubkey"):
        nostr_auth.verify_auth_tag(_owner_tag(), agent_pubkey.upper())
    uppercase_owner = _owner_tag()
    uppercase_owner[1] = uppercase_owner[1].upper()
    with pytest.raises(ValueError, match="invalid label or pubkey"):
        nostr_auth.verify_auth_tag(uppercase_owner, agent_pubkey)


def test_schnorr_verify_rejects_mutation_off_curve_and_scalar_bounds():
    message = bytes.fromhex("22" * 32)
    private_key = "00" * 31 + "02"
    public_key = nostr_auth.public_key_hex(private_key)
    signature = nostr_auth.schnorr_sign(
        message, private_key, auxiliary_randomness=bytes(32)
    )
    mutated = signature[:-1] + bytes([signature[-1] ^ 1])

    assert not nostr_auth.schnorr_verify(message, public_key, mutated.hex())
    assert not nostr_auth.schnorr_verify(message, "0" * 63 + "5", signature.hex())
    r_out_of_range = nostr_auth.FIELD_ORDER.to_bytes(32, "big") + signature[32:]
    s_out_of_range = signature[:32] + nostr_auth.CURVE_ORDER.to_bytes(32, "big")
    assert not nostr_auth.schnorr_verify(message, public_key, r_out_of_range.hex())
    assert not nostr_auth.schnorr_verify(message, public_key, s_out_of_range.hex())


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


def test_directory_projection_uses_live_policy_and_group_channels_only(monkeypatch):
    allowed = ["d" * 64, "a" * 64]
    monkeypatch.setattr(
        _buzz_mod,
        "_effective_runtime_policy",
        lambda: {"allowed_users": allowed, "allow_all_users": False},
    )
    adapter = _make_adapter()
    adapter._profile_name = "chip-agent"
    adapter._channel_state = {
        CHANNEL: {"chat_type": "group", "last_ts": 0, "seen": {}},
        "unjoined-id": {"chat_type": "group", "last_ts": 0, "seen": {}},
        "dm-id": {"chat_type": "dm", "last_ts": 0, "seen": {}},
        "relay-dm-id": {"chat_type": "group", "last_ts": 0, "seen": {}},
    }
    adapter._joined_channel_ids = {CHANNEL, "relay-dm-id"}
    adapter._channel_names = {
        CHANNEL: "general",
        "unjoined-id": "not joined",
        "dm-id": "DM",
        "relay-dm-id": "DM",
    }
    adapter._channel_meta = {
        CHANNEL: {"channel_id": CHANNEL, "name": "general", "description": "group"},
        "relay-dm-id": {
            "channel_id": "relay-dm-id",
            "name": "DM",
            "description": "",
        },
    }

    assert adapter._directory_content() == {
        "name": "chip-agent",
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
    for name in (
        "BUZZ_ALLOW_ALL_USERS",
        "GATEWAY_ALLOW_ALL_USERS",
        "GATEWAY_ALLOWED_USERS",
    ):
        monkeypatch.delenv(name, raising=False)
    content = _make_adapter()._directory_content()
    assert content["status"] == "online"
    assert content["respond_to"] == "allowlist"
    assert content["respond_to_allowlist"] == []


def test_directory_projection_never_widens_adapter_allowlist(monkeypatch):
    allowed = "a" * 64
    monkeypatch.setenv("BUZZ_ALLOW_ALL_USERS", "true")
    monkeypatch.setenv("GATEWAY_ALLOW_ALL_USERS", "true")
    adapter = _make_adapter({"allowed_users": [allowed]})

    projection = adapter._directory_content()

    assert projection["respond_to"] == "allowlist"
    assert projection["respond_to_allowlist"] == [allowed]


@pytest.mark.asyncio
async def test_publish_directory_signs_with_adapter_identity_and_requires_matching_ack(
    monkeypatch,
):
    monkeypatch.setattr(
        _buzz_mod,
        "_effective_runtime_policy",
        lambda: {"allowed_users": [], "allow_all_users": False},
    )
    monkeypatch.setattr(_buzz_mod.time, "time", lambda: 10)
    monkeypatch.setenv(
        "BUZZ_AUTH_TAG",
        json.dumps(_owner_tag(conditions="kind=10100&created_at>9")),
    )
    adapter = _make_adapter()
    adapter._self_pubkey = nostr_auth.public_key_hex(TEST_PRIVATE_KEY)

    class AckWebSocket:
        def __init__(self):
            self.sent = []

        async def send(self, raw):
            self.sent.append(json.loads(raw))

        async def recv(self):
            event = self.sent[-1][1]
            return json.dumps(["OK", event["id"], True, "stored"])

    websocket = AckWebSocket()
    assert await adapter._publish_directory_websocket(websocket) is True
    event = websocket.sent[0][1]
    assert event["kind"] == 10100
    assert event["pubkey"] == adapter._self_pubkey
    assert event["tags"] == [_owner_tag(conditions="kind=10100&created_at>9")]
    assert nostr_auth.schnorr_verify(
        bytes.fromhex(event["id"]), event["pubkey"], event["sig"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "conditions",
    [
        "kind=9",
        "created_at<1",
        "kind=10100&created_at>10&created_at<5",
    ],
)
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


@pytest.mark.asyncio
async def test_directory_publication_rejects_profile_signer_identity_mismatch(
    monkeypatch,
):
    profile_pubkey = nostr_auth.public_key_hex(TEST_PRIVATE_KEY)
    signer_private_key = "00" * 31 + "02"
    monkeypatch.setenv("BUZZ_AUTH_TAG", json.dumps(_owner_tag()))
    adapter = _make_adapter()
    adapter._self_pubkey = profile_pubkey
    adapter._private_key = signer_private_key
    websocket = AsyncMock()
    websocket.recv.side_effect = lambda: json.dumps(
        ["OK", json.loads(websocket.send.await_args.args[0])[1]["id"], True, "stored"]
    )

    with pytest.raises(ValueError, match="identity.*signing key"):
        await adapter._publish_directory_websocket(websocket)

    websocket.send.assert_not_awaited()


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

    assert await adapter._publish_directory_websocket(InterleavedWebSocket()) is True
    assert list(adapter._ws_deferred_frames) == [interleaved]


@pytest.mark.asyncio
async def test_authentication_defers_interleaved_frames_under_one_absolute_deadline(
    monkeypatch,
):
    adapter = _make_adapter()
    monkeypatch.setattr(_buzz_mod, "_WS_AUTH_TIMEOUT", 0.03)
    interleaved = json.dumps(["EVENT", "other", {"id": "message"}])

    class DripWebSocket:
        def __init__(self):
            self.responses = [interleaved, json.dumps(["AUTH", "challenge"])]

        async def recv(self):
            await asyncio.sleep(0.012)
            if self.responses:
                return self.responses.pop(0)
            return json.dumps(["OK", "0" * 64, True, "other event"])

        async def send(self, _raw):
            return None

    started = asyncio.get_running_loop().time()
    with pytest.raises(TimeoutError, match="AUTH timed out"):
        await adapter._authenticate_websocket(DripWebSocket())
    assert asyncio.get_running_loop().time() - started < 0.1
    assert list(adapter._ws_deferred_frames)[0] == interleaved


@pytest.mark.asyncio
async def test_directory_ack_wait_uses_one_absolute_deadline_for_drip_frames(
    monkeypatch,
):
    monkeypatch.delenv("BUZZ_AUTH_TAG", raising=False)
    adapter = _make_adapter()
    adapter._self_pubkey = nostr_auth.public_key_hex(TEST_PRIVATE_KEY)
    unrelated = json.dumps(["NOTICE", "still waiting"])
    deadlines = []

    async def recv_before_deadline(_websocket, deadline, _message):
        deadlines.append(deadline)
        if len(deadlines) == 1:
            return unrelated
        raise TimeoutError("directory ACK timed out")

    adapter._recv_before_deadline = recv_before_deadline
    websocket = AsyncMock()
    websocket.recv.side_effect = [unrelated, TimeoutError("directory ACK timed out")]

    with pytest.raises(TimeoutError, match="directory ACK timed out"):
        await adapter._publish_directory_websocket(websocket)

    assert len(deadlines) == 2
    assert deadlines[0] == deadlines[1]


@pytest.mark.asyncio
async def test_directory_publication_deduplicates_projection_but_republishes_on_reconnect():
    adapter = _make_adapter()

    class AckWebSocket:
        def __init__(self):
            self.events = []

        async def send(self, raw):
            frame = json.loads(raw)
            if frame[0] == "EVENT":
                self.events.append(frame[1])

        async def recv(self):
            return json.dumps(["OK", self.events[-1]["id"], True, "stored"])

    websocket = AckWebSocket()
    assert await adapter._publish_directory_websocket(websocket) is True
    assert await adapter._publish_directory_websocket(websocket) is False
    assert await adapter._publish_directory_websocket(websocket, force=True) is True
    assert len(websocket.events) == 2


@pytest.mark.asyncio
async def test_poll_transport_uses_bounded_authenticated_websocket_for_directory(
    monkeypatch,
):
    adapter = _make_adapter({"transport": "poll"})
    websocket = AsyncMock()
    context = AsyncMock()
    context.__aenter__.return_value = websocket
    connect = MagicMock(return_value=context)
    monkeypatch.setitem(sys.modules, "websockets", MagicMock(connect=connect))
    adapter._authenticate_websocket = AsyncMock()
    adapter._publish_directory_websocket = AsyncMock(return_value=True)

    assert await adapter._publish_directory_fallback() is True
    adapter._authenticate_websocket.assert_awaited_once_with(websocket)
    adapter._publish_directory_websocket.assert_awaited_once_with(
        websocket, force=False
    )
    assert connect.call_args.kwargs["open_timeout"] == _buzz_mod._WS_AUTH_TIMEOUT
    assert connect.call_args.kwargs["max_size"] == _buzz_mod._WS_MAX_MESSAGE_BYTES


@pytest.mark.asyncio
async def test_websocket_connection_republishes_directory_before_subscribing(
    monkeypatch,
):
    adapter = _make_adapter()
    websocket = AsyncMock()
    context = AsyncMock()
    context.__aenter__.return_value = websocket
    monkeypatch.setitem(
        sys.modules,
        "websockets",
        MagicMock(connect=MagicMock(return_value=context)),
    )
    order = []
    adapter._authenticate_websocket = AsyncMock(
        side_effect=lambda _ws: order.append("auth")
    )
    adapter._publish_directory_websocket = AsyncMock(
        side_effect=lambda _ws, force=False: order.append(("publish", force))
    )

    async def cancel_after_subscribe(_ws):
        order.append("subscribe")
        raise asyncio.CancelledError

    adapter._subscribe_websocket = cancel_after_subscribe
    with pytest.raises(asyncio.CancelledError):
        await adapter._websocket_loop()

    assert order == ["auth", ("publish", True), "subscribe"]


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
async def test_authentication_has_one_absolute_deadline_and_frame_cap(monkeypatch):
    adapter = _make_adapter()
    monkeypatch.setattr(_buzz_mod, "_WS_AUTH_TIMEOUT", 0.03)
    monkeypatch.setattr(_buzz_mod, "_WS_DEFERRED_FRAME_CAP", 2)

    class DripWebSocket:
        async def recv(self):
            await asyncio.sleep(0.012)
            return json.dumps(["EVENT", "other", {}])

        async def send(self, _raw):
            return None

    started = asyncio.get_running_loop().time()
    with pytest.raises((TimeoutError, ConnectionError)):
        await adapter._authenticate_websocket(DripWebSocket())
    assert asyncio.get_running_loop().time() - started < 0.1


@pytest.mark.asyncio
async def test_joined_channel_reconciliation_refreshes_directory_after_subscription():
    adapter = _make_adapter()
    adapter._channel_state = {
        CHANNEL: {"chat_type": "group", "last_ts": 100, "seen": {}},
    }
    new_channel = "4764ae67-7cd8-4f3e-967d-7dd93986b11a"

    async def discover(*, since, target_channel_id=""):
        adapter._channel_state[new_channel] = {
            "chat_type": "group",
            "last_ts": since,
            "seen": {},
        }
        adapter._joined_channel_ids.add(new_channel)
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
async def test_membership_reconciliation_republishes_channel_rename():
    adapter = _make_adapter()
    adapter._channel_state = {
        CHANNEL: {"chat_type": "group", "last_ts": 0, "seen": {}}
    }
    adapter._joined_channel_ids = {CHANNEL}
    adapter._channel_names = {CHANNEL: "old name"}
    adapter._channel_meta = {
        CHANNEL: {"channel_id": CHANNEL, "name": "old name", "description": "group"}
    }
    adapter._run_cli = AsyncMock(
        return_value=(
            0,
            json.dumps(
                [
                    {
                        "channel_id": CHANNEL,
                        "name": "new name",
                        "description": "group",
                    }
                ]
            ),
            "",
        )
    )
    adapter._discover_dms = AsyncMock()
    adapter._publish_directory_websocket = AsyncMock(return_value=True)
    websocket = AsyncMock()
    subscriptions = {"hermes-buzz-0": CHANNEL}

    await adapter._handle_membership_event(
        websocket,
        subscriptions,
        {"created_at": 1234, "kind": _buzz_mod._WS_MEMBERSHIP_KIND},
    )

    assert adapter._channel_names[CHANNEL] == "new name"
    assert adapter._directory_content()["channels"] == ["new name"]
    adapter._publish_directory_websocket.assert_awaited_once_with(websocket)


@pytest.mark.asyncio
async def test_membership_reconciliation_closes_removed_channel_and_republishes():
    adapter = _make_adapter()
    adapter._channel_state = {
        CHANNEL: {"chat_type": "group", "last_ts": 0, "seen": {}}
    }
    adapter._joined_channel_ids = {CHANNEL}
    adapter._channel_names = {CHANNEL: "general"}
    adapter._channel_meta = {
        CHANNEL: {"channel_id": CHANNEL, "name": "general", "description": "group"}
    }
    adapter._run_cli = AsyncMock(return_value=(0, "[]", ""))
    adapter._discover_dms = AsyncMock()
    adapter._publish_directory_websocket = AsyncMock(return_value=True)
    websocket = AsyncMock()
    subscriptions = {"hermes-buzz-0": CHANNEL}

    await adapter._handle_membership_event(
        websocket,
        subscriptions,
        {"created_at": 1234, "kind": _buzz_mod._WS_MEMBERSHIP_REMOVED_KIND},
    )

    assert CHANNEL not in adapter._channel_state
    assert subscriptions == {}
    assert json.loads(websocket.send.await_args_list[0].args[0]) == [
        "CLOSE",
        "hermes-buzz-0",
    ]
    assert adapter._directory_content()["channel_ids"] == []
    adapter._publish_directory_websocket.assert_awaited_once_with(websocket)


@pytest.mark.asyncio
async def test_websocket_startup_delivers_deferred_frame_exactly_once(monkeypatch):
    adapter = _make_adapter()
    event = {"id": "message", "created_at": 1}
    raw = json.dumps(["EVENT", "hermes-buzz-0", event])
    websocket = AsyncMock()
    websocket.__aiter__.side_effect = asyncio.CancelledError
    context = AsyncMock()
    context.__aenter__.return_value = websocket
    monkeypatch.setitem(
        sys.modules,
        "websockets",
        MagicMock(connect=MagicMock(return_value=context)),
    )
    adapter._authenticate_websocket = AsyncMock()

    async def publish(_ws, *, force=False):
        adapter._ws_deferred_frames.append(raw)
        return True

    adapter._publish_directory_websocket = publish
    adapter._subscribe_websocket = AsyncMock(
        return_value={"hermes-buzz-0": CHANNEL}
    )
    adapter._channel_state = {
        CHANNEL: {"chat_type": "group", "last_ts": 0, "seen": {}}
    }
    adapter._handle_event = AsyncMock()

    with pytest.raises(asyncio.CancelledError):
        await adapter._websocket_loop()

    adapter._handle_event.assert_awaited_once_with(
        CHANNEL, adapter._channel_state[CHANNEL], event
    )


@pytest.mark.asyncio
async def test_membership_republish_delivers_newly_deferred_frame_exactly_once(
    monkeypatch,
):
    adapter = _make_adapter()
    event = {"id": "message-after-membership", "created_at": 2}
    deferred_raw = json.dumps(["EVENT", "hermes-buzz-0", event])
    membership_raw = json.dumps(
        [
            "EVENT",
            _buzz_mod._WS_MEMBERSHIP_SUB_ID,
            {"id": "membership", "created_at": 1},
        ]
    )

    class MembershipSocket:
        def __init__(self):
            self.frames = iter([membership_raw])

        def __aiter__(self):
            return self

        async def __anext__(self):
            try:
                return next(self.frames)
            except StopIteration:
                raise asyncio.CancelledError

    websocket = MembershipSocket()
    context = AsyncMock()
    context.__aenter__.return_value = websocket
    monkeypatch.setitem(
        sys.modules,
        "websockets",
        MagicMock(connect=MagicMock(return_value=context)),
    )
    adapter._authenticate_websocket = AsyncMock()
    adapter._publish_directory_websocket = AsyncMock(return_value=True)
    adapter._subscribe_websocket = AsyncMock(
        return_value={
            "hermes-buzz-0": CHANNEL,
            _buzz_mod._WS_MEMBERSHIP_SUB_ID: None,
        }
    )
    adapter._channel_state = {
        CHANNEL: {"chat_type": "group", "last_ts": 0, "seen": {}}
    }
    adapter._handle_event = AsyncMock()

    async def membership_republish(_websocket, _subscriptions, _event):
        adapter._ws_deferred_frames.append(deferred_raw)

    adapter._handle_membership_event = membership_republish

    with pytest.raises(asyncio.CancelledError):
        await adapter._websocket_loop()

    adapter._handle_event.assert_awaited_once_with(
        CHANNEL, adapter._channel_state[CHANNEL], event
    )


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


def test_activity_owner_pubkey_rejects_poll_only_transport():
    owner_pubkey = nostr_auth.public_key_hex("00" * 31 + "02")
    with pytest.raises(ValueError, match="requires transport"):
        _make_adapter(
            {"activity_owner_pubkey": owner_pubkey, "transport": "poll"}
        )


@pytest.mark.asyncio
async def test_activity_auto_fallback_reports_websocket_requirement(
    monkeypatch, caplog
):
    owner_pubkey = nostr_auth.public_key_hex("00" * 31 + "02")
    adapter = _make_adapter({"activity_owner_pubkey": owner_pubkey})

    def invalid_websocket_url():
        raise ValueError("websocket unavailable")

    monkeypatch.setattr(adapter, "_websocket_url", invalid_websocket_url)
    with caplog.at_level("WARNING"):
        assert await adapter._start_websocket() is False

    assert "native activity is unavailable while using polling" in caplog.text


@pytest.mark.asyncio
async def test_terminal_send_failure_retries_once_on_same_live_socket(monkeypatch):
    owner_pubkey = nostr_auth.public_key_hex("00" * 31 + "02")
    adapter = _make_adapter({"activity_owner_pubkey": owner_pubkey})
    monkeypatch.setattr(_buzz_mod, "_ACTIVITY_TERMINAL_RETRY_DELAY", 0.01)

    event_counter = 0

    def build_event(**kwargs):
        nonlocal event_counter
        event_counter += 1
        return {
            "id": f"terminal-event-{event_counter}",
            "kind": 24200,
            "payload": kwargs["payload"],
        }

    monkeypatch.setattr(
        _buzz_mod,
        "_load_nostr_auth",
        lambda: SimpleNamespace(build_observer_event=build_event),
    )

    class FlakyWebSocket:
        def __init__(self):
            self.send_count = 0
            self.delivered = []

        async def send(self, raw):
            self.send_count += 1
            if self.send_count == 1:
                raise TimeoutError("relay backpressure")
            self.delivered.append(json.loads(raw))

    websocket = FlakyWebSocket()
    adapter._ws_active = True
    adapter._ws_connection = websocket
    generation = adapter._activity_ws_generation

    assert await adapter.publish_activity(
        "turn_completed",
        channel_id=CHANNEL,
        session_id="session-1",
        turn_id="turn-1",
    ) is True
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)
    assert websocket.send_count == 1
    assert list(adapter._activity_terminal_replay) == ["turn-1"]
    assert not adapter._activity_pending_event_ids

    await asyncio.sleep(0.03)
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)
    assert websocket.send_count == 2
    assert adapter._ws_connection is websocket
    assert adapter._activity_ws_generation == generation
    assert [frame[1]["payload"]["kind"] for frame in websocket.delivered] == [
        "turn_completed"
    ]
    assert not adapter._activity_terminal_replay

    await adapter._reset_activity_transport()


@pytest.mark.asyncio
async def test_reset_activity_transport_propagates_cancellation():
    adapter = _make_adapter()
    sender_blocked = asyncio.Event()
    adapter._activity_sender_task = asyncio.create_task(sender_blocked.wait())

    reset_task = asyncio.create_task(adapter._reset_activity_transport())
    await asyncio.sleep(0)
    reset_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await reset_task
    assert reset_task.cancelled()


@pytest.mark.asyncio
async def test_disconnect_completes_while_websocket_loop_is_resetting():
    adapter = _make_adapter()
    reset_entered = asyncio.Event()
    sender_blocked = asyncio.Event()
    adapter._activity_sender_task = asyncio.create_task(sender_blocked.wait())

    async def reconnecting_websocket_loop():
        while True:
            try:
                raise ConnectionError("relay disconnected")
            except Exception:
                reset_entered.set()
                await adapter._reset_activity_transport()
                await asyncio.sleep(3600)

    adapter._ws_task = asyncio.create_task(reconnecting_websocket_loop())
    await asyncio.wait_for(reset_entered.wait(), timeout=1)
    await asyncio.sleep(0)

    disconnect_task = asyncio.create_task(adapter.disconnect())
    try:
        await asyncio.wait_for(asyncio.shield(disconnect_task), timeout=0.1)
    finally:
        if not disconnect_task.done():
            if adapter._ws_task and not adapter._ws_task.done():
                adapter._ws_task.cancel()
            disconnect_task.cancel()
        try:
            await disconnect_task
        except asyncio.CancelledError:
            pass


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
async def test_rejected_terminal_is_retained_and_retried_once(monkeypatch, caplog):
    owner_pubkey = nostr_auth.public_key_hex("2".zfill(64))
    adapter = _make_adapter(extra={"activity_owner_pubkey": owner_pubkey})
    websocket = _FakeWebSocket()
    adapter._ws_connection = websocket
    adapter._ws_active = True
    monkeypatch.setattr(_buzz_mod, "_ACTIVITY_TERMINAL_RETRY_DELAY", 0.01)

    event_counter = 0

    def build_event(**kwargs):
        nonlocal event_counter
        event_counter += 1
        return {
            "id": f"terminal-event-{event_counter}",
            "kind": 24200,
            "payload": kwargs["payload"],
        }

    monkeypatch.setattr(
        _buzz_mod,
        "_load_nostr_auth",
        lambda: SimpleNamespace(build_observer_event=build_event),
    )

    assert await adapter.publish_activity(
        "turn_completed",
        channel_id=CHANNEL,
        session_id="session-1",
        turn_id="turn-1",
    )
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)

    with caplog.at_level("WARNING"):
        assert adapter._handle_activity_ack(
            ["OK", "terminal-event-1", False, "rate-limited: slow down"]
        ) is True

    assert list(adapter._activity_terminal_replay) == ["turn-1"]
    await asyncio.sleep(0.03)
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)
    assert len(websocket.sent) == 2

    assert adapter._handle_activity_ack(
        ["OK", "terminal-event-2", False, "rate-limited: slow down"]
    ) is True
    await asyncio.sleep(0.03)
    assert len(websocket.sent) == 2
    assert list(adapter._activity_terminal_replay) == ["turn-1"]
    assert "rate-limited: slow down" in caplog.text

    await adapter._reset_activity_transport()


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


@pytest.mark.asyncio
async def test_websocket_loop_replays_terminal_after_real_reconnect(monkeypatch):
    owner_pubkey = nostr_auth.public_key_hex("00" * 31 + "02")
    adapter = _make_adapter({"activity_owner_pubkey": owner_pubkey})
    second_delivery = asyncio.Event()

    class RelaySocket(_FakeWebSocket):
        def __init__(self, *, disconnect_after_terminal):
            super().__init__()
            self.disconnect_after_terminal = disconnect_after_terminal
            self.terminal_sent = asyncio.Event()

        async def send(self, raw):
            frame = json.loads(raw)
            self.sent.append(frame)
            if frame[0] == "EVENT" and frame[1].get("kind") == 24200:
                self.terminal_sent.set()

        async def recv(self):
            if self.sent:
                event = self.sent[-1][1]
                return json.dumps(["OK", event["id"], True, "stored"])
            return json.dumps(["AUTH", "relay-challenge"])

        def __aiter__(self):
            async def frames():
                await self.terminal_sent.wait()
                if not self.disconnect_after_terminal:
                    second_delivery.set()
                    await asyncio.Future()
                if False:
                    yield ""

            return frames()

    first_socket = RelaySocket(disconnect_after_terminal=True)
    second_socket = RelaySocket(disconnect_after_terminal=False)
    sockets = iter((first_socket, second_socket))

    class RelayConnection:
        def __init__(self, websocket):
            self.websocket = websocket

        async def __aenter__(self):
            return self.websocket

        async def __aexit__(self, exc_type, exc, traceback):
            return False

    def connect(*args, **kwargs):
        return RelayConnection(next(sockets))

    monkeypatch.setitem(sys.modules, "websockets", SimpleNamespace(connect=connect))
    terminal_payload = {
        "kind": "turn_completed",
        "seq": 1,
        "timestamp": "2026-08-03T14:00:00.000Z",
        "channelId": CHANNEL,
        "sessionId": "session-1",
        "turnId": "turn-1",
        "payload": {},
    }
    assert adapter._cache_terminal_activity(terminal_payload)

    websocket_task = asyncio.create_task(adapter._websocket_loop())
    try:
        await asyncio.wait_for(second_delivery.wait(), timeout=3)
        first_terminal = [
            frame
            for frame in first_socket.sent
            if frame[0] == "EVENT" and frame[1].get("kind") == 24200
        ]
        second_terminal = [
            frame
            for frame in second_socket.sent
            if frame[0] == "EVENT" and frame[1].get("kind") == 24200
        ]
        assert len(first_terminal) == 1
        assert len(second_terminal) == 1
        assert adapter._activity_ws_generation >= 3
    finally:
        if not websocket_task.done():
            websocket_task.cancel()
        try:
            await websocket_task
        except asyncio.CancelledError:
            pass


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
async def test_unacked_terminal_is_retained_on_ack_timeout(monkeypatch):
    owner_pubkey = nostr_auth.public_key_hex("00" * 31 + "02")
    adapter = _make_adapter({"activity_owner_pubkey": owner_pubkey})
    websocket = _FakeWebSocket()
    adapter._ws_active = True
    adapter._ws_connection = websocket
    monkeypatch.setattr(_buzz_mod, "_ACTIVITY_ACK_TIMEOUT", 0.01)
    captured_payloads = []

    def build_event(**kwargs):
        captured_payloads.append(kwargs["payload"])
        return {"id": f"event-{len(captured_payloads)}"}

    monkeypatch.setattr(
        _buzz_mod,
        "_load_nostr_auth",
        lambda: SimpleNamespace(build_observer_event=build_event),
    )

    assert await adapter.publish_activity(
        "turn_completed",
        channel_id=CHANNEL,
        session_id="session-1",
        turn_id="turn-1",
    )
    await asyncio.wait_for(adapter._activity_queue.join(), timeout=1)
    event_id = websocket.sent[0][1]["id"]
    await asyncio.sleep(0.03)

    assert event_id not in adapter._activity_pending_event_ids
    assert list(adapter._activity_terminal_replay) == ["turn-1"]
    assert len(websocket.sent) == 2
    assert all("_hermesAckRetry" not in payload for payload in captured_payloads)
    adapter._activity_sender_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await adapter._activity_sender_task


@pytest.mark.asyncio
async def test_activity_pending_ack_cap_cancels_evicted_deadline(monkeypatch):
    adapter = _make_adapter()
    monkeypatch.setattr(_buzz_mod, "_ACTIVITY_PENDING_CAP", 2)

    terminal_payload = {
        "kind": "turn_completed",
        "turnId": "turn-1",
        "sessionId": "session-1",
    }
    adapter._track_activity_ack("first", 1, terminal_payload)
    first_timer = adapter._activity_pending_event_ids["first"][1]
    adapter._track_activity_ack("second", 1)
    adapter._track_activity_ack("third", 1)

    assert list(adapter._activity_pending_event_ids) == ["second", "third"]
    assert first_timer.cancelled()
    assert list(adapter._activity_terminal_replay) == ["turn-1"]
    await adapter._reset_activity_transport()


def test_activity_owner_pubkey_rejects_non_curve_x_coordinate():
    with pytest.raises(ValueError, match="activity_owner_pubkey"):
        _make_adapter({"activity_owner_pubkey": "f" * 64})


def test_activity_owner_pubkey_is_config_only(monkeypatch):
    env_owner = nostr_auth.public_key_hex("00" * 31 + "02")
    monkeypatch.setenv("BUZZ_ACTIVITY_OWNER_PUBKEY", env_owner)

    adapter = _make_adapter()

    assert adapter.activity_owner_pubkey == ""
