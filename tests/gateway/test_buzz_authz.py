"""Authorization integration contracts for the Buzz plugin."""

from gateway.authz_mixin import GatewayAuthorizationMixin
from gateway.config import Platform
from gateway.session import SessionSource
from tests.gateway._plugin_adapter_loader import load_plugin_adapter


SELF_PUBKEY = "9fd5c7ba6d3ef224da78f541e0fcb9c50f72cc63edb19aae76ac6a0474dfa860"
SELF_NPUB = "npub1nl2u0wnd8mezfknc74q7pl9ec58h9nrrakce4tnk434qgaxl4psqe5twr6"
_buzz_mod = load_plugin_adapter("buzz")


class _AuthHarness(GatewayAuthorizationMixin):
    pairing_store = None
    pairing_stores = {}
    adapters = {}
    config = None


def test_buzz_npub_allowlist_authorizes_hex_sender(monkeypatch):
    from gateway.platform_registry import PlatformEntry, platform_registry

    previous_entry = platform_registry._entries.get("buzz")
    previous_deferred = platform_registry._deferred.get("buzz")
    platform_registry.unregister("buzz")
    platform_registry.register(PlatformEntry(
        name="buzz",
        label="Buzz",
        adapter_factory=lambda config: None,
        check_fn=lambda: True,
        allowed_users_env="BUZZ_ALLOWED_USERS",
        allow_all_env="BUZZ_ALLOW_ALL_USERS",
        auth_identity_normalizer=_buzz_mod._normalize_user_ref,
    ))
    monkeypatch.setenv("BUZZ_ALLOWED_USERS", SELF_NPUB)
    monkeypatch.setenv("BUZZ_ALLOW_ALL_USERS", "false")

    try:
        source = SessionSource(
            platform=Platform("buzz"),
            chat_id="channel-1",
            chat_type="group",
            user_id=SELF_PUBKEY,
        )
        assert _AuthHarness()._is_user_authorized(source) is True
    finally:
        platform_registry.unregister("buzz")
        if previous_entry is not None:
            platform_registry.register(previous_entry)
        elif previous_deferred is not None:
            platform_registry.register_deferred("buzz", previous_deferred)
