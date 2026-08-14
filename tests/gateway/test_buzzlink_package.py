"""Package identity and native subdirectory-install contract for BuzzLink."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).parents[2]
BUZZ_PLUGIN = PROJECT_ROOT / "plugins" / "platforms" / "buzz"


@dataclass
class InstalledBuzzLink:
    target: Path
    manifest: dict
    installed_name: str
    entry: object


@pytest.fixture
def installed_buzzlink(tmp_path, monkeypatch):
    """Install and load BuzzLink through the real external-plugin path."""
    if shutil.which("git") is None:
        pytest.skip("git not available")

    from hermes_cli import plugins_cmd

    repo = tmp_path / "source"
    packaged_plugin = repo / "plugins" / "platforms" / "buzz"
    shutil.copytree(BUZZ_PLUGIN, packaged_plugin, ignore=shutil.ignore_patterns("__pycache__"))

    git_env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Package Test",
        "GIT_AUTHOR_EMAIL": "package-test@example.invalid",
        "GIT_COMMITTER_NAME": "Package Test",
        "GIT_COMMITTER_EMAIL": "package-test@example.invalid",
    }
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=git_env)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=git_env)
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "package fixture"],
        cwd=repo,
        check=True,
        env=git_env,
    )

    home = tmp_path / "home"
    install_root = home / "plugins"
    install_root.mkdir(parents=True)
    monkeypatch.setattr(plugins_cmd, "_plugins_dir", lambda: install_root)

    target, manifest, installed_name = plugins_cmd._install_plugin_core(
        f"file://{repo}#plugins/platforms/buzz",
        force=False,
    )

    assert manifest["manifest_version"] == 1
    assert manifest["name"] == "hermes-buzzlink"
    assert manifest["label"] == "BuzzLink for Hermes"
    assert manifest["version"] == "0.1.0"
    assert installed_name == "hermes-buzzlink"
    assert target == install_root / "hermes-buzzlink"
    assert (target / "README.md").is_file()
    assert (target / "COMPATIBILITY.md").is_file()

    # Exercise the installed copy through the real user-plugin loader while the
    # bundled Buzz platform is also discoverable. Isolated registry dictionaries
    # cover the real collision path without leaking entries into other tests.
    (home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - hermes-buzzlink\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))

    from gateway.platform_registry import platform_registry
    from hermes_cli.plugins import PluginManager

    monkeypatch.setattr(platform_registry, "_entries", {})
    monkeypatch.setattr(platform_registry, "_deferred", {})

    namespace = "hermes_plugins.hermes_buzzlink"
    preexisting_modules = {
        name: module
        for name, module in list(sys.modules.items())
        if name == namespace or name.startswith(f"{namespace}.")
    }
    for module_name in preexisting_modules:
        sys.modules.pop(module_name, None)

    try:
        manager = PluginManager()
        manager.discover_and_load()

        loaded = manager._plugins["hermes-buzzlink"]
        assert loaded.enabled is True
        assert loaded.error is None
        entry = platform_registry.get("buzz")
        assert entry is not None
        assert entry.label == "BuzzLink for Hermes"
        assert entry.plugin_name == "hermes-buzzlink"
        assert "buzz" not in platform_registry._deferred
        adapter_module = sys.modules[entry.adapter_factory.__module__]
        assert adapter_module.__file__ is not None
        assert Path(adapter_module.__file__).resolve().is_relative_to(target.resolve())
        yield InstalledBuzzLink(target, manifest, installed_name, entry)
    finally:
        for module_name in list(sys.modules):
            if module_name == namespace or module_name.startswith(f"{namespace}."):
                sys.modules.pop(module_name, None)
        sys.modules.update(preexisting_modules)


def test_buzzlink_identity_and_native_subdirectory_install(installed_buzzlink):
    """The branded package installs independently without changing platform id."""
    installed = installed_buzzlink
    assert installed.manifest["manifest_version"] == 1
    assert installed.manifest["name"] == "hermes-buzzlink"
    assert installed.manifest["label"] == "BuzzLink for Hermes"
    assert installed.manifest["version"] == "0.1.0"
    assert installed.installed_name == "hermes-buzzlink"
    assert installed.target.name == "hermes-buzzlink"


@pytest.mark.asyncio
async def test_installed_buzzlink_native_gateway_reply_uses_inbound_event_parent(
    installed_buzzlink,
):
    """An installed Buzz mention traverses native gateway ingress and reply egress."""
    from gateway.config import PlatformConfig
    from gateway.platforms.base import MessageEvent

    adapter = installed_buzzlink.entry.adapter_factory(
        PlatformConfig(enabled=True, extra={"relay_url": "https://test.relay"})
    )
    self_pubkey = "9fd5c7ba6d3ef224da78f541e0fcb9c50f72cc63edb19aae76ac6a0474dfa860"
    sender_pubkey = "a" * 64
    channel_id = "ccc2bc1a-7a82-5a8f-8c4e-57a070cbe7cd"
    inbound_id = "b" * 64
    adapter._self_pubkey = self_pubkey
    adapter._display_name = "Chip"
    adapter._channel_names[channel_id] = "general"
    adapter._channel_meta[channel_id] = {"name": "general", "description": ""}
    adapter._channel_state[channel_id] = {
        "chat_type": "group",
        "last_ts": 0,
        "seen": {},
    }
    adapter._should_ack_sender = lambda *_args, **_kwargs: True

    cli_calls = []

    async def fake_cli(args, *, input_text=None):
        cli_calls.append((list(args), input_text))
        if args[:2] == ["users", "get"]:
            return 0, '[{"display_name": "Alice"}]', ""
        if args[:2] == ["messages", "send"]:
            return 0, '{"accepted": true, "event_id": "agent-reply"}', ""
        return 0, "{}", ""

    received = []

    async def gateway_handler(event):
        received.append(event)
        return "Hermes response"

    adapter._run_cli = fake_cli
    adapter.set_message_handler(gateway_handler)

    await adapter._handle_event(
        channel_id,
        adapter._channel_state[channel_id],
        {
            "id": inbound_id,
            "pubkey": sender_pubkey,
            "content": "@Chip status?",
            "created_at": 1_700_000_000,
            "kind": 9,
            "tags": [["h", channel_id], ["p", self_pubkey]],
        },
    )
    await asyncio.gather(*list(adapter._background_tasks))

    assert len(received) == 1
    assert isinstance(received[0], MessageEvent)
    assert received[0].text == "status?"
    assert received[0].message_id == inbound_id
    assert received[0].source.thread_id == inbound_id
    send_args, sent_text = next(
        call for call in cli_calls if call[0][:2] == ["messages", "send"]
    )
    assert sent_text == "Hermes response"
    assert send_args[-2:] == ["--reply-to", inbound_id]
