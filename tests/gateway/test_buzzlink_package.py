"""Package identity and native subdirectory-install contract for BuzzLink."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).parents[2]
BUZZ_PLUGIN = PROJECT_ROOT / "plugins" / "platforms" / "buzz"


def test_buzzlink_identity_and_native_subdirectory_install(tmp_path, monkeypatch):
    """The branded package installs independently without changing platform id."""
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

    for module_name in list(sys.modules):
        if module_name == "hermes_plugins.hermes_buzzlink" or module_name.startswith(
            "hermes_plugins.hermes_buzzlink."
        ):
            sys.modules.pop(module_name, None)
