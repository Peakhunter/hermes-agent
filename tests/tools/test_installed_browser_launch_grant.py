"""Installed Linux launch grant must reach the actual MCP process parameters."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

@pytest.mark.linux_only
@pytest.mark.parametrize('platform', ['linux', 'darwin'])
def test_existing_browser_grant_reaches_standard_runtime_launch(tmp_path, monkeypatch, platform):
    from tools.computer_use.cua_backend_session import _AsyncBridge, _CuaDriverSession

    (tmp_path / "config.yaml").write_text(
        "computer_use:\n  grant_existing_profile: true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    session = _CuaDriverSession(_AsyncBridge())
    captured = {}

    async def drive_lifecycle():
        def capture_params(**kwargs):
            captured.update(kwargs)
            if platform == "darwin":
                from pathlib import Path
                socket = Path(kwargs["args"][-1])
                assert socket.parent.stat().st_mode & 0o777 == 0o700
                assert socket.parent.name.startswith("hermes-cua-standard-")
            return MagicMock()

        with patch(
            "tools.computer_use.cua_backend_driver.resolve_cua_driver_cmd",
            return_value="/opt/cua-driver",
        ), patch(
            "tools.computer_use.cua_backend_driver._resolve_mcp_invocation",
            return_value=("/opt/cua-driver", ["mcp"]),
        ), patch(
            "mcp.StdioServerParameters", side_effect=capture_params
        ), patch(
            "mcp.client.stdio.stdio_client"
        ) as stdio_client, patch(
            "mcp.ClientSession"
        ) as client_session:
            stdio_client.return_value.__aenter__ = AsyncMock(
                return_value=(MagicMock(), MagicMock())
            )
            stdio_client.return_value.__aexit__ = AsyncMock(return_value=None)
            live_session = MagicMock()
            live_session.initialize = AsyncMock()
            live_session.list_tools = AsyncMock(return_value=MagicMock(tools=[]))
            client_session.return_value.__aenter__ = AsyncMock(
                return_value=live_session
            )
            client_session.return_value.__aexit__ = AsyncMock(return_value=None)

            async def stop_when_ready():
                while session._shutdown_event is None:
                    await asyncio.sleep(0)
                session._shutdown_event.set()

            stop_task = asyncio.create_task(stop_when_ready())
            try:
                with patch("sys.platform", platform):
                    await session._lifecycle_coro()
            finally:
                await stop_task

    asyncio.run(drive_lifecycle())

    assert captured["command"] == "/opt/cua-driver"
    assert captured["args"][:3] == ["mcp", "--grant", "existing-profile"]
    if platform == "darwin":
        from pathlib import Path
        assert captured["args"][3] == "--socket"
        assert not Path(captured["args"][4]).parent.exists()
    else:
        assert len(captured["args"]) == 3


def test_existing_profile_opt_in_remains_available_in_config():
    from hermes_cli.config import DEFAULT_CONFIG
    assert DEFAULT_CONFIG["computer_use"]["grant_existing_profile"] is False
