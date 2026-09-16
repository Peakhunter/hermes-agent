"""Installed typed-browser contract through the real registered dispatcher."""
import json
from unittest.mock import Mock

import pytest

from tools.computer_use import tool


@pytest.fixture(autouse=True)
def clean_backend():
    tool.reset_backend_for_tests()
    yield
    tool.reset_backend_for_tests()


def test_installed_browser_snapshot_and_mutation_require_fresh_exact_authority(monkeypatch):
    from tools.computer_use.cua_backend import CuaDriverBackend
    backend = CuaDriverBackend(permission_mode="standard")
    backend._session._has_tool = lambda name: True
    replies = [
        {"status": "ok", "target_id": "target-a", "binding_quality": "exact", "mutation_allowed": True,
         "tabs": [{"tab_id": "tab-a"}]},
        {"status": "ok", "tab_id": "tab-a", "binding_quality": "exact", "mutation_allowed": True,
         "refs": [{"ref": "field-a", "actions": ["type"]}]},
        {"status": "ok"},
    ]
    calls = []
    def call(name, args):
        calls.append((name, args))
        return {"structuredContent": replies.pop(0)}
    backend._session.call_tool = call
    monkeypatch.setattr(tool, "_get_backend", lambda **kw: backend)
    monkeypatch.setattr(tool, "_approval_callback", lambda *a: "approve_once")
    def dispatch(**args):
        return json.loads(tool.handle_computer_use(args, session_id="installed-contract"))
    bound = dispatch(action="cua_browser_state", pid=101, window_id=202)
    assert bound.get("binding_quality") == "exact", bound
    observed = dispatch(action="cua_browser_state", tab_id="tab-a")
    assert "error" not in observed, observed
    result = dispatch(action="cua_browser_type", tab_id="tab-a", ref="field-a", text="replacement", replace=True)
    assert result.get("status") == "ok", result
    assert calls[-1][0] == "browser_type"
    assert calls[-1][1]["replace"] is True
    assert calls[-1][1]["session"] == backend._session_id
    before = len(calls)
    denied = dispatch(action="cua_browser_type", tab_id="tab-a", ref="field-a", text="again")
    assert denied.get("status") == "refused", denied
    assert len(calls) == before


def test_schema_carries_installed_typed_dispatch_parameters():
    from tools.computer_use.schema import COMPUTER_USE_SCHEMA
    props = COMPUTER_USE_SCHEMA["parameters"]["properties"]
    assert tool._BROWSER_ACTIONS <= set(props["action"]["enum"])
    assert props["replace"]["type"] == "boolean"
    assert props["browser_type_mode"]["enum"] == ["insert_text", "keystrokes"]
    assert "grant_existing_profile" not in props


@pytest.mark.parametrize("grant", [False, True, "false", None])
def test_existing_profile_grant_is_file_scoped_and_not_model_supplied(tmp_path, monkeypatch, grant):
    import yaml
    from tools.computer_use.cua_backend import CuaDriverBackend
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"computer_use": {"grant_existing_profile": grant}}))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    backend = CuaDriverBackend(permission_mode="unrestricted")
    backend._session._has_tool = lambda name: True
    call = Mock(return_value={"structuredContent": {"status": "ok"}})
    backend._session.call_tool = call
    result = backend.typed_browser_prepare(pid=101, window_id=202, profile_mode="existing_profile",
                                          grant_existing_profile=True, permission_mode="bounded")
    assert (result.get("status") == "ok") is (grant is True), result
    assert call.call_count == int(grant is True)


def test_transport_reset_revokes_typed_browser_authority():
    from tools.computer_use.cua_backend import CuaDriverBackend
    backend = CuaDriverBackend()
    route = backend._browser_route()
    route.state.target_id = "target-before-reset"
    route.state.refs = {"old-ref": {"type"}}
    backend._handle_transport_reset()
    assert route.state.target_id is None
    assert not route.state.refs


def test_browser_type_hard_blocks_before_backend_or_approval(monkeypatch):
    backend = Mock()
    approval = Mock(return_value="approve_once")
    monkeypatch.setattr(tool, "_get_backend", backend)
    monkeypatch.setattr(tool, "_approval_callback", approval)
    result = json.loads(tool.handle_computer_use({"action": "cua_browser_type", "text": "sudo rm -rf /"}))
    assert "blocked pattern" in result.get("error", ""), result
    backend.assert_not_called()
    approval.assert_not_called()


def test_existing_profile_opt_in_avoids_redundant_prompt_only_for_attachment(tmp_path, monkeypatch):
    (tmp_path / "config.yaml").write_text("computer_use:\n  grant_existing_profile: true\n")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    approval = Mock(return_value="deny")
    backend = Mock()
    backend.typed_browser_prepare.return_value = {"status": "ok"}
    monkeypatch.setattr(tool, "_get_backend", lambda **kw: backend)
    monkeypatch.setattr(tool, "_approval_callback", approval)
    result = json.loads(tool.handle_computer_use({"action": "cua_browser_prepare", "profile_mode": "existing_profile", "pid": 101, "window_id": 202}))
    assert result.get("status") == "ok", result
    approval.assert_not_called()
    result = json.loads(tool.handle_computer_use({"action": "cua_browser_prepare", "profile_mode": "isolated_new", "pid": 101, "allow_launch": True}))
    assert result.get("error") == "denied by user"
    approval.assert_called_once()
