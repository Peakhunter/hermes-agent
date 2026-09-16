"""Installed typed-browser dispatch, kept separate from native input."""
import json
from typing import Any, Dict, List

def dispatch_browser(backend, action, args, **_):
    # cua-driver's typed browser surface is namespaced inside the existing
    # computer_use tool so it cannot collide with native browser/MCP tools.
    # The backend owns the opaque driver session, target, tab and ref state;
    # none of those capabilities can be supplied across Hermes sessions.
    if action == "cua_browser_state":
        state_args: Dict[str, Any] = {}
        for public, internal in (
            ("pid", "pid"),
            ("window_id", "window_id"),
            ("tab_id", "tab_id"),
            ("snapshot_format", "snapshot_format"),
            ("query", "query"),
            ("scope_ref", "scope_ref"),
            ("continuation", "continuation"),
            ("include_screenshot", "include_screenshot"),
        ):
            if args.get(public) is not None:
                state_args[internal] = args[public]
        return _browser_state_response(backend.typed_browser_state(**state_args))

    if action == "cua_browser_prepare":
        return json.dumps(backend.typed_browser_prepare(
            pid=args.get("pid"),
            window_id=args.get("window_id"),
            profile_mode=args.get("profile_mode", "isolated_new"),
            profile_name=args.get("profile_name"),
            allow_launch=bool(args.get("allow_launch")),
        ))

    browser_tools = {
        "cua_browser_navigate": "browser_navigate",
        "cua_browser_click": "browser_click",
        "cua_browser_type": "browser_type",
        "cua_browser_pointer": "browser_pointer",
        "cua_browser_dialog": "browser_dialog",
        "cua_browser_set_input_files": "browser_set_input_files",
        "cua_browser_download": "browser_download",
    }
    driver_tool = browser_tools.get(action)
    if driver_tool is not None:
        call_args: Dict[str, Any] = {}
        allowed_fields = {
            "browser_navigate": ("url",),
            "browser_click": ("ref", "input_route", "x", "y"),
            "browser_type": ("ref", "text", "replace"),
            "browser_pointer": (
                "ref", "destination_ref", "input_route", "x", "y",
                "to_x", "to_y", "delta_x", "delta_y",
            ),
            "browser_dialog": (
                "dialog_id", "prompt_text", "delivery_mode",
            ),
            "browser_set_input_files": ("ref", "files"),
            "browser_download": ("ref", "destination_root"),
        }
        for field in allowed_fields[driver_tool]:
            if args.get(field) is not None:
                call_args[field] = args[field]
        if (
            driver_tool in {"browser_click", "browser_pointer"}
            and args.get("coordinate") is not None
        ):
            coordinate = args["coordinate"]
            if isinstance(coordinate, (list, tuple)) and len(coordinate) == 2:
                call_args["x"], call_args["y"] = coordinate
        pointer_action = args.get("browser_pointer_action")
        dialog_action = args.get("browser_dialog_action")
        # Direct adapter callers may omit the public discriminator from args;
        # retain this narrow compatibility path without making it usable to
        # override the namespaced action selected by handle_computer_use.
        nested_action = args.get("action")
        if nested_action not in browser_tools:
            if driver_tool == "browser_pointer" and pointer_action is None:
                pointer_action = nested_action
            if driver_tool == "browser_dialog" and dialog_action is None:
                dialog_action = nested_action
        if pointer_action is not None:
            call_args["action"] = pointer_action
        if dialog_action is not None:
            call_args["action"] = dialog_action
        if args.get("browser_type_mode") is not None:
            call_args["mode"] = args["browser_type_mode"]
        return json.dumps(backend.typed_browser_action(
            driver_tool,
            tab_id=args.get("tab_id"),
            args=call_args,
        ))


def _browser_state_response(payload: Dict[str, Any]) -> Any:
    """Return browser state as JSON, preserving requested MCP image parts."""
    state = dict(payload)
    raw_images = state.pop("_mcp_images", None)
    if not isinstance(raw_images, list) or not raw_images:
        return json.dumps(state)

    text_summary = json.dumps(state)
    content: List[Dict[str, Any]] = [
        {"type": "text", "text": text_summary},
    ]
    image_count = 0
    for image in raw_images:
        if not isinstance(image, dict):
            continue
        data = image.get("data")
        if not isinstance(data, str) or not data:
            continue
        mime_type = image.get("mime_type")
        if not isinstance(mime_type, str) or not mime_type.startswith("image/"):
            mime_type = "image/jpeg" if data.startswith("/9j/") else "image/png"
        content.append({
            "type": "image_url",
            "image_url": {"url": f"data:{mime_type};base64,{data}"},
        })
        image_count += 1
    if image_count == 0:
        return text_summary
    return {
        "_multimodal": True,
        "content": content,
        "text_summary": text_summary,
        "meta": {"action": "cua_browser_state", "images": image_count},
    }
