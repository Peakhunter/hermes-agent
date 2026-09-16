"""Per-backend browser capabilities; never shared between sessions."""
from typing import Any, Dict, Optional
from tools.computer_use.browser_route import CuaTypedBrowserRoute

class BrowserMixin:
    def _browser_route(self) -> CuaTypedBrowserRoute:
        """Return the per-backend typed route, including test-constructed instances."""
        route = getattr(self, "_typed_browser", None)
        if route is None:
            route = CuaTypedBrowserRoute(
                session_id=self._session_id,
                call_tool=self._session.call_tool,
                has_tool=self._session._has_tool,
            )
            self._typed_browser = route
        return route

    def typed_browser_state(self, **kwargs: Any) -> Dict[str, Any]:
        """Exact-bind a native browser window or read fresh semantic state."""
        return self._browser_route().observe(**kwargs)

    def typed_browser_prepare(self, **kwargs: Any) -> Dict[str, Any]:
        """Prepare an explicitly approved driver-owned browser profile.

        The authorization inputs are resolved here, from config and this
        backend's immutable mode — never from model-supplied kwargs.
        """
        from tools.computer_use.cua_backend import _computer_use_cfg

        kwargs.pop("grant_existing_profile", None)
        kwargs.pop("permission_mode", None)
        return self._browser_route().prepare(
            grant_existing_profile=_computer_use_cfg().get("grant_existing_profile") is True,
            permission_mode=self.permission_mode,
            **kwargs,
        )

    def typed_browser_action(
        self,
        driver_tool: str,
        *,
        tab_id: Optional[str] = None,
        args: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Run one namespaced typed-browser mutation in this exact route."""
        return self._browser_route().mutate(driver_tool, tab_id=tab_id, args=args)
