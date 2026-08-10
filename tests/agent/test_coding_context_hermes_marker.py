"""Regression tests for Hermes-native project markers in non-Git workspaces."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agent import coding_context


class TestHermesProjectMarkers(unittest.TestCase):
    def _assert_marker_selects_coding_focus(self, marker: str) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / marker).write_text("# trusted project context\n", encoding="utf-8")

            mode = coding_context.resolve_runtime_mode(
                platform="cli",
                cwd=root,
                config={"agent": {"coding_context": "focus"}},
            )

            self.assertTrue(mode.is_coding)
            selected_toolsets = mode.toolset_selection()
            assert selected_toolsets is not None
            self.assertEqual(selected_toolsets[0], coding_context.CODING_TOOLSET)
            self.assertTrue(mode.compact_skill_categories())

    def test_dot_hermes_md_selects_coding_focus_without_git(self) -> None:
        self._assert_marker_selects_coding_focus(".hermes.md")

    def test_uppercase_hermes_md_selects_coding_focus_without_git(self) -> None:
        self._assert_marker_selects_coding_focus("HERMES.md")


if __name__ == "__main__":
    unittest.main()
