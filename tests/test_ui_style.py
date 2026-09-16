from pathlib import Path
import re
import unittest


class CtaStyleTests(unittest.TestCase):
    def test_full_width_actions_use_standard_size(self):
        pages = Path(__file__).resolve().parents[1] / "ui" / "pages"
        checked = 0
        for path in pages.rglob("*.slint"):
            for properties in re.findall(r"\bButton\s*\{([^{}]*)", path.read_text()):
                if not re.search(r"full-width\s*:\s*true\s*;", properties):
                    continue
                checked += 1
                with self.subTest(page=str(path.relative_to(pages)), properties=properties):
                    self.assertRegex(properties, r"\bsize\s*:\s*ControlSize\.md\s*;")
        self.assertGreater(checked, 0)


class MainMenuStyleTests(unittest.TestCase):
    def setUp(self):
        self.source = (
            Path(__file__).resolve().parents[1] / "ui" / "pages" / "page.slint"
        ).read_text()

    def test_main_menu_does_not_use_modal_popup(self):
        self.assertNotIn("PopupWindow", self.source)
        self.assertIn("if root.menu-open: menu-layer := Rectangle", self.source)

    def test_more_button_has_expanded_touch_target(self):
        touch = re.search(r"more-touch\s*:=\s*TouchArea\s*\{([^}]*)", self.source)
        self.assertIsNotNone(touch)
        properties = touch.group(1)
        self.assertRegex(properties, r"x\s*:\s*-8px\s*;")
        self.assertRegex(properties, r"y\s*:\s*-8px\s*;")
        self.assertRegex(properties, r"width\s*:\s*parent\.width\s*\+\s*16px\s*;")
        self.assertRegex(properties, r"height\s*:\s*parent\.height\s*\+\s*16px\s*;")

    def test_menu_uses_contrasting_theme_surface(self):
        self.assertIn("background: #00000080;", self.source)
        self.assertIn(
            "menu-background: Theme.is-dark ? Theme.palette-secondary : Theme.palette-surface;",
            self.source,
        )
        self.assertRegex(self.source, r"drop-shadow-blur\s*:\s*16px\s*;")


if __name__ == "__main__":
    unittest.main()
