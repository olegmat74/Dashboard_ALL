import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_server():
    spec = importlib.util.spec_from_file_location("dashboard_server", ROOT / "server.py")
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DashboardContractTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        mod = load_server()
        cls.html = mod.render()

    def test_title_is_dashboard(self):
        self.assertIn("<title>Dashboard</title>", self.html)

    def test_kpi_cards_present(self):
        for text in [
            "Постов всего",
            "Проектов",
            "Опубликовано сегодня",
            "Ошибки",
        ]:
            with self.subTest(text=text):
                self.assertIn(text, self.html)

    def test_project_sections_present(self):
        for text in [
            "Creative Fabrica",
            "Яндекс Ритм",
        ]:
            with self.subTest(text=text):
                self.assertIn(text, self.html)

    def test_table_columns(self):
        for text in ["Проект", "Всего", "Сегодня", "План", "Прогресс", "След.", "Сайт", "Статус"]:
            with self.subTest(text=text):
                self.assertIn(text, self.html)

    def test_system_pills_present(self):
        self.assertIn("Диск", self.html)
        self.assertIn("RAM", self.html)
        self.assertIn("Сервер", self.html)

    def test_no_font_weight_900(self):
        self.assertNotIn("font-weight:900", self.html)

    def test_has_server_info(self):
        self.assertIn("Срок сервера", self.html)

    def test_no_deleted_projects(self):
        for text in ["Wibes", "Unicaizer"]:
            with self.subTest(text=text):
                self.assertNotIn(text, self.html)
