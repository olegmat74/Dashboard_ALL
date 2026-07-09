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

    def test_title_is_dashboard_of_all_projects(self):
        self.assertIn("Дашборд всех проектов", self.html)

    def test_dashboard_is_split_into_project_blocks_and_non_project_blocks(self):
        for text in [
            "Cron",
            "Проект Creative Fabrica",
            "Проект Ритм",
            "Проект Unicaizer",
        ]:
            with self.subTest(text=text):
                self.assertIn(text, self.html)

    def test_project_tables_have_channel_name_column(self):
        for text in ["Название канала"]:
            with self.subTest(text=text):
                self.assertIn(text, self.html)

    def test_cron_table_has_correct_columns(self):
        for text in [
            "Профиль",
            "Включен или выключен",
            "Расписание",
            "Последний запуск",
            "Следующий запуск",
            "Статус",
        ]:
            with self.subTest(text=text):
                self.assertIn(text, self.html)

    def test_cron_table_does_not_have_old_columns(self):
        for text in ["Задача", "Ошибка"]:
            with self.subTest(text=text):
                self.assertNotIn(text, self.html)

    def test_no_bold_font(self):
        self.assertNotIn("font-weight:700", self.html)
        self.assertNotIn("font-weight:800", self.html)
        self.assertNotIn("<b>", self.html)

    def test_has_server_info_block(self):
        self.assertIn("Server1", self.html)
        self.assertIn("Действует до", self.html)
