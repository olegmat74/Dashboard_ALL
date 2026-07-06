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
        cls.html = load_server().render()

    def test_dashboard_is_split_into_project_blocks_and_non_project_blocks(self):
        for text in [
            "Оперативная память",
            "Жёсткий диск",
            "Cron всех проектов",
            "Проект Wibes",
            "Проект Creative Fabrica",
            "Проект Ритм",
            "Проект Unicaizer",
        ]:
            with self.subTest(text=text):
                self.assertIn(text, self.html)

    def test_project_tables_have_required_human_columns(self):
        for text in [
            "Название канала",
            "Pinterest аккаунт",
            "Сайт аккаунта",
            "Запланировано сегодня",
            "Опубликовано",
            "Осталось",
            "Следующая публикация",
            "Статус",
        ]:
            with self.subTest(text=text):
                self.assertIn(text, self.html)

    def test_project_blocks_have_summary_metrics(self):
        for text in [
            "Ошибки",
            "Всего опубликованных постов",
            "Всего постов за всё время",
            "Постов за сегодня",
            "Всего уникальных посетителей",
            "Уникальные посетители за сегодня",
            "Авторизованные в Telegram",
            "Видео обрабатываются сейчас",
        ]:
            with self.subTest(text=text):
                self.assertIn(text, self.html)


if __name__ == "__main__":
    unittest.main()
