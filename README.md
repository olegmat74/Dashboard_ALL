# Единый дашборд проектов

Компактный русский дашборд по проектам на сервере.

## Запуск

```bash
cd /home/hermes/projects-dashboard
python3 server.py --host 127.0.0.1 --port 8123
```

Открыть: http://127.0.0.1:8123

## Что показывает

- проекты и профили Hermes;
- статус health/systemd/cron;
- последние файлы;
- процессы;
- открытые порты;
- диск сервера;
- автообновление раз в минуту.

## Вход по паролю

При первом запуске используется пароль из локального файла:

```bash
cat /home/hermes/projects-dashboard/.initial_password.txt
```

Секретные файлы не коммитятся в GitHub:

- `.dashboard_password_hash`
- `.session_secret`
- `.initial_password.txt`

## API

API тоже закрыт сессией после входа:

```bash
curl http://127.0.0.1:8123/api/state
```
