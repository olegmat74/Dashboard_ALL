#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Единый компактный дашборд проектов Hermes.
Запуск: python3 server.py --host 127.0.0.1 --port 8123
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import html
import json
import os
import shutil
import socket
import subprocess
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

HOME = Path('/home/hermes')
PROFILES = HOME / '.hermes' / 'profiles'
DASH_ROOT = Path(__file__).resolve().parent
PASSWORD_HASH_FILE = DASH_ROOT / '.dashboard_password_hash'
SESSION_SECRET_FILE = DASH_ROOT / '.session_secret'
SESSION_COOKIE = 'projects_dashboard_session'


KNOWN_PROJECTS = [
    {
        'key': 'unicaizer',
        'title': 'UNICAIZER',
        'profile': 'unicaizer',
        'path': PROFILES / 'unicaizer' / 'workspace' / 'unicaizer-app',
        'kind': 'SaaS / обработка видео',
        'public_url': 'https://unicaizer.ru',
        'local_url': 'http://127.0.0.1:8000',
        'health_url': 'http://127.0.0.1:8000/health',
        'services': ['unicaizer-app-web.service', 'unicaizer-app-worker.service'],
    },
    {
        'key': 'wibes',
        'title': 'Wibes Automation',
        'profile': 'wibes',
        'path': PROFILES / 'wibes' / 'workspace' / 'wibes-automation',
        'kind': 'автозагрузка/обработка Wibes',
        'public_url': '',
        'local_url': '',
        'health_url': '',
        'services': [],
    },
    {
        'key': 'ritm',
        'title': 'Autopost Ritm',
        'profile': 'autopost_ritm',
        'path': PROFILES / 'autopost_ritm' / 'workspace' / 'ritm',
        'kind': 'автопостинг / витрины',
        'public_url': '',
        'local_url': '',
        'health_url': '',
        'services': [],
    },
    {
        'key': 'creative_fabrica',
        'title': 'Creative Fabrica Autopost',
        'profile': 'autopost_creative_fabrica',
        'path': PROFILES / 'autopost_creative_fabrica',
        'kind': 'Pinterest/WoopSocial мониторинг',
        'public_url': '',
        'local_url': '',
        'health_url': '',
        'services': [],
    },
]



def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 200_000).hex()
    return f'pbkdf2_sha256${salt}${digest}'


def verify_password(password: str) -> bool:
    try:
        scheme, salt, digest = PASSWORD_HASH_FILE.read_text().strip().split('$', 2)
        if scheme != 'pbkdf2_sha256':
            return False
        got = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 200_000).hex()
        return hmac.compare_digest(got, digest)
    except Exception:
        return False


def session_secret() -> str:
    if not SESSION_SECRET_FILE.exists():
        SESSION_SECRET_FILE.write_text(secrets.token_hex(32))
        SESSION_SECRET_FILE.chmod(0o600)
    return SESSION_SECRET_FILE.read_text().strip()


def make_session_cookie() -> str:
    ts = str(int(time.time()))
    sig = hmac.new(session_secret().encode('utf-8'), ts.encode('utf-8'), hashlib.sha256).hexdigest()
    return f'{ts}:{sig}'


def valid_session_cookie(value: str) -> bool:
    try:
        ts, sig = value.split(':', 1)
        if time.time() - int(ts) > 7 * 86400:
            return False
        good = hmac.new(session_secret().encode('utf-8'), ts.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac.compare_digest(good, sig)
    except Exception:
        return False


def login_page(error: str = '') -> str:
    err = f'<div class="error">{esc(error)}</div>' if error else ''
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Вход — дашборд проектов</title><style>
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#0b1020;color:#eef2ff}}.box{{width:min(420px,calc(100vw - 32px));background:#111936;border:1px solid #26304f;border-radius:22px;padding:26px;box-shadow:0 20px 60px #0008}}h1{{margin:0 0 8px;font-size:26px;letter-spacing:-.04em}}p{{margin:0 0 20px;color:#98a2b3}}label{{display:block;margin:0 0 8px;color:#c8d4ff;font-weight:700}}input{{width:100%;height:46px;border-radius:12px;border:1px solid #33405f;background:#070b17;color:#eef2ff;padding:0 12px;font-size:16px}}button{{width:100%;height:46px;margin-top:14px;border:0;border-radius:12px;background:#2563eb;color:white;font-weight:900;cursor:pointer}}.error{{background:#51101a;color:#ffb1bd;border:1px solid #9d2f3b;padding:10px;border-radius:12px;margin-bottom:14px}}
</style></head><body><form class="box" method="post" action="/login"><h1>Единый дашборд</h1><p>Введите пароль для доступа к проектам.</p>{err}<label>Пароль</label><input name="password" type="password" autocomplete="current-password" autofocus required><button type="submit">Войти</button></form></body></html>"""

def run(cmd: list[str], timeout: int = 4) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout).strip()
    except Exception as exc:
        return f''


def fmt_dt(value: str | None) -> str:
    if not value:
        return '—'
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return dt.astimezone().strftime('%d.%m %H:%M')
    except Exception:
        return str(value)[:16]


def rel_age(ts: float | None) -> str:
    if not ts:
        return '—'
    sec = max(0, time.time() - ts)
    if sec < 60:
        return f'{int(sec)} сек назад'
    if sec < 3600:
        return f'{int(sec//60)} мин назад'
    if sec < 86400:
        return f'{int(sec//3600)} ч назад'
    return f'{int(sec//86400)} дн назад'


def size_h(n: int) -> str:
    units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f'{f:.1f} {u}' if u != 'Б' else f'{int(f)} {u}'
        f /= 1024
    return str(n)


def dir_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for root, dirs, files in os.walk(path):
        # тяжелые кэши не считаем глубоко
        dirs[:] = [d for d in dirs if d not in {'.venv', 'venv', '__pycache__', 'node_modules', '.git'}]
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                pass
    return total


def count_glob(path: Path, pattern: str) -> int:
    try:
        return sum(1 for _ in path.rglob(pattern)) if path.exists() else 0
    except Exception:
        return 0


def recent_files(path: Path, limit: int = 4) -> list[dict[str, str]]:
    rows = []
    if not path.exists():
        return rows
    skip = {'.venv', 'venv', '__pycache__', 'node_modules', '.git'}
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip]
        for f in files:
            p = Path(root) / f
            try:
                st = p.stat()
                rows.append((st.st_mtime, p, st.st_size))
            except OSError:
                pass
    rows.sort(reverse=True, key=lambda x: x[0])
    out = []
    for ts, p, sz in rows[:limit]:
        out.append({'name': p.name, 'path': str(p), 'age': rel_age(ts), 'size': size_h(sz)})
    return out


def load_jobs(profile: str) -> list[dict[str, Any]]:
    p = PROFILES / profile / 'cron' / 'jobs.json'
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
        return data.get('jobs', [])
    except Exception:
        return []


def systemd_state(service: str) -> str:
    out = run(['systemctl', 'is-active', service], 2)
    return out or 'unknown'


def http_health(url: str) -> tuple[str, str]:
    if not url:
        return 'none', '—'
    out = run(['curl', '-fsS', '--max-time', '3', url], 5)
    if out:
        return 'ok', out[:120]
    return 'bad', 'не отвечает'


def port_summary() -> list[dict[str, str]]:
    out = run(['ss', '-tulpn'], 4)
    rows = []
    for line in out.splitlines():
        if 'LISTEN' not in line:
            continue
        parts = line.split()
        local = parts[4] if len(parts) > 4 else ''
        proc = parts[-1] if len(parts) > 6 else ''
        if any(x in local for x in [':80', ':443', ':8000', ':9119', ':8123']):
            rows.append({'local': local, 'process': proc.replace('users:', '')})
    return rows[:12]


def process_hits(project: dict[str, Any]) -> list[str]:
    out = run(['ps', '-eo', 'pid,cmd'], 4)
    needle = str(project['path'])
    hits = []
    for line in out.splitlines():
        if needle in line or project['key'] in line:
            hits.append(line.strip()[:180])
    return hits[:4]


def build_state() -> dict[str, Any]:
    projects = []
    for pr in KNOWN_PROJECTS:
        path = Path(pr['path'])
        jobs = load_jobs(pr['profile'])
        enabled_jobs = [j for j in jobs if j.get('enabled')]
        bad_jobs = [j for j in jobs if j.get('last_status') == 'error']
        health_status, health_text = http_health(pr.get('health_url', ''))
        service_states = [{'name': s, 'state': systemd_state(s)} for s in pr.get('services', [])]
        status = 'ok'
        reasons = []
        if not path.exists():
            status = 'bad'; reasons.append('папка не найдена')
        if health_status == 'bad':
            status = 'bad'; reasons.append('health не отвечает')
        if any(s['state'] not in ('active', 'unknown') for s in service_states):
            status = 'bad'; reasons.append('service problem')
        if bad_jobs and status == 'ok':
            status = 'warn'; reasons.append(f'ошибки cron: {len(bad_jobs)}')
        st = path.stat() if path.exists() else None
        projects.append({
            **{k: (str(v) if isinstance(v, Path) else v) for k, v in pr.items()},
            'exists': path.exists(),
            'status': status,
            'reasons': reasons,
            'modified': rel_age(st.st_mtime if st else None),
            'size': size_h(dir_size(path)),
            'videos': count_glob(path, '*.mp4') + count_glob(path, '*.mov'),
            'logs': count_glob(path, '*.log'),
            'jobs_total': len(jobs),
            'jobs_enabled': len(enabled_jobs),
            'jobs_error': len(bad_jobs),
            'jobs': [{
                'name': j.get('name') or j.get('id'),
                'enabled': bool(j.get('enabled')),
                'state': j.get('state') or '—',
                'status': j.get('last_status') or '—',
                'next': fmt_dt(j.get('next_run_at')),
                'last': fmt_dt(j.get('last_run_at')),
                'error': (j.get('last_error') or '')[:220],
            } for j in jobs[:8]],
            'health_status': health_status,
            'health_text': health_text,
            'services_state': service_states,
            'recent': recent_files(path),
            'processes': process_hits(pr),
        })
    disk = shutil.disk_usage('/')
    return {
        'generated': datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
        'host': socket.gethostname(),
        'projects': projects,
        'ports': port_summary(),
        'disk': {'total': size_h(disk.total), 'used': size_h(disk.used), 'free': size_h(disk.free), 'pct': round(disk.used / disk.total * 100)},
    }


def esc(x: Any) -> str:
    return html.escape(str(x if x is not None else ''))


def badge(status: str) -> str:
    labels = {'ok': 'ОК', 'warn': 'Внимание', 'bad': 'Проблема', 'none': '—'}
    return f'<span class="badge {esc(status)}">{labels.get(status, esc(status))}</span>'


def render() -> str:
    s = build_state()
    ok = sum(1 for p in s['projects'] if p['status'] == 'ok')
    warn = sum(1 for p in s['projects'] if p['status'] == 'warn')
    bad = sum(1 for p in s['projects'] if p['status'] == 'bad')
    cards = []
    for p in s['projects']:
        jobs = ''.join(
            f"<tr><td>{esc(j['name'])}</td><td>{'да' if j['enabled'] else 'нет'}</td><td>{esc(j['status'])}</td><td>{esc(j['last'])}</td><td>{esc(j['next'])}</td></tr>"
            for j in p['jobs']
        ) or '<tr><td colspan="5">Нет cron-задач</td></tr>'
        recent = ''.join(f"<li><b>{esc(r['name'])}</b> <span>{esc(r['age'])}</span> <em>{esc(r['size'])}</em></li>" for r in p['recent']) or '<li>Нет данных</li>'
        services = ''.join(f"<span class='chip'>{esc(x['name'])}: <b>{esc(x['state'])}</b></span>" for x in p['services_state']) or '<span class="muted">нет systemd сервисов</span>'
        procs = ''.join(f"<code>{esc(x)}</code>" for x in p['processes']) or '<span class="muted">процессы не найдены</span>'
        url = f"<a href='{esc(p['public_url'])}' target='_blank'>Открыть сайт</a>" if p.get('public_url') else '<span class="muted">нет публичной ссылки</span>'
        local = f"<a href='{esc(p['local_url'])}' target='_blank'>{esc(p['local_url'])}</a>" if p.get('local_url') else '<span class="muted">—</span>'
        reasons = ', '.join(p['reasons']) if p['reasons'] else 'всё нормально'
        cards.append(f"""
        <section class="card {esc(p['status'])}">
          <div class="top">
            <div><h2>{esc(p['title'])}</h2><p>{esc(p['kind'])}</p></div>
            {badge(p['status'])}
          </div>
          <div class="grid mini">
            <div><span>Профиль</span><b>{esc(p['profile'])}</b></div>
            <div><span>Файлы</span><b>{esc(p['size'])}</b></div>
            <div><span>Видео</span><b>{esc(p['videos'])}</b></div>
            <div><span>Cron</span><b>{esc(p['jobs_enabled'])}/{esc(p['jobs_total'])}</b></div>
            <div><span>Ошибки cron</span><b>{esc(p['jobs_error'])}</b></div>
            <div><span>Изменения</span><b>{esc(p['modified'])}</b></div>
          </div>
          <div class="line"><b>Статус:</b> {esc(reasons)}</div>
          <div class="line"><b>Путь:</b> <code>{esc(p['path'])}</code></div>
          <div class="line"><b>Ссылки:</b> {url} <span class="sep">•</span> local: {local}</div>
          <div class="line"><b>Health:</b> {badge(p['health_status'])} <code>{esc(p['health_text'])}</code></div>
          <div class="line"><b>Services:</b> {services}</div>
          <details><summary>Последние файлы</summary><ul>{recent}</ul></details>
          <details><summary>Процессы</summary><div class="proc">{procs}</div></details>
          <details><summary>Cron задачи</summary><table><thead><tr><th>Задача</th><th>Вкл</th><th>Статус</th><th>Был</th><th>След.</th></tr></thead><tbody>{jobs}</tbody></table></details>
        </section>
        """)
    ports = ''.join(f"<tr><td>{esc(r['local'])}</td><td><code>{esc(r['process'])}</code></td></tr>" for r in s['ports'])
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Единый дашборд проектов</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;font-family:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#0b1020;color:#eef2ff}}a{{color:#8bd3ff;text-decoration:none}}a:hover{{text-decoration:underline}}.wrap{{max-width:1320px;margin:0 auto;padding:22px}}header{{display:flex;gap:16px;justify-content:space-between;align-items:flex-start;margin-bottom:18px}}h1{{margin:0;font-size:28px;letter-spacing:-.04em}}h2{{margin:0;font-size:19px}}p{{margin:4px 0 0;color:#98a2b3}}.summary{{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:10px;margin-bottom:14px}}.stat{{background:#111936;border:1px solid #26304f;border-radius:16px;padding:14px}}.stat span,.mini span{{display:block;color:#98a2b3;font-size:12px}}.stat b{{font-size:22px}}.cards{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}}.card{{background:#111936;border:1px solid #26304f;border-radius:18px;padding:16px;box-shadow:0 10px 35px #0005}}.card.ok{{border-color:#1d7d55}}.card.warn{{border-color:#a87516}}.card.bad{{border-color:#9d2f3b}}.top{{display:flex;justify-content:space-between;gap:10px;margin-bottom:12px}}.badge{{display:inline-flex;align-items:center;height:26px;padding:0 10px;border-radius:999px;font-weight:800;font-size:12px}}.badge.ok{{background:#0d442f;color:#70ffbd}}.badge.warn{{background:#4a3109;color:#ffd27a}}.badge.bad{{background:#51101a;color:#ff94a3}}.badge.none{{background:#25304b;color:#aeb8d0}}.mini{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:10px 0}}.mini>div{{background:#0c132a;border:1px solid #222c49;border-radius:12px;padding:10px}}.mini b{{font-size:15px}}.line{{font-size:13px;color:#d9e2ff;margin:8px 0;overflow-wrap:anywhere}}code{{background:#070b17;border:1px solid #1d2744;border-radius:7px;padding:2px 5px;color:#d9e6ff}}.chip{{display:inline-block;background:#0c132a;border:1px solid #222c49;border-radius:999px;padding:4px 8px;margin:2px}}.sep,.muted{{color:#7c879d}}details{{border-top:1px solid #26304f;margin-top:10px;padding-top:9px}}summary{{cursor:pointer;color:#c8d4ff;font-weight:700}}ul{{margin:8px 0 0;padding-left:18px}}li{{margin:5px 0}}li span,li em{{color:#98a2b3;margin-left:8px}}table{{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px}}th,td{{text-align:left;border-bottom:1px solid #26304f;padding:7px;vertical-align:top}}th{{color:#98a2b3;font-weight:600}}.proc{{display:grid;gap:6px;margin-top:8px}}.side{{background:#111936;border:1px solid #26304f;border-radius:18px;padding:16px;margin-top:14px}}.refresh{{background:#2563eb;color:white;border:0;border-radius:12px;padding:10px 14px;font-weight:800;cursor:pointer}}@media(max-width:900px){{.cards,.summary{{grid-template-columns:1fr}}header{{display:block}}}}
</style></head>
<body><div class="wrap">
<header><div><h1>Единый дашборд проектов</h1><p>Сервер: {esc(s['host'])} • обновлено: {esc(s['generated'])}</p></div><button class="refresh" onclick="location.reload()">Обновить</button></header>
<div class="summary">
  <div class="stat"><span>Проектов</span><b>{len(s['projects'])}</b></div>
  <div class="stat"><span>ОК</span><b>{ok}</b></div>
  <div class="stat"><span>Внимание</span><b>{warn}</b></div>
  <div class="stat"><span>Проблемы</span><b>{bad}</b></div>
  <div class="stat"><span>Диск /</span><b>{esc(s['disk']['pct'])}%</b><span>свободно {esc(s['disk']['free'])}</span></div>
</div>
<main class="cards">{''.join(cards)}</main>
<section class="side"><h2>Открытые порты</h2><table><thead><tr><th>Адрес</th><th>Процесс</th></tr></thead><tbody>{ports}</tbody></table></section>
</div><script>setTimeout(()=>location.reload(),60000)</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {self.address_string()} {fmt % args}")

    def is_authed(self) -> bool:
        cookie = self.headers.get('Cookie', '')
        for part in cookie.split(';'):
            if '=' not in part:
                continue
            name, value = part.strip().split('=', 1)
            if name == SESSION_COOKIE and valid_session_cookie(value):
                return True
        return False

    def redirect_login(self) -> None:
        self.send_response(302)
        self.send_header('Location', '/login')
        self.end_headers()

    def write_html(self, body_text: str, status: int = 200) -> None:
        body = body_text.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != '/login':
            self.send_response(404); self.end_headers(); return
        length = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(min(length, 4096)).decode('utf-8', 'ignore')
        password = parse_qs(raw).get('password', [''])[0]
        if verify_password(password):
            self.send_response(302)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie', f'{SESSION_COOKIE}={make_session_cookie()}; HttpOnly; SameSite=Lax; Path=/; Max-Age={7*86400}')
            self.end_headers(); return
        self.write_html(login_page('Неверный пароль'), status=401)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == '/login':
            self.write_html(login_page()); return
        if not self.is_authed():
            self.redirect_login(); return
        if path == '/api/state':
            body = json.dumps(build_state(), ensure_ascii=False, indent=2).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        if path in ('/', '/dashboard'):
            body = render().encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        self.send_response(404); self.end_headers(); self.wfile.write(b'not found')


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8123)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f'Дашборд запущен: http://{args.host}:{args.port}')
    srv.serve_forever()

if __name__ == '__main__':
    main()
