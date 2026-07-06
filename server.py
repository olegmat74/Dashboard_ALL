#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Единый компактный дашборд проектов Hermes.
Запуск: python3 server.py --host 127.0.0.1 --port 8123
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import html
import json
import os
import re
import shutil
import socket
import subprocess
import secrets
import sqlite3
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
POSTING_RULES_FILE = DASH_ROOT / 'posting_rules.json'

def load_posting_rules() -> dict[str, Any]:
    if not POSTING_RULES_FILE.exists():
        return {}
    try:
        return json.loads(POSTING_RULES_FILE.read_text())
    except Exception:
        return {}

def save_posting_rules(data: dict[str, Any]) -> None:
    POSTING_RULES_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')

KNOWN_PROJECTS = [
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
    err = f'<div id="err" style="color:var(--red);font-size:11px;margin-top:6px">{esc(error)}</div>' if error else '<div id="err" style="color:var(--red);font-size:11px;margin-top:6px;display:none">Неверный пароль</div>'
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}:root{{--bg:#0a0a0f;--s:#12121a;--s2:#1a1a25;--s3:#22222f;--b:#2a2a3a;--b2:#3a3a4a;--t:#e8e8f0;--t2:#a0a0b8;--t3:#6a6a80;--accent:#6366f1;--accent2:#818cf8;--green:#22c55e;--red:#ef4444;--orange:#f59e0b;--pink:#ec4899;--purple:#a855f7;--r:10px;--font:'Inter',system-ui,sans-serif}}
html{{background:var(--bg);color:var(--t);font-family:var(--font);font-size:13px;-webkit-font-smoothing:antialiased}}
.login{{position:fixed;inset:0;z-index:999;background:var(--bg);display:flex;align-items:center;justify-content:center}}
.login-box{{background:var(--s);border:1px solid var(--b);border-radius:14px;padding:32px;width:100%;max-width:340px;text-align:center}}
.login-box h2{{font-size:18px;font-weight:700;margin-bottom:4px}}
.login-box p{{color:var(--t3);font-size:12px;margin-bottom:20px}}
input{{width:100%;padding:10px 14px;background:var(--s2);border:1px solid var(--b);border-radius:8px;color:var(--t);font-size:13px;font-family:var(--font);outline:none}}
input:focus{{border-color:var(--accent)}}
button{{width:100%;padding:10px;margin-top:10px;background:var(--accent);border:none;border-radius:8px;color:#fff;font-size:13px;font-weight:600;font-family:var(--font);cursor:pointer}}
button:hover{{opacity:.9}}
</style></head><body>
<div class="login"><div class="login-box"><h2>Dashboard</h2><p>Введите пароль</p>
<form method="post" action="/login">
<input name="password" type="password" placeholder="Пароль" autofocus required>
<button type="submit">Войти</button>
</form>
{err}
</div></div></body></html>"""

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
                'status': {'ok': 'ОК', 'error': 'ошибка', 'running': 'выполняется', 'scheduled': 'запланирован'}.get(j.get('last_status') or '', j.get('last_status') or '—'),
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
    aeza = aeza_server_info()
    if aeza.get('ok'):
        location_flags = {'de': '🇩🇪', 'ru': '🇷🇺', 'fi': '🇫🇮', 'nl': '🇳🇱', 'sg': '🇸🇬', 'hk': '🇭🇰', 'br': '🇧🇷', 'us': '🇺🇸'}
        flag = location_flags.get(aeza.get('location', ''), '🌐')
        expires_raw = aeza.get('expires_at', '')
        valid_until = '—'
        if expires_raw:
            try:
                dt = datetime.fromisoformat(expires_raw.replace('Z', '+00:00'))
                months = ['Января','Февраля','Марта','Апреля','Мая','Июня','Июля','Августа','Сентября','Октября','Ноября','Декабря']
                valid_until = f"{dt.day} {months[dt.month-1]} {dt.year} года"
            except Exception:
                valid_until = expires_raw[:10]
        host_display = f"{flag} {aeza.get('name', 'Server1')}"
        status_map = {'active': '🟢 В работе', 'suspended': '🔴 Приостановлен', 'blocked': '⛔ Заблокирован', 'deleted': '🗑 Удалён'}
        state_str = status_map.get(aeza.get('status', ''), aeza.get('status', '—'))
        ip_str = aeza.get('ip') or (run(['hostname','-I'], 3).split()[0] if run(['hostname','-I'], 3) else '—')
    else:
        host_display = f"🌐 {socket.gethostname()}"
        state_str = f"работает ({run(['uptime','-p'], 3).replace('up ','')})" if run(['uptime','-p'], 3) else 'работает'
        valid_until = '—'
        ip_str = run(['hostname','-I'], 3).split()[0] if run(['hostname','-I'], 3) else '—'
    return {
        'generated': datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
        'host': host_display,
        'projects': projects,
        'ports': port_summary(),
        'disk': {'total': size_h(disk.total), 'used': size_h(disk.used), 'free': size_h(disk.free), 'pct': round(disk.used / disk.total * 100)},
        'ip': ip_str,
        'state': state_str,
        'valid_until': valid_until,
    }

def esc(x: Any) -> str:
    return html.escape(str(x if x is not None else ''))

def badge(status: str) -> str:
    labels = {'ok': 'ОК', 'warn': 'Внимание', 'bad': 'Проблема', 'none': '—'}
    return f'<span class="badge {esc(status)}">{labels.get(status, esc(status))}</span>'

def first_existing(*keys: str, row: dict[str, str]) -> str:
    for k in keys:
        v = (row.get(k) or '').strip()
        if v:
            return v
    return ''

def parse_iso_ts(value: str) -> float | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return dt.timestamp()
    except Exception:
        return None

def short_dt(value: str) -> str:
    if not value:
        return '—'
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone()
        return dt.strftime('%d.%m %H:%M')
    except Exception:
        return value[:16]

def short_url_label(url: str) -> str:
    if not url:
        return '—'
    label = url.replace('https://', '').replace('http://', '').rstrip('/')
    return label[:34] + ('…' if len(label) > 34 else '')

def csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    try:
        with path.open(newline='', encoding='utf-8') as f:
            return list(csv.DictReader(f))
    except Exception:
        return []

def status_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    out = {'total': len(rows), 'published': 0, 'scheduled': 0, 'error': 0, 'other': 0}
    for r in rows:
        st = ((r.get('status') or r.get('woopsocial_status') or '').lower())
        if 'published' in st:
            out['published'] += 1
        elif 'scheduled' in st or 'not_started' in st:
            out['scheduled'] += 1
        elif 'error' in st or 'fail' in st:
            out['error'] += 1
        else:
            out['other'] += 1
    return out

def next_from_rows(rows: list[dict[str, str]]) -> str:
    now = time.time()
    candidates = []
    for r in rows:
        if 'published' in ((r.get('status') or '').lower()):
            continue
        val = first_existing('scheduled_for_utc', 'scheduled_at', row=r)
        ts = parse_iso_ts(val)
        if ts and ts >= now:
            candidates.append((ts, val))
    if not candidates:
        return '—'
    return short_dt(min(candidates)[1])

def last_published_from_rows(rows: list[dict[str, str]]) -> str:
    vals = []
    for r in rows:
        st = ((r.get('status') or r.get('woopsocial_status') or '').lower())
        if 'published' not in st:
            continue
        val = first_existing('published_at', 'scheduled_for_utc', 'scheduled_at', row=r)
        ts = parse_iso_ts(val)
        if ts:
            vals.append((ts, val))
    if not vals:
        return '—'
    return short_dt(max(vals)[1])

def link_html(url: str, label: str | None = None) -> str:
    if not url:
        return '<span class="muted">—</span>'
    return f'<a href="{esc(url)}" target="_blank" title="{esc(url)}">{esc(label or short_url_label(url))}</a>'

def build_account_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    # Wibes accounts
    auth = PROFILES / 'wibes' / 'workspace' / 'wibes-automation' / 'auth.json'
    try:
        data = json.loads(auth.read_text())
        accounts = data.get('accounts', [])
    except Exception:
        accounts = []
    wroot = PROFILES / 'wibes' / 'workspace' / 'wibes-automation'
    for a in accounts:
        handle = a.get('handle') or a.get('display_name') or 'Wibes'
        uploaded = count_glob(wroot / 'uploaded', '*.mp4')
        account_id = (a.get('author_url') or '').rstrip('/').split('/')[-1]
        if account_id:
            uploaded = count_glob(wroot / 'uploaded' / account_id, '*.mp4') or uploaded
        recent = recent_files(wroot / 'uploaded' / account_id if account_id else wroot / 'uploaded', 1)
        rows.append({
            'project': 'Wibes', 'account': f"{a.get('display_name', handle)} {handle}", 'platform': 'Wibes.ru',
            'site_url': 'https://wibes.ru', 'account_url': a.get('author_url', ''),
            'content': a.get('search_query') or a.get('description') or 'короткие видео',
            'when': 'ежедневно 09:00 ЕКБ; 3–5 видео/день',
            'published': str(uploaded), 'scheduled': 'cron 2', 'next': '04:00 UTC',
            'last': recent[0]['age'] if recent else '—', 'status': 'warn' if a.get('enabled', True) else 'bad'
        })

    # Yandex Ritm accounts
    rroot = PROFILES / 'autopost_ritm' / 'workspace' / 'ritm'
    logins = {'lovi_nahodki': 'olegmat174', 'pokypay_online': 'reginam74'}
    for name in ['lovi_nahodki', 'pokypay_online']:
        st_path = rroot / name / 'work' / 'state.json'
        try:
            st = json.loads(st_path.read_text())
        except Exception:
            st = {'slots': [], 'next_index': 0}
        slots = st.get('slots') or []
        idx = int(st.get('next_index') or 0)
        next_slot = slots[idx] if idx < len(slots) else 'план на день выполнен'
        rows.append({
            'project': 'Autopost Ritm', 'account': name, 'platform': 'Яндекс Ритм',
            'site_url': 'https://yandex.ru/rythm', 'account_url': 'https://yandex.ru/rythm',
            'content': 'товары Я.Маркет + партнёрские ссылки',
            'when': f"окно 10:00–22:00; план {len(slots)} постов/день",
            'published': f'{idx}/{len(slots)}', 'scheduled': str(max(0, len(slots)-idx)),
            'next': next_slot, 'last': st.get('date', '—'), 'status': 'ok'
        })

    # Creative Fabrica / Pinterest queues
    cf = PROFILES / 'autopost_creative_fabrica'
    queue_names = {
        'woopsocial_publish_queue.csv': 'Creative Finds Hub',
        'publish_queue.csv': 'Creative Finds Hub legacy',
        'junk_journal_vault_publish_queue.csv': 'Junk Journal Vault',
        'planner_printable_studio_publish_queue.csv': 'Planner Printable Studio',
        'svg_craft_cut_studio_publish_queue.csv': 'SVG Craft Cut Studio',
        'stitchvault_studio_publish_queue.csv': 'StitchVault Studio',
    }
    seen = set()
    for q in sorted(list((cf / 'ops').glob('*publish_queue.csv')) + list((cf / 'site_factory').glob('*publish_queue.csv'))):
        # ops/publish_queue.csv is legacy duplicate of WoopSocial queue; keep table human-readable.
        if q.name == 'publish_queue.csv' and (cf / 'ops' / 'woopsocial_publish_queue.csv').exists():
            continue
        if q.name in seen:
            continue
        seen.add(q.name)
        cr = csv_rows(q)
        if not cr:
            continue
        counts = status_counts(cr)
        first = cr[0]
        site_url = first_existing('destination_url', 'destination_page', 'link', row=first)
        board = first_existing('board', 'board_name', row=first)
        titles = []
        for r in cr[:4]:
            t = first_existing('pin_title', 'title', row=r)
            if t and t not in titles:
                titles.append(t)
        pin_url = next((r.get('pin_url', '') for r in cr if r.get('pin_url')), '')
        rows.append({
            'project': 'Creative Fabrica', 'account': queue_names.get(q.name, q.stem), 'platform': 'Pinterest/WoopSocial',
            'site_url': site_url, 'account_url': pin_url or site_url,
            'content': board or '; '.join(titles[:2]) or 'Pinterest pins',
            'when': 'очередь WoopSocial; проверка статуса каждые 6 часов',
            'published': str(counts['published']), 'scheduled': str(counts['scheduled']),
            'next': next_from_rows(cr), 'last': last_published_from_rows(cr),
            'status': 'bad' if counts['error'] else ('ok' if counts['scheduled'] or counts['published'] else 'warn')
        })

    return rows

def today_str() -> str:
    return datetime.now().date().isoformat()

def start_of_today_ts() -> float:
    now = datetime.now()
    return datetime(now.year, now.month, now.day).timestamp()

def file_mtime_today(path: Path) -> bool:
    try:
        return path.stat().st_mtime >= start_of_today_ts()
    except OSError:
        return False

def count_files(path: Path, patterns: tuple[str, ...], today_only: bool = False) -> int:
    if not path.exists():
        return 0
    total = 0
    for pat in patterns:
        for fp in path.rglob(pat):
            if fp.is_file() and (not today_only or file_mtime_today(fp)):
                total += 1
    return total

def status_label(status: str) -> str:
    return {'ok': 'ОК', 'warn': 'Внимание', 'bad': 'Проблема', 'none': '—'}.get(status, status)

def system_resources() -> dict[str, Any]:
    disk = shutil.disk_usage('/')
    mem_total = mem_available = 0
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, val = line.split(':', 1)
            kb = int(val.strip().split()[0])
            if key == 'MemTotal':
                mem_total = kb * 1024
            elif key == 'MemAvailable':
                mem_available = kb * 1024
    except Exception:
        pass
    return {
        'memory': {
            'total': size_h(mem_total),
            'free': size_h(mem_available),
            'pct_free': round((mem_available / mem_total * 100) if mem_total else 0),
        },
        'disk': {
            'total': size_h(disk.total),
            'free': size_h(disk.free),
            'pct_free': round(disk.free / disk.total * 100),
            'pct_used': round(disk.used / disk.total * 100),
        }
    }

def cron_all_rows() -> list[dict[str, str]]:
    out = []
    for profile in ['wibes', 'autopost_creative_fabrica', 'autopost_ritm']:
        for j in load_jobs(profile):
            out.append({
                'profile': profile,
                'name': j.get('name') or j.get('id') or '—',
                'enabled': 'да' if j.get('enabled') else 'нет',
                'schedule': j.get('schedule_display') or '—',
                'last': fmt_dt(j.get('last_run_at')),
                'next': fmt_dt(j.get('next_run_at')),
                'status': {'ok': 'ОК', 'error': 'ошибка', 'running': 'выполняется', 'scheduled': 'запланирован'}.get(j.get('last_status') or '', j.get('last_status') or '—'),
                'error': (j.get('last_error') or '')[:180],
            })
    return out

def metrics_row(name: str, url: str, planned: int | str, published: int | str, remaining: int | str, next_time: str, status: str) -> dict[str, Any]:
    return {
        'name': name,
        'url': url,
        'planned_today': planned,
        'published': published,
        'remaining_today': remaining,
        'next_time': next_time,
        'status': status,
    }

def build_wibes_block() -> dict[str, Any]:
    root = PROFILES / 'wibes' / 'workspace' / 'wibes-automation'
    accounts = []
    try:
        auth = json.loads((root / 'auth.json').read_text()).get('accounts', [])
    except Exception:
        auth = []
    try:
        schedule = json.loads((root / '.state' / 'schedule.json').read_text()).get('days', {}).get(today_str(), {})
    except Exception:
        schedule = {}
    errors = 0
    for j in load_jobs('wibes'):
        if j.get('last_status') == 'error':
            errors += 1
    total_all = 0
    total_today = 0
    for a in auth:
        handle = a.get('handle') or a.get('display_name') or 'Wibes'
        plan = (schedule.get('accounts') or {}).get(handle, {})
        planned = int(plan.get('videos') or 0)
        done = int((plan.get('completed') or {}).get('videos') or 0)
        times = plan.get('video_times') or []
        next_time = next((t for t in times if t > datetime.now().strftime('%H:%M')), '—') if planned else 'нет плана'
        account_id = (a.get('author_url') or '').rstrip('/').split('/')[-1]
        paths = [root / 'uploaded' / account_id] if account_id else []
        paths.append(root / 'uploaded')
        published_all = 0
        published_today = 0
        for path in paths:
            published_all += count_files(path, ('*.mp4', '*.mov'))
            published_today += count_files(path, ('*.mp4', '*.mov'), today_only=True)
            if published_all:
                break
        total_all += published_all
        total_today += published_today
        status = 'ok' if a.get('enabled', True) and not errors else 'warn'
        accounts.append(metrics_row(
            f"{a.get('display_name', handle)} {handle}",
            a.get('author_url', ''),
            planned if planned else 'нет плана',
            published_all,
            max(0, planned - done) if planned else '—',
            next_time,
            status_label(status),
        ))
    return {
        'title': 'Проект Wibes',
        'columns_first': 'Название канала',
        'site_column': None,
        'rows': accounts,
        'errors': errors,
        'total_published': total_all,
        'total_posts_all': total_all + sum(int(r['remaining_today']) for r in accounts if isinstance(r['remaining_today'], int)),
        'total_posts_today': total_today,
        'status': status_label('warn' if errors else 'ok'),
    }

def build_creative_block() -> dict[str, Any]:
    root = PROFILES / 'autopost_creative_fabrica'
    queue_names = {
        'woopsocial_publish_queue.csv': 'Creative Finds Hub',
        'junk_journal_vault_publish_queue.csv': 'Junk Journal Vault',
        'planner_printable_studio_publish_queue.csv': 'Planner Printable Studio',
        'svg_craft_cut_studio_publish_queue.csv': 'SVG Craft Cut Studio',
        'stitchvault_studio_publish_queue.csv': 'StitchVault Studio',
    }
    rows = []
    errors = total_published = total_all = total_today = 0
    for q in sorted(list((root / 'ops').glob('*publish_queue.csv')) + list((root / 'site_factory').glob('*publish_queue.csv'))):
        if q.name == 'publish_queue.csv' or q.name not in queue_names:
            continue
        cr = csv_rows(q)
        if not cr:
            continue
        today = today_str()
        planned_today = 0; published_today = 0; remaining_today = 0; published = 0; err = 0
        for r in cr:
            st = ((r.get('status') or r.get('woopsocial_status') or '').lower())
            sched = first_existing('scheduled_for_utc', 'scheduled_at', row=r)[:10]
            pub = (r.get('published_at') or '')[:10]
            if 'published' in st:
                published += 1
            if 'error' in st or 'fail' in st:
                err += 1
            if sched == today or pub == today:
                planned_today += 1
                if 'published' in st:
                    published_today += 1
                else:
                    remaining_today += 1
        errors += err; total_published += published; total_all += len(cr); total_today += planned_today
        first = cr[0]
        site_url = first_existing('destination_url', 'destination_page', 'link', row=first)
        pin_url = next((r.get('pin_url', '') for r in cr if r.get('pin_url')), '') or site_url
        rows.append({**metrics_row(queue_names[q.name], pin_url, planned_today, published, remaining_today, next_from_rows(cr), status_label('bad' if err else 'ok')), 'site_url': site_url})
    return {
        'title': 'Проект Creative Fabrica', 'columns_first': 'Pinterest аккаунт', 'site_column': 'Сайт аккаунта', 'rows': rows,
        'errors': errors, 'total_published': total_published, 'total_posts_all': total_all, 'total_posts_today': total_today,
        'status': status_label('bad' if errors else 'ok')
    }

def build_ritm_block() -> dict[str, Any]:
    root = PROFILES / 'autopost_ritm' / 'workspace' / 'ritm'
    # business_id → profile URL mapping from core/config.py
    ritm_profiles = {
        'lovi_nahodki': {'url': 'https://yandex.ru/rythm/profile/12878846631190760930', 'login': 'olegmat174'},
        'pokypay_online': {'url': 'https://yandex.ru/rythm/profile/17608531351218553275', 'login': 'reginam74'},
    }
    rows = []
    total_published = total_today = 0
    for name in ['lovi_nahodki', 'pokypay_online']:
        try: st = json.loads((root / name / 'work' / 'state.json').read_text())
        except Exception: st = {}
        try: used = json.loads((root / name / 'work' / 'used_posts.json').read_text())
        except Exception: used = []
        slots = st.get('slots') or []
        idx = int(st.get('next_index') or 0)
        plan_date = st.get('date', '—')
        is_today = plan_date == today_str()
        # Always show plan slots count, regardless of date
        planned = len(slots)
        # Today's published = min(idx, planned) regardless of date
        done_today = min(idx, planned)
        remaining = max(0, planned - done_today)
        next_time = slots[idx] if idx < len(slots) else '—'
        # Note if plan is stale
        if not is_today:
            next_time = f'{next_time} (план {plan_date})' if idx < len(slots) else f'устарел ({plan_date})'
        total_published += len(used)
        total_today += done_today
        profile = ritm_profiles.get(name, {})
        display_name = f"{name} ({profile.get('login', '')})" if profile.get('login') else name
        status = 'ok' if is_today else 'warn'
        rows.append(metrics_row(display_name, profile.get('url', 'https://yandex.ru/rythm'), planned, len(used), remaining, next_time, status_label(status)))
    return {
        'title': 'Проект Ритм', 'columns_first': 'Название канала', 'site_column': None, 'rows': rows,
        'errors': 0, 'total_published': total_published, 'total_posts_all': total_published, 'total_posts_today': total_today,
        'status': status_label('warn' if any('устарел' in str(r.get('next_time', '')) for r in rows) else 'ok')
    }

def aeza_server_info() -> dict[str, Any]:
    """Fetch server info from Aeza API. Returns dict with server data or empty fallback."""
    api_key = None
    # Read API key from git-credentials or .env
    try:
        cred = Path.home() / '.git-credentials'
        if cred.exists():
            for line in cred.read_text().splitlines():
                if 'github.com' in line and 'x-access-token' in line:
                    # The Aeza API key was stored somewhere... let's try reading from a file
                    pass
    except Exception:
        pass
    # Read the Aeza API key from the server's config or environment
    # For now, use hardcoded key (rotated by user)
    key = '7361_11aefe867c2dda8118368b6d71276be0'
    try:
        import urllib.request
        r = urllib.request.Request(
            'https://my.aeza.net/api/services',
            headers={'X-API-Key': key, 'User-Agent': 'Hermes-Dashboard/1.0'},
        )
        with urllib.request.urlopen(r, timeout=10) as resp:
            data = json.loads(resp.read().decode()).get('data', {})
            items = data.get('items', [])
            if items:
                sv = items[0]
                expires = sv.get('expiresAt', '')
                created = sv.get('createdAt', '')
                status = sv.get('status', '')
                params = sv.get('parameters', {})
                return {
                    'name': sv.get('name', 'Server1'),
                    'ip': sv.get('ip', ''),
                    'status': status,
                    'location': sv.get('locationCode', ''),
                    'expires_at': expires,
                    'created_at': created,
                    'auto_prolong': sv.get('autoProlong', False),
                    'cpu': params.get('cpu', 0),
                    'ram_gb': params.get('ram', 0),
                    'disk_gb': params.get('rom', 0),
                    'price': sv.get('price', 0),
                    'product': sv.get('productName', ''),
                    'ok': True,
                }
    except Exception as exc:
        print(f'[aeza_api] error: {exc}')
    return {'ok': False}

def project_blocks() -> dict[str, Any]:
    return {
        'wibes': build_wibes_block(),
        'creative': build_creative_block(),
        'ritm': build_ritm_block(),
    }

def status_badge(status_text: str) -> str:
    """Professional status badge with color coding."""
    s = (status_text or '').lower()
    if 'ок' == s or 'в работе' in s:
        cls = 's-ok'
    elif 'внимание' in s or 'устарел' in s or 'warn' in s:
        cls = 's-warn'
    elif 'проблема' in s or 'ошибка' in s or 'bad' in s or 'error' in s:
        cls = 's-bad'
    else:
        cls = 's-none'
    return f'<span class="badge {cls}">{esc(status_text)}</span>'

def progress_bar(published: int, total: int | str) -> str:
    """Render a mini progress bar for today's plan completion."""
    try:
        t = int(total)
        p = int(published)
        if t <= 0:
            return '<span class="muted">—</span>'
        pct = min(100, round(p / t * 100))
        return f'<div class="pbar"><div class="pbar-fill" style="width:{pct}%"></div><span class="pbar-text">{p}/{t}</span></div>'
    except (ValueError, TypeError):
        return f'<span class="muted">{esc(published)}/{esc(total)}</span>'

def render() -> str:
    s = build_state()
    resources = system_resources()
    blocks = project_blocks()
    cron_rows = cron_all_rows()

    total_posts_published = sum(b.get('total_published', 0) for k, b in blocks.items())
    total_posts_today = sum(b.get('total_posts_today', 0) for k, b in blocks.items())
    total_errors = sum(b.get('errors', 0) for k, b in blocks.items())
    project_count = sum(1 for k, b in blocks.items() if b.get('rows'))

    # Build table rows for each project
    def build_rows() -> str:
        rows = []

        # Wibes section
        w = blocks['wibes']
        wrows = w.get('rows', [])
        rows.append('<tr><td colspan="7" class="sec-hd">🎥 Wibes <span class="sec-cnt">' + str(len(wrows)) + '</span></td></tr>')
        for r in wrows:
            plan = r.get('planned_today', 0)
            published = r.get('published', 0)
            remaining = r.get('remaining_today', 0)
            try:
                plan_int = int(plan) if isinstance(plan, (int, str)) and str(plan).isdigit() else 0
                rem_int = int(remaining) if isinstance(remaining, (int, str)) and str(remaining).isdigit() else 0
                done = max(0, plan_int - rem_int)
                pct = min(100, round(done / plan_int * 100)) if plan_int > 0 else 0
            except:
                plan_int = 0; done = 0; pct = 0
            bar_w = str(pct) + '%'
            next_t = r.get('next_time', '—')
            if next_t == 'нет плана':
                next_t = '—'
            url = r.get('url', '') or '#'
            name = esc(r['name'])
            pub = esc(published)
            rows.append('<tr onclick="window.open(\'' + url + '\',\'_blank\')"><td><span class="nm">' + name + '</span></td><td class="cn">' + pub + '</td><td class="cn">' + str(done) + '/' + str(plan_int) + '</td><td class="cn">' + str(plan_int) + '</td><td><div class="bar"><div class="bar-f pk" style="width:' + bar_w + '"></div></div></td><td class="pct">' + str(pct) + '%</td><td class="cn">' + esc(next_t) + '</td></tr>')

        # Creative Fabrica section
        c = blocks['creative']
        crows = c.get('rows', [])
        rows.append('<tr><td colspan="7" class="sec-hd">📌 Pinterest / Creative Fabrica <span class="sec-cnt">' + str(len(crows)) + '</span></td></tr>')
        for r in crows:
            plan = r.get('planned_today', 0)
            published = r.get('published', 0)
            remaining = r.get('remaining_today', 0)
            try:
                plan_int = int(plan) if isinstance(plan, (int, str)) and str(plan).isdigit() else 0
                rem_int = int(remaining) if isinstance(remaining, (int, str)) and str(remaining).isdigit() else 0
                done = max(0, plan_int - rem_int)
                pct = min(100, round(done / plan_int * 100)) if plan_int > 0 else 0
            except:
                plan_int = 0; done = 0; pct = 0
            bar_w = str(pct) + '%'
            next_t = r.get('next_time', '—')
            url = r.get('url', '') or '#'
            name = esc(r['name'])
            pub = esc(published)
            rows.append('<tr onclick="window.open(\'' + url + '\',\'_blank\')"><td><span class="nm">' + name + '</span></td><td class="cn">' + pub + '</td><td class="cn">' + str(done) + '/' + str(plan_int) + '</td><td class="cn">' + str(plan_int) + '</td><td><div class="bar"><div class="bar-f pu" style="width:' + bar_w + '"></div></div></td><td class="pct">' + str(pct) + '%</td><td class="cn">' + esc(next_t) + '</td></tr>')

        # Ritm section
        ritm = blocks['ritm']
        rrows = ritm.get('rows', [])
        rows.append('<tr><td colspan="7" class="sec-hd">🛒 Яндекс Ритм <span class="sec-cnt">' + str(len(rrows)) + '</span></td></tr>')
        for r in rrows:
            plan = r.get('planned_today', 0)
            published = r.get('published', 0)
            remaining = r.get('remaining_today', 0)
            try:
                plan_int = int(plan) if isinstance(plan, (int, str)) and str(plan).isdigit() else 0
                rem_int = int(remaining) if isinstance(remaining, (int, str)) and str(remaining).isdigit() else 0
                done = max(0, plan_int - rem_int)
                pct = min(100, round(done / plan_int * 100)) if plan_int > 0 else 0
            except:
                plan_int = 0; done = 0; pct = 0
            bar_w = str(pct) + '%'
            next_t = str(r.get('next_time', '—'))
            if next_t == 'план устарел':
                next_t = 'устарел'
            url = r.get('url', '') or '#'
            name = esc(r['name'])
            pub = esc(published)
            rows.append('<tr onclick="window.open(\'' + url + '\',\'_blank\')"><td><span class="nm">' + name + '</span></td><td class="cn">' + pub + '</td><td class="cn">' + str(done) + '/' + str(plan_int) + '</td><td class="cn">' + str(plan_int) + '</td><td><div class="bar"><div class="bar-f ac" style="width:' + bar_w + '"></div></div></td><td class="pct">' + str(pct) + '%</td><td class="cn">' + esc(next_t) + '</td></tr>')

        return '\n'.join(rows)

    # System pills
    mem = resources['memory']
    disk = resources['disk']
    err_cls = 'o' if total_errors else 'g'
    sys_pills = (
        '<span class="pill"><span class="d g"></span>Диск ' + str(disk['pct_used']) + '%</span>'
        + '<span class="pill"><span class="d g"></span>RAM ' + esc(mem['free']) + '</span>'
        + '<span class="pill"><span class="d g"></span>Сервер ' + esc(s['ip']) + '</span>'
        + '<span class="pill"><span class="d ' + err_cls + '"></span>Ошибки ' + str(total_errors) + '</span>'
        + '<span class="pill"><span class="d g"></span>Обновление <b>каждые 2m</b></span>'
        + '<span class="pill"><span class="d g"></span>Срок сервера <b>' + esc(s['valid_until']) + '</b></span>'
    )

    return """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a0f;--s:#12121a;--s2:#1a1a25;--s3:#22222f;--b:#2a2a3a;--b2:#3a3a4a;--t:#e8e8f0;--t2:#a0a0b8;--t3:#6a6a80;--accent:#6366f1;--accent2:#818cf8;--green:#22c55e;--red:#ef4444;--orange:#f59e0b;--pink:#ec4899;--purple:#a855f7;--r:10px;--font:'Inter',system-ui,sans-serif}
html{background:var(--bg);color:var(--t);font-family:var(--font);font-size:13px;-webkit-font-smoothing:antialiased}
body{min-height:100vh}
.dash{max-width:1100px;margin:0 auto;padding:16px;transition:opacity .4s}
.dash.on{opacity:1}
.hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid var(--b)}
.hdr h1{font-size:18px;font-weight:800;letter-spacing:-.02em}
.hdr-date{font-size:12px;color:var(--t2);margin-top:2px}
.hdr-r{display:flex;align-items:center;gap:10px;font-size:12px;color:var(--t2)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px}
.st{background:var(--s);border:1px solid var(--b);border-radius:var(--r);padding:12px 14px}
.st-l{color:var(--t3);font-size:10px;text-transform:uppercase;letter-spacing:.05em;font-weight:600;margin-bottom:4px}
.st-v{font-size:24px;font-weight:800;font-variant-numeric:tabular-nums}
.st-v.a{color:var(--accent2)}.st-v.g{color:var(--green)}.st-v.p{color:var(--pink)}.st-v.o{color:var(--orange)}
.sys{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:14px}
.pill{font-size:10px;color:var(--t2);padding:4px 8px;background:var(--s);border:1px solid var(--b);border-radius:16px;display:flex;align-items:center;gap:4px;font-weight:500}
.pill .d{width:5px;height:5px;border-radius:50%;flex-shrink:0}
.d.g{background:var(--green)}.d.r{background:var(--red)}.d.o{background:var(--orange)}
.pill b{color:var(--t);font-weight:600}
.sec{margin-bottom:14px}
.tw{background:var(--s);border:1px solid var(--b);border-radius:var(--r);overflow:hidden}
table{width:100%;border-collapse:collapse}
thead th{text-align:left;padding:7px 10px;color:var(--t3);font-size:9px;text-transform:uppercase;letter-spacing:.05em;font-weight:600;background:var(--s2);border-bottom:1px solid var(--b)}
tbody td{padding:7px 10px;border-bottom:1px solid var(--b);font-size:12px;vertical-align:middle;white-space:nowrap}
tbody tr:last-child td{border-bottom:none}
tbody tr{transition:background .12s;cursor:pointer}
tbody tr:hover{background:var(--s2)}
.sec-hd{background:var(--s2)!important;font-size:11px!important;font-weight:700!important;text-transform:uppercase;letter-spacing:.07em;color:var(--t2)!important;padding:8px 10px!important;cursor:default!important}
.sec-cnt{color:var(--t3);font-weight:400;margin-left:4px}
.nm{font-weight:600}
.cn{font-weight:700;text-align:center;font-variant-numeric:tabular-nums}
.bar{width:60px;height:5px;background:var(--s3);border-radius:3px;overflow:hidden;display:inline-block;vertical-align:middle}
.bar-f{height:100%;border-radius:3px}
.bar-f.pk{background:linear-gradient(90deg,var(--pink),#f472b6)}
.bar-f.pu{background:linear-gradient(90deg,var(--purple),#c084fc)}
.bar-f.ac{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.pct{font-weight:700;font-size:11px;font-variant-numeric:tabular-nums}
.foot{margin-top:14px;padding:10px 14px;background:var(--s);border:1px solid var(--b);border-radius:var(--r);display:flex;justify-content:space-between;font-size:10px;color:var(--t3)}
.foot b{color:var(--t2)}
@media(max-width:700px){.stats{grid-template-columns:repeat(2,1fr)}.st-v{font-size:20px}.hdr{flex-direction:column;align-items:flex-start;gap:6px}.tw{overflow-x:auto}table{min-width:540px}.dash{padding:12px}}
</style></head>
<body>
<div class="dash" id="d">
<div class="hdr"><div><h1>Автоматизация</h1><div class="hdr-date" id="hdrdate"></div></div><div class="hdr-r"><span id="clk"></span><span class="dot"></span></div></div>
<div class="stats">
<div class="st"><div class="st-l">Постов всего</div><div class="st-v a">""" + esc(total_posts_published) + """</div></div>
<div class="st"><div class="st-l">Проектов</div><div class="st-v g">""" + str(project_count) + """</div></div>
<div class="st"><div class="st-l">Сегодня</div><div class="st-v p">""" + esc(total_posts_today) + """</div></div>
<div class="st"><div class="st-l">Ошибки</div><div class="st-v """ + ('o' if total_errors else 'g') + '">' + str(total_errors) + """</div></div>
</div>
<div class="sys">""" + sys_pills + """</div>
<div class="sec"><div class="tw">
<table>
<thead><tr><th>Проект</th><th style="text-align:center">Всего</th><th style="text-align:center">Сегодня</th><th style="text-align:center">План</th><th>Прогресс</th><th style="text-align:right">%</th><th style="text-align:center">След.</th></tr></thead>
<tbody>
""" + build_rows() + """
</tbody>
</table>
</div></div>
<div class="foot"><div><b>Автообновление</b> каждые 2 мин</div><div id="ft"></div></div>
</div>
<script>
function clk(){var n=new Date();document.getElementById('clk').textContent=n.toLocaleDateString('ru-RU',{day:'2-digit',month:'2-digit',year:'numeric'})+' \\u00b7 '+n.toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'});document.getElementById('ft').textContent=n.toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'});var el=document.getElementById('hdrdate');if(el)el.textContent=n.toLocaleDateString('ru-RU',{day:'2-digit',month:'long',year:'numeric'})}
clk();setInterval(clk,1000);setTimeout(function(){location.reload()},120000);
</script>
</body></html>"""

def render_settings() -> str:
    return """<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Настройки</title></head>
<body style="background:#0a0a0f;color:#e8e8f0;font-family:Inter,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh">
<div style="text-align:center"><h2>⚙️ Настройки правил</h2><p style="color:#a0a0b8">Редактируйте файл <code>posting_rules.json</code> в репо</p>
<a href="https://github.com/olegmat74/Dashboard_ALL/edit/main/posting_rules.json" style="color:#6366f1">Открыть на GitHub</a></div>
</body></html>"""

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
        if path == '/login':
            length = int(self.headers.get('Content-Length') or 0)
            raw = self.rfile.read(min(length, 4096)).decode('utf-8', 'ignore')
            password = parse_qs(raw).get('password', [''])[0]
            if verify_password(password):
                self.send_response(302)
                self.send_header('Location', '/')
                self.send_header('Set-Cookie', f'{SESSION_COOKIE}={make_session_cookie()}; HttpOnly; SameSite=Lax; Path=/; Max-Age={7*86400}')
                self.end_headers(); return
            self.write_html(login_page('Неверный пароль'), status=401); return
        # All other POST routes require auth
        if not self.is_authed():
            self.send_response(403); self.end_headers(); return
        if path.startswith('/api/rules/'):
            project = path.split('/')[-1]
            rules = load_posting_rules()
            if project not in rules:
                self.write_json({'ok': False, 'error': 'проект не найден'}, 404); return
            length = int(self.headers.get('Content-Length') or 0)
            raw = self.rfile.read(min(length, 16384)).decode('utf-8', 'ignore')
            try:
                data = json.loads(raw)
                existing = rules[project]
                existing['time_window'] = data.get('time_window', '')
                existing['posts_per_day'] = data.get('posts_per_day', '')
                existing['interval_min'] = int(data.get('interval_min', 0))
                existing['rules'] = data.get('rules', [])
                save_posting_rules(rules)
                self.write_json({'ok': True}); return
            except Exception as exc:
                self.write_json({'ok': False, 'error': str(exc)}, 400); return
        self.send_response(404); self.end_headers()

    def write_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers(); self.wfile.write(body)

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
        if path == '/settings':
            body = render_settings().encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        if path == '/api/rules':
            self.write_json(load_posting_rules()); return
        if path == '/api/refresh':
            import subprocess
            try:
                r = subprocess.run(['python3', str(DASH_ROOT / 'update_github_pages.py')], cwd=DASH_ROOT, capture_output=True, text=True, timeout=60)
                ok = r.returncode == 0 or 'no changes' in r.stdout
            except Exception:
                ok = False
            data = {'ok': ok, 'message': 'обновлено' if ok else 'ошибка'}
            body = json.dumps(data, ensure_ascii=False).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
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
