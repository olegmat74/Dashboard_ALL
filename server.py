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
        'ip': run(['hostname','-I'], 3).split()[0] if run(['hostname','-I'], 3) else '—',
        'state': f"работает (аптайм {run(['uptime','-p'], 3).replace('up ','')})" if run(['uptime','-p'], 3) else 'работает',
        'valid_until': (lambda p: run(['openssl','x509','-enddate','-noout','-in',str(p),'|','cut','-d=','-f2'], 6)[:16] if os.path.exists(str(p)) else '—')(Path('/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/unicaizer.ru/unicaizer.ru.crt')),

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
    return f'<a href="{esc(url)}" target="_blank">{esc(label or short_url_label(url))}</a>'


def build_account_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    # UNICAIZER — сайт, не автопостинг
    rows.append({
        'project': 'UNICAIZER', 'account': 'Сайт / продукт', 'platform': 'Web',
        'site_url': 'https://unicaizer.ru', 'account_url': 'https://unicaizer.ru',
        'content': 'AI обработка видео, субтитры, дубляж, блог', 'when': 'сайт 24/7; SEO cron ежедневно 09:00',
        'published': '—', 'scheduled': '1 SEO задача', 'next': 'ежедневно 09:00', 'last': '—', 'status': 'ok'
    })

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
    for profile in ['wibes', 'autopost_creative_fabrica', 'autopost_ritm', 'unicaizer']:
        for j in load_jobs(profile):
            out.append({
                'profile': profile,
                'name': j.get('name') or j.get('id') or '—',
                'enabled': 'да' if j.get('enabled') else 'нет',
                'schedule': j.get('schedule_display') or '—',
                'last': fmt_dt(j.get('last_run_at')),
                'next': fmt_dt(j.get('next_run_at')),
                'status': j.get('last_status') or '—',
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
    rows = []
    total_published = total_all = total_today = 0
    for name in ['lovi_nahodki', 'pokypay_online']:
        try: st = json.loads((root / name / 'work' / 'state.json').read_text())
        except Exception: st = {}
        try: used = json.loads((root / name / 'work' / 'used_posts.json').read_text())
        except Exception: used = []
        slots = st.get('slots') or []
        idx = int(st.get('next_index') or 0)
        is_today = st.get('date') == today_str()
        planned = len(slots) if is_today else 0
        published_today = min(idx, planned) if is_today else 0
        remaining = max(0, planned - published_today) if is_today else 'план устарел'
        next_time = slots[idx] if is_today and idx < len(slots) else ('план устарел' if not is_today else '—')
        total_published += len(used); total_all += len(used) + (remaining if isinstance(remaining, int) else 0); total_today += planned
        rows.append(metrics_row(name, 'https://yandex.ru/rythm', planned if is_today else f"0 ({st.get('date','—')})", len(used), remaining, next_time, status_label('ok' if is_today else 'warn')))
    return {
        'title': 'Проект Ритм', 'columns_first': 'Название канала', 'site_column': None, 'rows': rows,
        'errors': 0, 'total_published': total_published, 'total_posts_all': total_all, 'total_posts_today': total_today,
        'status': status_label('warn' if any('устарел' in str(r['remaining_today']) for r in rows) else 'ok')
    }


def build_unicaizer_block() -> dict[str, Any]:
    db = PROFILES / 'unicaizer' / 'workspace' / 'unicaizer-app' / 'unicalizator.sqlite3'
    m = {'unique_total': 0, 'unique_today': 0, 'telegram_users': 0, 'processing_now': 0, 'errors': 0, 'status': 'Проблема'}
    try:
        con = sqlite3.connect(db)
        cur = con.cursor()
        today_ts = start_of_today_ts()
        m['unique_total'] = cur.execute("select count(distinct coalesce(actor_key, session_id, ip_hash)) from page_views").fetchone()[0] or 0
        m['unique_today'] = cur.execute("select count(distinct coalesce(actor_key, session_id, ip_hash)) from page_views where created_at >= ?", (today_ts,)).fetchone()[0] or 0
        m['telegram_users'] = cur.execute("select count(*) from users where telegram_id is not null").fetchone()[0] or 0
        m['processing_now'] = cur.execute("select count(*) from jobs where status in ('queued','processing','running','started')").fetchone()[0] or 0
        m['errors'] = cur.execute("select count(*) from jobs where status='error' and updated_at >= ?", (today_ts,)).fetchone()[0] or 0
        hs, _ = http_health('http://127.0.0.1:8000/health')
        m['status'] = status_label('ok' if hs == 'ok' else 'bad')
    except Exception:
        pass
    return {'title': 'Проект Unicaizer', **m}


def project_blocks() -> dict[str, Any]:
    return {
        'wibes': build_wibes_block(),
        'creative': build_creative_block(),
        'ritm': build_ritm_block(),
        'unicaizer': build_unicaizer_block(),
    }

def render() -> str:
    s = build_state()
    resources = system_resources()
    blocks = project_blocks()
    cron_rows = cron_all_rows()

    def metric_cards(block: dict[str, Any]) -> str:
        return f"""
        <div class="mini-stats">
          <div><span>Ошибки</span><b>{esc(block['errors'])}</b></div>
          <div><span>Всего опубликованных постов</span><b>{esc(block['total_published'])}</b></div>
          <div><span>Всего постов за всё время</span><b>{esc(block['total_posts_all'])}</b></div>
          <div><span>Постов за сегодня</span><b>{esc(block['total_posts_today'])}</b></div>
          <div><span>Статус</span><b>{esc(block['status'])}</b></div>
        </div>"""

    def project_table(block: dict[str, Any]) -> str:
        site_head = '<th>Сайт аккаунта</th>' if block.get('site_column') else ''
        rows = []
        for r in block['rows']:
            site_cell = f"<td>{link_html(r.get('site_url',''), 'сайт')}</td>" if block.get('site_column') else ''
            rows.append(f"""
            <tr>
              <td><b>{link_html(r['url'], r['name'])}</b></td>
              {site_cell}
              <td class="num">{esc(r['planned_today'])}</td>
              <td class="num">{esc(r['published'])}</td>
              <td class="num">{esc(r['remaining_today'])}</td>
              <td>{esc(r['next_time'])}</td>
              <td>{esc(r['status'])}</td>
            </tr>""")
        return f"""<div class="tablebox"><table><thead><tr><th>{esc(block['columns_first'])}</th>{site_head}<th>Запланировано сегодня</th><th>Опубликовано</th><th>Осталось</th><th>Следующая публикация</th><th>Статус</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"""

    cron_html = ''.join(f"""
      <tr><td>{esc(r['profile'])}</td><td>{esc(r['name'])}</td><td>{esc(r['enabled'])}</td><td>{esc(r['schedule'])}</td><td>{esc(r['last'])}</td><td>{esc(r['next'])}</td><td>{esc(r['status'])}</td><td>{esc(r['error'])}</td></tr>
    """ for r in cron_rows) or '<tr><td colspan="8">Cron задач нет</td></tr>'

    uni = blocks['unicaizer']
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Дашборд всех проектов</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;font-family:Inter,'SF Pro Display',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;background:#f5f7fa;color:#1a1e2c;font-size:13px;line-height:1.45}}a{{color:#2563eb;text-decoration:none}}a:hover{{text-decoration:underline;color:#1d4ed8}}.wrap{{max-width:1500px;margin:0 auto;padding:12px}}header{{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;margin-bottom:10px;background:#fff;border-radius:14px;padding:14px 18px;box-shadow:0 1px 3px #0001;border:1px solid #e2e8f0}}h1{{margin:0;font-size:22px;font-weight:700;letter-spacing:-.03em;color:#0f172a}}.server-meta{{display:flex;flex-wrap:wrap;gap:8px;margin-top:6px}}.server-meta span{{display:inline-flex;align-items:center;gap:4px;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:999px;padding:3px 10px;font-size:11px;color:#475569;white-space:nowrap}}.muted{{color:#94a3b8}}h2{{margin:0 0 6px;font-size:15px;font-weight:700;color:#0f172a}}.topgrid{{display:grid;grid-template-columns:repeat(2,minmax(200px,1fr));gap:10px;margin-bottom:10px}}.stat,.panel{{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:10px 14px;box-shadow:0 1px 3px #0000000d}}.stat span,.mini-stats span{{display:block;color:#64748b;font-size:11px;font-weight:500}}.stat b{{font-size:19px;color:#0f172a}}.panel{{margin-bottom:8px}}.mini-stats{{display:grid;grid-template-columns:repeat(5,minmax(100px,1fr));gap:6px;margin:6px 0 8px}}.mini-stats>div{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:7px 9px}}.mini-stats b{{font-size:15px;color:#0f172a}}table{{width:100%;border-collapse:separate;border-spacing:0;font-size:11px}}th,td{{text-align:left;border-bottom:1px solid #e2e8f0;padding:6px 8px;vertical-align:top}}th{{color:#64748b;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.05em;background:#f8fafc;position:sticky;top:0;z-index:1}}td b{{display:block;font-weight:600}}td a{{font-weight:600}}.num{{text-align:center;font-weight:700;white-space:nowrap}}.refresh{{background:#2563eb;color:#fff;border:0;border-radius:10px;padding:8px 14px;font-weight:700;font-size:13px;cursor:pointer;transition:.15s}}.refresh:hover{{background:#1d4ed8}}details summary{{cursor:pointer;color:#2563eb;font-weight:700;font-size:12px;margin-bottom:6px}}.tablebox{{overflow:auto;border-radius:8px;border:1px solid #e2e8f0;background:#fff}}.unigrid{{display:grid;grid-template-columns:repeat(6,minmax(110px,1fr));gap:6px}}.unigrid>div{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:7px 9px}}.unigrid span{{display:block;color:#64748b;font-size:11px;font-weight:500}}.unigrid b{{font-size:15px;color:#0f172a}}@media(max-width:900px){{.topgrid,.mini-stats,.unigrid{{grid-template-columns:1fr 1fr}}table{{min-width:800px}}.wrap{{padding:8px}}}}
</style></head><body><div class="wrap">
<header><div><h1>Дашборд всех проектов</h1><div class="server-meta"><span>🌐 {esc(s['host'])}</span><span>📡 {esc(s['ip'])}</span><span>🟢 {esc(s['state'])}</span><span>📅 до {esc(s['valid_until'])}</span><span class="muted">обновлено: {esc(s['generated'])}</span></div></div><button class="refresh" onclick="location.reload()">↻</button></header>
<section class="topgrid">
  <div class="stat"><span>Оперативная память</span><b>{esc(resources['memory']['free'])}</b><span>свободно из {esc(resources['memory']['total'])} ({esc(resources['memory']['pct_free'])}%)</span></div>
  <div class="stat"><span>Жёсткий диск</span><b>{esc(resources['disk']['free'])}</b><span>свободно из {esc(resources['disk']['total'])}; занято {esc(resources['disk']['pct_used'])}%</span></div>
</section>
<details class="panel"><summary>Cron всех проектов</summary><div class="tablebox"><table><thead><tr><th>Профиль</th><th>Задача</th><th>Вкл</th><th>Расписание</th><th>Последний запуск</th><th>Следующий</th><th>Статус</th><th>Ошибка</th></tr></thead><tbody>{cron_html}</tbody></table></div></details>
<section class="panel"><h2>Проект Wibes</h2>{metric_cards(blocks['wibes'])}{project_table(blocks['wibes'])}</section>
<section class="panel"><h2>Проект Creative Fabrica</h2>{metric_cards(blocks['creative'])}{project_table(blocks['creative'])}</section>
<section class="panel"><h2>Проект Ритм</h2>{metric_cards(blocks['ritm'])}{project_table(blocks['ritm'])}</section>
<section class="panel"><h2>Проект Unicaizer</h2><div class="unigrid">
  <div><span>Всего уникальных посетителей</span><b>{esc(uni['unique_total'])}</b></div>
  <div><span>Уникальные посетители за сегодня</span><b>{esc(uni['unique_today'])}</b></div>
  <div><span>Авторизованные в Telegram</span><b>{esc(uni['telegram_users'])}</b></div>
  <div><span>Видео обрабатываются сейчас</span><b>{esc(uni['processing_now'])}</b></div>
  <div><span>Ошибки</span><b>{esc(uni['errors'])}</b></div>
  <div><span>Статус</span><b>{esc(uni['status'])}</b></div>
</div></section>
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
