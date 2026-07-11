#!/usr/bin/env python3
"""Dashboard watchdog — runs every 3h.

Checks:
  - New Pinterest accounts in WoopSocial vs dashboard coverage
  - All counters (Pinterest / Ritm totals, today, errors)
  - Render sanity (no raw template code leaked, import OK)
  - Deploys to Cloudflare if data changed or render was broken

Outputs a concise human-readable report to stdout.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

DASH = Path(__file__).resolve().parent
PROFILES = Path('/home/hermes/.hermes/profiles')
EVN = PROFILES / 'autopost_creative_fabrica' / 'key.evn'
sys.path.insert(0, str(DASH))


def load_evn() -> dict:
    env = {}
    try:
        for line in EVN.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip()
    except Exception:
        pass
    return env


def woopsocial_accounts(env: dict) -> list[dict]:
    import urllib.request
    pid = env.get('WOOPSOCIAL_PROJECT_ID')
    key = env.get('WOOPSOCIAL_API_KEY')
    if not pid or not key:
        return []
    url = f"https://api.woopsocial.com/v1/social-accounts?projectId={pid}"
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {key}'})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read().decode())
    except Exception as e:
        return [{'_error': str(e)}]
    return d if isinstance(d, list) else d.get('data') or d.get('socialAccounts') or []


def main() -> int:
    import server

    report = []
    report.append('=== Dashboard Watchdog ' + __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M') + ' ===')

    # 1) Import / render sanity
    try:
        html = server.render()
        render_ok = True
        if 'esc(pin_posts_published)' in html or 'esc(ritm_posts_published)' in html:
            render_ok = False
            report.append('❌ RENDER BROKEN: raw template code leaked into HTML')
        else:
            report.append('✅ Render OK (no raw template code)')
    except Exception as e:
        render_ok = False
        report.append(f'❌ RENDER ERROR: {e}')

    # 2) Accounts: WoopSocial vs dashboard coverage
    env = load_evn()
    ws = woopsocial_accounts(env)
    ws_err = ws and '_error' in ws[0]
    if ws_err:
        report.append(f'⚠️ WoopSocial API error: {ws[0]["_error"]}')
        ws_ids = set()
    else:
        ws_ids = {a.get('id') for a in ws}
        report.append(f'✅ WoopSocial accounts: {len(ws)}')

    # dashboard tracked S-codes come from env (WOOPSOCIAL_PINTEREST_SOCIAL_ACCOUNT_ID_Sxxx)
    env_id_map = {}
    for k, v in env.items():
        if k.startswith('WOOPSOCIAL_PINTEREST_SOCIAL_ACCOUNT_ID_'):
            scode = k.replace('WOOPSOCIAL_PINTEREST_SOCIAL_ACCOUNT_ID_', '')
            env_id_map[v] = scode
    dashboard_ids = set(env_id_map.keys())
    missing = ws_ids - dashboard_ids
    if missing:
        report.append(f'🆕 NEW ACCOUNTS in WoopSocial not in dashboard env: {len(missing)}')
        for mid in missing:
            report.append(f'   - {mid} ({(env_id_map.get(mid) or "NO S-CODE")})')
    else:
        report.append('✅ All WoopSocial accounts covered by dashboard')

    # 3) Counters
    cf = server.build_creative_block()
    ritm = server.build_ritm_block()
    report.append(f'📌 Pinterest аккаунтов: {len(cf["rows"])} | Всего: {cf["total_published"]} | Сегодня: {cf["total_published_today"]} | Запланировано сегодня: {cf["total_posts_today"]} | Ошибки: {cf["errors"]}')
    report.append(f'🛒 Ritm аккаунтов: {len(ritm["rows"])} | Всего: {ritm["total_published"]} | Сегодня: {ritm["total_published_today"]} | Ошибки: {ritm["errors"]}')
    for r in ritm['rows']:
        report.append(f'   - {r["name"]}: {r["published"]} {r.get("note","")}')
    report.append(f'📊 ИТОГО: Пинтерест {cf["total_published"]} + Ритм {ritm["total_published"]} = {cf["total_published"]+ritm["total_published"]}')

    # 4) Errors in Pinterest rows
    err_rows = [r['name'] for r in cf['rows'] if r.get('errors')]
    if err_rows:
        report.append(f'❌ Pinterest accounts with errors: {", ".join(err_rows)}')
    else:
        report.append('✅ No Pinterest posting errors')

    # 5) Deploy if broken or new accounts
    if (not render_ok) or missing or ws_err:
        try:
            r = subprocess.run(['python3', str(DASH / 'deploy_cloudflare.py')], cwd=DASH, capture_output=True, text=True, timeout=120)
            if r.returncode == 0:
                report.append('🚀 Deployed to Cloudflare Pages')
            else:
                report.append(f'⚠️ Deploy failed: {r.stderr[:200]}')
        except Exception as e:
            report.append(f'⚠️ Deploy error: {e}')
    else:
        report.append('ℹ️ No changes → skip deploy')

    print('\n'.join(report))
    return 0


if __name__ == '__main__':
    sys.exit(main())
