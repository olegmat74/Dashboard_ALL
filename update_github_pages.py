#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate encrypted GitHub Pages snapshot and push if changed."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent
PASSWORD_FILE = ROOT / '.pages_password'
DOCS = ROOT / 'docs'
INDEX = DOCS / 'index.html'
ITERATIONS = 250_000


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check)


def load_dashboard_html() -> str:
    spec = importlib.util.spec_from_file_location('dash_server', ROOT / 'server.py')
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    html = mod.render()
    notice = '''
<div style="max-width:1500px;margin:0 auto 0;padding:8px 14px;font-family:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:12px;color:#64748b;text-align:left">
Автообновление с сервера каждые 2 минуты
</div>
'''
    html = html.replace('<body><div class="wrap">', '<body>' + notice + '<div class="wrap">')
    html = html.replace('<script>setTimeout(()=>location.reload(),60000)</script>', '<script>setTimeout(()=>location.reload(),120000)</script>')
    return html


def encrypt_html(plaintext: str, password: str) -> dict[str, str | int]:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS, dklen=32)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode('utf-8'), None)
    return {
        'iterations': ITERATIONS,
        'salt': base64.b64encode(salt).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
    }


def shell_html(payload: dict[str, str | int]) -> str:
    return f'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Единый дашборд проектов</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#0b1020;color:#eef2ff}}.box{{width:min(440px,calc(100vw - 32px));background:#111936;border:1px solid #26304f;border-radius:22px;padding:26px;box-shadow:0 20px 60px #0008}}h1{{margin:0 0 8px;font-size:26px;letter-spacing:-.04em}}p{{margin:0 0 20px;color:#98a2b3}}label{{display:block;margin:0 0 8px;color:#c8d4ff;font-weight:700}}input{{width:100%;height:46px;border-radius:12px;border:1px solid #33405f;background:#070b17;color:#eef2ff;padding:0 12px;font-size:16px}}button{{width:100%;height:46px;margin-top:14px;border:0;border-radius:12px;background:#2563eb;color:white;font-weight:900;cursor:pointer}}.error{{display:none;background:#51101a;color:#ffb1bd;border:1px solid #9d2f3b;padding:10px;border-radius:12px;margin-bottom:14px}}.muted{{font-size:12px;color:#7c879d;margin-top:12px}}
</style></head><body>
<form class="box" id="login"><h1>Единый дашборд</h1><p>GitHub Pages версия. Введите пароль один раз в этой вкладке.</p><div class="error" id="err">Неверный пароль</div><label>Пароль</label><input id="pass" type="password" autocomplete="current-password" autofocus required><button type="submit">Войти</button><div class="muted">Данные зашифрованы в репозитории. Без пароля снимок не открывается.</div></form>
<script>
const payload = {{iterations:{payload['iterations']}, salt:'{payload['salt']}', nonce:'{payload['nonce']}', ciphertext:'{payload['ciphertext']}'}};
function b64(s) {{ return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }}
async function decrypt(password) {{
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({{name:'PBKDF2', salt:b64(payload.salt), iterations:payload.iterations, hash:'SHA-256'}}, baseKey, {{name:'AES-GCM', length:256}}, false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({{name:'AES-GCM', iv:b64(payload.nonce)}}, key, b64(payload.ciphertext));
  return new TextDecoder().decode(plain);
}}
async function openWith(password) {{
  try {{
    const html = await decrypt(password);
    sessionStorage.setItem('dashboard_pages_password', password);
    document.open(); document.write(html); document.close();
  }} catch(e) {{
    sessionStorage.removeItem('dashboard_pages_password');
    document.getElementById('err').style.display = 'block';
  }}
}}
const saved = sessionStorage.getItem('dashboard_pages_password');
if (saved) openWith(saved);
document.getElementById('login').addEventListener('submit', e => {{ e.preventDefault(); openWith(document.getElementById('pass').value); }});
</script></body></html>'''


def main() -> None:
    if not PASSWORD_FILE.exists():
        raise SystemExit(f'Missing password file: {PASSWORD_FILE}')
    password = PASSWORD_FILE.read_text().strip()
    DOCS.mkdir(exist_ok=True)
    (DOCS / '.nojekyll').write_text('', encoding='utf-8')
    plaintext = load_dashboard_html()
    INDEX.write_text(shell_html(encrypt_html(plaintext, password)), encoding='utf-8')
    run(['git', 'add', 'docs/index.html', 'docs/.nojekyll'])
    diff = run(['git', 'diff', '--cached', '--quiet'], check=False)
    if diff.returncode == 0:
        print('no changes')
        return
    run(['git', 'commit', '-m', 'Update GitHub Pages dashboard snapshot'])
    out = run(['git', 'push'])
    print(out.stdout.strip())


if __name__ == '__main__':
    main()
