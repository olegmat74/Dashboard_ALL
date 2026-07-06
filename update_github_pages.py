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
    html = html.replace('<body><div class="wrap">', '<body><div class="wrap">')
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
<title>Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}:root{{--bg:#0a0a0f;--s:#12121a;--s2:#1a1a25;--b:#2a2a3a;--t:#e8e8f0;--t2:#a0a0b8;--t3:#6a6a80;--accent:#6366f1;--red:#ef4444;--font:'Inter',system-ui,sans-serif}}
html{{background:var(--bg);color:var(--t);font-family:var(--font);font-size:13px;-webkit-font-smoothing:antialiased}}
.login{{position:fixed;inset:0;z-index:999;background:var(--bg);display:flex;align-items:center;justify-content:center;transition:opacity .3s,visibility .3s}}
.login.off{{opacity:0;visibility:hidden;pointer-events:none}}
.login-box{{background:var(--s);border:1px solid var(--b);border-radius:14px;padding:32px;width:100%;max-width:340px;text-align:center}}
.login-box h2{{font-size:18px;font-weight:700;margin-bottom:4px}}
.login-box p{{color:var(--t3);font-size:12px;margin-bottom:20px}}
.login-box input{{width:100%;padding:10px 14px;background:var(--s2);border:1px solid var(--b);border-radius:8px;color:var(--t);font-size:13px;font-family:var(--font);outline:none}}
.login-box input:focus{{border-color:var(--accent)}}
.login-box button{{width:100%;padding:10px;margin-top:10px;background:var(--accent);border:none;border-radius:8px;color:#fff;font-size:13px;font-weight:600;font-family:var(--font);cursor:pointer}}
.login-box button:hover{{opacity:.9}}
.login-err{{color:var(--red);font-size:11px;margin-top:6px;display:none}}
</style></head>
<body>
<div class="login" id="lo" style="display:none"><div class="login-box"><h2>Dashboard</h2><p>Введите пароль</p><input type="password" id="pw" placeholder="Пароль" autofocus><button onclick="go()">Войти</button><div class="login-err" id="err">Неверный пароль</div></div></div>
<div class="dash" id="d"></div>
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
    document.getElementById('d').innerHTML = html;
    document.getElementById('lo').style.display = 'none';
    // Run clock if script didn't execute
    if (typeof clk === 'undefined' && document.getElementById('clk')) {{
      var clk = function(){{
        var n = new Date();
        var el = document.getElementById('clk');
        if (el) el.textContent = n.toLocaleDateString('ru-RU',{{day:'2-digit',month:'2-digit',year:'numeric'}})+' \\u00b7 '+n.toLocaleTimeString('ru-RU',{{hour:'2-digit',minute:'2-digit'}});
        var ft = document.getElementById('ft');
        if (ft) ft.textContent = n.toLocaleTimeString('ru-RU',{{hour:'2-digit',minute:'2-digit'}});
      }};
      clk();
      setInterval(clk, 1000);
    }}
    // Auto refresh
    setTimeout(function(){{location.reload()}}, 120000);
  }} catch(e) {{
    sessionStorage.removeItem('dashboard_pages_password');
    document.getElementById('err').style.display = 'block';
    document.getElementById('pw').value = '';
    document.getElementById('lo').style.display = 'flex';
  }}
}}
async function go() {{
  const pw = document.getElementById('pw').value;
  document.getElementById('err').style.display = 'none';
  await openWith(pw);
}}
document.getElementById('pw').addEventListener('keydown', e => {{ if(e.key==='Enter') go(); }});
(async function init() {{
  const saved = sessionStorage.getItem('dashboard_pages_password');
  if (saved) {{ await openWith(saved); return; }}
  document.getElementById('lo').style.display = 'flex';
}})();
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
