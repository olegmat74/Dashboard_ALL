#!/usr/bin/env python3
"""Deploy dashboard to Cloudflare Pages and commit changes to git."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
KEY_FILE = Path('/home/hermes/.hermes/profiles/autopost_creative_fabrica/key.evn')
OPS_MANUAL = Path('/home/hermes/.hermes/profiles/autopost_creative_fabrica/ops/operations_manual.html')
PROJECT_NAME = 'pinterest-affiliate-ops'


def load_env():
    """Load Cloudflare credentials from key.evn."""
    env = {}
    if KEY_FILE.exists():
        for line in KEY_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def load_dashboard_html() -> str:
    spec = importlib.util.spec_from_file_location('dash_server', ROOT / 'server.py')
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod.render()


def main():
    env = load_env()
    token = env.get('CLOUDFLARE_API_TOKEN', '')
    account = env.get('CLOUDFLARE_ACCOUNT_ID', '')

    if not token or not account:
        print('Missing Cloudflare credentials')
        return 1

    html = load_dashboard_html()

    deploy_dir = Path(tempfile.mkdtemp(prefix='dashboard-deploy-'))
    (deploy_dir / 'index.html').write_text(html, encoding='utf-8')

    # Copy ops manual if it exists
    if OPS_MANUAL.exists():
        shutil.copy(OPS_MANUAL, deploy_dir / 'ops.html')

    export_env = os.environ.copy()
    export_env['CLOUDFLARE_API_TOKEN'] = token
    export_env['CLOUDFLARE_ACCOUNT_ID'] = account

    result = subprocess.run(
        ['npm', 'exec', '--yes', '--package=wrangler@latest', '--',
         'wrangler', 'pages', 'deploy', str(deploy_dir),
         '--project-name', PROJECT_NAME,
         '--branch', 'main',
         '--commit-dirty=true'],
        cwd=deploy_dir,
        env=export_env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    shutil.rmtree(deploy_dir, ignore_errors=True)

    # Also commit to git
    git_root = ROOT
    subprocess.run(['git', 'add', '-A'], cwd=git_root, capture_output=True)
    diff = subprocess.run(['git', 'diff', '--cached', '--quiet'], cwd=git_root)
    if diff.returncode != 0:
        subprocess.run(['git', 'commit', '-m', 'Dashboard changes'], cwd=git_root, capture_output=True)
        push = subprocess.run(['git', 'push'], cwd=git_root, capture_output=True, text=True)
        print(push.stdout.strip())

    if result.returncode == 0:
        print('Deployed to Cloudflare Pages')
    else:
        print(f'Deploy failed: {result.stderr}')
        return 1

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
