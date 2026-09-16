#!/usr/bin/env python3
"""Bounded release gates: clean environment, synthetic home, denied network.

Usage: python3 scripts/run_release_buzz.py backend|frontend|upstream_seams EVIDENCE_DIR
Requires repository .venv + locked node_modules and evidence-owned python-runtime/node-runtime.
No services or live configuration are mounted. Source and dependencies are read-only.
"""
from pathlib import Path
import json
import subprocess
import sys
import time

R = Path(__file__).resolve().parents[1]
mode, output = sys.argv[1:]
E = Path(output).resolve()
inventory = json.loads((R / 'scripts/release-buzz-tests.json').read_text(encoding='utf-8'))
assert mode in ('backend', 'frontend', 'upstream_seams')
assert not (E / (mode + '-result.json')).exists(), 'Use a fresh evidence directory'
E.mkdir(parents=True, exist_ok=True)
# Empty mount points only; no product source is made writable.
(R / 'test_durations.json').touch(exist_ok=True)
for mountpoint in ('.pytest-cache', 'node_modules/.vite', 'node_modules/.vite-temp',
                   'web/node_modules/.vite', 'web/node_modules/.vite-temp'):
    (R / mountpoint).mkdir(parents=True, exist_ok=True)
runtime = R.parent / 'release-v2026.9.11-evidence'
cmd = ['bwrap', '--die-with-parent', '--unshare-all', '--new-session', '--clearenv',
       '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
       '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
       '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
       '--dir', '/home/test', '--dir', '/etc', '--dir', '/etc/hermes',
       '--ro-bind', str(R), str(R),
       '--ro-bind', str(runtime / 'python-runtime'), str(runtime / 'python-runtime'),
       '--ro-bind', str(runtime / 'node-runtime'), '/opt/node',
       '--bind', str(E), '/evidence',
       '--setenv', 'PATH', f'{R}/.venv/bin:/opt/node/bin:/usr/bin:/bin',
       '--setenv', 'HOME', '/home/test', '--setenv', 'HERMES_HOME', '/home/test/.hermes',
       '--setenv', 'HERMES_MANAGED_DIR', '/etc/hermes',
       '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC',
       '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
       '--setenv', 'TMPDIR', '/tmp', '--setenv', 'CI', 'true']
pre = "import pathlib,socket,sys; s=socket.socket(); assert s.connect_ex(('192.0.2.1',9)) != 0; assert not pathlib.Path('/home/hermes/.hermes').exists(); assert not pathlib.Path('/home/hermes/.local/share/reinhold-runtime').exists(); assert not pathlib.Path('/projects').exists(); import gateway.authz_mixin; assert pathlib.Path(gateway.authz_mixin.__file__).resolve().is_relative_to(pathlib.Path.cwd()); print('PASS: denied network; live homes/runtime/projects absent; source='+gateway.authz_mixin.__file__+'; python='+sys.executable)"
precmd = cmd + ['--chdir', str(R), str(R / '.venv/bin/python'), '-c', pre]
p = subprocess.run(precmd, capture_output=True, text=True, timeout=30)
(E / (mode + '-preflight.log')).write_text(p.stdout + p.stderr, encoding='utf-8')
assert p.returncode == 0, p.stderr
if mode == 'frontend':
    for path in ('node_modules/.vite', 'node_modules/.vite-temp', 'web/node_modules/.vite', 'web/node_modules/.vite-temp'):
        cmd += ['--tmpfs', str(R / path)]
    cmd += ['--setenv', 'NODE_OPTIONS', '--max-old-space-size=1024',
            '--setenv', 'UV_THREADPOOL_SIZE', '1', '--setenv', 'RAYON_NUM_THREADS', '1',
            '--chdir', str(R / 'web'), '/opt/node/bin/node',
            str(R / 'node_modules/vitest/vitest.mjs'), 'run', '--maxWorkers=1',
            '--no-file-parallelism', '--pool=forks', '--reporter=verbose', *inventory[mode]]
else:
    # Native runner writes only its duration cache; mount that file separately.
    durations = E / (mode + '-durations.json')
    durations.write_text('{}\n', encoding='utf-8')
    cmd += ['--bind', str(durations), str(R / 'test_durations.json'),
            '--tmpfs', str(R / '.pytest-cache'),
            '--chdir', str(R), '/bin/bash', str(R / 'scripts/run_tests.sh'),
            '-j', '2', '--file-retries', '0', '--file-timeout', '90',
            *inventory[mode], '-q', '-p', 'no:cacheprovider', '-p', 'scripts.release_buzz_observer']
(E / (mode + '-command.json')).write_text(json.dumps(cmd, indent=2), encoding='utf-8')
start = time.monotonic()
with (E / (mode + '.log')).open('w', encoding='utf-8') as out:
    try:
        p = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT, timeout=480)
        code = p.returncode
    except subprocess.TimeoutExpired:
        code = 124
(E / (mode + '-result.json')).write_text(json.dumps({'exit_code': code, 'seconds': time.monotonic()-start,
    'tests': inventory[mode], 'network': 'denied', 'source': str(R), 'source_read_only': True,
    'native_backend_runner': 'scripts/run_tests.sh', 'file_retries': 0}, indent=2), encoding='utf-8')
print(mode, 'exit', code)
print((E / (mode + '.log')).read_text(encoding='utf-8')[-18000:])
sys.exit(code)
