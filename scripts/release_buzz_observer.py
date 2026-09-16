"""Evidence output adapter for the native per-file release gate.

No assertions, authorization fixtures, or expectations are changed. Paths live
inside the harness's writable /evidence mount; native runner drops inherited env.
"""
import hashlib
import os
from pathlib import Path


def pytest_configure(config):
    root = Path('/evidence')
    assert root.is_dir(), 'Run through scripts/run_release_buzz.py'
    os.environ['THREAD_OBSERVATIONS'] = str(root / 'thread-observations.jsonl')
    # One XML per subprocess, avoiding aggregate-file overwrite races.
    key = hashlib.sha256('\n'.join(map(str, config.args)).encode()).hexdigest()[:16]
    config.option.xmlpath = str(root / f'backend-{key}.xml')
