#!/usr/bin/env python3
"""Local developer entry point; never connects a wallet or a public chain."""
import argparse
import fcntl
import json
import os
import platform
import shutil
import subprocess
from regtest_node import ROOT, start, rpc, status


def doctor():
    tools = {}
    for name, arguments in [('rustc', ['--version']), ('cargo', ['--version']),
                            ('node', ['--version']), ('npm', ['--version']),
                            ('forge', ['--version']), ('anvil', ['--version']),
                            ('cast', ['--version']), ('docker', ['info', '--format', '{{.ServerVersion}}'])]:
        if not shutil.which(name):
            tools[name] = {'ready': False, 'reason': 'not installed'}
            continue
        result = subprocess.run([name, *arguments], cwd=ROOT, capture_output=True, text=True)
        tools[name] = {'ready': result.returncode == 0,
                       'version': result.stdout.splitlines()[0] if result.stdout else 'unavailable'}
    arch = platform.machine().lower() in ('arm64', 'aarch64')
    free = shutil.disk_usage(ROOT).free // 2**30
    report = {'tools': tools, 'arm64_node_bootstrap_supported': arch, 'free_disk_gib': free,
              'ready': arch and free >= 5 and all(v['ready'] for v in tools.values())}
    print(json.dumps(report, indent=2), flush=True)
    return report['ready']


def command(*args):
    subprocess.run(args, cwd=ROOT, check=True, env=dict(os.environ, RAYON_NUM_THREADS='2', CARGO_BUILD_JOBS='2'))


def setup():
    if not doctor():
        raise SystemExit('Install/start the missing prerequisites from docs/reproduce.md, then retry.')
    os.umask(0o077)
    (ROOT / '.local').mkdir(mode=0o700, exist_ok=True)
    with (ROOT / '.local/chain-driver.lock').open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        command('npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund')
        command('cargo', 'build', '--locked', '--release', '-j', '2', '-p', 'shielded-swap-native')
        command('forge', 'build')
        info = start()
        if info['blocks'] < 2:
            rpc('generate', [2 - info['blocks']], timeout=300)
        print(json.dumps(status(), indent=2), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['doctor', 'setup', 'demo', 'verify'])
    action = parser.parse_args().action
    if action == 'doctor':
        raise SystemExit(0 if doctor() else 1)
    if action in ('setup', 'demo'):
        setup()
    if action == 'demo':
        os.execvp('python3', ['python3', str(ROOT / 'scripts/demo_server.py')])
    if action == 'verify':
        command('cargo', 'clippy', '--locked', '--all-targets', '-j', '2', '--', '-D', 'warnings')
        command('cargo', 'test', '--locked', '-j', '2')
        command('forge', 'test', '-vv')
        command('python3', 'scripts/check_swap_model.py')
