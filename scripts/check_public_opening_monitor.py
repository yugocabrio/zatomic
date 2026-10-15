#!/usr/bin/env python3
"""Explicit provider transcripts + real consent/adaptor/native verification.

No public request or new proof. The exposure scalar comes from the retained
isolated pending-claim fixture; its public-profile transaction is modeled.
"""
import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from check_public_authority import OWNER_FILES
from check_public_outgoing import copy_private
import public_opening_monitor as monitor
import public_opening as opening
from regtest_wallet import ROOT, save
from testnet_wallet import read


class Provider:
    def __init__(self, head=1000, fork_at=None, branch=1):
        self.head, self.fork_at, self.branch = head, fork_at, branch
        self.calls, self.queries = [], []
        self.transaction, self.events, self.after_logs = None, [], None

    def hash(self, height):
        if height == 0: return monitor.sepolia.GENESIS
        branch = self.branch if self.fork_at is not None and height >= self.fork_at else 0
        return '0x'+f'{branch*2**128+height:064x}'

    def __call__(self, method, params):
        monitor.sepolia.read_method(method, params)
        self.calls.append((method, params))
        if method == 'eth_chainId': return hex(monitor.sepolia.CHAIN_ID)
        if method == 'eth_getBlockByNumber':
            height = self.head if params[0] == 'latest' else int(params[0], 16)
            assert 0 <= height <= self.head
            return {'number': hex(height), 'hash': self.hash(height), 'timestamp': hex(1_800_000_000+height)}
        if method == 'eth_getTransactionByHash': return self.transaction
        if method == 'eth_getLogs':
            self.queries.append((int(params[0]['fromBlock'], 16), int(params[0]['toBlock'], 16)))
            result = copy.deepcopy(self.events)
            if self.after_logs: self.after_logs()
            return result
        raise RuntimeError('unexpected transcript request')


def setup(root, fixture):
    root.mkdir(mode=0o700)
    owner = root/'bob'; owner.mkdir(mode=0o700)
    for name in OWNER_FILES: copy_private(fixture/'bob'/name, owner/name)
    consents = root/'consents.json'; copy_private(fixture/'coordinator/conditional-consents.json', consents)
    result = monitor.operate('init', owner, consents, first=100, overlap=12, endpoint='https://invalid.invalid')
    assert not result['network_used'] and not result['send_authorized']
    files, checked, _ = opening.context(owner, consents)
    directory = opening.workspace(owner, files, checked)
    folder, config = monitor.configuration(directory, checked)
    return owner, consents, directory, files['proposal']['agreement'], checked, folder, config


def check_ranges(values):
    _, _, directory, agreement, checked, folder, config = values
    def tick(provider): return monitor.tick(directory, checked, agreement, folder, config, provider)
    provider = Provider()
    first = tick(provider)
    assert provider.queries == [(100, 355)] and first['blocks_behind_observed_head'] == 645
    provider = Provider()
    second = tick(provider)
    assert provider.queries == [(344, 599)] and second['cursor']['anchor']['height'] == 587
    # Fork inside overlap: retain prefix through the previously checked anchor.
    provider = Provider(head=610, fork_at=595)
    third = tick(provider)
    assert provider.queries == [(588, 610)] and not third['rewound_to_start']
    # Deeper fork invalidates the retained anchor; repeat from configured start.
    provider = Provider(head=620, fork_at=580, branch=2)
    fourth = tick(provider)
    assert provider.queries == [(100, 355)] and fourth['rewound_to_start']
    before = fourth['cursor']
    # A branch change after an empty response must not advance the cursor.
    provider = Provider(head=630, fork_at=580, branch=2)
    def change(): provider.fork_at, provider.branch = 550, 3
    provider.after_logs = change
    try: tick(provider)
    except RuntimeError as e: assert 'branch changed during scan' in str(e)
    else: raise AssertionError('unstable range committed')
    _, cursor, pending = monitor.history(folder, config)
    assert cursor == before and pending is not None
    resumed, report = monitor.recover(directory, checked, agreement, folder, config)
    assert resumed == before and report is None and monitor.history(folder, config)[2] is None
    provider.after_logs = None; provider.queries = []
    tick(provider)
    assert provider.queries == [(344, 599)]
    # A temporarily shorter provider head cannot keep an old high cursor.
    provider = Provider(head=120)
    result = tick(provider)
    assert provider.queries == [(100, 120)] and result['rewound_to_start']
    provider = Provider(head=99)
    result = tick(provider)
    assert result['status'] == 'awaiting-start' and result['cursor'] is None and provider.queries == []
    # No range skipping after restart/head recovery.
    provider = Provider(head=400)
    tick(provider)
    assert provider.queries == [(100, 355)]
    # Explicit transport error: no interpretation as absence or cursor progress.
    def fail(method, params):
        if method == 'eth_getLogs': raise OSError('modeled transport interruption')
        return provider(method, params)
    before = monitor.history(folder, config)[1]
    try: tick(fail)
    except OSError: pass
    else: raise AssertionError('transport failure accepted')
    assert monitor.history(folder, config)[1] == before
    monitor.recover(directory, checked, agreement, folder, config)
    # Exhaustion must stop network work rather than delete history/reset coverage.
    original = monitor.LIMIT
    monitor.LIMIT = len(monitor.history(folder, config)[0])
    calls = []
    try:
        try: tick(lambda *args: calls.append(args))
        except RuntimeError as e: assert 'history full' in str(e)
        else: raise AssertionError('history cap did not stop')
    finally: monitor.LIMIT = original
    assert calls == []
    return {'bounded_contiguous_catchup_and_overlap': True, 'deep_reorg_restarts_from_configured_height': True,
        'head_shrink_resets_cursor': True, 'unstable_scan_and_transport_failure_never_advance': True,
        'incomplete_response_replay_keeps_previous_cursor': True, 'history_exhaustion_stops_before_rpc': True}


def crash_worker(owner, consents, packet):
    files, checked, _ = opening.context(owner, consents)
    directory = opening.workspace(owner, files, checked)
    folder, config = monitor.configuration(directory, checked)
    provider = Provider(); provider.transaction = read(packet)
    def crash(*args): os.kill(os.getpid(), signal.SIGKILL)
    # Only interrupt at the native boundary, never replace successful crypto.
    opening.native = crash
    monitor.tick(directory, checked, files['proposal']['agreement'], folder, config, provider)


def check_exposure(values, fixture, pending):
    owner, consents, directory, agreement, checked, folder, config = values
    tx = read(pending)['response']
    tx.update(to=agreement['escrow']['contract'], input=opening.CLAIM_SELECTOR+opening.eth.order_id(agreement)[2:]+tx['input'][-64:])
    packet = owner.parent/'provider-packet.json'; save(packet, tx)
    monitor.operate('add-hash', owner, consents, txid=tx['hash'])
    monitor.operate('add-hash', owner, consents, txid=tx['hash'])
    assert monitor.known_hashes(folder) == [tx['hash']]
    # Known pending hash must win even when the history endpoint is unavailable.
    provider = Provider(); provider.transaction = tx
    def no_history(method, params):
        if method == 'eth_getLogs' or (method == 'eth_getBlockByNumber' and params[0] != '0x0'):
            raise AssertionError('opening waited for event history')
        return provider(method, params)
    # First simulate SIGKILL after response + candidate fsync, before acceptance.
    env = dict(os.environ, PYTHONPATH=str(ROOT/'scripts'), RAYON_NUM_THREADS='2')
    crashed = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--crash', str(owner), str(consents), str(packet)],
        cwd=ROOT, env=env, capture_output=True, timeout=120)
    assert crashed.returncode == -signal.SIGKILL and not (directory/'opening.json').exists()
    assert monitor.history(folder, config)[2] is not None
    policy = '(version 1)(allow default)(deny network*)'+''.join(
        '(deny file-read* file-write* (subpath '+json.dumps(str(p))+'))' for p in (fixture, pending.parent))
    command = ['/usr/bin/sandbox-exec', '-p', policy, sys.executable, str(ROOT/'scripts/public_opening_monitor.py'),
        'inspect', str(owner), str(consents)]
    resumed = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=120)
    assert resumed.returncode == 2, 'offline native monitor replay failed'
    report = json.loads(resumed.stdout)
    assert report['opening_available'] and report['native_authorization']['native_claim_authorization_verified']
    assert report['cursor'] is None and not report['network_used'] and not report['send_authorized']
    retained = (directory/'opening.json').read_bytes()
    calls = []
    result = monitor.tick(directory, checked, agreement, folder, config, lambda *args: calls.append(args))
    assert result['opening_available'] and calls == [] and (directory/'opening.json').read_bytes() == retained
    again = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=120)
    assert again.returncode == 2 and json.loads(again.stdout) == report
    # Separately exercise live lower-reader ordering with a fresh owner workspace.
    fresh = setup(owner.parent/'fresh', fixture)
    o, c, d, a, v, m, cfg = fresh
    monitor.operate('add-hash', o, c, txid=tx['hash'])
    got = monitor.tick(d, v, a, m, cfg, no_history)
    assert got['opening_available'] and provider.queries == []
    # Public entry refuses this synthetic agreement before any actual network.
    refused = subprocess.run(['/usr/bin/sandbox-exec', '-p', policy, sys.executable, '-c',
        'from pathlib import Path;import sys;from public_opening_monitor import operate\n'
        'try: operate("poll",Path(sys.argv[1]),Path(sys.argv[2]))\n'
        'except RuntimeError as e:\n assert "synthetic inputs" in str(e)\n'
        'else: raise AssertionError("synthetic monitor reached RPC")', str(o), str(c)],
        cwd=ROOT, env=env, capture_output=True, timeout=120)
    assert refused.returncode == 0
    return {'real_sigkill_saved_response_recovers_offline': True, 'real_native_opening_authorization': True,
        'restart_denies_network_and_original_roots': True, 'known_pending_hash_precedes_event_catchup': True,
        'accepted_opening_stops_further_rpc_and_survives_replay': True, 'public_synthetic_guard_intact': True}


def check(root, fixture, pending):
    root.mkdir(mode=0o700)
    ranges = check_ranges(setup(root/'ranges', fixture))
    exposure = check_exposure(setup(root/'exposure', fixture), fixture, pending)
    return {'scope': 'explicit provider transcripts; actual native consent/adaptor verification; synthetic native inputs',
        **ranges, **exposure, 'public_rpc_calls': 0, 'new_proofs': 0, 'public_transfers': 0,
        'complete_mempool_monitor': False, 'funded_public_swap': False}


if __name__ == '__main__':
    os.umask(0o077)
    if sys.argv[1] == '--crash': crash_worker(*(Path(p).resolve() for p in sys.argv[2:5]))
    else: print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:4])), indent=2))
