#!/usr/bin/env python3
"""Read-only ownership check against the existing Docker container.

No start, stop, mining or wallet operation is performed. A conflicting checkout's
start/status entry points must refuse before side effects or RPC access.
"""
import copy
import json
from pathlib import Path
import tempfile
import regtest_node as node


def refuses(fn):
    try: fn()
    except RuntimeError as e:
        assert 'ownership' in str(e) or 'another checkout' in str(e)
    else: raise AssertionError('foreign node scope accepted')


def check():
    original = node.inspect() # Actual Docker metadata; never a fake live node.
    if original is None: raise RuntimeError('existing owned container required for this check')
    node.validate_container(original)
    for mode in ('state-root', 'read-only', 'duplicate', 'label'):
        changed = copy.deepcopy(original)
        if mode == 'state-root':
            next(m for m in changed['Mounts'] if m['Destination'] == '/state')['Source'] += '-different-checkout'
        elif mode == 'read-only': next(m for m in changed['Mounts'] if m['Destination'] == '/zebra')['RW'] = True
        elif mode == 'duplicate': changed['Mounts'][-1] = copy.deepcopy(changed['Mounts'][0])
        else: changed['Config']['Labels'][node.LABEL] = 'another-project'
        refuses(lambda: node.validate_container(changed))
    current = node.NODE_DIR
    with tempfile.TemporaryDirectory(prefix='latch-scope-') as temporary:
        alternate = Path(temporary)/'fresh-checkout'/'state'
        node.NODE_DIR = alternate
        try:
            refuses(node.inspect)
            refuses(node.status)
            refuses(node.start)
            assert not alternate.exists()
        finally: node.NODE_DIR = current
    after = node.inspect()
    mounts = lambda item: sorted(item['Mounts'], key=lambda m: m['Destination'])
    assert after['Id'] == original['Id'] and mounts(after) == mounts(original)
    assert after['State'] == original['State'], 'container state changed during read-only check'
    return {'scope': 'actual read-only Docker ownership metadata plus explicit mutations',
        'existing_checkout_accepted': True, 'different_checkout_inspect_status_start_refused': True,
        'wrong_mount_write_mode_duplicate_and_label_refused': True,
        'foreign_start_creates_no_state': True, 'existing_container_state_unchanged': True,
        'chain_rpc_calls': 0, 'starts': 0, 'stops': 0, 'broadcast': False}


if __name__ == '__main__': print(json.dumps(check(), indent=2))
