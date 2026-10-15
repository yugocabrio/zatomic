#!/usr/bin/env python3
"""Resumable, bounded opening observer. No sender or complete mempool claim.

Operator-supplied exact hashes are checked before catching up exact-order logs.
Saved raw responses are replayed OFFLINE before another network request. Coverage
means only a trusted provider's numbered event ranges, never non-exposure.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import public_opening as opening
import public_outgoing as outgoing
import probe_sepolia as sepolia
from source_inputs import publish
from testnet_wallet import read

LIMIT = 4096
HASH_LIMIT = 8


def configuration(directory, checked):
    monitor = directory/'monitor'; outgoing.private_directory(monitor)
    config = read(monitor/'config.json')
    if (set(config) != {'format', 'agreement_digest', 'bundle_digest', 'from_block', 'overlap', 'endpoint'}
            or config['format'] != 'latch-opening-monitor-v1'
            or any(config[k] != checked[k] for k in ('agreement_digest', 'bundle_digest'))
            or type(config['from_block']) is not int or not 1 <= config['from_block'] < 2**64
            or type(config['overlap']) is not int or not 1 <= config['overlap'] <= 64):
        raise RuntimeError('monitor configuration/binding invalid')
    sepolia.ReadOnlyRpc(config['endpoint']) # Validate URL only; no request.
    return monitor, config


def header(tag, call):
    value = sepolia.block(tag, call)
    if not 0 <= value['height'] < 2**64 or (tag != 'latest' and value['height'] != sepolia.quantity(tag)):
        raise RuntimeError('monitor block height mismatch')
    return {'height': value['height'], 'hash': value['hash']}


def validate_cursor(cursor, config):
    if cursor is None: return
    if not isinstance(cursor, dict) or set(cursor) != {'tail', 'anchor'}:
        raise RuntimeError('invalid retained event cursor')
    for h in cursor.values():
        if (set(h) != {'height', 'hash'} or type(h['height']) is not int or not 0 <= h['height'] < 2**64
                or not isinstance(h['hash'], str) or not re.fullmatch('0x[0-9a-f]{64}', h['hash'])):
            raise RuntimeError('invalid retained block identity')
    if (cursor['tail']['height'] < config['from_block']
            or cursor['anchor']['height'] != max(config['from_block']-1, cursor['tail']['height']-config['overlap'])):
        raise RuntimeError('retained overlap changed')


def history(monitor, config):
    folder = monitor/'rounds'; outgoing.private_directory(folder)
    entries = sorted(folder.iterdir())
    if len(entries) > LIMIT or [p.name for p in entries] != [f'{i:04d}' for i in range(len(entries))]:
        raise RuntimeError('monitor history gap/bound; preserve all observations')
    cursor, pending = None, None
    for i, entry in enumerate(entries):
        outgoing.private_directory(entry)
        # A directory can exist after a crash before the first fsynced intent.
        # No request was allowed yet. Do not salvage unidentified query files.
        if not (entry/'intent.json').exists():
            if i != len(entries)-1 or any(not p.name.startswith('.source-pending-') for p in entry.iterdir()):
                raise RuntimeError('unidentified monitor files')
            publish(entry/'intent.json', {'config_digest': opening.eth.digest(config),
                'previous_cursor': cursor, 'hashes': [], 'started_unix': None})
        intent = read(entry/'intent.json')
        if (intent['config_digest'] != opening.eth.digest(config) or intent['previous_cursor'] != cursor
                or not isinstance(intent['hashes'], list) or len(intent['hashes']) > HASH_LIMIT
                or len(set(intent['hashes'])) != len(intent['hashes'])):
            raise RuntimeError('monitor intent chain changed')
        for txid in intent['hashes']: sepolia.read_method('eth_getTransactionByHash', [txid])
        if not (entry/'finish.json').exists():
            if i != len(entries)-1: raise RuntimeError('unfinished earlier monitor round')
            pending = entry
        else:
            result = read(entry/'finish.json')
            if result['intent_digest'] != opening.eth.digest(intent): raise RuntimeError('monitor result binding changed')
            validate_cursor(result['cursor'], config)
            if result['status'] == 'scanned':
                first, last = result['range']
                if not config['from_block'] <= first <= last < 2**64 or last-first >= 256 or result['cursor']['tail']['height'] != last:
                    raise RuntimeError('invalid saved event range')
                expected = config['from_block'] if cursor is None or result['rewound_to_start'] else cursor['anchor']['height']+1
                if first != expected: raise RuntimeError('event coverage skipped a range')
            elif result['status'] == 'awaiting-start':
                if result['cursor'] is not None: raise RuntimeError('unexpected future coverage')
            elif result['status'] in ('interrupted', 'opening-available'):
                if result['cursor'] != cursor: raise RuntimeError('interrupted round advanced cursor')
            else: raise RuntimeError('unknown monitor result')
            cursor = result['cursor']
    return entries, cursor, pending


def finish(entry, cursor, status, **extra):
    result = {'intent_digest': opening.eth.digest(read(entry/'intent.json')), 'cursor': cursor,
        'status': status, **extra}
    publish(entry/'finish.json', result)
    return result


def query(entry, name, agreement, directory, checked, call, txid=None, first=None, last=None):
    folder = entry/name; outgoing.private_directory(folder)
    outgoing.immutable(folder/'query.json', {'transaction': txid, 'from_block': first, 'to_block': last})
    return opening.acquire(agreement, directory, checked, folder, call, txid, first, last)


def recover(directory, checked, agreement, monitor, config):
    """Only local replay, including a response persisted just before SIGKILL."""
    entries, cursor, pending = history(monitor, config)
    if pending is not None:
        intent = read(pending/'intent.json')
        for name in [*(f'hash-{i}' for i in range(len(intent['hashes']))), 'events']:
            folder = pending/name
            raw_name = 'events.json' if name == 'events' else 'transaction.json'
            if not (folder/raw_name).exists(): continue
            outgoing.private_directory(folder)
            q = read(folder/'query.json')
            if name == 'events':
                if (q['transaction'] is not None or type(q['from_block']) is not int or type(q['to_block']) is not int
                        or not config['from_block'] <= q['from_block'] <= q['to_block'] < 2**64
                        or q['to_block']-q['from_block'] >= 256):
                    raise RuntimeError('retained monitor event query invalid')
            elif q != {'transaction': intent['hashes'][int(name[5:])], 'from_block': None, 'to_block': None}:
                raise RuntimeError('retained monitor hash query changed')
            def saved(method, params):
                expected = 'eth_getLogs' if name == 'events' else 'eth_getTransactionByHash'
                if method != expected: raise RuntimeError('retained monitor source changed')
                sepolia.read_method(method, params)
                return read(folder/raw_name)['response']
            result = opening.acquire(agreement, directory, checked, folder, saved,
                q['transaction'], q['from_block'], q['to_block'])
            if result['opening_available']: break
        # A saved response alone cannot attest to a stable post-query head.
        # Preserve the prior cursor and repeat the range on the next live tick.
        finish(pending, cursor, 'opening-available' if opening.accepted(directory, checked) else 'interrupted')
    return cursor, opening.accepted(directory, checked)


def known_hashes(monitor):
    folder = monitor/'hashes'; outgoing.private_directory(folder)
    entries = sorted(folder.iterdir())
    # Ignore only publish()'s incomplete temporary files, never an invalid hash.
    entries = [p for p in entries if not p.name.startswith('.source-pending-')]
    if len(entries) > HASH_LIMIT: raise RuntimeError('known hash bound exceeded')
    result = []
    for path in entries:
        txid = path.stem
        sepolia.read_method('eth_getTransactionByHash', [txid])
        if path.suffix != '.json' or read(path) != {'transaction': txid}: raise RuntimeError('known hash record changed')
        result.append(txid)
    return result


def summary(cursor, opening_report, **extra):
    return {'format': 'latch-opening-monitor-status-v1', 'cursor': cursor,
        'opening_available': opening_report is not None, 'native_authorization': opening_report,
        'coverage_scope': 'provider-returned exact-order logs since configured height only',
        'mempool_completeness_claimed': False, 'exposure_excluded': False,
        'settlement_verified': False, 'send_authorized': False, 'broadcast': False, **extra}


def tick(directory, checked, agreement, monitor, config, call):
    """Reader boundary for explicit transcripts; native verification stays real.

    Live callers must hold the owner lock, verify consent and reject synthetic
    provenance before entry. Tests exercise this reader without public access.
    """
    cursor, accepted = recover(directory, checked, agreement, monitor, config)
    if accepted: return summary(cursor, accepted, status='opening-available', network_used=False)
    entries, _, _ = history(monitor, config)
    if len(entries) >= LIMIT: raise RuntimeError('monitor history full; offline inspect remains available')
    txids = known_hashes(monitor)
    entry = monitor/'rounds'/f'{len(entries):04d}'; outgoing.private_directory(entry)
    publish(entry/'intent.json', {'config_digest': opening.eth.digest(config), 'previous_cursor': cursor,
        'hashes': txids, 'started_unix': int(time.time())})
    # Identity before disclosing any hash/address/order; never wait for finality
    # to learn an opening. Provider failure stops, with no retry/rotation loop.
    if sepolia.quantity(call('eth_chainId', [])) != sepolia.CHAIN_ID or header('0x0', call)['hash'] != sepolia.GENESIS:
        raise RuntimeError('monitor provider identity mismatch')
    for i, txid in enumerate(txids):
        got = query(entry, f'hash-{i}', agreement, directory, checked, call, txid=txid)
        if got['opening_available']:
            finish(entry, cursor, 'opening-available')
            return summary(cursor, got['native_authorization'], status='opening-available', network_used=True)
    latest = header('latest', call)
    start = config['from_block']
    rewind, old_anchor = False, None
    if cursor is not None:
        old_anchor = cursor['anchor']
        if latest['height'] < old_anchor['height'] or header(hex(old_anchor['height']), call) != old_anchor:
            rewind, old_anchor = True, None
        else: start = old_anchor['height']+1
    if latest['height'] < config['from_block']:
        finish(entry, None, 'awaiting-start')
        return summary(None, None, status='awaiting-start', provider_latest=latest, network_used=True)
    last = min(latest['height'], start+255)
    # A head shrink to exactly the anchor requires a reset too: no empty range.
    if last < start:
        start, last, rewind, old_anchor = config['from_block'], min(latest['height'], config['from_block']+255), True, None
    tail = header(hex(last), call)
    anchor = header(hex(max(config['from_block']-1, last-config['overlap'])), call)
    publish(entry/'range.json', {'first': start, 'last': last, 'tail': tail, 'anchor': anchor,
        'old_anchor': old_anchor, 'rewound_to_start': rewind, 'provider_latest': latest})
    got = query(entry, 'events', agreement, directory, checked, call, first=start, last=last)
    if got['opening_available']:
        # Do not let a later RPC error or reorg gate delay an already useful t.
        finish(entry, cursor, 'opening-available')
        return summary(cursor, got['native_authorization'], status='opening-available', network_used=True)
    for expected in (tail, anchor, old_anchor):
        if expected is not None and header(hex(expected['height']), call) != expected:
            raise RuntimeError('event branch changed during scan; retained range must be repeated')
    cursor = {'tail': tail, 'anchor': anchor}
    finish(entry, cursor, 'scanned', range=[start, last], rewound_to_start=rewind)
    return summary(cursor, None, status='scanned', provider_latest=latest, rewound_to_start=rewind,
        blocks_behind_observed_head=latest['height']-last, network_used=True)


def operate(operation, owner, consents, first=None, overlap=12, endpoint=sepolia.ENDPOINT, txid=None):
    with opening.authority.owner_locked(owner):
        files, checked, caller = opening.context(owner, consents)
        if operation == 'poll' and checked['synthetic_inputs'] is not False:
            raise RuntimeError('synthetic inputs cannot enter public opening monitor')
        directory = opening.workspace(owner, files, checked)
        if operation == 'init':
            if type(first) is not int or not 1 <= first < 2**64 or type(overlap) is not int or not 1 <= overlap <= 64:
                raise RuntimeError('explicit starting height and bounded overlap required')
            sepolia.ReadOnlyRpc(endpoint)
            monitor = directory/'monitor'; outgoing.private_directory(monitor)
            outgoing.immutable(monitor/'config.json', {'format': 'latch-opening-monitor-v1',
                'agreement_digest': checked['agreement_digest'], 'bundle_digest': checked['bundle_digest'],
                'from_block': first, 'overlap': overlap, 'endpoint': endpoint})
        monitor, config = configuration(directory, checked)
        if operation == 'add-hash':
            sepolia.read_method('eth_getTransactionByHash', [txid])
            hashes = known_hashes(monitor)
            if txid not in hashes and len(hashes) >= HASH_LIMIT: raise RuntimeError('known hash history full; preserve existing hashes')
            outgoing.immutable(monitor/'hashes'/(txid+'.json'), {'transaction': txid})
        if operation == 'poll':
            result = tick(directory, checked, files['proposal']['agreement'], monitor, config,
                sepolia.ReadOnlyRpc(config['endpoint']))
        else:
            cursor, accepted = recover(directory, checked, files['proposal']['agreement'], monitor, config)
            result = summary(cursor, accepted, status='offline', known_hashes=len(known_hashes(monitor)), network_used=False)
        if opening.authority.bind_owner(owner, files, checked, 'native_claim') != caller or read(consents) != files['consents']:
            raise RuntimeError('caller acceptance changed during monitor round')
        return result


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('init', 'add-hash', 'inspect', 'poll'))
    p.add_argument('owner', type=Path); p.add_argument('consents', type=Path)
    p.add_argument('--from-block', type=int); p.add_argument('--overlap', type=int, default=12)
    p.add_argument('--endpoint', default=sepolia.ENDPOINT); p.add_argument('--transaction')
    p.add_argument('--rounds', type=int, default=1); p.add_argument('--interval', type=int, default=20)
    a = p.parse_args()
    if not 1 <= a.rounds <= LIMIT or not 20 <= a.interval <= 60 or (a.operation != 'poll' and a.rounds != 1):
        raise RuntimeError('bounded round count and 20-60 second interval required')
    for i in range(a.rounds):
        result = operate(a.operation, a.owner, a.consents, a.from_block, a.overlap, a.endpoint, a.transaction)
        print(json.dumps(result), flush=True)
        if result['opening_available']: break
        # Release owner lock between rounds for add-hash and recovery clients.
        # Interval is a minimum pause, NOT a wall-clock observation guarantee.
        if i+1 < a.rounds: time.sleep(a.interval)
    return 2 # An observed opening is never a sending authorization.


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Monitor stopped; retain private history and run offline inspect. No transaction sent.') from None
