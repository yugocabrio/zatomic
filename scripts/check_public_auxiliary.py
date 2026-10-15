#!/usr/bin/env python3
"""Actual native agreement/aux-target extraction; explicit UTXO response models.

No provider request, key access, new proof or transaction. Native receipt/consent
verification uses the retained synthetic fixture, whose coins do not exist.
"""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from public_preflight import native_auxiliary
from regtest_wallet import ROOT, save


def check(root, fixture):
    root.mkdir(mode=0o700)
    source = fixture/'coordinator'
    names = ('native-recovery.json', 'conditional-proposal.json', 'conditional-consents.json')
    for name in names:
        save(root/name, json.loads((source/name).read_text()))
    agreement = json.loads((root/'conditional-proposal.json').read_text())['agreement']
    policy = '(version 1)(allow default)(deny file-read* file-write* (subpath '+json.dumps(str(fixture))+'))'
    probe = subprocess.run(['/usr/bin/sandbox-exec', '-p', policy, sys.executable, '-c',
        'import pathlib,sys\ntry: pathlib.Path(sys.argv[1]).read_bytes()\nexcept PermissionError: sys.exit(0)\nelse: sys.exit(9)',
        str(source/'conditional-consents.json')], capture_output=True)
    if probe.returncode: raise RuntimeError('original fixture denial ineffective')
    checked = json.loads(subprocess.run(['/usr/bin/sandbox-exec', '-p', policy,
        str(ROOT/'target/release/shielded-swap-native'), 'testnet-check-consents',
        *[str(root/name) for name in names]], capture_output=True, text=True,
        timeout=180, check=True, env=dict(os.environ, RAYON_NUM_THREADS='2')).stdout)
    assert checked['both_owner_signatures_verified'] is True and checked['synthetic_inputs'] is True
    target = checked['native_auxiliary']
    assert target['txid'] == '13'*32 and target['index'] == 0 and target['value_zatoshi'] == 20_000
    # Independently decode Base58Check: the target address must encode the exact
    # P2PKH hash from the verified refund, not an unrelated caller address.
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = 0
    for character in target['aux_address']: n = n*58+alphabet.index(character)
    encoded = n.to_bytes((n.bit_length()+7)//8, 'big')
    assert encoded[:2] == bytes.fromhex('1d25')
    assert encoded[2:22].hex() == target['aux_script'][6:-4]
    assert hashlib.sha256(hashlib.sha256(encoded[:-4]).digest()).digest()[:4] == encoded[-4:]
    now = int(time.time())
    coin = {'txid': target['txid'], 'index': target['index'], 'value_zatoshi': 20_000,
        'height': 4_500_000, 'script': target['aux_script'], 'confirmations_by_provider': 12}
    observation = {'format': 'latch-testnet-auxiliary-observation-v1', 'genesis': target['genesis'],
        'auxiliary_address': target['aux_address'], 'auxiliary_script': target['aux_script'],
        'observed_tip': {'height': 4_500_011, 'hash': 'ab'*32, 'timestamp': now},
        'observed_at': datetime.fromtimestamp(now, timezone.utc).isoformat(), 'utxos': [coin]}
    assert native_auxiliary(agreement, target, observation, now)['confirmations_by_provider'] == 12
    def refused(value):
        try: native_auxiliary(agreement, target, value, now)
        except RuntimeError: return
        raise RuntimeError('unusable exact refund auxiliary accepted')
    for kind in ('missing', 'same-value-replacement', 'duplicate', 'shallow', 'changed-script', 'stale'):
        bad = copy.deepcopy(observation)
        if kind == 'missing': bad['utxos'] = []
        elif kind == 'same-value-replacement': bad['utxos'][0]['txid'] = '14'*32
        elif kind == 'duplicate': bad['utxos'].append(copy.deepcopy(coin))
        elif kind == 'shallow': bad['observed_tip']['height'] -= 1; bad['utxos'][0]['confirmations_by_provider'] -= 1
        elif kind == 'changed-script': bad['utxos'][0]['script'] = '51'
        else: bad['observed_at'] = datetime.fromtimestamp(now-121, timezone.utc).isoformat()
        refused(bad)
    # Exercise the new file-based JS entry without a source wallet/key. A bad
    # network must reach utxoRequest's refusal, not an RPC or wallet-key error.
    invalid = dict(target, genesis='00'*32)
    save(root/'invalid-target.json', invalid)
    result = subprocess.run(['node', str(ROOT/'scripts/observe_testnet_auxiliary.mjs'),
        '--receiver', str(root/'invalid-target.json'), str(root/'invalid-observation')],
        capture_output=True, text=True, timeout=10)
    if result.returncode != 1 or result.stderr.strip() != 'dedicated testnet P2PKH receiver required':
        raise RuntimeError('receiver-file path did not refuse before network access')
    return {'scope': 'real native verification and target derivation; explicit synthetic UTXO-response tests only',
        'agreement_digest': checked['agreement_digest'], 'signed_refund_target_derived_without_source_keys': True,
        'original_source_and_owner_fixture_os_denied': True,
        'address_checksum_and_script_match_independently_checked': True,
        'exact_outpoint_required_not_same_value_substitution': True,
        'missing_duplicate_shallow_changed_script_stale_refused': True,
        'receiver_file_wrong_network_refused_before_rpc': True,
        'public_funded_auxiliary_observed': False, 'broadcast': False, 'funding_authorized': False}


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:3])), indent=2))
