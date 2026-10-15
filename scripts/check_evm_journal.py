#!/usr/bin/env python3
"""Validate real signed local intents and reject corrupt replay metadata offline.

Reads a private completed fixture; never prints raw calldata or broadcasts.
"""
import argparse
import copy
import json
from pathlib import Path
import subprocess
from evm_journal import validate_intent
from run_native_evm_gate import calldata


def run(directory):
    intents = [json.loads(p.read_text()) for p in sorted((directory / 'evm-outgoing').glob('*.json'))]
    assert intents, 'fixture has no signed outgoing intents'
    for intent in intents:
        validate_intent(intent)
    claim = next(intent for intent in intents if intent['kind'] == 'claim')
    mutations = [
        ('claim relabeled withdrawal', lambda j: j.update(kind='withdraw')),
        ('claim relabeled deployment', lambda j: j.update(kind='deploy')),
        ('transaction identity', lambda j: j.update(txid='0x' + '00' * 32)),
        ('network metadata', lambda j: j.update(chain_id=1)),
        ('sender metadata', lambda j: j['transaction'].update({'from': '0x' + '00' * 20})),
        ('recipient metadata', lambda j: j['transaction'].update(to='0x' + '00' * 20)),
        ('nonce metadata', lambda j: j['transaction'].update(nonce='0xffffffff')),
        ('amount metadata', lambda j: j['transaction'].update(value='0x1')),
        ('method metadata', lambda j: j['transaction'].update(data='0x00000000')),
        ('invalid signature encoding', lambda j: j.update(raw='0x00')),
    ]
    for name, mutate in mutations:
        changed = copy.deepcopy(claim)
        mutate(changed)
        try:
            validate_intent(changed)
        except (RuntimeError, ValueError):
            pass
        else:
            raise AssertionError(f'accepted corrupt intent: {name}')
    # Only public test scalars go to the external reference encoder's argv.
    order = '0x' + '12' * 32
    for scalar in (0, 1, 2**255, 2**256 - 1):
        reference = subprocess.check_output(['cast', 'calldata', 'claim(bytes32,uint256)', order, str(scalar)], text=True).strip()
        assert calldata('claim(bytes32,uint256)', order, scalar) == reference
    for order, scalar in [('0x12', 1), ('0x' + '12' * 32, -1), ('0x' + '12' * 32, 2**256)]:
        try:
            calldata('claim(bytes32,uint256)', order, scalar)
        except RuntimeError:
            pass
        else:
            raise AssertionError('accepted invalid static ABI claim')
    return {'scope': 'offline signed intent decoding; no chain mutation',
        'validated_actual_signed_transactions': len(intents),
        'rejected': [name for name, _ in mutations],
        'claim_abi_matches_independent_encoder': True,
        'unrevealed_witness_excluded_from_process_arguments': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(run(parser.parse_args().directory.resolve()), indent=2))
