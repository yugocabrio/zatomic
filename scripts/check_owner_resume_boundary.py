#!/usr/bin/env python3
"""Adversarial checks on a real owner claim-send interruption, before recovery.

Uses only the owned restored Anvil checkpoint and real accepted native funding.
Never edits the saved checkpoint, exposes the signed intent, or broadcasts a
replacement. Run while the original claim window is still open.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import owner_swap as flow
import run_native_evm_gate as evm
from run_client_swap import client


def digest(path):
    return hashlib.sha256(path.read_bytes()).digest()


def check(directory):
    checkpoint = directory / 'evm-checkpoint.json'
    intent = directory / 'owners/alice/eth-intent-claim.json'
    before = (digest(checkpoint), digest(intent))
    with flow.chain_lock(), flow.node(directory, restore=True):
        agreement = flow.validate_recovery(directory)
        order = flow.read(directory / '04-eth-locked.json')['order']
        if flow.order_state(agreement, agreement['native'], order) != 1:
            raise RuntimeError('requires checkpoint before an actually signed claim')
        identity = directory / 'owners/alice/identity.json'
        unavailable = identity.with_suffix('.unavailable')
        if unavailable.exists():
            raise RuntimeError('test identity temporary path occupied')
        identity.rename(unavailable)
        try:
            try:
                flow.validate_recovery(directory)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError('missing owner identity did not reject recovery')
        finally:
            unavailable.rename(identity)
        evm.rpc('evm_setNextBlockTimestamp', [agreement['eth_expiry']])
        evm.rpc('evm_mine')
        client('claim', directory / 'owners/alice', {'order': order}, reject=True)
        if flow.order_state(agreement, agreement['native'], order) != 1:
            raise RuntimeError('failed claim unexpectedly resolved escrow')
        if (directory / 'owners/bob/eth-intent-refund.json').exists():
            raise RuntimeError('claim ambiguity became a refund intent')
    if before != (digest(checkpoint), digest(intent)):
        raise RuntimeError('rejection changed durable checkpoint/intent')
    return {'scope': 'actual paused owner flow; temporary owned-node clock only',
        'missing_owner_identity_rejected': True, 'expired_ambiguous_claim_rejected': True,
        'no_refund_created': True, 'checkpoint_and_signed_intent_unchanged': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(check(args.directory.resolve()), indent=2))
