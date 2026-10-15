#!/usr/bin/env python3
"""Refuse an orphaned agreed anchor before source signing/release.

Use a fresh offer paused at both-consented. Restores the original owned chain;
then the normal resume command can fund and settle the same signed offer.
"""
import argparse
import json
import os
from pathlib import Path
import owner_swap as flow
from check_native_reorg import invalidated, restore
from check_evm_reorg import digest
from funding_wallet import authorize
from regtest_node import rpc, status
from regtest_wallet import save


def check(directory):
    with flow.chain_lock():
        restore(directory)
        staged = directory / 'coordinator-native-offline'
        if (staged / 'funding.hex').exists() or (directory / 'source-release.json').exists():
            raise RuntimeError('requires an unreleased fully consented offer')
        packet = directory / 'consent-packet.json'
        terms = flow.read(packet)['agreement']['native']
        bank = Path(flow.read(directory / 'setup.json')['bank'])
        original, original_packet = status()['tip'], digest(packet)
        with flow.node(directory, restore=True):
            with invalidated(directory, terms['funding_anchor_tip']):
                before, pool = status()['tip'], rpc('getrawmempool')
                try:
                    authorize(bank, staged, packet)
                except RuntimeError as exc:
                    if str(exc) != 'source wallet refuses an orphaned funding anchor':
                        raise
                else:
                    raise RuntimeError('source wallet signed against an orphaned anchor')
                if (status()['tip'] != before or rpc('getrawmempool') != pool
                        or (staged / 'funding.hex').exists()
                        or (directory / 'source-release.json').exists()
                        or digest(packet) != original_packet):
                    raise RuntimeError('orphaned anchor rejection altered source authority')
        if status()['tip'] != original:
            raise RuntimeError('source release check failed to restore original branch')
        result = {'scope': 'actual native fork before source release',
            'orphaned_agreed_anchor_rejected': True, 'source_release_absent': True,
            'broadcastable_funding_absent': True, 'signed_offer_unchanged': True,
            'no_native_mutation_by_wallet': True, 'original_branch_restored': True}
        save(directory / 'funding-anchor-release-checks.json', result)
        return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    print(json.dumps(check(a.directory.resolve()), indent=2))
