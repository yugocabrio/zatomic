"""Alice's local source-wallet release policy for a staged, signed swap offer.

The Rust gate independently verifies both pinned owner signatures and the exact
unsigned native transaction. This client additionally observes the own nodes,
escrow code and controlled-fixture time window immediately before release.
Do not expose the lower-level offline CLI as a network authorization service.
"""
import argparse
import json
from pathlib import Path
import os
import run_native_evm_gate as evm
from regtest_node import status, rpc as zrpc
from regtest_wallet import native
from evm_journal import verify_contract, InjectedStop
from run_regtest_swap import require_aux_unspent


def authorize(bank, staged, packet, stop_before_sign=False):
    # Signatures/immutable policy are checked first, even if funding.hex exists.
    verified = native('regtest-check-consent', staged, packet)
    agreement = json.loads(packet.read_text())['agreement']
    if int(evm.rpc('eth_chainId'), 16) != evm.CHAIN:
        raise RuntimeError('source wallet observed wrong EVM chain')
    verify_contract(agreement)
    now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
    if now + 300 >= agreement['eth_expiry'] or status()['blocks'] + 12 >= agreement['native']['refund_height']:
        raise RuntimeError('source wallet refuses an expired funding window')
    require_aux_unspent(agreement['native'])
    terms = agreement['native']
    if 'funding_anchor_height' in terms:
        if (terms['funding_anchor_height'] > status()['blocks']
                or zrpc('getblockhash', [terms['funding_anchor_height']]) != terms['funding_anchor_tip']):
            raise RuntimeError('source wallet refuses an orphaned funding anchor')
    if 'source_guard' in agreement['native']:
        native('regtest-commit-funding', staged, packet)
        if stop_before_sign:
            raise InjectedStop('source-release-intent')
    result = native('regtest-authorize-funding', bank, staged, packet)
    if result['txid'] != verified['funding_txid']:
        raise RuntimeError('source wallet funding identity changed')
    return dict(verified, file=result['file'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bank', type=Path)
    parser.add_argument('staged', type=Path)
    parser.add_argument('packet', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(authorize(args.bank.resolve(), args.staged.resolve(), args.packet.resolve())))
