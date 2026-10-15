#!/usr/bin/env python3
"""Check exact user-entered amounts and authenticated quotes without any funds."""
import copy
import json
import os
from pathlib import Path
import sys
from check_independent_operators import Operators
from latch_operator import manifest_digest
from otc_offer import units


def check(root):
    root.mkdir(mode=0o700)
    (root / 'harness').mkdir(mode=0o700)
    actors = Operators(root)
    identities = {r: actors.invoke(r, 'init')['manifest'] for r in ('alice', 'bob')}
    for role in identities:
        peer = identities['bob' if role == 'alice' else 'alice']
        actors.invoke(role, 'trust-peer', {'manifest': peer, 'expected_manifest_sha256': manifest_digest(peer)})
    invalid = ['0', '-1', 'NaN', '1e-8', ' 1', '01', '1.', '0.000000001', 0.01, True]
    for value in invalid:
        try:
            units(value, 8, 21_000_000 * 10**8 - 20_000)
        except ValueError:
            pass
        else:
            raise RuntimeError('noncanonical/invalid amount accepted')
    assert units('0.00000001', 8, 10**8) == 1
    assert units('0.150000000000000001', 18, 10**19) == 150000000000000001
    request = {'zec_amount': '5', 'eth_amount': '0.150000000000000001'}
    offer = actors.invoke('alice', 'offer-create', request)
    if actors.invoke('alice', 'offer-create', request) != offer:
        raise RuntimeError('seller retry changed the quote')
    mutations = [(['payout_zatoshi'], 500_000_001), (['eth_amount_wei'], 150000000000000002),
        (['claim_fee_zatoshi'], 0), (['native_genesis'], '00' * 32), (['eth_chain_id'], 1),
        (['quote_id'], '00' * 32), (['owners','bob','public_key'], identities['alice']['identity']['public_key'])]
    for path, value in mutations:
        changed = copy.deepcopy(offer)
        part = changed['offer']['payload']
        for key in path[:-1]:
            part = part[key]
        part[path[-1]] = value
        actors.invoke('bob', 'offer-review', changed, reject=True)
    reviewed = actors.invoke('bob', 'offer-review', offer)
    accepted = actors.invoke('bob', 'offer-accept', offer)
    damaged = copy.deepcopy(accepted)
    damaged['acceptance']['payload']['quote_digest'] = '00' * 32
    actors.invoke('alice', 'offer-accept', damaged, reject=True)
    if actors.invoke('alice', 'offer-accept', accepted) != accepted:
        raise RuntimeError('seller accepted a different quote')
    actors.invoke('alice', 'offer-create', {'zec_amount':'6','eth_amount':request['eth_amount']}, reject=True)
    return {'scope':'fresh operator keys, no source wallet or chain transactions',
        'canonical_decimal_rejections':len(invalid),'signed_quote_mutation_rejections':len(mutations),
        'changed_acceptance_rejected':True,'seller_replacement_rejected':True,
        'exact_smallest_units':True,'seller_retry_identical':True,
        'review':reviewed,'funded_swap':False}


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(Path(sys.argv[1]).resolve()), indent=2))
