"""Owner-local exact-price OTC quotes. No discovery, market pricing or broadcasting.

Public messages contain economic terms and owner identities, never note data.
The subsequent complete cross-chain consent is still required before funding.
"""
import hashlib
import json
import os
import re
from decimal import Decimal, localcontext
from pathlib import Path
import evm_wallet
from regtest_node import GENESIS, BRANCH
from regtest_wallet import native, save
from signer_transport import private_file


def read(path):
    return json.loads(private_file(path, 200_000))


def profile(directory):
    chain = read(directory / 'identity.json')['chain_id']
    if chain == 31338:
        return GENESIS, chain, ''
    if chain == 11155111:
        from testnet_wallet import GENESIS as testnet_genesis
        return testnet_genesis, chain, 'testnet-'
    raise RuntimeError('unsupported quote identity network')


def digest(domain, payload):
    return hashlib.sha256(domain + json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).digest()


def units(text, decimals, maximum):
    if not isinstance(text, str) or not re.fullmatch(r'(?:0|[1-9][0-9]*)(?:\.[0-9]{1,' + str(decimals) + r'})?', text) or len(text) > 60:
        raise ValueError('plain decimal amount with supported precision required')
    whole, _, fraction = text.partition('.')
    value = int(whole) * 10**decimals + int(fraction.ljust(decimals, '0'))
    if not 0 < value <= maximum:
        raise ValueError('positive amount within the isolated profile required')
    return value


def decimal_amount(value, decimals):
    whole, fraction = divmod(value, 10**decimals)
    return str(whole) + (('.' + str(fraction).zfill(decimals).rstrip('0')) if fraction else '')


def owners(directory):
    own = read(directory / 'identity.json')
    peer = read(directory / 'trusted-peer.json')['identity']
    return own, {own['role']: own, peer['role']: peer}


def verify(directory, packet, accepted=False):
    candidate = directory / ('otc-message-' + digest(b'', packet).hex() + '.json')
    save(candidate, packet)
    _, _, prefix = profile(directory)
    result = native(prefix + ('otc-verify-acceptance' if accepted else 'otc-verify-offer'), candidate)
    _, expected = owners(directory)
    if packet['offer']['payload']['owners'] != expected:
        raise RuntimeError('OTC identities differ from authenticated local pins')
    return result


def summary(packet, result):
    p = packet['offer']['payload']
    zec = decimal_amount(p['payout_zatoshi'], 8)
    eth = decimal_amount(p['eth_amount_wei'], 18)
    with localcontext() as ctx:
        ctx.prec = 40
        rate = format(Decimal(eth) / Decimal(zec), '.12f')
    return dict(result, seller='alice', buyer='bob', zec_received_by_bob=zec,
        eth_received_by_alice=eth, indicative_eth_per_zec=rate,
        price_source='agreed by peers; no market price feed',
        claim_fee_zatoshi=10_000, refund_auxiliary_fee_zatoshi=5_000,
        amount_excludes_source_funding_fee=True, quote_does_not_authorize_funding=True)


def execute(directory, action, packet):
    own, pins = owners(directory)
    genesis, chain, _ = profile(directory)
    if action == 'offer-create':
        if own['role'] != 'alice':
            raise RuntimeError('only the ZEC seller creates an OTC quote')
        p = {'version': 1, 'native_genesis': genesis, 'native_branch': BRANCH,
            'eth_chain_id': chain, 'owners': pins, 'quote_id': os.urandom(32).hex(),
            'payout_zatoshi': units(packet['zec_amount'], 8, 21_000_000 * 10**8 - 20_000),
            'eth_amount_wei': units(packet['eth_amount'], 18, 10 * 10**18),
            'claim_fee_zatoshi': 10_000, 'refund_aux_fee_zatoshi': 5_000}
        # One quote per fresh operator session. Never create signatures for a
        # replacement after the seller has already pinned an offer.
        if (directory / 'created-offer.json').exists():
            previous = read(directory / 'created-offer.json')
            if any(previous['offer']['payload'][k] != p[k] for k in p if k != 'quote_id'):
                raise RuntimeError('seller has already issued different terms')
            return previous
        offer = {'payload': p, 'signature': evm_wallet.sign_digest(directory / 'ethereum', digest(b'Latch OTC offer v1\0', p))}
        value = {'offer': offer}
        verify(directory, value)
        save(directory / 'created-offer.json', value)
        return value
    if action == 'offer-review':
        return summary(packet, verify(directory, packet, 'acceptance' in packet))
    if action == 'offer-accept':
        result = verify(directory, packet)
        if own['role'] == 'bob':
            # Pin the exact offer BEFORE returning a reusable acceptance signature.
            save(directory / 'reviewed-offer.json', {'offer': packet['offer']})
            p = {'version': 1, 'role': 'bob', 'quote_digest': result['quote_digest']}
            accepted = {'offer': packet['offer'], 'acceptance': {'payload': p,
                'signature': evm_wallet.sign_digest(directory / 'ethereum', digest(b'Latch OTC acceptance v1\0', p))}}
        else:
            if read(directory / 'created-offer.json')['offer'] != packet['offer']:
                raise RuntimeError('acceptance is not for the seller issued quote')
            accepted = packet
        verify(directory, accepted, True)
        save(directory / 'accepted-trade.json', accepted)
        return accepted
    raise RuntimeError('unknown OTC command')
