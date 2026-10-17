"""Local browser adapter for canonical owner-signed OTC quotes. Never funds."""
import otc_offer
from public_authority import owner_locked
from regtest_wallet import native, save
from run_client_swap import client


def create(directory, zec, eth):
    # Validate before allocating identities. Demo bankroll is intentionally small;
    # protocol/CLI limits remain independent of this local UI limit.
    otc_offer.units(zec,8,100_000_000)
    otc_offer.units(eth,18,10*10**18)
    directory.mkdir(mode=0o700)
    owners=directory/'owners'; owners.mkdir(mode=0o700)
    identities={}
    for role in ('alice','bob'):
        owner=owners/role;owner.mkdir(mode=0o700)
        identities[role]=client('key-init',owner,role=role)
    for role in identities:
        save(owners/role/'trusted-peer.json',{'identity':identities['bob' if role=='alice' else 'alice']})
    with owner_locked(owners/'alice'):
        offer=otc_offer.execute(owners/'alice','offer-create',{'zec_amount':zec,'eth_amount':eth})
    save(directory/'offer.json',offer)
    return describe(directory)


def describe(directory):
    accepted=(directory/'accepted.json').exists()
    packet=otc_offer.read(directory/('accepted.json' if accepted else 'offer.json'))
    # Public presentation derives strings from canonical signed integers, never
    # floating point. The immutable accepted record survives moving owner roots.
    checked=native('otc-verify-acceptance' if accepted else 'otc-verify-offer',directory/('accepted.json' if accepted else 'offer.json'))
    summary=otc_offer.summary(packet,checked)
    payload=packet['offer']['payload']
    # Only public quote fields: amounts, fixed fees, chain domain and the two
    # signers' ETH identities that Bob must recognize before accepting.
    return {'zec_amount':summary['zec_received_by_bob'],'eth_amount':summary['eth_received_by_alice'],
        'quote_digest':summary['quote_digest'],'alice_signed':True,'bob_accepted':accepted,
        'funding_authorized':False,'indicative_eth_per_zec':summary['indicative_eth_per_zec'],
        'claim_fee_zec':otc_offer.decimal_amount(payload['claim_fee_zatoshi'],8),
        'refund_aux_fee_zec':otc_offer.decimal_amount(payload['refund_aux_fee_zatoshi'],8),
        'alice_address':payload['owners']['alice']['address'],'bob_address':payload['owners']['bob']['address'],
        'eth_chain_id':payload['eth_chain_id']}


def accept(directory):
    offer=otc_offer.read(directory/'offer.json')
    with owner_locked(directory/'owners/bob'):
        accepted=otc_offer.execute(directory/'owners/bob','offer-accept',offer)
    with owner_locked(directory/'owners/alice'):
        otc_offer.execute(directory/'owners/alice','offer-accept',accepted)
    save(directory/'accepted.json',accepted)
    return describe(directory)
