#!/usr/bin/env python3
"""The two-party relay sees identities in the clear and nothing else of a trade.

Run against a finished two-party workspace. Every relay record must be either an
identity manifest (public keys and ETH addresses) or an envelope sealed to the
recipient. The trade's private values (ZEC amounts, funding txid, joint note
commitment, refund auxiliary outpoint, receive addresses, ETH salt and quote)
must not appear anywhere in the relay's files. Reads local private files to
learn those values; prints only counts and field names.
"""
import json
from pathlib import Path
import sys

MANIFEST_FIELDS = {'version', 'role', 'certificate_pem', 'certificate_sha256', 'identity', 'relay_public_key'}
COORDINATOR_FIELDS = {'version', 'role', 'certificate_pem', 'certificate_sha256'}
ENVELOPE_FIELDS = {'v', 'from', 'to', 'epk', 'nonce', 'ct'}
# Field names of the sealed messages; none may be visible to the relay.
PRIVATE_NAMES = ('principal_zatoshi', 'payout_zatoshi', 'eth_amount_wei', 'amount_wei', 'funding_txid',
    'pending_cmx', 'aux_outpoint', 'refund_height', 'quote_id', 'eth_salt', 'quote_digest', 'agreement')


def private_values(workspace):
    terms = json.loads((workspace / 'alice-source/swap/terms.json').read_text())
    policy = json.loads(next(workspace.rglob('claim-policy.json')).read_text())
    agreement = json.loads((workspace / 'alice-app/state.json').read_text())['agreement']
    offer = terms['trade']['offer']['payload']
    return {'funding_txid': terms['funding_txid'], 'pending_cmx': terms['pending_cmx'],
        'aux_txid': terms['aux_outpoint']['txid'], 'alice_receiver': policy['alice_receiver'],
        'bob_receiver': policy['bob_receiver'], 'eth_salt': agreement['eth_salt'], 'quote_id': offer['quote_id']}


def check(workspace):
    records = sorted((workspace / 'relay').glob('*.json'))
    raw = [path.read_text() for path in records]
    messages = [json.loads(text) for text in raw]
    sealed = clear = 0
    for message in messages:
        body = message['body']
        if message['topic'] == 'manifest':
            for role, manifest in body.items():
                allowed = COORDINATOR_FIELDS if role == 'coordinator' else MANIFEST_FIELDS
                if role not in ('alice', 'bob', 'coordinator') or not set(manifest) <= allowed:
                    raise RuntimeError('identity manifest carries more than public identity fields')
            clear += 1
        elif message['topic'] == 'sealed' and set(body) == ENVELOPE_FIELDS and body['from'] == message['from']:
            sealed += 1
        else:
            raise RuntimeError(f'relay record {message["seq"]} is neither an identity nor a sealed envelope')
    text = '\n'.join(raw)
    names = [name for name in PRIVATE_NAMES if f'"{name}"' in text]
    values = [label for label, value in private_values(workspace).items() if value.lower() in text.lower()]
    if names or values:
        raise RuntimeError(f'relay exposes {names + values}')
    return {'scope': 'one finished two-party workspace', 'relay_records': len(messages),
        'identity_manifests_in_clear': clear, 'sealed_envelopes': sealed,
        'private_field_names_found': 0, 'private_values_found': 0,
        'private_values_checked': sorted(private_values(workspace))}


if __name__ == '__main__':
    print(json.dumps(check(Path(sys.argv[1]).resolve()), indent=2))
