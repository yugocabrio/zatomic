#!/usr/bin/env python3
"""Capture an already exposed opening, never reveal one or send a transaction.

Exact known transaction hashes include pending/reverted/orphaned attempts. Bounded
event queries cover only provider-returned logs, not all mempools. Acceptance is
the real native adaptor/signature check and is independent of ETH finality.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
import public_authority as authority
import public_evm_observation as eth
import public_outgoing as outgoing
import probe_sepolia as sepolia
from regtest_wallet import native
from source_inputs import publish
from testnet_wallet import read

CLAIM_SELECTOR = '0x63f44968'
Q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001


def scalar(word):
    value = int.from_bytes(eth.data(word, 32), 'big')
    if not 0 < value < Q: raise RuntimeError('noncanonical or zero opening')
    return value.to_bytes(32, 'little').hex()


def from_transaction(agreement, txid, value):
    if value is None: return None
    order = eth.order_id(agreement)
    if (not isinstance(value, dict) or value.get('hash') != txid
            or value.get('to') != agreement['escrow']['contract']
            or sepolia.quantity(value['chainId']) != agreement['eth_chain_id']
            or sepolia.quantity(value['value']) != 0):
        raise RuntimeError('observed claim transaction domain mismatch')
    payload = value['input']
    if not isinstance(payload, str) or not re.fullmatch(CLAIM_SELECTOR + order[2:] + '[0-9a-f]{64}', payload):
        raise RuntimeError('exact agreed claim calldata required')
    # No success/receipt/block/finality condition: the bytes themselves expose t.
    return scalar('0x'+payload[-64:])


def from_event(agreement, event, first, last):
    if (not isinstance(event, dict) or event.get('address') != agreement['escrow']['contract']
            or event.get('topics') != [sepolia.CLAIM_TOPIC, eth.order_id(agreement)]
            or not first <= sepolia.quantity(event['blockNumber']) <= last
            or type(event.get('removed')) is not bool):
        raise RuntimeError('observed claim event domain/range mismatch')
    eth.data(event['blockHash'], 32); eth.data(event['transactionHash'], 32)
    sepolia.quantity(event['logIndex'])
    # Even removed logs can carry a valid, irrevocably learned opening.
    return scalar(event['data'])


def context(owner, consents):
    files, checked = authority.verified_files(owner/'public-native-recovery.json',
        owner/'public-consent-proposal.json', consents)
    caller = authority.bind_owner(owner, files, checked, 'native_claim')
    return files, checked, caller


def workspace(owner, files, checked):
    directory = owner/'public-observed-opening'; outgoing.private_directory(directory)
    outgoing.immutable(directory/'binding.json', {'agreement_digest': checked['agreement_digest'],
        'bundle_digest': checked['bundle_digest'], 'synthetic_inputs': checked['synthetic_inputs'], 'role': 'bob'})
    outgoing.immutable(directory/'native-recovery.json', files['bundle'])
    outgoing.immutable(directory/'owner-receipt.json', files['proposal']['receipts']['bob'])
    return directory


def accepted(directory, checked):
    path = directory/'opening.json'
    if not path.exists() and not path.is_symlink(): return None
    # Never trust saved verification booleans; replay verifies the scalar and
    # actual native claim against the retained bundle, even with RPC unavailable.
    report = native('testnet-accept-opening', directory, path, path)
    if (report['bundle_digest'] != checked['bundle_digest']
            or report['synthetic_inputs'] != checked['synthetic_inputs']
            or report['native_claim_authorization_verified'] is not True):
        raise RuntimeError('observed opening no longer matches accepted native bundle')
    return report


def acquire(agreement, directory, checked, observation, call, txid=None, first=None, last=None):
    """Narrow reader boundary; real native acceptance is NEVER injected.

    Public entry validates identity first. Offline checks use explicit transcripts
    here without misrepresenting synthetic inputs as public chain funds.
    """
    if eth.digest(agreement) != checked['agreement_digest'] or agreement['bundle_digest'] != checked['bundle_digest']:
        raise RuntimeError('opening query differs from accepted agreement')
    if txid is not None:
        params = [txid]; sepolia.read_method('eth_getTransactionByHash', params)
        raw = call('eth_getTransactionByHash', params)
        outgoing.immutable(observation/'transaction.json', {'response': raw})
        values = [from_transaction(agreement, txid, raw)]
    else:
        params = [{'address': agreement['escrow']['contract'], 'fromBlock': hex(first), 'toBlock': hex(last),
            'topics': [sepolia.CLAIM_TOPIC, eth.order_id(agreement)]}]
        sepolia.read_method('eth_getLogs', params)
        raw = call('eth_getLogs', params)
        outgoing.immutable(observation/'events.json', {'response': raw})
        if not isinstance(raw, list) or len(raw) > 8: raise RuntimeError('bounded claim-event response required')
        values = (from_event(agreement, v, first, last) for v in raw)
    count = 0
    for candidate in values:
        if candidate is None: continue
        path = observation/f'candidate-{count}.json'; count += 1
        outgoing.immutable(path, {'witness_le': candidate})
        # Durably accept before any subsequent reader can fail. Invalid scalar
        # relations fail closed without deleting earlier valid observations.
        report = native('testnet-accept-opening', directory, path, directory/'opening.json')
        if report['bundle_digest'] != checked['bundle_digest']:
            raise RuntimeError('native opening bundle changed')
    report = accepted(directory, checked)
    return {'format': 'latch-public-opening-observation-v1', 'agreement_digest': checked['agreement_digest'],
        'opening_available': report is not None, 'candidates_checked': count,
        'native_authorization': report, 'settlement_verified': False, 'provider_trusted_for_provenance': True,
        'mempool_completeness_claimed': False, 'exposure_excluded': False, 'broadcast': False, 'send_authorized': False}


def capture(owner, consents, txid=None, first=None, last=None, endpoint=sepolia.ENDPOINT):
    with authority.owner_locked(owner):
        files, checked, caller = context(owner, consents)
        if checked['synthetic_inputs'] is not False:
            raise RuntimeError('synthetic inputs cannot enter public opening capture')
        agreement = files['proposal']['agreement']
        if txid is not None:
            if first is not None or last is not None: raise RuntimeError('choose one observation source')
            sepolia.read_method('eth_getTransactionByHash', [txid])
        elif type(first) is not int or type(last) is not int or not 0 <= first <= last < 2**64 or last-first >= 256:
            raise RuntimeError('explicit bounded event heights required')
        call = sepolia.ReadOnlyRpc(endpoint)
        directory = workspace(owner, files, checked)
        prior = accepted(directory, checked)
        folder = directory/'observations'; outgoing.private_directory(folder)
        if len(list(folder.iterdir())) >= 128: raise RuntimeError('opening history full; preserve it and use offline inspect')
        observation = folder/uuid.uuid4().hex; outgoing.private_directory(observation)
        publish(observation/'intent.json', {'agreement_digest': checked['agreement_digest'], 'endpoint': endpoint,
            'transaction': txid, 'from_block': first, 'to_block': last, 'previously_accepted': prior is not None})
        # Identity before disclosing contract/order/hash. No finality/balance/
        # timestamp gate: learning a valid opening is useful even after expiry.
        if sepolia.quantity(call('eth_chainId', [])) != sepolia.CHAIN_ID:
            raise RuntimeError('opening provider chain mismatch')
        genesis = sepolia.block('0x0', call)
        if genesis['height'] != 0 or genesis['hash'] != sepolia.GENESIS:
            raise RuntimeError('opening provider genesis mismatch')
        result = acquire(agreement, directory, checked, observation, call, txid, first, last)
        if authority.bind_owner(owner, files, checked, 'native_claim') != caller or read(consents) != files['consents']:
            raise RuntimeError('caller acceptance changed during opening capture')
        publish(observation/'report.json', result)
        return result


def inspect(owner, consents):
    with authority.owner_locked(owner):
        files, checked, _ = context(owner, consents)
        directory = workspace(owner, files, checked)
        return {'native_authorization': accepted(directory, checked), 'offline': True,
            'send_authorized': False, 'settlement_verified': False}


def resume(owner, consents, identifier):
    """Resume an interrupted raw-response -> acceptance boundary without RPC.

    A crash may precede candidate parsing or the native durable acceptance.
    Replay the original private response against the same owner's agreement.
    """
    if not re.fullmatch('[0-9a-f]{32}', identifier): raise RuntimeError('exact observation ID required')
    with authority.owner_locked(owner):
        files, checked, _ = context(owner, consents)
        directory = workspace(owner, files, checked)
        folder = directory/'observations'/identifier
        if not folder.exists(): raise RuntimeError('retained observation required')
        outgoing.private_directory(folder)
        intent = read(folder/'intent.json')
        if intent['agreement_digest'] != checked['agreement_digest']: raise RuntimeError('retained observation agreement changed')
        txid, first, last = intent['transaction'], intent['from_block'], intent['to_block']
        if txid is not None:
            if first is not None or last is not None: raise RuntimeError('retained observation source ambiguous')
            expected_method, name = 'eth_getTransactionByHash', 'transaction.json'
        else:
            if type(first) is not int or type(last) is not int or not 0 <= first <= last < 2**64 or last-first >= 256:
                raise RuntimeError('retained event range invalid')
            expected_method, name = 'eth_getLogs', 'events.json'
        def saved(method, params):
            if method != expected_method: raise RuntimeError('retained observation source changed')
            sepolia.read_method(method, params)
            return read(folder/name)['response']
        return dict(acquire(files['proposal']['agreement'], directory, checked, folder, saved, txid, first, last), offline=True)


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('capture', 'inspect', 'resume'))
    p.add_argument('owner', type=Path); p.add_argument('consents', type=Path)
    p.add_argument('--observation', help='exact private observation ID to resume without RPC')
    p.add_argument('--transaction'); p.add_argument('--from-block', type=int); p.add_argument('--to-block', type=int)
    p.add_argument('--endpoint', default=sepolia.ENDPOINT)
    a = p.parse_args()
    if a.operation == 'resume':
        if a.observation is None: raise RuntimeError('resume requires --observation')
        result = resume(a.owner, a.consents, a.observation)
    elif a.operation == 'inspect': result = inspect(a.owner, a.consents)
    else: result = capture(a.owner, a.consents, a.transaction, a.from_block, a.to_block, a.endpoint)
    print(json.dumps(result, indent=2))
    return 2 # A private verified opening is not a sending decision.


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Opening observation refused; retained private data preserved, no transaction sent.') from None
