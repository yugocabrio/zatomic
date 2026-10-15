#!/usr/bin/env python3
"""Owner-local Sepolia action authorization, never a broadcaster.

An immutable claim decision precedes reading the opening or signing. Missing raw
bytes/receipts never clear possible exposure. Only the live prepare wrapper can
start from fresh observations; resume finishes exactly the existing decision.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
import evm_wallet
import fee_policy
import public_authority as authority
import public_evm_observation as eth
import public_opening as opening
import public_outgoing as outgoing
import public_preflight as preflight
import probe_sepolia
from regtest_wallet import native
from source_inputs import publish
from testnet_wallet import read

JOURNAL = 'public-eth-outgoing'
CHAIN = 11155111
PHASE = {'lock': 'eth_lock', 'claim': 'first_reveal'}
ROLE = {'lock': 'bob', 'claim': 'alice'}


def action_role(kind, role=None):
    expected = {'lock': 'bob', 'claim': 'alice', 'refund': 'bob', 'withdraw': role}.get(kind)
    if expected not in ('alice', 'bob') or (role is not None and role != expected):
        raise RuntimeError('wrong owner action')
    return expected


def context(owner, consents, action=None):
    files, checked = authority.verified_files(owner/'public-native-recovery.json',
        owner/'public-consent-proposal.json', consents)
    role = read(owner/'identity.json')['role']
    kind = action or {'alice': 'claim', 'bob': 'lock'}[role]
    action_role(kind, role)
    caller = authority.bind_owner(owner, files, checked, action_phase(kind, role))
    return files, checked, caller, kind


def action_phase(kind, role):
    action_role(kind, role)
    return PHASE[kind] if kind in PHASE else {'alice': 'native_refund', 'bob': 'native_claim'}[role]


def workspace(owner, files, checked, role):
    directory = owner/JOURNAL; outgoing.private_directory(directory)
    binding = {'format': 'latch-public-eth-outgoing-v1', 'role': role,
        'agreement_digest': checked['agreement_digest'], 'bundle_digest': checked['bundle_digest'],
        'synthetic_inputs': checked['synthetic_inputs'], 'send_authorized': False}
    outgoing.immutable(directory/'binding.json', binding)
    for name in ('bundle', 'proposal', 'consents'): outgoing.immutable(directory/(name+'.json'), files[name])
    return directory, binding


def exposure(owner, files, checked):
    """Caller holds operator.lock. No raw, key, opening or RPC read required.

    Only an initialized exact journal can say this client never began a claim.
    This is a local-history assertion, not proof of no out-of-band disclosure.
    """
    directory = owner/JOURNAL
    if not directory.exists() and not directory.is_symlink():
        return {'local_history_initialized': False, 'local_claim_may_be_exposed': True,
            'external_exposure_excluded': False}
    outgoing.private_directory(directory)
    role = read(owner/'identity.json')['role']
    expected = {'format': 'latch-public-eth-outgoing-v1', 'role': role,
        'agreement_digest': checked['agreement_digest'], 'bundle_digest': checked['bundle_digest'],
        'synthetic_inputs': checked['synthetic_inputs'], 'send_authorized': False}
    if read(directory/'binding.json') != expected or any(read(directory/(k+'.json')) != files[k] for k in files):
        raise RuntimeError('ETH exposure history context changed')
    # An interrupted directory creation before decision persistence is already
    # uncertain. Do not infer non-exposure from missing decision/raw/receipt.
    path = directory/'claim'
    return {'local_history_initialized': True,
        'local_claim_may_be_exposed': path.exists() or path.is_symlink(),
        'external_exposure_excluded': False}


def require_no_local_claim(owner, files, checked):
    status = exposure(owner, files, checked)
    if not status['local_history_initialized'] or status['local_claim_may_be_exposed']:
        raise RuntimeError('missing or possibly exposed local claim history; no refund fallback')
    return status


def prefix(agreement, kind, role=None):
    if kind == 'claim': return opening.CLAIM_SELECTOR + eth.order_id(agreement)[2:]
    if kind == 'refund': return '0x'+evm_wallet.keccak(b'refund(bytes32)')[:4].hex()+eth.order_id(agreement)[2:]
    if kind == 'withdraw':
        address = agreement['owners'][action_role(kind, role)]['address']
        return '0x'+evm_wallet.keccak(b'withdraw(address)')[:4].hex()+eth.data(address, 20).hex().rjust(64, '0')
    if kind != 'lock': raise RuntimeError('unsupported public ETH action')
    selector = evm_wallet.keccak(b'lock(bytes32,address,uint64,(uint256,uint256),bytes32)')[:4].hex()
    return '0x'+selector+agreement['escrow']['salt'][2:]+agreement['recipient'][2:].rjust(64, '0')+''.join(
        n.to_bytes(32, 'big').hex() for n in (agreement['eth_expiry'],
        int(agreement['point_x'], 16), int(agreement['point_y'], 16), int(eth.digest(agreement), 16)))


def transaction_base(agreement, kind, reserve, role=None):
    p = fee_policy.policy(agreement)
    role = action_role(kind, role); address = agreement['owners'][role]['address']
    if (agreement['eth_chain_id'] != CHAIN or reserve['address'] != address or reserve['action'] != kind
            or type(reserve['nonce']) is not int or not 0 <= reserve['nonce'] < 2**64
            or type(reserve['gas_price_wei']) is not int or not 0 < reserve['gas_price_wei'] <= p['max_gas_price_wei']
            or reserve['gas_limit'] != p['gas_limits'][kind]
            or reserve['required_balance_wei'] != fee_policy.required_balance(agreement, kind)
            or min(reserve['confirmed_balance_wei'], reserve['pending_balance_wei']) < reserve['required_balance_wei']):
        raise RuntimeError('ETH signing reserve differs from accepted action/policy')
    return {'from': address, 'to': agreement['escrow']['contract'], 'chainId': hex(CHAIN), 'type': '0x0',
        'nonce': hex(reserve['nonce']), 'gasPrice': hex(reserve['gas_price_wei']),
        'gas': hex(p['gas_limits'][kind]), 'value': hex(agreement['amount_wei'] if kind == 'lock' else 0)}


def commit(directory, binding, agreement, kind, reserve, observation):
    """Offline persistence primitive; live caller must supply fresh checks.

    A transcript is useful in diagnostics, but this function never establishes
    chain state or grants send authority. No opening/key is read here.
    """
    role = action_role(kind, binding['role'])
    value = {'format': 'latch-public-eth-decision-v1', 'binding_digest': eth.digest(binding), 'kind': kind,
        'transaction_base': transaction_base(agreement, kind, reserve, role), 'calldata_prefix': prefix(agreement, kind, role),
        'observation': observation, 'possible_secret_exposure': kind == 'claim', 'send_authorized': False}
    action = directory/kind; outgoing.private_directory(action)
    outgoing.immutable(action/'decision.json', value)
    return action


def decision(directory, binding, agreement, kind):
    action = directory/kind; outgoing.private_directory(action)
    value = read(action/'decision.json'); tx = value['transaction_base']; p = fee_policy.policy(agreement)
    role = action_role(kind, binding['role'])
    if (value['format'] != 'latch-public-eth-decision-v1' or value['kind'] != kind
            or value['binding_digest'] != eth.digest(binding)
            or value['calldata_prefix'] != prefix(agreement, kind, role)
            or value['possible_secret_exposure'] is not (kind == 'claim') or value['send_authorized'] is not False
            or set(tx) != {'from', 'to', 'chainId', 'type', 'nonce', 'gasPrice', 'gas', 'value'}
            or tx['from'] != agreement['owners'][role]['address'] or tx['to'] != agreement['escrow']['contract']
            or tx['chainId'] != hex(CHAIN) or tx['type'] != '0x0'
            or fee_policy.quantity(tx['nonce']) >= 2**64
            or not 0 < fee_policy.quantity(tx['gasPrice']) <= p['max_gas_price_wei']
            or fee_policy.quantity(tx['gas']) != p['gas_limits'][kind]
            or fee_policy.quantity(tx['value']) != (agreement['amount_wei'] if kind == 'lock' else 0)):
        raise RuntimeError('retained ETH decision differs from agreement')
    return action, value


def check_opening(directory, files, checked, witness):
    # The Bob receipt is a public signed protocol packet already held by Alice,
    # not access to Bob's keys/directory. Real native claim verification follows.
    folder = directory/'opening-check'; outgoing.private_directory(folder)
    outgoing.immutable(folder/'native-recovery.json', files['bundle'])
    outgoing.immutable(folder/'owner-receipt.json', files['proposal']['receipts']['bob'])
    outgoing.immutable(folder/'candidate.json', {'witness_le': witness})
    result = native('testnet-accept-opening', folder, folder/'candidate.json', folder/'opening.json')
    if result['bundle_digest'] != checked['bundle_digest'] or result['native_claim_authorization_verified'] is not True:
        raise RuntimeError('claim opening differs from accepted native authorization')


def sign(owner, tx):
    fields = [fee_policy.quantity(tx[k]) for k in ('nonce', 'gasPrice', 'gas')]
    fields += [eth.data(tx['to'], 20), fee_policy.quantity(tx['value']), bytes.fromhex(tx['data'][2:])]
    signed = evm_wallet.sign_digest(owner/'ethereum', evm_wallet.keccak(evm_wallet.rlp(fields+[CHAIN, 0, 0])))
    if signed['parity'] not in (0, 1): raise RuntimeError('invalid Ethereum signature parity')
    return evm_wallet.rlp(fields+[2*CHAIN+35+signed['parity'], int(signed['r'], 16), int(signed['s'], 16)])


def verify_raw(action, value, files, checked, raw):
    # Foundry decodes/reconstructs the actual signer. Neither raw calldata nor
    # decoder errors go into argv, terminal output or network requests.
    result = subprocess.run(['cast', 'decode-transaction', '--json'], input='0x'+raw.hex()+'\n',
        capture_output=True, text=True, timeout=15, check=True)
    actual = json.loads(result.stdout); tx = value['transaction_base']; kind = value['kind']
    if (actual['hash'].lower() != '0x'+evm_wallet.keccak(raw).hex()
            or any(fee_policy.quantity(actual[k]) != fee_policy.quantity(tx[k]) for k in
                ('chainId', 'type', 'nonce', 'gasPrice', 'gas', 'value'))
            or actual['signer'].lower() != tx['from'] or actual['to'].lower() != tx['to']):
        raise RuntimeError('signed ETH bytes differ from committed transaction/signer')
    payload = actual['input'].lower()
    if kind != 'claim':
        if payload != value['calldata_prefix']: raise RuntimeError('signed ETH action effects changed')
    else:
        if not re.fullmatch(value['calldata_prefix']+'[0-9a-f]{64}', payload):
            raise RuntimeError('signed ETH claim effects changed')
        witness = opening.scalar('0x'+payload[-64:])
        check_opening(action, files, checked, witness)
    return {'format': 'latch-public-eth-bytes-v1', 'txid': actual['hash'].lower(),
        'bytes_sha256': hashlib.sha256(raw).hexdigest(), 'kind': kind,
        'signer_and_exact_calldata_verified': True, 'synthetic_inputs': checked['synthetic_inputs'],
        'native_opening_verified': kind == 'claim', 'broadcast': False, 'send_authorized': False}


def finish(owner, directory, binding, files, checked, kind, inspect=False):
    agreement = files['proposal']['agreement']
    action, value = decision(directory, binding, agreement, kind)
    path = action/'transaction.hex'
    if not path.exists() and not path.is_symlink():
        if inspect:
            return {'private_signed_bytes_saved': False, 'possible_secret_exposure': kind == 'claim',
                'broadcast': False, 'send_authorized': False}
        payload = value['calldata_prefix']
        if kind == 'claim':
            # The durable decision already exists. First materialization can
            # fail or be killed; that never resets local exposure history.
            witness = read(owner/'setup-round1.json')['witness_le']
            check_opening(action, files, checked, witness)
            payload += int.from_bytes(bytes.fromhex(witness), 'little').to_bytes(32, 'big').hex()
        raw = sign(owner, dict(value['transaction_base'], data=payload))
        verify_raw(action, value, files, checked, raw)
        outgoing.publish_raw(path, raw)
        reused = False
    else:
        raw = outgoing.raw_bytes(path); reused = True
    result = verify_raw(action, value, files, checked, raw)
    journal = {'decision_digest': eth.digest(value), 'checked': result}
    if not inspect: outgoing.immutable(action/'signed.json', journal)
    elif (action/'signed.json').exists() and read(action/'signed.json') != journal:
        raise RuntimeError('ETH raw bytes differ from durable signed journal')
    return {'private_signed_bytes_saved': True, 'raw_bytes_reused': reused,
        'signed_journal_present': (action/'signed.json').exists(), 'checked': result,
        'possible_secret_exposure': kind == 'claim', 'broadcast': False, 'send_authorized': False}


def operate(operation, owner, consents, endpoint=probe_sepolia.ENDPOINT, action=None):
    with authority.owner_locked(owner):
        files, checked, caller, kind = context(owner, consents, action)
        role = read(owner/'identity.json')['role']
        if operation == 'prepare' and checked['synthetic_inputs'] is not False:
            raise RuntimeError('synthetic inputs cannot enter public ETH preparation')
        if operation != 'init' and not (owner/JOURNAL/'binding.json').exists():
            raise RuntimeError('initialize exact ETH execution history first')
        directory, binding = workspace(owner, files, checked, role)
        if operation == 'init': return exposure(owner, files, checked)
        existing = (directory/kind).exists() or (directory/kind).is_symlink()
        if operation == 'prepare' and not existing:
            observed = directory/('observation-'+uuid.uuid4().hex)
            if kind in PHASE:
                report = preflight.observe_verified(directory/'bundle.json', files['proposal']['agreement'], checked,
                    PHASE[kind], observed, endpoint, None)
                publish(observed/'report.json', report)
                reserve = read(observed/'eth.json')['reserves'][role]
            else:
                # Same owner lock and shared sticky claim history as the read-only
                # reconciler; never turn a later negative read into no exposure.
                import public_eth_reconcile
                report = public_eth_reconcile.observe_locked(owner, consents, endpoint, action=kind)
                require_recovery_action(kind, report)
                reserve = report['action_checks']['reserve']
                observed = Path(report['observation_directory'])
            if authority.bind_owner(owner, files, checked, action_phase(kind, role)) != caller or read(consents) != files['consents']:
                raise RuntimeError('owner acceptance changed before ETH decision')
            commit(directory, binding, files['proposal']['agreement'], kind, reserve,
                {'directory': str(observed.relative_to(owner)), 'report_digest': eth.digest(report), 'live_checks_in_this_invocation': True})
        elif not existing:
            raise RuntimeError('no committed ETH action; use prepare for fresh checks')
        return finish(owner, directory, binding, files, checked, kind, operation == 'inspect')


def require_recovery_action(kind, report):
    if report['action_checks']['action'] != kind:
        raise RuntimeError('recovery action observation mismatch')
    if kind == 'refund' and (report['claim_seen_ever'] or report['verified_native_opening_available']):
        raise RuntimeError('known claim/opening forbids ETH refund fallback; retain native recovery')


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('init', 'prepare', 'resume', 'inspect'))
    p.add_argument('owner', type=Path); p.add_argument('consents', type=Path)
    p.add_argument('--eth-rpc', default=probe_sepolia.ENDPOINT)
    p.add_argument('--action', choices=('lock', 'claim', 'refund', 'withdraw'))
    a = p.parse_args()
    print(json.dumps(operate(a.operation, a.owner, a.consents, a.eth_rpc, a.action), indent=2))
    return 2


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('ETH preparation refused; preserve decision and signed bytes. No transaction sent.') from None
