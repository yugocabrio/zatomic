#!/usr/bin/env python3
"""Send Alice's deferred refund auxiliary A, only on the no-reveal refund path.

A spends her own F change and creates the transparent coin that her signed
refund R spends. A settled swap never sends it. This sender refuses while her
local claim history may be exposed, or while the ETH order is not stably empty
or refunded. Check is read-only on both networks; --broadcast-testnet submits
the exact re-proved A after persisting possible delivery. R is sent separately
(public_native_execute.py) once A has the agreed native confirmations.
"""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import uuid
import public_authority as authority
import public_eth_outgoing as eth_outgoing
import public_eth_reconcile as eth_reconcile
import public_native_execute as delivery
import public_native_reconcile as native_observer
import public_outgoing as out
import public_source as source
import probe_sepolia
import testnet_wallet
from testnet_wallet import NATIVE, invoke, read


def refund_path(owner, consents, endpoint):
    """Caller holds operator.lock. Same no-exposure and ETH conditions as R."""
    files, checked, caller, kind = eth_outgoing.context(owner, consents)
    if kind != 'claim':
        raise RuntimeError('only Alice sends her refund auxiliary')
    if checked['synthetic_inputs'] is not False:
        raise RuntimeError('synthetic inputs cannot enter public execution')
    if checked['native_auxiliary'].get('deferred') is not True:
        raise RuntimeError('this agreement spends a pre-funded coin; nothing to send')
    local = eth_outgoing.exposure(owner, files, checked)
    if not local['local_history_initialized'] or local['local_claim_may_be_exposed']:
        raise RuntimeError('possible claim exposure: the refund path is closed')
    ethereum = eth_reconcile.observe_locked(owner, consents, endpoint)
    states = ethereum['escrow']['states']
    final, latest = states['provider_finalized']['state'], states['latest']['state']
    if ethereum['claim_seen_ever'] or 2 in (final, latest) or final not in (0, 3) or latest != final:
        raise RuntimeError('ETH order not stably empty or refunded; refund path not chosen')
    return files, checked, caller, kind, ethereum


def state(txid, directory, agreement):
    observation = native_observer.live_query(txid, directory)
    if (observation['requested_txid'] != txid or observation['genesis'] != agreement['native_genesis']
            or observation['branch'] != agreement['native_branch']):
        raise RuntimeError('auxiliary observation domain mismatch')
    if observation['status'] == 'not_found':
        return 'unobserved-by-provider'
    if observation['status'] == 'mined':
        required = agreement['observation_policy']['native_min_confirmations']
        return 'confirmed-by-provider' if observation['confirmations_by_provider'] >= required else 'confirming-by-provider'
    return observation['status'] + '-by-provider'


def prove(wallet, directory, batches):
    """Re-prove A at a source checkpoint with twelve confirmations."""
    testnet_wallet.sync(wallet, batches)
    info, current = testnet_wallet.checkpoint(wallet)
    if current is None:
        raise RuntimeError('synchronize the source wallet first')
    anchors = sorted((read(f)['height'], f) for f in wallet.glob('compact-*.json')
        if read(f)['birthday_height'] == info['birthday'] and read(f)['height'] <= current['height']-11)
    if not anchors:
        raise RuntimeError('retain a source checkpoint with twelve confirmations')
    return invoke(NATIVE, 'testnet-auxiliary-prove', wallet, anchors[-1][1],
        wallet/info['checkpoint'], wallet/'public-source-auxiliary/versions')


def execute(owner, wallet, consents, batches=4, endpoint=probe_sepolia.ENDPOINT, broadcast=False):
    with authority.owner_locked(owner) as owner_fd:
        files, checked, caller, kind, ethereum = refund_path(owner, consents, endpoint)
        agreement = files['proposal']['agreement']
        policy = agreement['execution_plan']['policy']
        with source.locked(wallet) as source_fd:
            source.source_identity(wallet, agreement, released=True)
            base = wallet/'public-source-auxiliary'; out.private_directory(base)
            runs = base/'observations'; out.private_directory(runs)
            if len(list(runs.iterdir())) >= 128:
                raise RuntimeError('auxiliary observation history full; preserve it')
            directory = runs/uuid.uuid4().hex; out.private_directory(directory)
            txid = checked['native_auxiliary']['txid']
            observed = state(txid, directory/'transaction', agreement)
            if observed != 'unobserved-by-provider':
                return {'action': 'monitor-refund-auxiliary', 'state': observed, 'txid': txid,
                    'new_submission': False, 'broadcast': False}
            version = prove(wallet, directory, batches)
            if version['txid'] != txid:
                raise RuntimeError('re-proved auxiliary changed identity')
            raw = out.raw_bytes(Path(version['file']))
            eth_time = datetime.fromisoformat(ethereum['clock']['observed_at'].replace('Z', '+00:00')).timestamp()

            def fresh_guard():
                now = datetime.now().timestamp()
                if not -policy['clock_error_seconds'] <= now-eth_time <= policy['observation_max_age_seconds']:
                    raise RuntimeError('ETH observation became stale before sending A')
                if (authority.bind_owner(owner, files, checked, eth_outgoing.PHASE[kind]) != caller
                        or read(consents) != files['consents']):
                    raise RuntimeError('owner acceptance changed before sending A')
                return int(min(now+60, eth_time+policy['observation_max_age_seconds']))

            result = {'action': 'ready-for-explicit-testnet-send', 'txid': txid,
                'bytes_sha256': version['bytes_sha256'], 'change_confirmations': version['change_confirmations'],
                'new_submission': False, 'broadcast': False}
            if not broadcast:
                fresh_guard()
                return result
            identity = {'agreement_digest': checked['agreement_digest'], 'mode': 'auxiliary',
                'txid': txid, 'bytes_sha256': version['bytes_sha256']}
            delivery_dir = base/'delivery'; out.private_directory(delivery_dir)
            submitted = delivery.send_once(delivery_dir/version['bytes_sha256'], identity, raw, fresh_guard,
                lambda data, validity: delivery.transport(data, validity, txid, [owner_fd, source_fd]))
            return dict(result, action='monitor-refund-auxiliary', submission=submitted, new_submission=True)


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('owner', type=Path); p.add_argument('source', type=Path); p.add_argument('consents', type=Path)
    p.add_argument('--batches', type=int, default=4)
    p.add_argument('--eth-rpc', default=probe_sepolia.ENDPOINT)
    p.add_argument('--broadcast-testnet', action='store_true', help='explicit network side effect; user authorization required')
    a = p.parse_args()
    print(json.dumps(execute(a.owner, a.source, a.consents, a.batches, a.eth_rpc, a.broadcast_testnet), indent=2))
    return 2


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError):
        raise SystemExit('Auxiliary send stopped; retain all private attempts and reconcile before retrying.') from None
