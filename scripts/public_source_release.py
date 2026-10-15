#!/usr/bin/env python3
"""Prepare private F authorization after fresh checks, never broadcast it.

The durable intent commits ONE source graph before any signature. Resume can
finish that same authorization after a crash; it never grants permission for a
late first broadcast. The future sender still needs fresh live reconciliation.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import uuid
import public_authority as authority
import public_evm_observation as eth
import public_outgoing as outgoing
import public_preflight as preflight
import public_source as source
import public_source_guard as guard
import probe_sepolia
import source_inputs
from regtest_wallet import NATIVE
from source_inputs import publish
from testnet_wallet import read


def workspace(wallet, files):
    directory = wallet/'public-source-funding'; outgoing.private_directory(directory)
    for name in ('bundle', 'proposal', 'consents'):
        outgoing.immutable(directory/(name+'.json'), files[name])
    return directory


def intent(directory, files, checked, pinned, observations):
    value = {'format': 'latch-public-source-signing-intent-v1',
        'agreement_digest': checked['agreement_digest'], 'bundle_digest': checked['bundle_digest'],
        'authority_digest': pinned['authority_digest'], 'consents_digest': eth.digest(files['consents']),
        'synthetic_inputs': checked['synthetic_inputs'], 'observations': observations,
        'authorization_may_exist': True, 'broadcast': False, 'send_authorized': False}
    outgoing.immutable(directory/'intent.json', value)
    return value


def native_worker(wallet, package, lock_fd, synthetic=False, inspect=False):
    command = 'testnet-inspect-source' if inspect else 'testnet-sign-source'
    if synthetic: command = 'check-public-source-inspect' if inspect else 'check-public-source-signing'
    # Unlike an unrelated process, this bounded worker retains the inherited
    # wallet lock even if its Python parent dies. It cannot broadcast. A timeout
    # kills only this direct child; the durable intent remains for recovery.
    result = subprocess.run([str(NATIVE), command, str(wallet), str(package), str(lock_fd)],
        pass_fds=(lock_fd,), env=dict(os.environ, RAYON_NUM_THREADS='2'),
        capture_output=True, text=True, check=True, timeout=300)
    return json.loads(result.stdout)


def operate(operation, owner, wallet, consents, endpoint=probe_sepolia.ENDPOINT):
    with authority.owner_locked(owner):
        files, checked = authority.verified_files(owner/'public-native-recovery.json',
            owner/'public-consent-proposal.json', consents)
        caller = authority.bind_owner(owner, files, checked, 'funding')
        if checked['synthetic_inputs'] is not False:
            raise RuntimeError('synthetic inputs cannot enter public source release')
        agreement = files['proposal']['agreement']
        with source.locked(wallet) as lock_fd:
            if (wallet/guard.CANCELLED).exists() or (wallet/guard.CANCELLED).is_symlink():
                raise RuntimeError('source permanently cancelled')
            pinned = guard.identity_locked(wallet, agreement)
            retained = source_inputs.replay(wallet, agreement['execution_plan_digest'], agreement['native']['principal_zatoshi'])
            if retained is None: raise RuntimeError('existing source reservation required')
            package = Path(retained['file']).parent
            directory = workspace(wallet, files)
            committed = (directory/'intent.json').exists() or (directory/'intent.json').is_symlink()
            if operation == 'prepare' and not committed:
                guard.active_locked(wallet)
                observations = directory/('observation-'+uuid.uuid4().hex)
                # Same invocation, same owner + source locks. A saved report is
                # never accepted as a fresh authorization input by this CLI.
                observed = preflight.observe_verified(directory/'bundle.json', agreement, checked,
                    'funding', observations, endpoint, wallet)
                if authority.bind_owner(owner, files, checked, 'funding') != caller or read(consents) != files['consents']:
                    raise RuntimeError('caller changed during funding observation')
                publish(observations/'report.json', observed)
                pinned_after = guard.check_locked(wallet, agreement)
                if any(pinned_after[k] != pinned[k] for k in pinned):
                    raise RuntimeError('source authority changed before release intent')
                intent(directory, files, checked, pinned, {'directory': observations.name,
                    'report_digest': eth.digest(observed), 'live_checks_in_this_invocation': True})
            elif not committed:
                raise RuntimeError('no committed source intent; use prepare for fresh checks')
            saved = read(directory/'intent.json')
            if (saved['agreement_digest'] != checked['agreement_digest'] or saved['bundle_digest'] != checked['bundle_digest']
                    or saved['authority_digest'] != pinned['authority_digest'] or saved['consents_digest'] != eth.digest(files['consents'])
                    or saved['synthetic_inputs'] is not False):
                raise RuntimeError('retained release intent changed')
            return native_worker(wallet, package, lock_fd, inspect=operation == 'inspect')


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('prepare', 'resume', 'inspect'))
    p.add_argument('owner', type=Path); p.add_argument('wallet', type=Path); p.add_argument('consents', type=Path)
    p.add_argument('--eth-rpc', default=probe_sepolia.ENDPOINT)
    a = p.parse_args()
    print(json.dumps(operate(a.operation, a.owner, a.wallet, a.consents, a.eth_rpc), indent=2))
    return 2 # Private signed bytes still do not authorize network transmission.


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Source release refused; preserve private reservation, intent and bytes. No transaction sent.') from None
