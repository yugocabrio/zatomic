#!/usr/bin/env python3
"""Real private F signing and crash recovery on explicitly nonexistent inputs.

Creates one new synthetic proof graph and uses copied unfunded owner keys. No
RPC, reservation forgery, deployment or transfer. Original fixtures are intact.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from check_independent_operators import Operators
import public_authority as authority
import public_evm_observation as eth
import public_source as source
import public_source_guard as guard
import public_source_release as release
from regtest_wallet import ROOT, NATIVE, save
from testnet_wallet import read
import timestamp_policy


def inspect_retained(root, setup):
    wallet = root/'coordinator/synthetic-source'
    graph = root/'coordinator'
    raw = (wallet/'funding.hex').read_bytes()
    env = dict(os.environ, RAYON_NUM_THREADS='2')
    # A real native verifier retains the same lock after the parent closes its
    # descriptor. Its source-local files suffice; peer/original roots and network
    # are denied. Only this diagnostic graph's source key is accessible.
    policy = '(version 1)(allow default)(deny network*)'+''.join(
        '(deny file-read* file-write* (subpath '+json.dumps(str(p))+'))'
        for p in (setup, root/'alice', root/'bob'))
    for invalid in (0, 999999):
        p = subprocess.run([str(NATIVE), 'check-public-source-inspect', str(wallet), str(graph), str(invalid)],
            capture_output=True, text=True, env=env, timeout=30)
        if p.returncode != 1: raise RuntimeError('invalid source descriptor did not fail cleanly')
    with source.locked(wallet) as fd:
        child = subprocess.Popen(['/usr/bin/sandbox-exec', '-p', policy, str(NATIVE),
            'check-public-source-inspect', str(wallet), str(graph), str(fd)], pass_fds=(fd,),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
    try:
        try:
            with source.locked(wallet): raise RuntimeError('native worker lost inherited source lock')
        except BlockingIOError: pass
        stdout, stderr = child.communicate(timeout=180)
        if child.returncode:
            save(root/'harness/offline-error.json', {'stderr': stderr})
            raise RuntimeError('offline native source inspection failed')
        inspected = json.loads(stdout)
    finally:
        if child.poll() is None: child.kill(); child.communicate(timeout=15)
    with source.locked(wallet): pass
    if (wallet/'funding.hex').read_bytes() != raw: raise RuntimeError('inspection changed retained bytes')
    if inspected['checked'] != read(wallet/'public-source-outgoing.json')['checked']:
        raise RuntimeError('retained source journal does not match actual bytes')
    return inspected


def check(root, setup):
    if shutil.disk_usage(ROOT).free < 2 * 1024**3:
        raise RuntimeError('two GiB free required before synthetic proof work')
    root.mkdir(mode=0o700); (root/'harness').mkdir(mode=0o700)
    for role in ('alice', 'bob'):
        if not (setup/role/'setup-complete.json').is_file():
            raise RuntimeError('completed unfunded public owner setup required')
        shutil.copytree(setup/role, root/role)
    actors = Operators(root)
    env = dict(os.environ, RAYON_NUM_THREADS='2')

    def run(args, reject=False, **kwargs):
        p = subprocess.run(list(map(str, args)), capture_output=True, text=True,
            timeout=600, env=env, **kwargs)
        if (p.returncode != 0) != reject:
            save(root/'harness'/('error-'+str(time.time_ns())+'.json'),
                {'stdout': p.stdout, 'stderr': p.stderr})
            raise RuntimeError('unexpected source-release check result: '+str(args[1]))
        return None if reject else json.loads(p.stdout)

    def owner(role, command, packet):
        incoming = root/role/(command+'-input.json'); save(incoming, packet)
        return run(actors.command(role, [str(NATIVE), command, str(root/role), str(incoming)]))

    graph = root/'coordinator'
    run([NATIVE, 'check-unsigned-graph-synthetic', graph, root/'alice/authenticated-destinations.json'])
    meta = read(graph/'graph.json')
    save(graph/'plan.json', timestamp_policy.build(meta['refund_lock']['value']-108000))
    save(graph/'destinations.json', read(root/'alice/authenticated-destinations.json'))
    run([NATIVE, 'testnet-export-review', graph, graph/'destinations.json', graph/'plan.json', graph/'review.json'])
    review = read(graph/'review.json')
    for role in ('alice', 'bob'): owner(role, 'testnet-owner-review', review)
    commands = root/'harness/commands.json'
    save(commands, {r: actors.command(r, [str(NATIVE), 'testnet-owner-signer', str(root/r)]) for r in ('alice', 'bob')})
    run([sys.executable, ROOT/'scripts/presign_testnet_review.py', graph/'review.json', commands, root/'presigned'])
    run([NATIVE, 'check-public-recovery-synthetic', graph/'review.json',
        root/'presigned/exit-presignatures.json', graph/'native-recovery.json'])
    bundle = read(graph/'native-recovery.json')
    save(graph/'receipts.json', {r: owner(r, 'testnet-owner-recovery', bundle) for r in ('alice', 'bob')})
    run([NATIVE, 'testnet-stage-agreement', graph/'native-recovery.json', graph/'receipts.json',
        '0x'+'11'*20, '0x'+os.urandom(32).hex(), graph/'conditional-proposal.json'])
    proposal = read(graph/'conditional-proposal.json')
    consents_path = graph/'conditional-consents.json'
    save(consents_path, {r: owner(r, 'testnet-owner-consent', proposal) for r in ('alice', 'bob')})
    files, checked = authority.verified_files(graph/'native-recovery.json', graph/'conditional-proposal.json', consents_path)
    wallet = graph/'synthetic-source'; pins = graph/'owners.json'
    save(pins, proposal['agreement']['owners'])
    with source.locked(wallet):
        guard.initialize_locked(wallet, pins, eth.digest(read(pins)))
        pinned = guard.identity_locked(wallet, proposal['agreement'])
        directory = release.workspace(wallet, files)
        release.intent(directory, files, checked, pinned,
            {'synthetic_transcript': True, 'live_checks_in_this_invocation': False})

    # This fixture must never enter the live wrapper, regardless of endpoint.
    try: release.operate('prepare', root/'alice', wallet, consents_path, 'http://127.0.0.1:1')
    except RuntimeError as error:
        if 'synthetic inputs' not in str(error): raise
    else: raise RuntimeError('live source wrapper accepted synthetic inputs')

    def refused(call):
        try: call()
        except RuntimeError: return
        raise RuntimeError('unsafe source operation accepted')

    marker, raw_path = wallet/guard.RELEASE, wallet/'funding.hex'
    with source.locked(wallet) as fd:
        refused(lambda: guard.cancel_locked(wallet))
        refused(lambda: guard.initialize_locked(wallet, pins, eth.digest(read(pins))))
        run([NATIVE, 'testnet-sign-source', wallet, graph, fd], True, pass_fds=(fd,))
        other = os.open(root/'harness/wrong-lock', os.O_CREAT | os.O_RDWR, 0o600)
        try: run([NATIVE, 'check-public-source-signing', wallet, graph, other], True, pass_fds=(other,))
        finally: os.close(other)
        # Damage only this new private test workspace, before any source marker.
        bad = copy.deepcopy(files['consents']); bad['bob']['signature']['s'] = '00'*32
        (directory/'consents.json').write_text(json.dumps(bad))
        try: run([NATIVE, 'check-public-source-signing', wallet, graph, fd], True, pass_fds=(fd,))
        finally: (directory/'consents.json').write_text(json.dumps(files['consents']))
        if marker.exists() or raw_path.exists(): raise RuntimeError('refused context signed F')
        pending = release.native_worker(wallet, graph, fd, True, True)
        if pending['private_source_authorization_saved'] or marker.exists():
            raise RuntimeError('inspection signed pending source')
        child = subprocess.Popen([str(NATIVE), 'check-public-source-signing', str(wallet), str(graph), str(fd)],
            pass_fds=(fd,), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        try:
            deadline = time.monotonic()+180
            while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            if not marker.exists() or raw_path.exists():
                raise RuntimeError('did not reach release-before-raw crash boundary')
            child.kill(); child.communicate(timeout=15)
        finally:
            if child.poll() is None: child.kill(); child.communicate(timeout=15)
        if raw_path.exists(): raise RuntimeError('raw publication raced crash boundary')
        refused(lambda: guard.cancel_locked(wallet))
        resumed = release.native_worker(wallet, graph, fd, True)
        raw = raw_path.read_bytes(); journal_path = wallet/'public-source-outgoing.json'
        journal = journal_path.read_bytes()
        replay = release.native_worker(wallet, graph, fd, True)
        if (not resumed['private_source_authorization_saved'] or not replay['raw_bytes_reused']
                or raw_path.read_bytes() != raw or journal_path.read_bytes() != journal):
            raise RuntimeError('exact signed source replay changed')
        # Simulated raw-before-outgoing-journal interruption; retain its backup.
        journal_path.rename(wallet/'outgoing-test-backup.json')
        if release.native_worker(wallet, graph, fd, True, True)['outgoing_record_present']:
            raise RuntimeError('inspection fabricated a missing journal')
        if not release.native_worker(wallet, graph, fd, True)['raw_bytes_reused'] or journal_path.read_bytes() != journal:
            raise RuntimeError('partial outgoing journal replay changed')
        damaged = bytearray.fromhex(raw.decode()); damaged[-1] ^= 1
        raw_path.write_text(damaged.hex())
        try: run([NATIVE, 'check-public-source-inspect', wallet, graph, fd], True, pass_fds=(fd,))
        finally: raw_path.write_bytes(raw)

    inspected = inspect_retained(root, setup)
    if inspected['checked'] != resumed['checked']: raise RuntimeError('offline source bytes differ')
    if raw_path.read_bytes() != raw: raise RuntimeError('diagnostic changed retained bytes')
    result = {'scope': 'real native source signature/proof, actual isolated owner consents; nonexistent synthetic inputs',
        'source_funding': inspected['checked'], 'both_owner_consents_verified': True,
        'public_wrapper_and_native_refuse_synthetic': True, 'wrong_inherited_lock_refused': True,
        'invalid_owner_consent_refused_before_release_marker': True,
        'intent_alone_refuses_cancel_and_reinitialize': True, 'inspection_never_signs': True,
        'actual_sigkill_after_release_before_raw_resumed': True, 'exact_raw_and_journal_replay': True,
        'partial_raw_before_journal_resumed': True, 'same_effects_damaged_authorization_refused': True,
        'inherited_lock_survives_parent_descriptor_close': True,
        'closed_and_standard_descriptors_fail_cleanly': True,
        'offline_inspection_with_original_and_owner_roots_denied': True,
        'public_funded_source': False, 'fresh_public_preflight_positive': False,
        'node_acceptance': False, 'broadcast': False}
    save(root/'report.json', result)
    return result


if __name__ == '__main__':
    os.umask(0o077)
    inspect_only = sys.argv[1:2] == ['--inspect-retained']
    args = sys.argv[2:] if inspect_only else sys.argv[1:]
    result = (inspect_retained if inspect_only else check)(*(Path(p).resolve() for p in args))
    print(json.dumps(result, indent=2))
