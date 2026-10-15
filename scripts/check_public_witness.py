#!/usr/bin/env python3
"""Actual portable C/R reproofs with synthetic public-profile compact data.

The F preview has zero authorizations and nonexistent source inputs. Block
hashes in this test are invented; this is NOT a public/isolated mined swap.
Also reprove a previously mined isolated refund from its retained watch export.
No network, mining, source signatures, peer processes or original state changes.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import public_recovery_watch
from regtest_wallet import ROOT, NATIVE, save
from testnet_wallet import read, head


def check_initialization_guard(root, portable):
    root.mkdir(mode=0o700)
    # Only a nonsecret marker is needed; not one file may be added or changed.
    save(root/'network.json', {'test_only_existing_wallet_marker': True})
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    p = subprocess.run([str(NATIVE), 'testnet-recovery-watch', str(portable), str(root), '4500000'],
        capture_output=True, text=True, timeout=30)
    if (p.returncode == 0 or 'refuse to initialize recovery over an existing wallet/directory' not in p.stderr
            or {p.name: p.read_bytes() for p in root.iterdir()} != before):
        raise RuntimeError('existing wallet initialization guard failed')
    return {'existing_wallet_unchanged_and_no_files_added': True}


def check(root, portable, owner_fixture):
    root.mkdir(mode=0o700)
    env = dict(os.environ, CARGO_BUILD_JOBS='2', RAYON_NUM_THREADS='2',
        LATCH_WITNESS_FIXTURE=str(portable/'alice'), LATCH_WITNESS_CAPTURES=str(root/'captures'))
    p = subprocess.run(['cargo', 'test', '--release', '--locked', '-p', 'shielded-swap-native', '-j2',
        'public_witness::tests::synthetic_compact_capture', '--', '--ignored'],
        cwd=ROOT, env=env, capture_output=True, timeout=180)
    if p.returncode:
        (root/'capture-error.log').write_bytes(p.stdout+p.stderr)
        raise RuntimeError('synthetic capture fixture failed')
    # Simulates the already-exposed opening delivered to Bob. Do not copy the
    # original Alice identity, spending key or DKG share into either watch wallet.
    save(root/'observed-opening.json', {'witness_le': read(owner_fixture/'alice/setup-round1.json')['witness_le']})
    denied = [portable, owner_fixture]
    policy = '(version 1)(allow default)'+''.join(
        '(deny file-read* file-write* (subpath '+json.dumps(str(path))+'))' for path in denied)
    def run(args, reject=None, isolate=True):
        command = list(map(str, args))
        if isolate: command = ['/usr/bin/sandbox-exec', '-p', policy, *command]
        p = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
        if reject is not None:
            if p.returncode == 0 or reject not in p.stderr: raise RuntimeError('expected recovery refusal absent')
            return
        if p.returncode:
            save(root/'failure.json', {'stdout': p.stdout, 'stderr': p.stderr})
            raise RuntimeError('portable recovery command failed; private diagnostic retained')
        return json.loads(p.stdout)
    probe = subprocess.run(['/usr/bin/sandbox-exec', '-p', policy, sys.executable, '-c',
        'from pathlib import Path;import sys\ntry: Path(sys.argv[1]).read_bytes()\nexcept PermissionError: sys.exit(0)\nelse: sys.exit(9)',
        str(owner_fixture/'alice/graph-review.json')], capture_output=True)
    if probe.returncode: raise RuntimeError('original-root denial ineffective')
    proofs = {}
    for role in ('alice', 'bob'):
        export = root/(role+'-export'); export.mkdir(mode=0o700)
        for name in ('native-recovery.json', 'owner-receipt.json'):
            shutil.copyfile(portable/role/name, export/name); os.chmod(export/name, 0o600)
        wallet = root/role
        args = [NATIVE, 'testnet-recovery-watch', export, wallet, 4_500_000]
        initialized = run(args)
        first = run([NATIVE, 'compact-scan', wallet, root/'captures/funding.json'])
        current = run([NATIVE, 'compact-scan', wallet, root/'captures/confirmed.json', first['file']])
        if first['received_notes'] != 1 or current['unspent_notes'] != 1:
            raise RuntimeError('exact funding note not decrypted/resumed')
        head(wallet, {'genesis': read(wallet/'network.json')['genesis'], 'birthday': 4_500_000,
            'checkpoint': Path(current['file']).name})
        saved_head = (wallet/'head.json').read_bytes()
        if run(args) != initialized or (wallet/'head.json').read_bytes() != saved_head:
            raise RuntimeError('watch initialization replay reset synced head')
        run([*args[:-1], 4_500_001], 'immutable watch workspace changed')
        run([NATIVE, 'testnet-recovery-snapshot', wallet, first['file'], current['file'], root/(role+'-snapshot.json')])
        run([NATIVE, 'testnet-recovery-snapshot', wallet, first['file'], first['file'], root/'shallow.json'],
            'twelve observed confirmations')
        changed = read(Path(current['file'])); changed['notes'][0]['txid'] = '00'*32
        bad = root/(role+'-wrong-origin.json'); save(bad, changed)
        run([NATIVE, 'testnet-recovery-snapshot', wallet, first['file'], bad, root/'wrong-origin-output.json'],
            'funding origin mismatch')
        changed = read(Path(first['file'])); changed['notes'][0]['witness'] = '00'
        bad = root/(role+'-wrong-witness.json'); save(bad, changed)
        # Serialization error text is backend-specific; simply require nonzero.
        failure = subprocess.run([str(NATIVE), 'testnet-recovery-snapshot', str(wallet), str(bad), current['file'],
            str(root/'wrong-witness-output.json')], capture_output=True, timeout=30)
        if failure.returncode == 0: raise RuntimeError('corrupt persisted witness accepted')
        try: public_recovery_watch.observe(wallet, root/(role+'-live-must-not-exist'), 1)
        except RuntimeError as error:
            if str(error) != 'synthetic recovery is offline only; no public observer queries': raise
        else: raise RuntimeError('synthetic live observer enabled')
        if (root/(role+'-live-must-not-exist')).exists(): raise RuntimeError('synthetic refusal happened too late')
        proof = [NATIVE, 'testnet-recovery-prove', wallet, first['file'], current['file'], root/(role+'-proof')]
        if role == 'bob':
            proof.append(root/'observed-opening.json')
            save(root/'wrong-opening.json', {'witness_le': '00'*32})
            run([*proof[:-2], root/'bad-proof', root/'wrong-opening.json'], 'wrong witness')
        proofs[role] = run(proof)
        assert proofs[role]['proof_and_signatures_verified'] and proofs[role]['agreed_effects_preserved']
        assert proofs[role]['synthetic_inputs'] and not proofs[role]['broadcast']
        spent = run([NATIVE, 'compact-scan', wallet, root/'captures/spent.json', current['file']])
        if spent['spent_notes'] != 1 or spent['unspent_notes'] != 0: raise RuntimeError('funding nullifier not observed')
        run([NATIVE, 'testnet-recovery-snapshot', wallet, first['file'], spent['file'], root/'spent-output.json'],
            'exact funding note absent/spent')
        if any((wallet/name).exists() for name in ('spending-key.bin', 'frost-key.bin', 'ethereum-key.bin')):
            raise RuntimeError('unexpected signing material')
    # Regression for the common proving helper using a real previously mined
    # F/witness. Its refund already settled; this historical reproof is not sent.
    legacy_source = ROOT/'.local/native-timestamp-002/recovery'
    legacy = root/'historical-regtest'; legacy.mkdir(mode=0o700); (legacy/'alice').mkdir(mode=0o700)
    for name in ('terms.json', 'pending-note.json', 'joint-fvk.bin', 'alice/refund.pczt'):
        shutil.copyfile(legacy_source/name, legacy/name); os.chmod(legacy/name, 0o600)
    scan = next(legacy_source.glob('scan-3800-*.json'))
    shutil.copyfile(scan, legacy/'historical-scan.json'); os.chmod(legacy/'historical-scan.json', 0o600)
    historical = run([NATIVE, 'regtest-finish', legacy, legacy/'historical-scan.json', 'refund'])
    if historical['txid'] != read(ROOT/'.local/native-timestamp-002/prepared-refund.json')['txid']:
        raise RuntimeError('historical refund effects changed')
    guard = check_initialization_guard(root/'existing-wallet', portable/'alice')
    return {'scope': 'actual native proofs; public-profile blocks/inputs explicitly synthetic; no network calls',
        'watch_only_init_and_advanced_head_replay': True, 'compact_receive_resume_spend': True,
        'both_native_exit_proofs_and_signatures_verified': True, 'original_owner_source_roots_denied': True,
        'wrong_origin_witness_opening_shallow_and_spent_refused': True,
        'synthetic_refused_before_live_sync': True, 'historical_real_regtest_refund_reproved_same_txid': True,
        'public_funded_recovery': False, 'broadcast': False, 'spending_keys_exported': False, **guard}


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:4])), indent=2))
