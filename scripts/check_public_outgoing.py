#!/usr/bin/env python3
"""Real native bytes/signatures and SIGKILL recovery; no RPC or new proof.

Existing public-profile proofs spend synthetic/nonexistent inputs. Copy only
accepted packets and raw transactions, never keys or an adaptor opening.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
from check_public_authority import OWNER_FILES
import public_outgoing as outgoing
from regtest_wallet import ROOT, native, save
from testnet_wallet import read


def copy_private(source, target):
    shutil.copyfile(source, target); os.chmod(target, 0o600)


def hashes(directory):
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in directory.rglob('*') if p.is_file()}


def run(args, denied, failure=False):
    policy = '(version 1)(allow default)'+''.join(
        '(deny file-read* file-write* (subpath '+json.dumps(str(p))+'))' for p in denied)
    result = subprocess.run(['/usr/bin/sandbox-exec', '-p', policy, *map(str, args)],
        cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT/'scripts')),
        capture_output=True, text=True, timeout=180)
    if failure:
        if result.returncode == 0: raise RuntimeError('invalid native outgoing accepted')
        return result
    if result.returncode: raise RuntimeError('outgoing check failed: '+result.stderr[:1500])
    return json.loads(result.stdout)


def check_empty_journal(root):
    owner = root/'empty-owner'; owner.mkdir(mode=0o700)
    source = root/'alice'
    for name in OWNER_FILES: copy_private(source/name, owner/name)
    journal = owner/outgoing.JOURNAL; journal.mkdir(mode=0o700)
    for name in ('binding.json', 'native-recovery.json', 'owner-receipt.json', 'proposal.json', 'consents.json'):
        copy_private(source/outgoing.JOURNAL/name, journal/name)
    result = run([sys.executable, ROOT/'scripts/public_outgoing.py', 'inspect', owner], [root/'alice', root/'bob'])
    assert result['versions'] == [] and not result['all_raw_versions_present'] and not result['send_authorized']
    return {'context_only_crash_not_reported_as_complete': True}


def check(root, fixture, proofs, portable):
    root.mkdir(mode=0o700)
    saved = {}
    for role in ('alice', 'bob'):
        owner = root/role; owner.mkdir(mode=0o700)
        for name in OWNER_FILES: copy_private(fixture/role/name, owner/name)
        pack = root/(role+'-portable'); pack.mkdir(mode=0o700)
        for name in ('native-recovery.json', 'owner-receipt.json'):
            copy_private(portable/role/name, pack/name)
        raw_path = root/(role+'.hex')
        copy_private(proofs/(role+'-proof')/'transaction.hex', raw_path)
        both = root/(role+'-consents.json')
        copy_private(fixture/'coordinator/conditional-consents.json', both)
        peer = root/('bob' if role == 'alice' else 'alice')
        denied = [fixture, proofs, portable, peer]
        # Check the OS restriction before using it as evidence.
        probe = run([sys.executable, '-c',
            'from pathlib import Path;import sys\ntry:Path(sys.argv[1]).read_bytes()\nexcept PermissionError:print("true")\nelse:sys.exit(9)',
            fixture/role/'identity.json'], denied)
        assert probe is True
        command = [sys.executable, ROOT/'scripts/public_outgoing.py', 'stage', owner, pack, raw_path, both]
        # Kill the actual production path after its fsynced version intent and
        # before raw publication. The hook exists only in this test subprocess.
        crash = run([sys.executable, '-c',
            'import os,signal,sys;from pathlib import Path;import public_outgoing as p\n'
            'def stop(*args):os.kill(os.getpid(),signal.SIGKILL)\n'
            'p.publish_raw=stop\np.stage(*map(Path,sys.argv[1:]))', owner, pack, raw_path, both], denied, True)
        if crash.returncode != -signal.SIGKILL: raise RuntimeError('did not stop at raw persistence boundary')
        inspect = [sys.executable, ROOT/'scripts/public_outgoing.py', 'inspect', owner]
        partial = run(inspect, denied)
        assert len(partial['versions']) == 1 and not partial['all_raw_versions_present']
        assert partial['versions'][0]['status'] == 'interrupted-before-raw-persistence'
        finished = run(command, denied)
        assert finished['all_raw_versions_present'] and not finished['send_authorized']
        before = hashes(owner/outgoing.JOURNAL)
        assert run(command, denied) == finished
        assert hashes(owner/outgoing.JOURNAL) == before
        # Inspect relies only on the owner's retained outgoing journal/state,
        # not the original proof, portable export, peer, keys or secret opening.
        assert run(inspect, [*denied, pack, raw_path, both]) == finished
        raw = outgoing.raw_bytes(raw_path)
        original_id = native('regtest-inspect', raw_path)['txid']
        for label, offset in (('binding-signature', -1), ('proof', -193)):
            # Two Ironwood actions: last proof byte precedes 2*64 spend and
            # 64 binding signature bytes in pinned librustzcash's v6 format.
            invalid = bytearray(raw); invalid[offset] ^= 1
            path = root/(role+'-'+label+'.hex'); path.write_text(invalid.hex()); os.chmod(path, 0o600)
            assert native('regtest-inspect', path)['txid'] == original_id
            refused = run([ROOT/'target/release/shielded-swap-native', 'testnet-inspect-exit', pack, path], denied, True)
            if 'proof or signature invalid' not in refused.stderr: raise RuntimeError('unexpected raw refusal')
            run([*command[:-2], path, both], denied, True)
        if role == 'alice':
            # v6 header20 bytes; one vin; outpoint36 bytes; short P2PKH script.
            assert raw[20] == 1 and 9 < raw[57] < 253
            invalid = bytearray(raw); invalid[60] ^= 1
            path = root/'changed-refund-aux.hex'; path.write_text(invalid.hex()); os.chmod(path, 0o600)
            assert native('regtest-inspect', path)['txid'] == original_id
            refused = run([ROOT/'target/release/shielded-swap-native', 'testnet-inspect-exit', pack, path], denied, True)
            if 'auxiliary authorization changed' not in refused.stderr: raise RuntimeError('wrong auxiliary refusal')
        # A forged status JSON is unnecessary: recovery ignores proof.json and
        # revalidates actual stored bytes, even when the stored metadata is intact.
        retained = next((owner/outgoing.JOURNAL/'versions').glob('*.hex'))
        original = retained.read_bytes(); invalid = bytearray(raw); invalid[-1] ^= 1
        retained.write_text(invalid.hex())
        run(inspect, denied, True)
        retained.write_bytes(original)
        assert run(inspect, denied) == finished
        saved[role] = finished
    # A correctly signed/proved refund is not Bob's agreed claim.
    run([ROOT/'target/release/shielded-swap-native', 'testnet-inspect-exit', root/'bob-portable', root/'alice.hex'],
        [fixture, proofs, portable], True)
    check_empty_journal(root)
    return {'scope': 'real native verification and durable private bytes; existing synthetic public-profile proofs',
        'both_claim_and_refund_actual_bytes_verified': True,
        'sigkill_after_fsynced_intent_before_raw_observed_and_resumed': True,
        'context_only_crash_not_reported_as_complete': True,
        'idempotent_replay_preserved_every_journal_byte': True,
        'original_fixtures_peer_and_external_inputs_denied_on_inspection': True,
        'same_txid_corrupted_proof_and_signature_refused': True,
        'same_txid_corrupted_refund_auxiliary_signature_refused': True,
        'wrong_role_and_corrupt_persisted_raw_refused': True,
        'owner_keys_and_opening_not_copied': True,
        'new_proofs': 0, 'rpc_calls': 0, 'broadcast': False,
        'funded_public_execution': False, 'send_intent_and_live_reconciliation_implemented': False}


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:5])), indent=2))
