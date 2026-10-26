#!/usr/bin/env python3
"""Public record that both exits of a public run were fixed before funding.

For each run workspace it links four things, all by hash:
  the Sepolia lock calldata -> the agreement both owners signed
  the agreement            -> the exit bundle both owners accepted
  the exit bundle          -> the v6 effects txids of claim C and refund R
  those txids              -> the exit actually mined (and the other, never mined)

Reads private run files (PCZTs, receipts, consents) and prints only digests,
txids and verification flags. PCZTs are written to a private temporary
directory just long enough for the native binary to compute their txids.

    python3 scripts/export_prefunding_evidence.py OUTPUT.json \\
        004=.local/public-launch-004 005=.local/public-launch-005
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'target/release/shielded-swap-native'
RECORD = ROOT / 'evidence/2026-10-21-public-testnet-v2.json'
RPC = 'https://ethereum-sepolia-rpc.publicnode.com'


def digest(value):
    # Same as funding_consent::hash: SHA-256 of compact JSON with sorted keys.
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def effects_txid(pczt_hex, scratch):
    path = Path(scratch) / 'exit.hex'
    path.write_text(pczt_hex)
    try:
        out = subprocess.run([str(NATIVE), 'pczt-effects-txid', str(path)], capture_output=True, text=True, check=True)
    finally:
        path.unlink()
    return json.loads(out.stdout)['txid']


def lock_calldata(txid):
    # publicnode rejects urllib's default agent, so send an explicit one.
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getTransactionByHash', 'params': [txid]}).encode()
    request = urllib.request.Request(RPC, body, {'Content-Type': 'application/json', 'User-Agent': 'curl/8'})
    return json.load(urllib.request.urlopen(request, timeout=30))['result']['input']


def run_record(label, workspace, public, scratch):
    workspace = Path(workspace)
    agreement = load(workspace / 'alice/launch-consent.json')['agreement']
    bundle = load(workspace / 'bob/launch-recovery-accept.json')
    agreement_digest = digest(agreement)
    if digest(bundle) != agreement['bundle_digest']:
        raise SystemExit(f'{label}: accepted bundle does not match the agreement')
    exits = {'C': effects_txid(bundle['review']['claim'], scratch),
             'R': effects_txid(bundle['refund'], scratch)}
    if effects_txid(bundle['review']['claim_check'], scratch) != exits['C'] or \
            effects_txid(bundle['refund_check'], scratch) != exits['R']:
        raise SystemExit(f'{label}: proving copies do not match the exits')
    txs = {t['step'].split(':')[0]: t for t in public['transactions']}
    lock = next(t for t in public['transactions'] if t['step'].startswith('Bob locks ETH'))
    funding = txs['F']
    mined = 'C' if 'C' in txs else 'R'
    unused = 'R' if mined == 'C' else 'C'
    if txs[mined]['txid'] != exits[mined] or funding['txid'] != agreement['native']['funding_txid']:
        raise SystemExit(f'{label}: mined transactions do not match the prepared ones')
    receipts = {}
    for owner in ('alice', 'bob'):
        receipt = load(workspace / f'{owner}/public-native-recovery-receipt.json')['payload']
        ready = load(workspace / f'{owner}-portable/recovery-ready.json')
        if receipt['bundle_digest'] != agreement['bundle_digest']:
            raise SystemExit(f'{label}: {owner} receipt names another bundle')
        receipts[owner] = {
            'bundle_digest': receipt['bundle_digest'],
            'native_exit_bundle_verified': receipt['native_exit_bundle_verified'],
            'conditional_claim_verified': ready['conditional_claim_verified'],
            'refund_shielded_and_auxiliary_signatures_verified': ready['refund_shielded_and_auxiliary_signatures_verified'],
            'funding_authorized_at_receipt': receipt['funding_authorized'],
        }
    consents = load(next(workspace.glob('bob/public-eth-outgoing/lock/send-check-*/verified-consents.json')))
    calldata = lock_calldata(lock['txid'])
    return {
        'run': label,
        'outcome': public['outcome'],
        'agreement_digest': agreement_digest,
        'agreement_in_lock_calldata': {
            'lock_txid': lock['txid'], 'sepolia_block': lock['block'],
            'calldata_contains_agreement_digest': agreement_digest in calldata,
            'explorer': lock['explorer'],
        },
        'agreement_commits_to': {
            'funding_txid': agreement['native']['funding_txid'],
            'exit_bundle_digest': agreement['bundle_digest'],
            'native_refund_lock': agreement['native']['refund_lock'],
        },
        'both_owner_signatures_on_agreement_verified_before_lock': consents['both_owner_signatures_verified']
            and consents['agreement_digest'] == agreement_digest,
        'owner_receipts_before_funding': receipts,
        'exits_in_the_bundle': {'claim_C_effects_txid': exits['C'], 'refund_R_effects_txid': exits['R']},
        'on_chain': {
            'funding_F': {'txid': funding['txid'], 'zcash_height': funding['height']},
            'mined_exit': mined, 'mined_txid': txs[mined]['txid'], 'zcash_height': txs[mined]['height'],
            'mined_exit_matches_prepared': True,
            'unused_exit': unused, 'unused_txid': exits[unused],
            'unused_exit_mined': False,
        },
    }


def main():
    output, runs = sys.argv[1], dict(arg.split('=', 1) for arg in sys.argv[2:])
    public = {r['run']: r for r in load(RECORD)['runs']}
    with tempfile.TemporaryDirectory() as scratch:
        os.chmod(scratch, 0o700)
        records = [run_record(label, path, public[label], scratch) for label, path in runs.items()]
    out = {
        'date': '2026-10-21',
        'scope': 'Both exits of the two public V2 runs (004 settled, 005 no reveal) were fixed before funding.',
        'runs': records,
        'how_the_links_hold': [
            'v6 txids exclude anchors, proofs and signatures, so an exit\'s txid is fixed when it is prepared.',
            'The agreement digest and the bundle digest are SHA-256 over compact JSON with sorted keys, as in funding_consent::hash.',
            'The source signer refuses to sign F until both owners have signed the agreement, and the owners sign only after their receipts.',
        ],
        'what_anyone_can_check': [
            'The Sepolia lock calldata contains the agreement digest.',
            'F and the mined exit are on the Zcash testnet with the listed txids; the unused exit\'s txid is not.',
        ],
        'limits': [
            'The agreement and the bundle are not published: they hold one-time receive addresses and PCZTs. The digest links were checked from the owners\' private files with this script.',
            'The lock is mined after F, so its timestamp shows both exits were fixed before any ETH moved and before t was revealed. That they were accepted before F was broadcast rests on the owners\' receipts and the source signer\'s check, not on an external timestamp.',
        ],
        'command': 'python3 scripts/export_prefunding_evidence.py evidence/2026-10-21-prefunding-exits.json 004=.local/public-launch-004 005=.local/public-launch-005',
        'private_material_committed': False,
    }
    Path(output).write_text(json.dumps(out, indent=2) + '\n')
    for r in records:
        print(r['run'], r['on_chain']['mined_exit'], r['on_chain']['mined_txid'][:12], 'unused', r['on_chain']['unused_exit'], r['on_chain']['unused_txid'][:12],
              'lock calldata', r['agreement_in_lock_calldata']['calldata_contains_agreement_digest'])


if __name__ == '__main__':
    main()
