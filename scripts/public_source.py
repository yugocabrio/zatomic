"""Fresh source-note checks under the source wallet's sync lock; never signing.

The final provider query must happen AFTER slower escrow/auxiliary observations.
A changed current tip requires another compact scan, never a cached success or
automatic release of the existing source reservation.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import time
import public_evm_observation as eth
from regtest_wallet import ROOT, native, save
import source_inputs
import testnet_wallet
import timestamp_policy


@contextmanager
def locked(wallet):
    meta = wallet.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_mode & 0o077:
        raise RuntimeError('private source wallet directory required')
    if testnet_wallet.read(wallet/'network.json')['genesis'] != testnet_wallet.GENESIS:
        raise RuntimeError('public source wallet required')
    fd = os.open(wallet/'sync.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def exact_note(original, fresh):
    # Selection may find another usable note if the original was spent. It must
    # not silently replace the agreed source or change the pre-proved F anchor.
    fields = ('format', 'genesis', 'branch', 'fvk_fingerprint', 'principal_zatoshi',
        'anchor_height', 'anchor_tip', 'anchor_tree', 'anchor', 'notes')
    if any(original[field] != fresh[field] for field in fields):
        raise RuntimeError('reserved source note or original funding anchor changed')
    if fresh['height'] < original['height']:
        raise RuntimeError('source wallet checkpoint moved backwards')


def prepare(wallet, bundle_path, agreement, verified, directory):
    """Caller holds sync.lock. Bind offline reservation BEFORE provider requests."""
    bundle = testnet_wallet.read(bundle_path)
    if eth.digest(bundle) != agreement['bundle_digest'] or bundle['synthetic_inputs'] is not False:
        raise RuntimeError('source bundle changed or contains synthetic inputs')
    plan = agreement['execution_plan']
    timestamp_policy.require_window(plan, 'funding', int(time.time()))
    previous = source_inputs.replay(wallet, agreement['execution_plan_digest'], agreement['native']['principal_zatoshi'])
    if previous is None:
        raise RuntimeError('existing source reservation required before live preflight')
    folder = Path(previous['file']).parent
    directory.mkdir(mode=0o700)
    save(directory/'review.json', bundle['review'])
    # Shared with the real source auxiliary preparation: exact package members,
    # PCZT hashes, unsigned F and its zero-authorized preview, graph and plan.
    checked = native('testnet-check-reserved-graph', wallet, folder, directory/'review.json')
    expected_aux = verified['native_auxiliary']
    if (checked['review_packet_digest'] != agreement['review_packet_digest']
            or checked['plan_digest'] != agreement['execution_plan_digest']
            or checked['principal_zatoshi'] != agreement['native']['principal_zatoshi']
            or checked['selected_auxiliary_outpoint'] != {'txid': expected_aux['txid'], 'index': expected_aux['index']}):
        raise RuntimeError('reserved graph differs from both conditional consents')
    original = testnet_wallet.read(folder/'source.json')
    if checked['selected_note_commitment'] != original['notes'][0]['cmx']:
        raise RuntimeError('reserved note commitment changed')
    # Synchronization keeps every old checkpoint; on a fork it refuses instead
    # of rewinding or replacing the reservation. Bounded batches, no busy retry.
    sync = testnet_wallet.sync(wallet, 4)
    if sync['caught_up_to_observed_tip'] is not True:
        raise RuntimeError('source still behind provider tip; continue explicit wallet sync')
    _, current = testnet_wallet.checkpoint(wallet)
    save(directory/'current.json', current)
    native('compact-source-snapshot', wallet, folder/'anchor.json', directory/'current.json',
        agreement['native']['principal_zatoshi'], directory/'source.json')
    fresh = testnet_wallet.read(directory/'source.json')
    exact_note(original, fresh)
    save(directory/'reserved-graph-check.json', checked)
    return {'directory': directory, 'snapshot': fresh}


def observe(context, agreement):
    """Recheck the exact old anchor and the freshly scanned current tip live."""
    directory, snapshot = context['directory'], context['snapshot']
    subprocess.run(['node', str(ROOT/'scripts/observe_testnet_source.mjs'),
        str(directory/'source.json'), str(directory/'canonical.json')],
        capture_output=True, text=True, timeout=150, check=True)
    canonical = testnet_wallet.read(directory/'canonical.json')
    source_inputs.fresh(canonical, int(time.time()))
    if (canonical['genesis'] != agreement['native_genesis']
            or canonical['branch'] != agreement['native_branch']
            or canonical['observed_tip']['height'] != snapshot['height']
            or canonical['observed_tip']['hash'] != snapshot['tip']
            or canonical['anchor']['height'] != snapshot['anchor_height']
            or canonical['anchor']['hash'] != snapshot['anchor_tip']):
        raise RuntimeError('source canonical observation differs from checked snapshots')
    timestamp_policy.require_window(agreement['execution_plan'], 'funding', int(time.time()))
    clock = {'genesis': canonical['genesis'], 'branch_id': canonical['branch'],
        'observed_at': canonical['observed_at'], 'provider_header_timestamp': canonical['observed_tip']['timestamp'],
        # observeSource has just rejected any announced nonzero upgrade height.
        'announced_upgrade': {'height': 0}}
    summary = {'exact_reserved_graph_and_source_note_checked': True,
        'observed_tip': canonical['observed_tip'], 'anchor': canonical['anchor'],
        'source_confirmations_by_provider': snapshot['source_confirmations'],
        'provider_trusted': True, 'reservation_preserved': True, 'funding_authorized': False}
    return clock, summary
