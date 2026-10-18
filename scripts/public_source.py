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
import public_source_guard


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
        yield fd
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


def source_identity(wallet, agreement, released=False):
    if not released: return public_source_guard.check_locked(wallet, agreement)
    if ((wallet/public_source_guard.CANCELLED).exists() or (wallet/public_source_guard.CANCELLED).is_symlink()
            or not (wallet/public_source_guard.RELEASE).is_file()):
        raise RuntimeError('existing uncancelled exact release required')
    return public_source_guard.identity_locked(wallet, agreement)


def prepare(wallet, bundle_path, agreement, verified, directory, released=False, replay=False):
    """Caller holds sync.lock. Bind offline reservation BEFORE provider requests."""
    if replay and not released: raise RuntimeError('late replay requires an existing source release')
    authority = source_identity(wallet, agreement, released)
    bundle = testnet_wallet.read(bundle_path)
    if eth.digest(bundle) != agreement['bundle_digest'] or bundle['synthetic_inputs'] is not False:
        raise RuntimeError('source bundle changed or contains synthetic inputs')
    plan = agreement['execution_plan']
    if not replay: timestamp_policy.require_window(plan, 'funding', int(time.time()))
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
    if (original['fvk_fingerprint'] != authority['source_fvk_fingerprint']
            or expected_aux['aux_script'] != authority['source_aux_script']):
        raise RuntimeError('reserved graph is not controlled by the source-approved wallet keys')
    save(directory/'reserved-graph-check.json', checked)
    return {'directory': directory, 'authority': authority, 'wallet': wallet, 'folder': folder,
        'original': original, 'principal': agreement['native']['principal_zatoshi'],
        'released': released, 'replay': replay}


def scan(context, attempt):
    """Synchronize to the provider tip and snapshot the exact reserved note.

    Synchronization keeps every old checkpoint; on a fork it refuses instead of
    rewinding or replacing the reservation. Bounded batches.
    """
    wallet, folder = context['wallet'], context['folder']
    work = context['directory']/('scan-'+str(attempt)); work.mkdir(mode=0o700)
    sync = testnet_wallet.sync(wallet, 4)
    if sync['caught_up_to_observed_tip'] is not True:
        raise RuntimeError('source still behind provider tip; continue explicit wallet sync')
    _, current = testnet_wallet.checkpoint(wallet)
    save(work/'current.json', current)
    native('compact-source-snapshot', wallet, folder/'anchor.json', work/'current.json',
        context['principal'], work/'source.json')
    fresh = testnet_wallet.read(work/'source.json')
    exact_note(context['original'], fresh)
    return work, fresh


def observe(context, agreement):
    """Recheck the exact old anchor and the freshly scanned current tip live.

    Scans immediately before the provider query, after the slower escrow
    observations. Zcash blocks arrive about every 75 seconds; if one lands
    mid-check the tip no longer matches, so scan again (at most three times)
    rather than skip the new block's nullifiers.
    """
    if source_identity(context['wallet'], agreement, context.get('released', False)) != context['authority']:
        raise RuntimeError('source authority changed during observations')
    for attempt in range(3):
        directory, snapshot = scan(context, attempt)
        observed = subprocess.run(['node', str(ROOT/'scripts/observe_testnet_source.mjs'),
            str(directory/'source.json'), str(directory/'canonical.json')],
            capture_output=True, text=True, timeout=150)
        if observed.returncode == 0:
            break
        if 'synchronized to the current provider tip' not in observed.stderr:
            raise RuntimeError('source canonical observation refused')
    else:
        raise RuntimeError('source tip kept advancing during observation')
    canonical = testnet_wallet.read(directory/'canonical.json')
    source_inputs.fresh(canonical, int(time.time()))
    if (canonical['genesis'] != agreement['native_genesis']
            or canonical['branch'] != agreement['native_branch']
            or canonical['observed_tip']['height'] != snapshot['height']
            or canonical['observed_tip']['hash'] != snapshot['tip']
            or canonical['anchor']['height'] != snapshot['anchor_height']
            or canonical['anchor']['hash'] != snapshot['anchor_tip']):
        raise RuntimeError('source canonical observation differs from checked snapshots')
    if not context.get('replay', False):
        timestamp_policy.require_window(agreement['execution_plan'], 'funding', int(time.time()))
    clock = {'genesis': canonical['genesis'], 'branch_id': canonical['branch'],
        'observed_at': canonical['observed_at'], 'provider_header_timestamp': canonical['observed_tip']['timestamp'],
        # observeSource has just rejected any announced nonzero upgrade height.
        'announced_upgrade': {'height': 0}}
    summary = {'exact_reserved_graph_and_source_note_checked': True,
        'source_authority_digest': context['authority']['authority_digest'],
        'source_wallet_and_owner_pins_bound': True,
        'observed_tip': canonical['observed_tip'], 'anchor': canonical['anchor'],
        'source_confirmations_by_provider': snapshot['source_confirmations'],
        'provider_trusted': True, 'reservation_preserved': True, 'funding_authorized': False}
    return clock, summary
