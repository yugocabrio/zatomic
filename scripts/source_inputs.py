"""Private source input preparation. Caller MUST hold the wallet's sync.lock.

One outstanding preparation per source wallet. Reservations do not time out:
deadline expiry cannot prove an authorized transaction is no longer spendable.
There is deliberately no release/send operation while the public sender and
terminal-state reconciliation are unfinished.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import uuid
from datetime import datetime
from testnet_wallet import GENESIS, NATIVE, ROOT, checkpoint, invoke, read
import timestamp_policy


def digest(path):
    # Enforce the same private bounded file check before hashing.
    read(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def publish(path, value):
    """Durable create-once JSON. A crash never publishes a partial reservation."""
    fd, temporary = tempfile.mkstemp(prefix='.source-pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path) # Atomic and fails if another reservation exists.
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.unlink(temporary)


def checked_plan(path):
    candidate = read(path)
    plan = candidate['plan']
    timestamp_policy.validate(plan)
    if candidate['plan_digest'] != timestamp_policy.digest(plan):
        raise RuntimeError('candidate execution plan digest mismatch')
    return plan, candidate['plan_digest']


def origin_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or meta.st_size > 4_000_000:
            raise RuntimeError('bounded private auxiliary origin required')
        with os.fdopen(fd, 'r', closefd=False) as stream:
            raw = stream.read()
        if not re.fullmatch(r'(?:[0-9a-f]{2})+', raw):
            raise RuntimeError('auxiliary origin encoding')
        return raw
    finally:
        os.close(fd)


def replay(directory, plan_digest, principal):
    path = directory / 'source-reservation.json'
    if not path.exists() and not path.is_symlink():
        return None
    saved = read(path)
    if (saved['format'] != 'latch-source-reservation-v1' or saved['genesis'] != GENESIS
            or saved['plan_digest'] != plan_digest or saved['principal_zatoshi'] != principal):
        raise RuntimeError('wallet already has a different source reservation; preserve it for reconciliation')
    name = saved['package']
    if not re.fullmatch(r'source-inputs-[0-9a-f]{32}', name):
        raise RuntimeError('invalid source package reference')
    folder = directory / name
    if folder.is_symlink() or not folder.is_dir() or folder.stat().st_mode & 0o077:
        raise RuntimeError('private source package required')
    manifest = read(folder / 'manifest.json')
    if digest(folder / 'manifest.json') != saved['manifest_sha256']:
        raise RuntimeError('reserved manifest changed; preserve reservation')
    for member, expected in manifest['files'].items():
        if not re.fullmatch(r'[a-z-]+\.json', member) or digest(folder/member) != expected:
            raise RuntimeError('reserved input package changed; preserve reservation')
    return {'file': str(folder/'manifest.json'), 'reserved': True, 'reused_reservation': True,
        'live_revalidated': False, 'funding_authorized': False, 'broadcast': False}


def fresh(value, now):
    observed = datetime.fromisoformat(value['observed_at'].replace('Z', '+00:00')).timestamp()
    if not 0 <= now-observed <= 120:
        raise RuntimeError('stale/future source input observation')


def auxiliary_coin(observation, snapshot, receiver, now):
    fresh(observation, now)
    if (observation['format'] != 'latch-testnet-auxiliary-observation-v1'
            or observation['genesis'] != GENESIS
            or observation['auxiliary_address'] != receiver['aux_address']
            or observation['auxiliary_script'] != receiver['aux_script']
            or observation['observed_tip']['height'] != snapshot['height']
            or observation['observed_tip']['hash'] != snapshot['tip']):
        raise RuntimeError('auxiliary observation differs from the source wallet/tip')
    # observeAuxiliary already verifies each raw non-coinbase v6/NU7 origin.
    candidates = [u for u in observation['utxos'] if type(u['value_zatoshi']) is int
        and u['value_zatoshi'] == 20_000 and type(u['height']) is int
        and snapshot['height']-u['height']+1 >= 12 and u['script'] == receiver['aux_script']]
    if not candidates:
        raise RuntimeError('no confirmed dedicated 20000-zatoshi auxiliary coin')
    return sorted(candidates, key=lambda u: (u['txid'],u['index']))[0]


def reserve(directory, candidate, principal):
    if type(principal) is not int or not 10_000 < principal <= 2_100_000_000_000_000-10_000:
        raise RuntimeError('principal_zatoshi must include a positive payout and the 10000-zatoshi claim fee')
    plan, plan_digest = checked_plan(candidate)
    previous = replay(directory, plan_digest, principal)
    if previous:
        return previous # Recovery inspection is allowed even after plan expiry.
    timestamp_policy.require_window(plan, 'funding', int(time.time()))
    info, current = checkpoint(directory)
    if current is None:
        raise RuntimeError('synchronize source wallet before preparing inputs')
    anchors = []
    for file in directory.glob('compact-*.json'):
        value = read(file)
        if (value['genesis'] == GENESIS and value['birthday_height'] == info['birthday']
                and type(value['height']) is int and value['height'] <= current['height']-11):
            anchors.append((value['height'], file, value))
    if not anchors:
        raise RuntimeError('retain a wallet checkpoint with twelve provider confirmations before preparing')
    _, _, anchor = max(anchors, key=lambda a: a[0])
    folder = directory / ('source-inputs-' + uuid.uuid4().hex)
    folder.mkdir(mode=0o700)
    publish(folder/'anchor.json', anchor)
    publish(folder/'current.json', current)
    publish(folder/'plan.json', plan)
    # This cryptographically validates both checkpoint paths against the wallet
    # before any auxiliary address is disclosed or any reservation is created.
    invoke(NATIVE, 'compact-source-snapshot', directory, folder/'anchor.json',
        folder/'current.json', principal, folder/'source.json')
    snapshot = read(folder/'source.json')
    receiver = invoke(NATIVE, 'testnet-wallet-receivers', directory)
    observed = invoke('node', ROOT/'scripts/observe_testnet_auxiliary.mjs', directory, folder/'auxiliary')
    auxiliary = read(Path(observed['file']))
    # Run the full-current-tip check AFTER the auxiliary index/origin reads.
    invoke('node', ROOT/'scripts/observe_testnet_source.mjs', folder/'source.json', folder/'canonical.json')
    canonical = read(folder/'canonical.json')
    now = int(time.time())
    timestamp_policy.require_window(plan, 'funding', now)
    fresh(canonical, now)
    coin = auxiliary_coin(auxiliary, snapshot, receiver, now)
    publish(folder/'auxiliary.json', auxiliary)
    publish(folder/'selected-auxiliary.json', coin)
    publish(folder/'auxiliary-source.json', {'height':coin['height'],'index':coin['index'],
        'tx':origin_bytes(folder/'auxiliary'/(coin['txid']+'.hex'))})
    members = ['anchor.json','current.json','plan.json','source.json','canonical.json',
        'auxiliary.json','selected-auxiliary.json','auxiliary-source.json']
    manifest = {'format':'latch-source-inputs-v1','genesis':GENESIS,'plan_digest':plan_digest,
        'principal_zatoshi':principal,'files':{name:digest(folder/name) for name in members},
        'selected_note_commitment':snapshot['notes'][0]['cmx'],
        'selected_auxiliary_outpoint':{'txid':coin['txid'],'index':coin['index']},
        'funding_authorized':False,'broadcast':False,'created_at':now,
        'scope':'private input preparation only; not a signed swap or canonicality proof'}
    publish(folder/'manifest.json', manifest)
    # Last durable step; an abandoned earlier package is not an active input
    # reservation. Never overwrite/expire this record on errors or restart.
    publish(directory/'source-reservation.json', {'format':'latch-source-reservation-v1',
        'genesis':GENESIS,'plan_digest':plan_digest,'principal_zatoshi':principal,
        'package':folder.name,'manifest_sha256':digest(folder/'manifest.json'),
        'selected_note_commitment':manifest['selected_note_commitment'],
        'selected_auxiliary_outpoint':manifest['selected_auxiliary_outpoint']})
    return {'file':str(folder/'manifest.json'),'reserved':True,'reused_reservation':False,
        'live_revalidated':True,'source_confirmations':snapshot['source_confirmations'],
        'anchor_confirmations':snapshot['anchor_confirmations'],
        'auxiliary_confirmations':snapshot['height']-coin['height']+1,
        'funding_authorized':False,'broadcast':False}


def replay_graph(folder, roles_digest):
    """Inspect an existing immutable draft; never infer fresh spendability."""
    receipt_path = folder/'graph-draft.json'
    if receipt_path.exists() or receipt_path.is_symlink():
        receipt = read(receipt_path)
        if receipt['destinations_sha256'] != roles_digest or not re.fullmatch(r'graph-[0-9a-f]{32}', receipt['directory']):
            raise RuntimeError('reserved graph destinations changed')
        output = folder/receipt['directory']
        if output.is_symlink() or not output.is_dir() or output.stat().st_mode & 0o077:
            raise RuntimeError('private graph directory required')
        checked = read(output/'graph.json')
        if digest(output/'graph.json') != receipt['graph_digest']:
            raise RuntimeError('reserved graph changed; retain all inputs')
        for name, expected_hash in checked['files'].items():
            if not re.fullmatch(r'(funding|claim|refund)(-check)?\.pczt',name):
                raise RuntimeError('invalid graph member')
            fd = os.open(output/name, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                meta = os.fstat(fd)
                if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or meta.st_size > 1_000_000:
                    raise RuntimeError('private bounded graph member required')
                with os.fdopen(fd,'rb',closefd=False) as stream:
                    if hashlib.sha256(stream.read()).hexdigest() != expected_hash:
                        raise RuntimeError('reserved graph member changed')
            finally:
                os.close(fd)
        return {'file':str(output/'graph.json'),'graph_digest':receipt['graph_digest'],
            'reused_graph':True,'live_revalidated':False,'funding_authorized':False,'broadcast':False}
    return None


def graph(directory, destinations):
    """Build at most one unsigned graph for this reservation under sync.lock.

    Both destination receipts and the quote are verified before construction.
    Final graph/plan consent and real-input signing remain separate, disabled
    steps. Expiry cannot release inputs.
    """
    saved = read(directory/'source-reservation.json')
    previous = replay(directory, saved['plan_digest'], saved['principal_zatoshi'])
    if previous is None:
        raise RuntimeError('source inputs must be reserved before graph preparation')
    folder = Path(previous['file']).parent
    plan = read(folder/'plan.json')
    timestamp_policy.validate(plan)
    roles = read(destinations)
    checked = invoke(NATIVE,'testnet-setup-verify',destinations)
    if checked['principal_zatoshi'] != saved['principal_zatoshi']:
        raise RuntimeError('reserved amount differs from owner-accepted quote')
    roles_digest = hashlib.sha256(json.dumps(roles,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    existing = replay_graph(folder,roles_digest)
    if existing:
        return existing
    receipt_path = folder/'graph-draft.json'
    timestamp_policy.require_window(plan,'funding',int(time.time()))
    token = uuid.uuid4().hex
    public_roles = folder/('destinations-'+token+'.json')
    publish(public_roles,roles)
    output = folder/('graph-'+token)
    report = invoke(NATIVE,'testnet-unsigned-graph',directory,folder,public_roles,output)
    if report['graph_digest'] != digest(output/'graph.json'):
        raise RuntimeError('native graph digest mismatch')
    publish(receipt_path,{'directory':output.name,'destinations_sha256':roles_digest,
        'graph_digest':report['graph_digest']})
    return dict(report,reused_graph=False,live_revalidated=False)
