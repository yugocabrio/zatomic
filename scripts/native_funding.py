"""Owner-retained, already-published native funding bytes, not signing material.

Only the caller's independently checked canonical ETH settlement may authorize
recovery. This module never creates/re-signs/re-proves F or consults a source key.
Node observation is trusted local RPC, not an SPV proof.
"""
import json
import re
import tempfile
from regtest_node import rpc, status, GENESIS, BRANCH, RpcError
from regtest_wallet import save, native
from signer_transport import private_file
from evm_journal import InjectedStop


def inspect_raw(directory, raw, expected):
    if not isinstance(raw, str) or len(raw) > 4_000_000 or not re.fullmatch(r'(?:[0-9a-f]{2})+', raw):
        raise RuntimeError('invalid observed native funding encoding')
    # Parse with the pinned native implementation. The temporary file contains
    # only already-published transaction bytes, and is removed on normal exit.
    with tempfile.NamedTemporaryFile(dir=directory, prefix='.observed-funding-', suffix='.hex') as handle:
        handle.write(raw.encode())
        handle.flush()
        info = native('regtest-inspect', handle.name)
    if info['txid'] != expected or info['transparent_inputs'] != 0 or info['expiry_height'] != 0:
        raise RuntimeError('observed native funding differs from agreed effects')
    return info['authorization_bytes_sha256']


def observe(directory, terms, transaction):
    if not transaction.get('in_active_chain') or transaction.get('confirmations', 0) < 2:
        raise RuntimeError('funding observation requires two current confirmations')
    raw = transaction['hex']
    digest = inspect_raw(directory, raw, terms['funding_txid'])
    folder = directory / 'native-funding-observed'
    folder.mkdir(mode=0o700, exist_ok=True)
    if folder.is_symlink():
        raise RuntimeError('observed funding directory must not be a symlink')
    # Stable bytes/domain only. A previous observation is never used as proof
    # that its block remains canonical. Different authorizations coexist.
    save(folder / f'{digest}.json', {'version': 1, 'genesis': GENESIS, 'branch': BRANCH,
        'txid': terms['funding_txid'], 'raw': raw, 'bytes_sha256': digest})


def history(directory, terms):
    folder = directory / 'native-funding-observed'
    files = sorted(folder.glob('*.json'))
    if folder.is_symlink() or not 1 <= len(files) <= 32:
        raise RuntimeError('missing or excessive published funding history')
    values = []
    for path in files:
        value = json.loads(private_file(path, 4_100_000))
        if (value['version'] != 1 or value['genesis'] != GENESIS or value['branch'] != BRANCH
                or value['txid'] != terms['funding_txid']):
            raise RuntimeError('published funding observation domain changed')
        digest = inspect_raw(directory, value['raw'], terms['funding_txid'])
        if value['bytes_sha256'] != digest or path.name != f'{digest}.json':
            raise RuntimeError('published funding bytes differ from their identity')
        values.append(value)
    return values


def current(txid):
    try:
        return rpc('getrawtransaction', [txid, 1])
    except RpcError as exc:
        if exc.code != -5:
            raise
        return {}


def restore_published(directory, terms, fault_after_send=False):
    """Caller has verified a current canonical ETH claim for this exact order."""
    status()
    versions = history(directory, terms)  # Validate ALL retained versions first.
    txid = terms['funding_txid']
    transaction = current(txid)
    depth = transaction.get('confirmations', 0) if transaction.get('in_active_chain') else 0
    sent = False
    if depth < 1 and txid not in rpc('getrawmempool'):
        for version in versions:
            try:
                accepted = rpc('sendrawtransaction', [version['raw']], timeout=180)
            except RpcError as exc:
                # Another retained published authorization may have a valid
                # anchor. Transport/unknown failures never trigger a fallback.
                if 'unknown Ironwood anchor' in str(exc):
                    continue
                raise
            if accepted != txid:
                raise RuntimeError('published funding replay changed transaction identity')
            sent = True
            break
        if not sent:
            raise RuntimeError('all published funding anchors unavailable; source re-proving is not implemented')
        if fault_after_send:
            raise InjectedStop('published-funding-send-before-confirmation')
    if depth < 2:
        # Explicitly local harness mining, never a public finality policy.
        rpc('generate', [2 - depth], timeout=300)
    confirmed = current(txid)
    if not confirmed.get('in_active_chain') or confirmed.get('confirmations', 0) < 2:
        raise RuntimeError('published funding replay did not confirm')
    observe(directory, terms, confirmed)
    return {'action': 'restore-funding', 'txid': txid, 'new_transaction': sent,
        'chain': 'native', 'new_source_signature': False, 'source_wallet_accessed': False,
        'published_bytes_only': True, 'confirmations': confirmed['confirmations']}
