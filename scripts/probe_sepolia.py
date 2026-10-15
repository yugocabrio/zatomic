#!/usr/bin/env python3
"""Pinned Sepolia read-only observations for the future public swap profile.

All hashes, safe/finalized labels and fees are provider claims, not an Ethereum
light-client proof. No wallet address, key, calldata or transaction is sent.
"""
from datetime import datetime, timezone
import json
import re
import time
import urllib.request

ENDPOINT = 'https://ethereum-sepolia-rpc.publicnode.com'
CHAIN_ID = 11155111
GENESIS = '0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9'
ALLOWED = {'eth_chainId', 'eth_getBlockByNumber', 'eth_maxPriorityFeePerGas'}
_last_request = 0.0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('RPC redirects are not permitted')


class RpcError(RuntimeError):
    def __init__(self, method, code):
        self.code = code
        super().__init__(f'{method}: RPC error code {code}')


def rpc(method, params):
    global _last_request
    if method not in ALLOWED:
        raise ValueError('read-only Sepolia RPC method required')
    # Pace public requests; a 429 still stops the run (no automatic retry).
    time.sleep(max(0, 2.0 - (time.monotonic() - _last_request)))
    _last_request = time.monotonic()
    req = urllib.request.Request(ENDPOINT,
        json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
        {'Content-Type': 'application/json', 'User-Agent': 'Latch-readonly-testnet/1'})
    with urllib.request.build_opener(NoRedirect).open(req, timeout=15) as response:
        raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise RuntimeError('RPC response size bound')
        result = json.loads(raw)
    if not isinstance(result, dict) or result.get('jsonrpc') != '2.0' or type(result.get('id')) is not int or result['id'] != 1:
        raise RuntimeError(f'{method}: invalid Sepolia RPC envelope')
    if 'error' in result:
        raise RpcError(method, result['error'].get('code') if isinstance(result['error'], dict) else None)
    if 'result' not in result:
        raise RuntimeError(f'{method}: missing Sepolia RPC result')
    return result['result']


def quantity(value):
    if not isinstance(value, str) or not re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]{0,63})', value):
        raise RuntimeError('noncanonical RPC quantity')
    return int(value, 16)


def block(tag):
    b = rpc('eth_getBlockByNumber', [tag, False])
    if not isinstance(b, dict) or not re.fullmatch(r'0x[0-9a-f]{64}', b.get('hash', '')):
        raise RuntimeError('requested Sepolia block is unavailable')
    return {'height': quantity(b['number']), 'hash': b['hash'], 'timestamp': quantity(b['timestamp']),
        'base_fee_wei': quantity(b['baseFeePerGas']) if b.get('baseFeePerGas') is not None else None}


def observe():
    started = time.monotonic()
    if quantity(rpc('eth_chainId', [])) != CHAIN_ID:
        raise RuntimeError('Sepolia chain ID mismatch')
    genesis_verified = False
    try:
        genesis = block('0x0')
        if genesis['height'] != 0 or genesis['hash'] != GENESIS:
            raise RuntimeError('Sepolia genesis mismatch')
        genesis_verified = True
    except RpcError as error:
        if error.code != 4444:
            raise
        # A pruned-history observation can still help diagnose clocks/fees.
        # It MUST be labeled incomplete, and the CLI exits non-success below.
    finalized, safe, latest = [block(tag) for tag in ('finalized', 'safe', 'latest')]
    if not (finalized['height'] <= safe['height'] <= latest['height']
            and finalized['timestamp'] <= safe['timestamp'] <= latest['timestamp']):
        raise RuntimeError('provider finality labels inconsistent')
    for observed in (finalized, safe, latest):
        if block(hex(observed['height'])) != observed:
            raise RuntimeError('provider canonical block changed during observation')
    priority = quantity(rpc('eth_maxPriorityFeePerGas', []))
    elapsed = time.monotonic() - started
    if elapsed > 60 or latest['base_fee_wei'] is None:
        raise RuntimeError('stale/incomplete fee observation')
    now = int(time.time())
    return {'scope': 'read-only TLS Sepolia RPC; provider trusted, no consensus/finality proof',
        'endpoint': ENDPOINT, 'chain_id': CHAIN_ID, 'expected_genesis': GENESIS,
        'rpc_genesis_verified': genesis_verified,
        'status': 'observed' if genesis_verified else 'incomplete-genesis-history-pruned',
        'observed_at': datetime.fromtimestamp(now, timezone.utc).isoformat(), 'elapsed_seconds': round(elapsed, 3),
        'latest': latest, 'provider_safe': safe, 'provider_finalized': finalized,
        'latest_age_seconds_by_local_clock': now - latest['timestamp'],
        'suggested_priority_fee_wei': priority, 'keys_or_addresses_sent': False,
        'broadcast': False, 'deployment': False, 'funding_authorized': False,
        'limits': ['Provider labels are not locally verified finality.',
            'Fee observations are not gas estimation, inclusion guarantees or spending authorization.',
            'This observer is not connected to the isolated owner transaction sender.']}


if __name__ == '__main__':
    try:
        observed = observe()
        print(json.dumps(observed, indent=2))
        if not observed['rpc_genesis_verified']:
            raise SystemExit(2)
    except (RuntimeError, ValueError, OSError, KeyError, TypeError) as error:
        raise SystemExit(str(error)) from None
