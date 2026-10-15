#!/usr/bin/env python3
"""Read-only/adversarial requests against the owned local demo API. No valid action."""
import json
import urllib.error
import urllib.request
from urllib.parse import urlsplit

ROOT = 'http://127.0.0.1:8787'


def request(path, method='GET', headers=None, body=None):
    req = urllib.request.Request(ROOT + path, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def main():
    assert urlsplit(ROOT).hostname == '127.0.0.1'
    code, body, headers = request('/api/state')
    assert code == 200
    state = json.loads(body)
    token = state['token']
    public = json.dumps(state['jobs'])
    for forbidden in ['spending-key', 'frost-share', 'witness_le', 'presignature', 'claim-policy', 'joint_fvk', 'evm-checkpoint']:
        assert forbidden not in public, forbidden
    assert headers['Cache-Control'] == 'no-store'
    assert "frame-ancestors 'none'" in headers['Content-Security-Policy']
    auth = {'Content-Type': 'application/json', 'X-Latch-Token': token}
    cases = [
        ('private filesystem', '/.local/demo/index.json', 'GET', {}, None, 404),
        ('path traversal', '/api/evidence/../../.local/chain-driver.lock', 'GET', {}, None, 404),
        ('encoded traversal', '/api/evidence/%2e%2e%2f.local%2fsecret', 'GET', {}, None, 404),
        ('host rebinding', '/api/state', 'GET', {'Host': 'evil.example'}, None, 403),
        ('foreign origin read', '/api/state', 'GET', {'Origin': 'https://evil.example'}, None, 403),
        ('missing token', '/api/start', 'POST', {'Content-Type': 'application/json'}, b'{"scenario":"success"}', 403),
        ('foreign origin action', '/api/start', 'POST', {**auth, 'Origin': 'https://evil.example'}, b'{"scenario":"success"}', 403),
        ('invalid content type', '/api/start', 'POST', {'X-Latch-Token': token}, b'{}', 415),
        ('malformed JSON', '/api/start', 'POST', auth, b'{', 409),
        ('non-object JSON', '/api/start', 'POST', auth, b'[]', 409),
        ('arbitrary command', '/api/start', 'POST', auth, b'{"scenario":"; echo unsafe"}', 409),
        ('arbitrary recovery path', '/api/recover', 'POST', auth, b'{"id":"../../outside"}', 409),
        ('oversized request', '/api/start', 'POST', auth, b' ' * 4097, 409),
    ]
    for name, path, method, headers, payload, expected in cases:
        got, _, _ = request(path, method, headers, payload)
        assert got == expected, (name, expected, got)
    print(json.dumps({'scope': 'local HTTP API boundary checks; no valid action submitted',
        'rejected': [c[0] for c in cases], 'private_state_not_exposed': True,
        'cache_and_framing_headers_checked': True}, indent=2))


if __name__ == '__main__':
    main()
