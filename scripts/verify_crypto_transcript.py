#!/usr/bin/env python3
"""Independent public-input affine arithmetic; NEVER use for secret-key work.

Python integers/hashlib only: no Rust, pasta_curves, FROST or Solidity arithmetic
calls. Verifies disposable transcripts from the actual custom Rust signer and
the existing public Solidity vectors. This is not an independent security audit.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import stat

P = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
Q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
G = (0x375523b328f1d6063b8d187c3e5f445f0c7f0ce37b70a10c8d1a7284b875c963,
     0x1ad0357fdf1a66db7b10bcfcfed624fbdfc914fec005bdd84ce33e817b0c3bc9)


def require(value):
    if not value:
        raise ValueError('cryptographic equation or canonical encoding rejected')


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u:
        if (y + v) % P == 0:
            return None
        slope = 3 * x * x * pow(2 * y, -1, P) % P
    else:
        slope = (v - y) * pow(u - x, -1, P) % P
    xx = (slope * slope - x - u) % P
    return xx, (slope * (x - xx) - y) % P


def mul(n, a=G):
    require(n >= 0)
    out = None
    while n:
        if n & 1:
            out = add(out, a)
        a = add(a, a)
        n >>= 1
    return out


def sqrt(value):
    # Tonelli-Shanks, needed because P is 1 mod 4.
    if value == 0:
        return 0
    require(pow(value, (P - 1) // 2, P) == 1)
    odd, bits = P - 1, 0
    while odd % 2 == 0:
        odd //= 2
        bits += 1
    nonresidue = 2
    while pow(nonresidue, (P - 1) // 2, P) == 1:
        nonresidue += 1
    c, t, root = pow(nonresidue, odd, P), pow(value, odd, P), pow(value, (odd + 1) // 2, P)
    while t != 1:
        i, squared = 0, t
        while squared != 1:
            squared = squared * squared % P
            i += 1
            require(i < bits)
        b = pow(c, 1 << (bits - i - 1), P)
        root = root * b % P
        c = b * b % P
        t = t * c % P
        bits = i
    require(root * root % P == value)
    return root


def raw(value, size=32):
    out = bytes.fromhex(value)
    require(len(out) == size)
    return out


def scalar(value):
    n = int.from_bytes(raw(value), 'little')
    require(n < Q)
    return n


def encode(point):
    require(point is not None)
    x, y = point
    return (x | ((y & 1) << 255)).to_bytes(32, 'little')


def point(value):
    data = raw(value)
    require(data != bytes(32))
    n = int.from_bytes(data, 'little')
    x, sign = n & ((1 << 255) - 1), n >> 255
    require(x < P)
    y = sqrt((pow(x, 3, P) + 5) % P)
    if y & 1 != sign:
        y = P - y
    result = x, y
    require(0 <= y < P and encode(result) == data)
    return result


def h(person, data):
    return hashlib.blake2b(data, digest_size=64, person=person).digest()


def hs(person, data):
    return int.from_bytes(h(person, data), 'little') % Q


def verify(t):
    alpha = scalar(t['randomizer'])
    public, rk, target = point(t['public_key']), point(t['randomized_key']), point(t['adaptor_point'])
    require(rk == add(public, mul(alpha)))
    people = t['participants']
    ids = [scalar(p['id']) for p in people]
    require(ids == [1, 2])
    encoded = b''.join(raw(p['id']) + raw(p['hiding']) + raw(p['binding']) for p in people)
    prefix = (raw(t['randomized_key']) + h(b'FROST_RedPallasM', raw(t['message']))
        + h(b'FROST_RedPallasC', encoded) + b'ShieldedSwap/adaptor/v1'
        + raw(t['session']) + raw(t['adaptor_point']) + raw(t['randomizer']))
    challenge = hs(b'Zcash_RedPallasH', raw(t['r_hat']) + raw(t['randomized_key']) + raw(t['message']))
    total_nonce, total_public, total_share = None, None, 0
    for part, i in zip(people, ids):
        coefficient = 1
        for j in ids:
            if i != j:
                coefficient = coefficient * j * pow(j - i, -1, Q) % Q
        rho = hs(b'FROST_RedPallasR', prefix + raw(part['id']))
        nonce = add(point(part['hiding']), mul(rho, point(part['binding'])))
        vi, zi = point(part['verifying_share']), scalar(part['signature_share'])
        require(mul(zi) == add(nonce, mul(coefficient * challenge % Q, add(vi, mul(alpha)))))
        total_nonce = add(total_nonce, nonce)
        total_public = add(total_public, mul(coefficient, vi))
        total_share = (total_share + zi) % Q
    require(total_public == public and add(total_nonce, target) == point(t['r_hat']))
    require(total_share == scalar(t['s_hat']))
    rhat = point(t['r_hat'])
    require(mul(total_share) == add(add(rhat, (target[0], -target[1] % P)), mul(challenge, rk)))
    signature = raw(t['signature'], 64)
    require(signature[:32] == raw(t['r_hat']))
    s = scalar(signature[32:].hex())
    require(mul(s) == add(rhat, mul(challenge, rk)))
    witness = scalar(t['witness'])
    require(witness != 0 and (s - total_share) % Q == witness and mul(witness) == target)


def check(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size < 100_000 and info.st_mode & 0o077 == 0)
    data = path.read_bytes()
    envelope = json.loads(data)
    require(envelope['version'] == 1 and envelope['current_native_verifier_passed'] is True)
    require(mul(Q) is None and mul(1) == G and (G[1] * G[1] - G[0]**3 - 5) % P == 0)
    rejected = set()
    for transcript in envelope['transcripts']:
        verify(transcript)
        for field in ('session', 'message', 'randomizer', 'adaptor_point', 'randomized_key', 'r_hat', 's_hat', 'signature', 'witness'):
            altered = copy.deepcopy(transcript)
            b = bytearray.fromhex(altered[field])
            b[0] ^= 1
            altered[field] = b.hex()
            try:
                verify(altered)
            except ValueError:
                rejected.add(field)
            else:
                raise RuntimeError('changed transcript accepted: ' + field)
        for field in ('hiding', 'binding', 'verifying_share', 'signature_share', 'id'):
            altered = copy.deepcopy(transcript)
            b = bytearray.fromhex(altered['participants'][0][field])
            b[0] ^= 1
            altered['participants'][0][field] = b.hex()
            try:
                verify(altered)
            except ValueError:
                rejected.add(field)
            else:
                raise RuntimeError('changed participant accepted: ' + field)
    solidity = Path(__file__).resolve().parents[1] / 'contracts/test/PallasVectors.t.sol'
    vectors = re.findall(r'require\(Pallas.opens\((0x[0-9a-f]+), Pallas.Point\((0x[0-9a-f]+), (0x[0-9a-f]+)\)\)\);', solidity.read_text())
    require(len(vectors) == 15)
    for value, x, y in vectors:
        require(mul(int(value, 16)) == (int(x, 16), int(y, 16)))
    return {'scope': 'independent Python affine arithmetic and hashlib; implementation cross-check, not external audit',
        'transcript_sha256': hashlib.sha256(data).hexdigest(), 'transcripts': len(envelope['transcripts']),
        'randomizers': ['zero', 'random', 'q-minus-one'], 'signature_and_share_equations': True,
        'binding_factor_context_verified': True, 'witness_extraction_verified': True,
        'changed_fields_rejected': sorted(rejected), 'solidity_vectors_cross_checked': len(vectors),
        'private_transcript_committed': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('private_transcript', type=Path)
    a = p.parse_args()
    print(json.dumps(check(a.private_transcript), indent=2))
