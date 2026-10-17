#!/usr/bin/env python3
"""Alice's owner signer releases a claim share only after Bob's share verifies.

A peer whose hiding nonce is shifted by -T could otherwise finish claim C from
Alice's raw share without the witness (see the shielded-swap-crypto test
shifted_peer_nonce_cannot_obtain_witness_free_signature). This drives the real
testnet-owner-signer processes over a COPY of an unfunded synthetic review
fixture. No node/RPC, proof generation, source signature or broadcast.
"""
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
from check_independent_operators import Operators
from regtest_node import ROOT


def check(root, review, binary=ROOT / 'target/release/shielded-swap-native'):
    for role in ('alice', 'bob'):
        for name in ('graph-review.json', 'reviewed-graph-packet.json', 'reviewed-graph-policy.json'):
            if not (review / role / name).is_file():
                raise RuntimeError('finish both owner reviews before copying the fixture')
    shutil.copytree(review, root)
    actors = Operators(root)
    packet = json.loads((root / 'alice/reviewed-graph-packet.json').read_text())
    if packet['graph']['input_binding']['synthetic'] is not True:
        raise RuntimeError('only unfunded synthetic review fixtures allowed')
    policy = json.loads((root / 'alice/reviewed-graph-policy.json').read_text())

    def start(role):
        p = subprocess.Popen(actors.command(role, [str(binary), 'testnet-owner-signer', str(root / role)]),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if not select.select([p.stdout], [], [], 30)[0] or not p.stdout.readline():
            p.kill(); p.wait(); raise RuntimeError('signer startup failed')
        return p

    def send(p, value):
        p.stdin.write(json.dumps(value) + '\n'); p.stdin.flush()
        if not select.select([p.stdout], [], [], 15)[0]:
            raise RuntimeError('signer response timeout')
        line = p.stdout.readline()
        return json.loads(line) if line else None

    def session(alice_sign):
        alice, bob = start('alice'), start('bob')
        try:
            request = {'command': 'commit', 'policy': dict(policy, mode='claim', session=os.urandom(32).hex()),
                'pczt': packet['claim'], 'adaptor_point': packet['destinations']['setup']['adaptor_point']}
            a, b = send(alice, request), send(bob, request)
            bz = send(bob, {'command': 'sign', 'ours': b['commitment'], 'theirs': a['commitment']})['share']
            response = send(alice, alice_sign(a['commitment'], b['commitment'], bz))
            refused = response is None and alice.wait(timeout=10) != 0
            return response, refused
        finally:
            for p in (alice, bob):
                if p.poll() is None:
                    p.kill(); p.wait()

    missing, refused_missing = session(lambda a, b, bz: {'command': 'sign', 'ours': a, 'theirs': b})
    wrong = lambda a, b, bz: {'command': 'sign', 'ours': a, 'theirs': b,
        'peer_share': bz[:-2] + format(int(bz[-2:], 16) ^ 1, '02x')}
    flipped, refused_wrong = session(wrong)
    honest, refused_honest = session(lambda a, b, bz: {'command': 'sign', 'ours': a, 'theirs': b, 'peer_share': bz})
    if missing is not None or not refused_missing:
        raise RuntimeError('Alice released a claim share without a peer share')
    if flipped is not None or not refused_wrong:
        raise RuntimeError('Alice released a claim share against an invalid peer share')
    if refused_honest or len(bytes.fromhex(honest['share'])) != 32:
        raise RuntimeError('Alice refused a valid peer-first session')
    consumed = {r: len(list((root / r).glob('public-consumed-*.json'))) for r in ('alice', 'bob')}
    if consumed != {'alice': 3, 'bob': 3}:
        raise RuntimeError('every attempt must burn exactly one nonce per owner')
    return {'scope': 'real public-profile owner signers over a synthetic unfunded review fixture',
        'missing_peer_share_refused': True, 'invalid_peer_share_refused': True,
        'valid_peer_first_share_released': True, 'consumed_attempts': consumed,
        'refusal_burns_nonce': True, 'funding_authorized': False, 'broadcast': False}


if __name__ == '__main__':
    os.umask(0o077)
    # Optional third argument: another signer binary, e.g. to show an older
    # build fails this check. The default is the current release build.
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:4])), indent=2))
