#!/usr/bin/env python3
"""Adversarial IPC tests against a completed private local swap's signer journals.

No chain mutation or signatures are produced. One valid nonce commitment is
reserved then its process is killed; the attempt must remain burned on restart.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'target/release/shielded-swap-native'


def start(directory, participant=2):
    process = subprocess.Popen([str(BIN), 'participant', str(directory), str(participant)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    hello = process.stdout.readline()
    if not hello or not json.loads(hello).get('resumed'):
        process.kill()
        raise RuntimeError('signer did not resume its durable key package')
    return process


def request(process, value):
    process.stdin.write(json.dumps(value) + '\n')
    process.stdin.flush()
    return process.stdout.readline()


def must_reject(directory, packet, expected, participant=2):
    process = start(directory, participant)
    try:
        response = request(process, packet)
        process.wait(timeout=10)
        error = process.stderr.read()
        if response or process.returncode == 0 or expected not in error:
            raise RuntimeError('participant did not reject the specified attack')
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()


def run(swap):
    os.umask(0o077)
    policy = json.loads((swap / 'claim-policy.json').read_text())
    pre = json.loads((swap / 'bob/presignature.json').read_text())
    policy['session'] = os.urandom(32).hex()
    packet = {'command': 'commit', 'policy': policy,
        'adaptor_point': pre['adaptor_point'],
        'pczt': (swap / 'bob/claim.pczt').read_bytes().hex()}
    bob = swap / 'bob'
    must_reject(bob, {'command': 'sign'}, 'nonce absent or already consumed')
    changed = copy.deepcopy(packet)
    changed['policy']['bob_receiver'] = policy['alice_receiver']
    must_reject(bob, changed, 'own receiver changed')
    changed = copy.deepcopy(packet)
    changed['policy']['pending']['value'] += 1
    must_reject(bob, changed, 'note commitment mismatch')
    changed = copy.deepcopy(packet)
    changed['adaptor_point'] = '00' * 32
    must_reject(swap / 'alice', changed, 'Alice witness point changed', 1)
    must_reject(bob, changed, 'claim adaptor point changed')
    changed = copy.deepcopy(packet)
    changed['policy']['funding'] = (swap / 'funding.hex').read_text().strip()
    must_reject(bob, changed, 'funding authorization must be withheld')
    # Native claim verification passes first; the persisted agreement must then
    # reject a coordinator changing the companion refund's deadline.
    # Older fixtures may not yet have an agreement; establish it with a valid
    # commitment below before exercising this attack.
    process = start(bob)
    try:
        reply = json.loads(request(process, packet))
        marker = bob / f'attempt-{policy["session"]}.json'
        if not marker.exists() or json.loads(marker.read_text())['message'] != reply['message']:
            raise RuntimeError('commitment escaped before durable reservation')
    finally:
        process.kill()
        process.wait()
    must_reject(bob, packet, 'AlreadyExists')
    changed = copy.deepcopy(packet)
    changed['policy']['session'] = os.urandom(32).hex()
    changed['policy']['refund_height'] += 1
    must_reject(bob, changed, 'swap agreement changed')
    # A previously consumed claim attempt is also rejected after restart.
    old = next(p for p in bob.glob('attempt-*.json')
               if json.loads(p.read_text())['mode'] == 'claim'
               and (bob / p.name.replace('attempt-', 'consumed-')).exists())
    replay = copy.deepcopy(packet)
    replay['policy']['session'] = old.stem.removeprefix('attempt-')
    must_reject(bob, replay, 'AlreadyExists')
    return {'scope': 'actual persisted signer processes, no chain mutations',
        'rejected': ['signature without live nonce', 'own recipient replacement',
            'pending amount replacement', 'Alice witness-point replacement',
            'Bob persisted witness-point replacement', 'broadcastable funding during preparation',
            'reuse after killed commitment process', 'companion refund deadline change',
            'reuse of consumed signing attempt'],
        'commitment_reserved_before_response': True,
        'nonce_secrets_persisted': False, 'same_host_not_os_sandbox': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('swap', type=Path)
    print(json.dumps(run(parser.parse_args().swap.resolve()), indent=2))
