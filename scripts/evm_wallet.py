"""Minimal owner-local EIP-155 signer using pinned libsecp256k1 and Foundry.

Keys and unrevealed claim calldata never go into argv, logs or the RPC signer.
The higher-level participant must validate an action before calling sign().
Only the isolated fixture chain is supported; this is not a general wallet.
"""
import json
from pathlib import Path
import subprocess
from regtest_wallet import NATIVE, native, save
import run_native_evm_gate as evm


def integer(value):
    if type(value) is not int or value < 0 or value >= 2**256:
        raise ValueError('nonnegative uint256 required')
    return value.to_bytes((value.bit_length() + 7) // 8, 'big')


def rlp(value):
    if type(value) is int:
        value = integer(value)
    if isinstance(value, bytes):
        if len(value) == 1 and value[0] < 128:
            return value
        offset, encoded = 128, value
    elif isinstance(value, list):
        offset, encoded = 192, b''.join(map(rlp, value))
    else:
        raise ValueError('RLP bytes, integers or lists required')
    if len(encoded) <= 55:
        return bytes([offset + len(encoded)]) + encoded
    length = integer(len(encoded))
    return bytes([offset + 55 + len(length)]) + length + encoded


def keccak(raw):
    result = subprocess.run(['cast', 'keccak'], input='0x' + raw.hex(),
        capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError('local Keccak operation failed')
    return bytes.fromhex(result.stdout.strip().removeprefix('0x'))


def initialize(directory):
    public = bytes.fromhex(native('evm-key-init', directory)['public_key'])
    if len(public) != 65 or public[0] != 4:
        raise RuntimeError('unexpected Ethereum public key')
    identity = {'address': '0x' + keccak(public[1:])[-20:].hex(), 'chain_id': evm.CHAIN}
    save(directory / 'identity.json', identity)
    return identity


def sign(directory, transaction, kind):
    identity = json.loads((directory / 'identity.json').read_text())
    if transaction['from'].lower() != identity['address'] or identity['chain_id'] != evm.CHAIN:
        raise RuntimeError('owner signing identity mismatch')
    tx = dict(transaction, chainId=hex(evm.CHAIN), type='0x0')
    to = bytes.fromhex(tx['to'].removeprefix('0x'))
    data = bytes.fromhex(tx['data'].removeprefix('0x'))
    if len(to) != 20 or len(data) > 1024:
        raise RuntimeError('bounded contract call required')
    fields = [int(tx[k], 16) for k in ('nonce', 'gasPrice', 'gas')]
    fields += [to, int(tx.get('value', '0x0'), 16), data]
    digest = keccak(rlp(fields + [evm.CHAIN, 0, 0]))
    result = subprocess.run([str(NATIVE), 'evm-sign-digest', str(directory)],
        input=digest.hex() + '\n', capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError('owner Ethereum signing failed')
    signed = json.loads(result.stdout)
    if signed['parity'] not in (0, 1):
        raise RuntimeError('invalid Ethereum recovery parity')
    raw = rlp(fields + [2 * evm.CHAIN + 35 + signed['parity'], int(signed['r'], 16), int(signed['s'], 16)])
    return {'chain_id': evm.CHAIN, 'kind': kind, 'transaction': tx,
        'raw': '0x' + raw.hex(), 'txid': '0x' + keccak(raw).hex()}


def check_standard_vector():
    # Public EIP-155 example; no transaction is broadcast and no mainnet key is
    # created. See https://eips.ethereum.org/EIPS/eip-155#example.
    encoded = rlp([9, 20 * 10**9, 21000, bytes.fromhex('35' * 20), 10**18, b'', 1, 0, 0])
    assert encoded.hex() == 'ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080'
    assert keccak(encoded).hex() == 'daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53'
    assert rlp(0) == b'\x80'
    assert rlp(b'\x00') == b'\x00'
    assert rlp(b'a' * 55)[:1] == b'\xb7'
    assert rlp(b'a' * 56)[:2] == b'\xb8\x38'
    assert rlp([b'a' * 56])[:2] == b'\xf8\x3a'
    return {'published_eip155_signing_payload_and_hash': True, 'rlp_boundaries': True}


if __name__ == '__main__':
    print(json.dumps(check_standard_vector(), indent=2))
