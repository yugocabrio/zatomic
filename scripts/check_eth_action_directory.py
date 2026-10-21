#!/usr/bin/env python3
"""Reading an uncommitted ETH action must not leave a directory behind.

On the 2026-10-21 V2 public run a withdraw send ran before any withdraw
decision existed; the reader created an empty action directory, and every
later prepare took it for a committed decision and refused. Offline only.
"""
import json
import os
from pathlib import Path
import tempfile

import public_eth_outgoing as out


def check():
    with tempfile.TemporaryDirectory() as base:
        directory = Path(base)/'journal'; directory.mkdir(mode=0o700)
        try:
            out.decision(directory, {}, {}, 'withdraw')
        except RuntimeError as error:
            assert 'no committed ETH action' in str(error)
        else:
            raise AssertionError('missing decision accepted')
        assert not (directory/'withdraw').exists(), 'reader created the action directory'
    return {'missing_decision_refused_without_side_effect': True}


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(), indent=2))
