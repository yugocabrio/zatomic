#!/usr/bin/env python3
"""A Zcash tip that moves mid-observation is observed again, at most three times.

On the 2026-10-21 V2 refund run testnet blocks arrived every few seconds, and
Alice's R check kept failing because a block landed between the watch scan and
its canonical check. Offline only: the single observation is replaced.
"""
import json

import public_native_reconcile as reconcile

TIP = RuntimeError('wallet must be synchronized to the current provider tip')


def run(outcomes):
    calls = []
    def once(*args):
        calls.append(args)
        outcome = outcomes[len(calls) - 1]
        if isinstance(outcome, Exception): raise outcome
        return outcome
    original = reconcile.observe_once_locked
    reconcile.observe_once_locked = once
    try:
        return reconcile.observe_locked('owner', '00' * 32, None, 4), len(calls)
    except RuntimeError as error:
        return error, len(calls)
    finally:
        reconcile.observe_once_locked = original


def check():
    assert run(['report']) == ('report', 1)
    assert run([TIP, TIP, 'report']) == ('report', 3)
    error, calls = run([TIP, TIP, TIP])
    assert error is TIP and calls == 3, 'a tip that keeps moving must still refuse'
    other = RuntimeError('watch wallet differs from this owner outgoing journal')
    error, calls = run([other, 'report'])
    assert error is other and calls == 1, 'only the tip race is retried'
    return {'tip_race_retried_at_most_three_times': True, 'other_refusals_not_retried': True}


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
