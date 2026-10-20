#!/usr/bin/env python3
"""Check the default and short public-testnet timing profiles (offline).

Both profiles must pass the strict cross-chain gap check, the short profile
must give a 3-hour ETH deadline and a native refund 6 hours later, unknown or
edited profiles must be rejected, and the default must stay selected unless
LATCH_TIMING_PROFILE=short.
"""
import copy
import json
import os
import timestamp_policy as tp

NOW = 1_800_000_000


def rejects(plan):
    try:
        tp.validate(plan)
    except RuntimeError:
        return True
    return False


os.environ.pop('LATCH_TIMING_PROFILE', None)
default = tp.build(NOW)
assert default['policy'] == tp.POLICY
os.environ['LATCH_TIMING_PROFILE'] = 'short'
short = tp.build(NOW)
os.environ.pop('LATCH_TIMING_PROFILE')
assert short['policy'] == tp.SHORT and short['policy']['profile'] != tp.POLICY['profile']
assert short['eth_expiry'] - NOW == 3 * 3600
assert short['native_refund_lock']['value'] - short['eth_expiry'] == 6 * 3600
assert short['fund_before'] - NOW == 3600 and short['first_reveal_before'] - NOW == 2 * 3600

report = {}
for name, plan in (('default', default), ('short', short)):
    gaps = tp.validate(plan)
    assert gaps['native_gap_slack_seconds'] > 0 and gaps['first_reveal_slack_seconds'] > 0
    report[name] = {'eth_expiry_hours': (plan['eth_expiry'] - NOW) / 3600,
        'native_refund_hours': (plan['native_refund_lock']['value'] - NOW) / 3600,
        'native_gap_slack_minutes': gaps['native_gap_slack_seconds'] / 60}

edited = copy.deepcopy(short); edited['policy']['native_refund_after_eth_expiry_seconds'] = 17000
assert rejects(edited), 'an edited short profile must be rejected'
unknown = copy.deepcopy(short); unknown['policy']['profile'] = 'made-up'
assert rejects(unknown), 'an unknown profile must be rejected'
mixed = copy.deepcopy(short); mixed['policy'] = copy.deepcopy(tp.POLICY)
assert rejects(mixed), 'a plan whose deadlines do not match its profile must be rejected'
os.environ['LATCH_TIMING_PROFILE'] = 'fast'
try:
    tp.build(NOW)
    raise AssertionError('an unknown LATCH_TIMING_PROFILE must be refused')
except RuntimeError:
    pass
finally:
    os.environ.pop('LATCH_TIMING_PROFILE')

print(json.dumps({'timing_profiles_ok': True, **report}, indent=1))
