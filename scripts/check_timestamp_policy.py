#!/usr/bin/env python3
"""Candidate public-policy arithmetic/binding only; no chain execution claim."""
import copy
from datetime import datetime, timezone
import json
import timestamp_policy as policy


def rejects(fn):
    try: fn()
    except (RuntimeError,ValueError,TypeError,KeyError): return
    raise AssertionError('unsafe or ambiguous candidate accepted')


def check():
    now=1792053000;plan=policy.build(now);bounds=policy.validate(plan)
    assert bounds['native_gap_slack_seconds']==69180
    assert bounds['first_reveal_slack_seconds']==480
    for phase,field in [('funding','fund_before'),('first_reveal','first_reveal_before')]:
        policy.require_window(plan,phase,plan[field]-1)
        rejects(lambda:policy.require_window(plan,phase,plan[field]))
    rejects(lambda:policy.require_window(plan,'recovery',now))
    rejects(lambda:policy.build(0xffffffff))
    for alter in [lambda p:p['native_refund_lock'].update(kind='height'),
            lambda p:p['native_refund_lock'].update(value=p['eth_expiry']+7200),
            lambda p:p['policy'].update(native_early_header_seconds=0),
            lambda p:p.update(created_at=True),lambda p:p.update(extra=1)]:
        damaged=copy.deepcopy(plan);alter(damaged);rejects(lambda:policy.validate(damaged))
    agreement={'execution_plan_digest':policy.digest(plan),'eth_chain_id':11155111,
        'native_genesis':policy.GENESIS,'native_branch':'77190ad9',
        'eth_expiry':plan['eth_expiry'],'fee_policy':plan['fee_policy'],
        'native':{'refund_lock':plan['native_refund_lock']}}
    policy.require_agreement_binding(plan,agreement)
    for alter in [lambda a:a.update(execution_plan_digest='00'*32),lambda a:a.update(eth_expiry=a['eth_expiry']-1),
            lambda a:a.update(eth_chain_id=1),lambda a:a.update(native_genesis='00'*32),lambda a:a['native'].update(refund_height=42),
            lambda a:a['native']['refund_lock'].update(value=float(a['native']['refund_lock']['value']))]:
        damaged=copy.deepcopy(agreement);alter(damaged);rejects(lambda:policy.require_agreement_binding(plan,damaged))
    stamp=datetime.fromtimestamp(now,timezone.utc).isoformat()
    z={'genesis':policy.GENESIS,'branch_id':'77190ad9','provider_header_timestamp':now,
        'observed_at':stamp,'announced_upgrade':{'height':0}}
    e={'chain_id':11155111,'expected_genesis':policy.ETH_GENESIS,'latest':{'timestamp':now},
        'observed_at':stamp,'rpc_genesis_verified':True,'status':'observed'}
    assert policy.clock_blockers(plan,z,e,now)==[]
    assert 'eth-provider-identity-incomplete' in policy.clock_blockers(plan,z,dict(e,rpc_genesis_verified=False),now)
    assert 'native-observation-stale-or-future' in policy.clock_blockers(plan,z,e,now+121)
    assert 'native-upgrade-cutoff-unresolved' in policy.clock_blockers(plan,dict(z,announced_upgrade={'height':5000000}),e,now)
    assert 'native-tip-outside-clock-bounds' in policy.clock_blockers(plan,dict(z,provider_header_timestamp=now+7261),e,now)
    assert 'eth-tip-outside-clock-bounds' in policy.clock_blockers(plan,z,dict(e,latest={'timestamp':now-121}),now)
    return {'scope':'offline candidate timestamp arithmetic and agreement binding; no funded swap',
        'passed':True,'arithmetic':bounds,'strict_cutoff_units_staleness_upgrade_identity_checks':True}


if __name__=='__main__':
    print(json.dumps(check(),indent=2))
