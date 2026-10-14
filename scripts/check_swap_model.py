#!/usr/bin/env python3
"""Bounded timing model, NOT blockchain execution or a security proof."""
import itertools
import json
from dataclasses import dataclass

@dataclass(frozen=True)
class Policy:
    eth_expiry: int = 6
    zec_refund_time: int = 11
    eth_delivery: int = 2
    observation: int = 1
    zec_delivery: int = 2
    zec_clock_lead: int = 1
    native_lock_enabled: bool = True

    def reveal_allowed(self, now):
        return now + self.eth_delivery < self.eth_expiry

    def funding_allowed(self):
        return (self.native_lock_enabled and
                self.zec_refund_time - self.zec_clock_lead >
                self.eth_expiry + self.observation + self.zec_delivery)

    def earliest_refund(self, lead):
        return self.zec_refund_time - lead + 1 if self.native_lock_enabled else 0

def enumerate_cases(policy):
    alice_cases, bob_cases = [], []
    # Alice honest, Bob adversarial. Disclosure precedes ETH inclusion. Bob
    # cannot redirect the fixed ETH recipient even if he front-runs the claim.
    for reveal, delay in itertools.product(range(12), range(policy.eth_delivery + 1)):
        if policy.reveal_allowed(reveal):
            alice_cases.append({'reveal': reveal, 'eth_delay': delay,
                                'safe': reveal + delay < policy.eth_expiry})
    # Bob honest, Alice adversarial. Alice may reveal at the last moment and
    # immediately race her earliest consensus-valid Zcash refund.
    for reveal, observe, delay, lead in itertools.product(
        range(policy.eth_expiry), range(policy.observation + 1),
        range(policy.zec_delivery + 1), range(policy.zec_clock_lead + 1)):
        claim = reveal + observe + delay
        refund = policy.earliest_refund(lead)
        bob_cases.append({'reveal': reveal, 'observe': observe, 'zec_delay': delay,
                          'clock_lead': lead, 'zec_claim': claim,
                          'zec_refund': refund, 'safe': claim < refund})
    return alice_cases, bob_cases

def main():
    p = Policy()
    assert p.funding_allowed()
    alice, bob = enumerate_cases(p)
    assert all(c['safe'] for c in alice + bob)
    counterexamples = {}
    for label, bad in [
        ('shielded_only_refund_lock_is_ineffective', Policy(native_lock_enabled=False)),
        ('inter_chain_gap_too_short', Policy(zec_refund_time=7))]:
        assert not bad.funding_allowed()
        failures = [c for c in enumerate_cases(bad)[1] if not c['safe']]
        assert failures
        counterexamples[label] = failures[0]
    late = p.eth_expiry - 1
    assert not p.reveal_allowed(late) and late + p.eth_delivery >= p.eth_expiry
    print(json.dumps({'scope':'bounded timing model, no chain transactions',
        'policy':p.__dict__, 'honest_alice_cases':len(alice), 'honest_bob_cases':len(bob),
        'safe_cases':len(alice)+len(bob), 'counterexamples':counterexamples,
        'assumptions':['bounded inclusion/observation', 'no deep reorg',
          'valid prepared native claim/refund', 'fresh matching Pallas witness',
          'verified funding and immutable ETH escrow', 'honest client cutoff/monitoring'],
        'not_proved':['cryptographic composition security', 'real network timing bounds',
                      'native consensus acceptance']}, indent=2))

if __name__ == '__main__': main()
