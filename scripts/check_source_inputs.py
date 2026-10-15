#!/usr/bin/env python3
"""Exercise input selection against existing real compact checkpoints.

No network, new coins or proof generation. Test mutations are isolated copies.
Optionally supply a pre-spend checkpoint from the same real captured history.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from testnet_wallet import NATIVE, invoke, read
from source_inputs import GENESIS, publish, replay, digest


def refused(*args):
    result = subprocess.run([str(NATIVE),*map(str,args)], capture_output=True, text=True)
    if not result.returncode:
        raise RuntimeError('unsafe source input accepted')
    return result.stderr.strip()


def check(directory, wallet, before_spend=None):
    directory.mkdir(mode=0o700)
    source = directory/'wallet'
    source.mkdir(mode=0o700)
    shutil.copyfile(wallet/'spending-key.bin', source/'spending-key.bin')
    os.chmod(source/'spending-key.bin', 0o600)
    states = sorted([(read(f)['height'],f) for f in wallet.glob('compact-*.json')])
    eligible = [(h,f) for h,f in states if read(f)['notes']]
    anchor_file, current_file = eligible[-2][1], eligible[-1][1]
    anchor, current = read(anchor_file), read(current_file)
    publish(source/'network.json', {'genesis':current['genesis']})
    result = invoke(NATIVE,'compact-source-snapshot',source,anchor_file,current_file,
        1_010_000,directory/'selected.json')
    selected = read(directory/'selected.json')
    note = selected['notes'][0]
    reference = next(n for n in anchor['notes'] if n['cmx']==note['cmx'])
    assert note['path']==reference['path'] and selected['anchor']==anchor['anchor']
    assert selected['height']==current['height'] and selected['tip']==current['tip']
    assert len(selected['notes'])==1 and 'witness' not in note
    reasons = []
    mutations = [
        ('spent',lambda v: v.update(notes=[])),
        ('foreign-wallet',lambda v: v.update(fvk_fingerprint='00'*32)),
        ('false-tree-root',lambda v: v.update(anchor='00'*32)),
        ('corrupt-witness',lambda v: v['notes'][0].update(witness='00')),
        ('changed-origin',lambda v: v['notes'][0].update(txid='00'*32)),
        ('wrong-network',lambda v: v.update(genesis=GENESIS)),
    ]
    for name, change in mutations:
        bad = copy.deepcopy(current); change(bad)
        altered = directory/(name+'.json'); publish(altered,bad)
        reasons.append(refused('compact-source-snapshot',source,anchor_file,altered,
            1_010_000,directory/(name+'-output.json')))
        assert not (directory/(name+'-output.json')).exists()
    reasons.append(refused('compact-source-snapshot',source,current_file,current_file,
        1_010_000,directory/'shallow.json'))
    actual_spent_rejected = False
    if before_spend:
        old = read(before_spend)
        assert {n['cmx'] for n in old['notes']}.isdisjoint(n['cmx'] for n in current['notes'])
        reason = refused('compact-source-snapshot',source,before_spend,current_file,
            1_010_000,directory/'actual-spent.json')
        assert 'no mature unspent note' in reason
        actual_spent_rejected = True
    # Atomic create-once reservation publication with two real processes. This
    # is file durability/race verification, not a funded public wallet fixture.
    race = directory/'race.json'
    env = dict(os.environ,PYTHONPATH=str(Path(__file__).parent))
    processes = [subprocess.Popen([sys.executable,'-c',
        'import sys; from pathlib import Path; from source_inputs import publish; '
        'publish(Path(sys.argv[1]), {"writer":int(sys.argv[2])})', str(race),str(i)],
        env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for i in range(2)]
    for process in processes: process.communicate()
    assert sorted(p.returncode==0 for p in processes)==[False,True]
    assert read(race)['writer'] in (0,1)
    fixture = directory/'reservation-fixture'; fixture.mkdir(mode=0o700)
    package = fixture/('source-inputs-'+'a'*32);package.mkdir(mode=0o700)
    publish(package/'source.json',selected)
    publish(package/'manifest.json',{'files':{'source.json':digest(package/'source.json')}})
    publish(fixture/'source-reservation.json',{'format':'latch-source-reservation-v1',
        'genesis':GENESIS,'package':package.name,'manifest_sha256':digest(package/'manifest.json'),
        'plan_digest':'b'*64,'principal_zatoshi':1_010_000})
    assert replay(fixture,'b'*64,1_010_000)['live_revalidated'] is False
    for plan,amount in [('c'*64,1_010_000),('b'*64,2_010_000)]:
        try: replay(fixture,plan,amount)
        except RuntimeError: pass
        else: raise AssertionError('reservation conflict accepted')
    with open(package/'source.json','w') as stream: json.dump({},stream)
    try: replay(fixture,'b'*64,1_010_000)
    except RuntimeError: pass
    else: raise AssertionError('reserved input corruption accepted')
    assert (fixture/'source-reservation.json').exists()
    return {'scope':'real isolated ciphertext input selection plus isolated mutation/file-race fixtures',
        'height':result['height'],'anchor_height':result['anchor_height'],
        'source_confirmations':result['source_confirmations'],
        'anchor_confirmations':result['anchor_confirmations'],
        'real_path_carried_unchanged':True,'negative_cases':len(reasons),
        'actual_spent_note_rejected':actual_spent_rejected,
        'atomic_reservation_one_writer':True,'conflicting_replay_rejected':True,
        'corrupt_package_preserves_reservation':True,'public_funded_reservation':False,'broadcast':False}


if __name__=='__main__':
    os.umask(0o077)
    print(json.dumps(check(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),
        Path(sys.argv[3]).resolve() if len(sys.argv)>3 else None),indent=2))
