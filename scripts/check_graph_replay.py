#!/usr/bin/env python3
"""Draft-journal replay using actual generated (synthetic) PCZT files.

Exercises immutable draft inspection only. No source reservation, funded wallet,
network observation or authenticated participant binding is simulated here.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from source_inputs import digest, publish, replay_graph


def check(root, original):
    root.mkdir(mode=0o700)
    output=root/('graph-'+'a'*32)
    shutil.copytree(original,output)
    os.chmod(output,0o700)
    for f in output.iterdir(): os.chmod(f,0o600)
    roles_digest='b'*64 # File-journal binding fixture, not authenticated owners.
    receipt={'directory':output.name,'destinations_sha256':roles_digest,
        'graph_digest':digest(output/'graph.json')}
    publish(root/'graph-draft.json',receipt)
    before={p.name:p.read_bytes() for p in output.iterdir()}
    first=replay_graph(root,roles_digest)
    resumed=subprocess.run([sys.executable,'-c',
        'import json,sys; from pathlib import Path; from source_inputs import replay_graph; '
        'print(json.dumps(replay_graph(Path(sys.argv[1]),sys.argv[2])))',str(root),roles_digest],
        capture_output=True,text=True,check=True,
        env=dict(os.environ,PYTHONPATH=str(Path(__file__).parent.resolve())))
    second=json.loads(resumed.stdout)
    assert first==second and first['reused_graph'] and not first['live_revalidated']
    assert before=={p.name:p.read_bytes() for p in output.iterdir()}
    try: replay_graph(root,'c'*64)
    except RuntimeError: pass
    else: raise AssertionError('changed destinations accepted')
    with open(output/'claim.pczt','ab') as stream: stream.write(b'corrupt')
    try: replay_graph(root,roles_digest)
    except RuntimeError: pass
    else: raise AssertionError('changed graph member accepted')
    assert (root/'graph-draft.json').exists()
    return {'scope':'private draft journal with real generated PCZT files, synthetic inputs',
        'same_graph_replayed_without_rebuild':True,'files_unchanged_on_replay':True,
        'fresh_process_replay':True,
        'changed_destinations_and_pczt_rejected':True,'receipt_retained_after_corruption':True,
        'no_live_spendability_claim':True,'broadcast':False}


if __name__=='__main__':
    os.umask(0o077)
    print(json.dumps(check(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve()),indent=2))
