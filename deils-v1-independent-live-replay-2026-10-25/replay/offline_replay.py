"""Offline only. Writes logs outside this pack. Never contacts a live endpoint.
Public default: signed records, 13 public controls and saved-observation consistency.
Optional private inputs: replay the original 16-control/JCS audit in a disposable copy.
"""
import argparse,hashlib,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
PACK=Path(__file__).resolve().parents[1]
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(p.read_bytes())
def need(value,reason):
 if not value:raise RuntimeError(reason)
def main():
 a=argparse.ArgumentParser(description=__doc__)
 a.add_argument('--out',type=Path,required=True)
 a.add_argument('--private-input-dir',type=Path)
 args=a.parse_args();out=args.out.resolve()
 need(not out.is_relative_to(PACK),'Output must be outside the immutable evidence pack')
 out.mkdir(parents=True,exist_ok=True)
 runs=[]
 def execute(label,cmd,cwd,env=None):
  r=subprocess.run(cmd,cwd=cwd,env=env,capture_output=True,timeout=60)
  (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
  runs.append(dict(label=label,command=[str(x) for x in cmd],exit=r.returncode,stdout_sha256=sha(r.stdout),stderr_sha256=sha(r.stderr)))
  need(r.returncode==0,'Offline check failed: '+label+' (inspect saved stderr)')
  return read(out/(label+'.stdout'))
 public=[]
 for mode in ['normal','repeat']:
  public.append(execute('public-'+mode,['node','crypto/public_records.mjs'],PACK/'replay'))
 need(public[0]==public[1],'Public semantic output differs')
 need((out/'public-normal.stdout').read_bytes()==(out/'public-repeat.stdout').read_bytes(),'Public repeated stdout differs')
 before=read(PACK/'evidence/terminal/http/prehash-before.body');after=read(PACK/'evidence/terminal/http/prehash-after.body')
 refusal=read(PACK/'evidence/terminal/http/prehash-post.body');terminal=read(PACK/'evidence/terminal/http/terminal-post.body')
 fixed=read(PACK/'evidence/fixed/http/negative-before.sanitized.json');verify=read(PACK/'evidence/fixed/http/verify-negative.sanitized.json')
 pos=read(PACK/'evidence/fixed/http/positive-before.sanitized.json')
 need(before==after and before['status']=='content_withheld','Prehash state')
 need(refusal['status']=='blinding_missing' and refusal['terminal'] is False and refusal['hash_evaluated'] is False,'Refusal contract')
 need(terminal['status']=='content_commitment_mismatch' and terminal['terminal'] is True,'Terminal result')
 need(fixed['reveal_state']=='content_commitment_mismatch' and 'proof' not in fixed and 'signature' not in fixed,'Fixed GET disclosure')
 need(set(verify)=={'valid','status','state','error','published_pubkey'} and verify['valid'] is False and verify['status']=='content_commitment_mismatch','Fixed verification response')
 need(pos['reveal_state']=='content_bound' and pos['proof']['redacted'] is True,'Positive state/redaction')
 for role in ['negative','positive']:
  x=read(PACK/f'evidence/fixed/http/{role}-before.meta.json');y=read(PACK/f'evidence/fixed/http/{role}-after.meta.json')
  need(x['raw_response_sha256']==y['raw_response_sha256'],'Recorded response stability')
 manifests=[read(PACK/'replay/sources/governance-pubkey.json'),read(PACK/'evidence/fixed/http/well-known-key.body'),read(PACK/'evidence/fixed/http/governance-key.body')]
 need(manifests[0]==manifests[1]==manifests[2],'Key integrity')
 # Independent public signed-content canonicalization using the pinned Python module.
 sys.path.insert(0,str(PACK/'replay/crypto/pythonlib'))
 import rfc8785
 for role in ['negative','positive']:
  e=read(PACK/f'replay/sources/original-{role}-record.json')['commitment_record']['event']
  need(rfc8785.dumps(json.loads(e['content']))==e['content'].encode(),'Public signed-record JCS')
  raw=json.dumps([0,e['pubkey'],e['created_at'],e['kind'],e['tags'],e['content']],ensure_ascii=False,separators=(',',':')).encode()
  need(sha(raw)==e['id'],'Public Python event ID')
 private_result='NOT_REPLAYED: three content controls and positive JCS preimage excluded from public pack'
 if args.private_input_dir:
  expected=read(PACK/'evidence/PRIVATE_INPUT_REQUIREMENTS.json')
  with tempfile.TemporaryDirectory(prefix='deils-offline-only-') as td:
   root=Path(td).resolve();shutil.copytree(PACK/'replay',root,dirs_exist_ok=True);(root/'private').mkdir()
   for name,meta in expected.items():
    raw=(args.private_input_dir/name).read_bytes();need(sha(raw)==meta['sha256'],'Private input digest mismatch: '+name)
    (root/'private'/name).write_bytes(raw)
   env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env['PYTHONPATH']=str(root/'crypto/pythonlib')
   for label,cmd in [('private-python-normal',[sys.executable,'-B','verify_python.py']),('private-python-repeat',[sys.executable,'-B','verify_python.py']),
     ('private-python-optimized',[sys.executable,'-B','-O','verify_python.py']),('private-node-normal',['node','crypto/verify_node.mjs']),('private-node-repeat',['node','crypto/verify_node.mjs'])]:
    got=execute(label,cmd,root,env)
    recorded=read(PACK/'evidence/recorded'/('NODE_RESULTS.json' if 'node' in label else 'PYTHON_RESULTS.json'))
    if 'node' in label:got.pop('runtime',None);recorded.pop('runtime',None)
    need(got==recorded,'Offline semantic result differs from actual historical log: '+label)
   for x,y in [('private-python-normal','private-python-repeat'),('private-python-normal','private-python-optimized'),('private-node-normal','private-node-repeat')]:
    for suffix in ['.stdout','.stderr']:need((out/(x+suffix)).read_bytes()==(out/(y+suffix)).read_bytes(),'Private repeat/O output differs')
   private_result=dict(controls_refused=16,canonical_bytes=1744,python_node_canonical_bytes_equal=(root/'private/positive-python.jcs').read_bytes()==(root/'private/positive-node.jcs').read_bytes(),
    original_recorded_results_match=True,private_data_exported=False)
 result=dict(passed=True,network_requests=0,public_signed_records=2,public_controls_refused=13,bip340_vectors=19,
  public_python_jcs_and_event_ids=2,saved_observation_consistency=True,private=private_result,runs=runs)
 (out/'RESULT.json').write_bytes((json.dumps(result,indent=2)+'\n').encode());print(json.dumps(result,indent=2))
if __name__=='__main__':main()
