"""Python RFC8785/identity/privacy checks. Does not verify Schnorr itself."""
import copy
import hashlib
import json
from pathlib import Path
import re
import rfc8785

ROOT=Path(__file__).resolve().parent
SAFE=2**53-1
def sha(b):return hashlib.sha256(b).hexdigest()
def pairs(items):
 d={}
 for k,v in items:
  if k in d:raise ValueError('DUPLICATE_JSON_MEMBER')
  d[k]=v
 return d
def no_float(token):raise ValueError('OUTSIDE_INTEGER_LANE')
def read(name):return json.loads((ROOT/name).read_bytes(),object_pairs_hook=pairs,parse_float=no_float,parse_constant=no_float)
def save(name,d):(ROOT/name).write_bytes((json.dumps(d,indent=2)+'\n').encode())
def require(c,msg):
 if not c:raise RuntimeError(msg)
def lane(x):
 if type(x) is int:require(-SAFE<=x<=SAFE,'UNSAFE_INTEGER')
 elif isinstance(x,str):x.encode('utf8','strict')
 elif isinstance(x,list):
  for v in x:lane(v)
 elif isinstance(x,dict):
  for k,v in x.items():lane(k);lane(v)
 elif x is not None and type(x) is not bool:raise ValueError('INVALID_JSON_TYPE')
def event_id(e):return sha(json.dumps([0,e['pubkey'],e['created_at'],e['kind'],e['tags'],e['content']],ensure_ascii=False,separators=(',',':')).encode())
def main():
 negative=read('private/negative-before.raw.json');positive=read('private/positive-before.raw.json')
 remote=read('private/verify-negative.raw.json');manifest=read('sources/governance-pubkey.json')
 records={}
 for role,row,pos,proof in [('negative',negative,17,'proof_f0c2bd0e9bd475f872fd'),('positive',positive,16,'proof_d7aea6052737f4335eb8')]:
  old=read(f'sources/original-{role}-record.json');e=row['commitment_record']['event']
  record=json.loads(e['content'],object_pairs_hook=pairs,parse_float=no_float,parse_constant=no_float)
  expected=dict(type='deils-commitment-record',proof_id=proof,ledger_position=pos,profile='deils-reveal-v1',commitment_hash=row['commitment_hash'])
  require(record==expected and type(record['ledger_position']) is int,'RECORD_BINDING')
  require(all(row[k]==old[k] for k in ['proof_id','ledger_position','commitment_hash','commitment_profile','commitment_record']),'ORIGINAL_RECORD_CHANGED')
  require(row['proof_id']==proof and row['ledger_position']==pos and row['commitment_profile']==record['profile'],'ROW_BINDING')
  require(event_id(e)==e['id'],'NIP01_ID')
  require(rfc8785.dumps(record)==e['content'].encode(),'SIGNED_RECORD_NOT_EXACT_JCS')
  records[role]=dict(event_id=e['id'],record_binding=True,original_record_unchanged=True,nip01_id=True,signed_record_jcs=True,record=record)
 require(positive['reveal_state']=='content_bound','POSITIVE_STATE')
 content=positive['proof'];lane(content)
 require(isinstance(content,dict) and isinstance(content.get('blinding'),str) and re.fullmatch('[0-9a-f]{64}',content['blinding']) is not None,'BLINDING_FORMAT')
 raw=rfc8785.dumps(content);digest='sha256:'+sha(raw)
 require(digest==records['positive']['record']['commitment_hash'],'POSITIVE_COMMITMENT')
 (ROOT/'private/positive-python.jcs').write_bytes(raw)
 # Presence and source attribution are checked recursively, not just by removing fields.
 require(set(negative)=={'proof_id','status','reveal_state','terminal','ledger_position','commitment_hash','created_at','mismatch_evidence','note','attestation_url','commitment_profile','commitment_record'},'UNCLASSIFIED_NEGATIVE_FIELD')
 require(negative['status']==negative['reveal_state']=='content_commitment_mismatch' and negative['terminal'] is True,'NEGATIVE_STATE')
 mismatch=negative['mismatch_evidence'];caller=read('sources/historical-caller-submission.json')['content']
 require(set(mismatch)=={'committed_hash','revealed_content','recomputed_hash'},'UNKNOWN_MISMATCH_FIELD')
 require(mismatch['revealed_content']==caller,'UNCLASSIFIED_CONTENT_SOURCE')
 require(mismatch['committed_hash']==records['negative']['record']['commitment_hash'],'MISMATCH_REFERENCE')
 require(mismatch['recomputed_hash']=='sha256:'+sha(rfc8785.dumps(caller)),'CALLER_HASH')
 require(negative['note']=='the committed content stays withheld after a mismatch; only the disagreement is public.','UNCLASSIFIED_NOTE')
 require(negative['attestation_url']=='https://api.babyblueviper.com/attestations/'+negative['proof_id'],'UNCLASSIFIED_URL')
 old_negative=read('sources/original-negative-record.json')
 require(negative['commitment_record']==old_negative['commitment_record'],'UNCLASSIFIED_NESTED_RECORD')
 # Full object inventory exhausted: only scalar existence metadata, exact public record,
 # and exact caller-owned synthetic content remain. No extra serialized object is ignored.
 require(set(remote)=={'valid','status','state','error','published_pubkey'},'UNCLASSIFIED_VERIFY_FIELD')
 require(remote['valid'] is False and remote['status']=='content_commitment_mismatch' and remote['state']=='not_evaluated','REMOTE_NEGATIVE_STATE')
 require(remote['published_pubkey']==manifest['verifier_pubkey'],'REMOTE_KEY')
 require(remote['error']=='content held back — it is disclosed only after POST /prove/{proof_id}/reveal binds it.','UNCLASSIFIED_VERIFY_ERROR')
 def walk(x,path=''):
  out=[]
  if isinstance(x,dict):
   for k,v in x.items():
    if k in ['blinding','proof','proof_payload','signature']:out.append(dict(path=path+'/'+k,type=type(v).__name__))
    out+=walk(v,path+'/'+k)
  elif isinstance(x,list):
   for i,v in enumerate(x):out+=walk(v,path+'/'+str(i))
  return out
 leaves=walk(negative)
 require(leaves==[dict(path='/mismatch_evidence/revealed_content/blinding',type='str')],'UNCLASSIFIED_SENSITIVE_PATH')
 require(walk(remote)==[],'VERIFY_PROOF_DISCLOSURE')
 # Independently alter admitted content; do not publish any original values.
 controls=[]
 mutated=copy.deepcopy(content);mutated['__local_audit_change']=True
 controls.append(dict(name='modified_revealed_content',commitment_matches='sha256:'+sha(rfc8785.dumps(mutated))==digest,expected=False))
 mutated=copy.deepcopy(content);mutated['blinding']=('1' if mutated['blinding'][0]=='0' else '0')+mutated['blinding'][1:]
 controls.append(dict(name='modified_blinding',commitment_matches='sha256:'+sha(rfc8785.dumps(mutated))==digest,expected=False))
 mutated=copy.deepcopy(content);mutated['profile']='deils-reveal-v0'
 controls.append(dict(name='content_driven_downgrade',commitment_matches='sha256:'+sha(rfc8785.dumps(mutated))==digest,expected=False,selected_profile=records['positive']['record']['profile']))
 for c in controls:c['passed']=c['commitment_matches']==c['expected']
 require(all(c['passed'] for c in controls),'CONTENT_MUTATION_SURVIVED')
 out=dict(passed=True,records=records,positive=dict(state='content_bound',profile_source='authenticated original commitment record',
   canonical_bytes=len(raw),canonical_sha256=sha(raw),commitment=digest,blinding_format=True,integer_lane=True,
   private_canonical_path='private/positive-python.jcs',canonical_bytes_not_in_shareable_archive=True),
  privacy=dict(get_state='content_commitment_mismatch',get_fields_exhaustively_classified=True,nested_sensitive_paths=leaves,
   caller_content_exactly_matches_prior_request=True,stored_proof_payload_present=False,stored_proof_signature_present=False,
   server_original_blinding_disclosure_observed=False,only_blinding_source='Known caller-submitted synthetic fixture',
   verify_valid=False,verify_state='not_evaluated',verify_status=remote['status'],verify_sensitive_paths=[],
   limitation='Bounded response inspection and source attribution, not a server-side noninterference proof'),
  content_mutations=controls,signature_algorithm_note='Schnorr checked separately by pinned Node noble; Python independently recomputes IDs/JCS/hashes')
 save('PYTHON_RESULTS.json',out);print(json.dumps(out,indent=2))
if __name__=='__main__':main()
