// Independent integer-lane canonicalization and pinned Noble BIP340 verification.
// Offline only. Full disclosed content remains in private/ and is never printed.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {schnorr} from '@noble/curves/secp256k1.js';
const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read=n=>JSON.parse(fs.readFileSync(path.join(ROOT,n),'utf8'));
const sha=x=>createHash('sha256').update(x).digest('hex');
const require=(c,m)=>{if(!c)throw Error(m);};
const hex=x=>Uint8Array.from(Buffer.from(x,'hex'));
const clone=x=>JSON.parse(JSON.stringify(x));
function string(s){
  for(let i=0;i<s.length;i++){
    const a=s.charCodeAt(i);
    if(a>=0xd800&&a<=0xdbff){const b=s.charCodeAt(++i);require(b>=0xdc00&&b<=0xdfff,'INVALID_UNICODE');}
    else require(!(a>=0xdc00&&a<=0xdfff),'INVALID_UNICODE');
  }
  return JSON.stringify(s);
}
function jcs(x){
  if(x===null)return 'null';
  if(typeof x==='boolean')return x?'true':'false';
  if(typeof x==='string')return string(x);
  if(typeof x==='number'){require(Number.isSafeInteger(x),'OUTSIDE_INTEGER_LANE');return JSON.stringify(x);}
  if(Array.isArray(x))return '['+x.map(jcs).join(',')+']';
  require(typeof x==='object','NOT_JSON');
  return '{'+Object.keys(x).sort().map(k=>string(k)+':'+jcs(x[k])).join(',')+'}';
}
const bytes=x=>Buffer.from(jcs(x),'utf8');
const eid=e=>sha(Buffer.from(JSON.stringify([0,e.pubkey,e.created_at,e.kind,e.tags,e.content]),'utf8'));
function signature(e){try{return schnorr.verify(hex(e.sig),hex(e.id),hex(e.pubkey));}catch{return false;}}
const manifest=read('sources/governance-pubkey.json');
function inspect(row,role){
  const e=row.commitment_record.event, r=JSON.parse(e.content);
  const position=role==='positive'?16:17;
  const proof=role==='positive'?'proof_d7aea6052737f4335eb8':'proof_f0c2bd0e9bd475f872fd';
  const keys=manifest.keys.filter(k=>k.verifier_pubkey===e.pubkey);
  const k=keys.length===1?keys[0]:null;
  const eventTime=1000*e.created_at;
  const structure=typeof e.content==='string'&&Number.isSafeInteger(e.created_at)&&Number.isSafeInteger(e.kind)&&e.kind>=0&&e.kind<=65535&&
    /^[0-9a-f]{64}$/.test(e.id)&&/^[0-9a-f]{64}$/.test(e.pubkey)&&/^[0-9a-f]{128}$/.test(e.sig)&&
    Array.isArray(e.tags)&&e.tags.every(t=>Array.isArray(t)&&t.every(s=>typeof s==='string'));
  const trust=!!k&&e.pubkey===manifest.verifier_pubkey&&k.status==='active'&&manifest.status==='active'&&
    !manifest.revocation.revoked_key_ids.includes(k.key_id)&&eventTime>=Date.parse(k.valid_from)&&
    (k.valid_to===null||eventTime<=Date.parse(k.valid_to));
  const tagNames=['d','type','proof_id','ledger_position','profile','commitment_hash'];
  const tagUnique=tagNames.every(n=>e.tags.filter(t=>t[0]===n).length<=1);
  // Binding is to signed content, never inferred from unsigned tags or revealed content.
  const binding=r.type==='deils-commitment-record'&&r.proof_id===proof&&row.proof_id===proof&&
    r.ledger_position===position&&row.ledger_position===position&&r.profile==='deils-reveal-v1'&&
    row.commitment_profile===r.profile&&r.commitment_hash===row.commitment_hash;
  const out={structure,trust,tag_unique:tagUnique,nip01_id:eid(e)===e.id,bip340:signature(e),
    signed_content_exact_jcs:jcs(r)===e.content,row_binding:binding};
  out.accepted=Object.values(out).every(v=>v===true);
  return out;
}
const official=fs.readFileSync(path.join(ROOT,'sources/test-vectors.csv'),'utf8').trim().split(/\r?\n/).slice(1);
let officialPassed=0;
for(const line of official){const c=line.split(',');const actual=signature({pubkey:c[2].toLowerCase(),id:c[4].toLowerCase(),sig:c[5].toLowerCase()});require(actual===(c[6]==='TRUE'),'BIP340_OFFICIAL_VECTOR_'+c[0]);officialPassed++;}
const results={};
for(const role of ['negative','positive']){
  const row=read('private/'+role+'-before.raw.json');
  const result=inspect(row,role);require(result.accepted,'RECORD_FAILED_'+role);
  const original=read('sources/original-'+role+'-record.json');
  const same=['proof_id','ledger_position','commitment_hash','commitment_profile','commitment_record'].every(k=>jcs(row[k])===jcs(original[k]));
  require(same,'ORIGINAL_RECORD_CHANGED');
  results[role]={...result,event_id:row.commitment_record.event.id,original_record_unchanged:same};
}
const positive=read('private/positive-before.raw.json');
const content=positive.proof, canonical=bytes(content);
const selectedProfile=JSON.parse(positive.commitment_record.event.content).profile;
const commitment='sha256:'+sha(canonical);
require(content&&typeof content==='object'&&!Array.isArray(content),'CONTENT_SHAPE');
require(typeof content.blinding==='string'&&/^[0-9a-f]{64}$/.test(content.blinding),'BLINDING_SHAPE');
require(commitment===positive.commitment_hash,'CONTENT_COMMITMENT');
require(canonical.equals(fs.readFileSync(path.join(ROOT,'private/positive-python.jcs'))),'PYTHON_NODE_BYTE_DISAGREEMENT');
fs.writeFileSync(path.join(ROOT,'private/positive-node.jcs'),canonical);
const mutations=[];
for(const [field,value] of [['profile','deils-reveal-v0'],['proof_id','local-only-modified-proof'],['ledger_position',17],['commitment_hash','sha256:'+'0'.repeat(64)]]){
  const changed=clone(positive),e=changed.commitment_record.event,r=JSON.parse(e.content);
  r[field]=value;e.content=jcs(r);
  const got=inspect(changed,'positive');
  require(got.bip340===true&&got.nip01_id===false&&got.accepted===false,'OLD_ID_CONTROL_FAILED_'+field);
  mutations.push({name:'signed_'+field+'_old_id',...got,expected_refusal:'NIP01_ID_MISMATCH',passed:true});
  e.id=eid(e);
  const rebuilt=inspect(changed,'positive');
  require(rebuilt.nip01_id===true&&rebuilt.bip340===false&&rebuilt.accepted===false,'REBUILT_ID_CONTROL_FAILED_'+field);
  mutations.push({name:'signed_'+field+'_recomputed_id',...rebuilt,expected_refusal:'BIP340_SIGNATURE_INVALID',passed:true});
}
for(const [field,value] of [['proof_id','local-only-modified-proof'],['ledger_position',17],['commitment_hash','sha256:'+'0'.repeat(64)],['commitment_profile','deils-reveal-v0']]){
  const row=clone(positive);row[field]=value;const got=inspect(row,'positive');
  require(got.nip01_id&&got.bip340&&!got.row_binding&&!got.accepted,'ROW_CONTROL_FAILED_'+field);
  mutations.push({name:'unsigned_row_'+field,...got,expected_refusal:'ROW_BINDING_MISMATCH',passed:true});
}
for(const mode of ['modified_revealed_content','modified_blinding','content_driven_downgrade']){
  const c=clone(content);
  if(mode==='modified_revealed_content')c.__local_audit_change=true;
  if(mode==='modified_blinding')c.blinding=(c.blinding[0]==='0'?'1':'0')+c.blinding.slice(1);
  if(mode==='content_driven_downgrade')c.profile='deils-reveal-v0';
  const match='sha256:'+sha(bytes(c))===commitment;
  require(!match&&selectedProfile==='deils-reveal-v1','CONTENT_CONTROL_FAILED');
  mutations.push({name:mode,commitment_matches:match,selected_profile:selectedProfile,expected_refusal:'CONTENT_COMMITMENT_MISMATCH',passed:true});
}
const corrupt=clone(positive);const sig=corrupt.commitment_record.event.sig;
corrupt.commitment_record.event.sig=(sig[0]==='0'?'1':'0')+sig.slice(1);
const got=inspect(corrupt,'positive');require(got.nip01_id&&!got.bip340&&!got.accepted,'SIG_CONTROL_FAILED');
mutations.push({name:'signature_byte_changed',...got,expected_refusal:'BIP340_SIGNATURE_INVALID',passed:true});
// Canonicalizer positive and refusal controls, unrelated to live state.
const canonicalControls=[
  [null,'null'],[{z:1,a:-0},'{"a":0,"z":1}'],[{v:9007199254740991},'{"v":9007199254740991}'],
  [{v:-9007199254740991},'{"v":-9007199254740991}'],[{s:'é\n𝄞'},'{"s":"é\\n𝄞"}']
];
for(const [x,expected] of canonicalControls)require(jcs(x)===expected,'JCS_POSITIVE_CONTROL');
let admissionRefused=0;
for(const x of [{v:0.5},{v:9007199254740992},{s:'\ud800'},{s:'\udc00'}]){
  let refused=false;try{jcs(x);}catch{refused=true;}require(refused,'ADMISSION_CONTROL');admissionRefused++;
}
const out={passed:true,runtime:process.version,bip340_implementation:'@noble/curves 2.0.1, pinned existing dependency bytes',
  official_bip340_vectors:{passed:officialPassed,total:official.length},records:results,
  positive:{canonical_bytes:canonical.length,canonical_sha256:sha(canonical),commitment,python_node_bytes_equal:true,
    blinding_format:true,integer_lane:true,selected_profile:selectedProfile,profile_source:'authenticated original commitment record'},
  local_mutations:{total:mutations.length,rejected:mutations.filter(m=>m.passed).length,unexpected_acceptances:0,crashes:0,results:mutations},
  canonicalizer_controls:{positive:canonicalControls.length,admission_refusals:admissionRefused},
  limitation:'Node JSON.parse is not an independent duplicate-member detector; Python strict parsing rejects duplicates before comparison.'};
fs.writeFileSync(path.join(ROOT,'NODE_RESULTS.json'),JSON.stringify(out,null,2)+'\n');
console.log(JSON.stringify(out,null,2));
