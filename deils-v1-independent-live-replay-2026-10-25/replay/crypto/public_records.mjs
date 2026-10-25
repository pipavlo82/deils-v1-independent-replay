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
let passed=0;
for(const line of official){const c=line.split(',');require(signature({pubkey:c[2].toLowerCase(),id:c[4].toLowerCase(),sig:c[5].toLowerCase()})===(c[6]==='TRUE'),'BIP340_VECTOR');passed++;}
const records={};
for(const role of ['negative','positive']){records[role]=inspect(read('sources/original-'+role+'-record.json'),role);require(records[role].accepted,'ORIGINAL_RECORD');}
const positive=read('sources/original-positive-record.json');
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
const corrupt=clone(positive);const sig=corrupt.commitment_record.event.sig;
corrupt.commitment_record.event.sig=(sig[0]==='0'?'1':'0')+sig.slice(1);
const got=inspect(corrupt,'positive');require(got.nip01_id&&!got.bip340&&!got.accepted,'SIG_CONTROL_FAILED');
mutations.push({name:'signature_byte_changed',...got,expected_refusal:'BIP340_SIGNATURE_INVALID',passed:true});

const historical=JSON.parse(fs.readFileSync(path.join(ROOT,'../evidence/recorded/NODE_RESULTS.json'),'utf8'));
for(const m of mutations)require(JSON.stringify(m)===JSON.stringify(historical.local_mutations.results.find(x=>x.name===m.name)),'RECORDED_CONTROL_DIFF');
console.log(JSON.stringify({passed:true,records,official_bip340_vectors:passed,public_local_controls:mutations.length,
 controls:mutations,private_content_controls:'3 historical controls require the excluded positive content; NOT REPLAYED by this public command'},null,2));
