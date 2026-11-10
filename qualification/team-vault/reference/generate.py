"""Independent synthetic byte oracle. Never use deterministic entropy in a product.
PyNaCl/libsodium: Ed25519 and XChaCha. cryptography/OpenSSL: X25519/ChaCha/HKDF.
argon2-cffi/libargon2: exact production-profile Argon2. No Rust code is imported.
"""
from pathlib import Path
import hashlib,hmac,json,struct,copy,importlib.metadata,base64
from nacl.signing import SigningKey
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2.low_level import hash_secret_raw,Type
P=Path(__file__).resolve().parents[1]
def u(n,w=8):return n.to_bytes(w,'big')
def t(label,*f):
 l=label.encode();return b'bitbid-team-v1/'+u(len(l),2)+l+u(len(f),2)+b''.join(u(len(x),4)+x for x in f)
def ls(es):return u(len(es),4)+b''.join(u(len(x),4)+x for x in es)
def H(b):return hashlib.sha256(b).digest()
def extract(salt,ikm):return hmac.new(salt or bytes(32),ikm,'sha256').digest()
def expand(prk,info,n):
 out=b'';last=b''
 for i in range(1,(n+31)//32+1):last=hmac.new(prk,last+info+bytes([i]),'sha256').digest();out+=last
 return out[:n]
def hkdf(root,info):return expand(extract(b'',root),info,32)
def hpke(pk,info,aad,pt,ikm):
 def lx(s,l,x):return extract(s,b'HPKE-v1'+suite+l+x)
 def le(p,l,x,n):return expand(p,u(n,2)+b'HPKE-v1'+suite+l+x,n)
 suite=b'KEM'+u(32,2);prk=lx(b'',b'dkp_prk',ikm);sk=le(prk,b'sk',b'',32)
 e=X25519PrivateKey.from_private_bytes(sk);enc=e.public_key().public_bytes_raw();dh=e.exchange(__import__('cryptography.hazmat.primitives.asymmetric.x25519',fromlist=['X25519PublicKey']).X25519PublicKey.from_public_bytes(pk))
 shared=le(lx(b'',b'eae_prk',dh),b'shared_secret',enc+pk,32)
 suite=b'HPKE'+u(32,2)+u(1,2)+u(3,2);context=b'\0'+lx(b'',b'psk_id_hash',b'')+lx(b'',b'info_hash',info)
 sec=lx(shared,b'secret',b'');key=le(sec,b'key',context,32);nonce=le(sec,b'base_nonce',context,12)
 return enc,ChaCha20Poly1305(key).encrypt(nonce,pt,aad)
records={};counter=0

def random(n):
 global counter
 counter+=1;return H(b'PUBLIC-SYNTHETIC-ONLY'+u(counter))[:n]
def wire(kind,payload,key=None):
 if key:payload=t('signed-envelope',key['id'],payload,key['ed'].sign(t('signed-record',kind.encode(),key['id'],payload)).signature)
 b=t('wire',u(1,2),u(1,2),kind.encode(),payload);h=H(b);records[h.hex()]=b.hex();return h

def identity(a,g=1):
 root=H(b'SYNTHETIC-ACCOUNT-ROOT'+a+u(g));sk=hkdf(root,t('signing-seed',a,u(g)));x=hkdf(root,t('recipient-seed',a,u(g)));ed=SigningKey(sk);pk=X25519PrivateKey.from_private_bytes(x).public_key().public_bytes_raw();p=t('identity',a,u(g),pk,bytes(ed.verify_key));k={'account':a,'g':g,'root':root,'ed':ed,'x':x,'pk':pk,'id':H(p)};k['wire']=wire('identity',p,k);return k
O=identity(bytes([1])*16);M=identity(bytes([2])*16);A=identity(bytes([3])*16);M2=identity(M['account'],2)
keys={k['id']:k for k in [O,M,A,M2]};team=bytes([11])*16;vault=bytes([21])*16;vault2=bytes([22])*16;item=bytes([31])*16

def roster(a):return ls([t('member',acc,m['key'],u(m['role'],1),u(m['status'],1))for acc,m in sorted(a.items())])
def policies(vs):return ls([t('vault-policy',v,u(p['epoch']),u(p['phase'],1),p['commit'],ls([t('permission',a,u(x,1))for a,x in sorted(p['perms'].items())]))for v,p in sorted(vs.items())])
def plan(st,action,actor,seq=None):return t('authority-plan',team,u(seq if seq is not None else st['seq']+1),st['hash'],action.encode(),actor['id'],roster(st['roster']),policies(st['vaults']))
def gr(g):return t('grant-ref',g['a'],g['k'],g['v'],u(g['epoch']),g['hash'])
def grsort(gs):return sorted(gs,key=lambda g:(g['v'],g['epoch'],g['a'],g['k']))
def content(v,epoch,i,kind,revision,ph,V,who,plain):
 nonce=random(24);head=t('content-header',team,v,i,u(epoch),u(revision),u(kind,1),ph,nonce)
 h=wire('content',t('content',head,crypto_aead_xchacha20poly1305_ietf_encrypt(plain,head,nonce,V)),who)
 return {'kind':kind,'rev':revision,'hash':h,'plain':plain}
def snapshot(v,epoch,ph,who,objects,old=None,raw_refs=None):
 refs=ls(raw_refs if raw_refs is not None else [t('content-ref',i,u(c['kind'],1),u(c['rev']),c['hash'])for i,c in sorted(objects.items())])
 seq=1 if old is None else old['seq']+1;prev=bytes(32)if old is None else old['hash'];h=wire('snapshot',t('snapshot',team,v,u(epoch),u(seq),prev,ph,refs),who)
 return {'v':v,'epoch':epoch,'seq':seq,'hash':h,'objects':copy.deepcopy(objects),'plan':ph}
def makegrant(v,pol,recipient,ph,actor):
 G=t('grant-header',team,v,u(pol['epoch']),recipient['account'],recipient['id'],actor['id'],ph,pol['commit']);enc,ct=hpke(recipient['pk'],t('hpke-info',G),G,pol['V'],random(32));h=wire('grant',t('grant',G,enc,ct),actor)
 return {'v':v,'epoch':pol['epoch'],'a':recipient['account'],'k':recipient['id'],'hash':h}
def acceptance(st,who,ph,grants):
 refs=ls([gr(g)for g in grsort(grants)if g['a']==who['account']and g['k']==who['id']]);h=wire('acceptance',t('acceptance',team,who['account'],who['id'],ph,H(t('recipient-grants',refs))),who);return who['account'],who['id'],h

def finish(base,st,action,actor=O,accept=(),seq=None,overrides=None):
 pl=plan(st,action,actor,seq);ph=H(pl);oldvs=base['vaults'];grants=[];heads={}
 for v,p in sorted(st['vaults'].items()):
  old=oldvs.get(v);active=p['phase']==1;new=old is None or old['epoch']!=p['epoch']
  eligible={(a,st['roster'][a]['key'])for a in p['perms']if st['roster'][a]['status']==2}
  prior=[g for g in base['grants']if g['v']==v]
  if active:
   for a,k in sorted(eligible):
    existing=next((g for g in prior if g['a']==a and g['k']==k),None)
    grants.append(copy.deepcopy(existing)if existing and not new else makegrant(v,p,keys[k],ph,actor))
  else:grants.extend(copy.deepcopy(g)for g in prior if(g['a'],g['k'])in eligible)
  if new:
   if old is None:obj={bytes(16):content(v,p['epoch'],bytes(16),1,1,ph,p['V'],actor,t('vault-label',b'Public synthetic vault'))}
   else:obj={i:content(v,p['epoch'],i,c['kind'],c['rev']+1,ph,p['V'],actor,c['plain'])for i,c in base['heads'][v]['objects'].items()}
   heads[v]=snapshot(v,p['epoch'],ph,actor,obj,base['heads'].get(v))
  else:heads[v]=copy.deepcopy(base['heads'][v])
 ars=[acceptance(st,keys[k],ph,grants)for k in accept]
 refs=ls([gr(g)for g in grsort(grants)]);srefs=ls([t('snapshot-ref',v,u(h['epoch']),h['hash'])for v,h in sorted(heads.items())]);arefs=ls([t('acceptance-ref',a,k,h)for a,k,h in sorted(ars)])
 if overrides:
  pl,refs,srefs,arefs=overrides(pl,refs,srefs,arefs)
 h=wire('authority',t('authority',pl,refs,srefs,arefs),actor)
 st=copy.deepcopy(st);st.update(hash=h,seq=seq if seq is not None else st['seq']+1,plan=ph,grants=grants,heads=heads)
 return st

def member(k,role=3,status=2):return {'key':k['id'],'role':role,'status':status}
def policy(epoch=1,perms=None,v=vault):
 V=random(32);return {'epoch':epoch,'phase':1,'V':V,'commit':H(t('vault-key-commitment',team,v,u(epoch),V)),'perms':perms or {O['account']:2}}
empty={'hash':bytes(32),'seq':0,'roster':{},'vaults':{},'heads':{},'grants':[]};s=copy.deepcopy(empty);s['roster'][O['account']]=member(O,1);gen=finish(empty,s,'genesis')
steps=[];cases=[]
def step(kind,h):return {'kind':kind,'hash':h.hex()}
def case(name,prior,kind,h,ok=True):cases.append({'name':name,'prefix':copy.deepcopy(prior),'operation':step(kind,h),'accept':ok})
def authcase(name,base,mutate,action,ok=True,accept=(),actor=O,seq=None):
 st=copy.deepcopy(base);mutate(st);n=finish(base,st,action,actor,accept,seq);case(name,steps,'authority',n['hash'],ok);return n
steps=[step('authority',gen['hash'])]
s=copy.deepcopy(gen);s['vaults'][vault]=policy();new=finish(gen,s,'new-vault');case('new vault/offline existing Owner no acceptance',steps,'authority',new['hash']);steps.append(step('authority',new['hash']))
invite=authcase('ordinary pending invite',new,lambda s:s['roster'].update({M['account']:member(M,3,1)}),'invite');steps.append(step('authority',invite['hash']))
def activate(s):s['roster'][M['account']]['status']=2;s['vaults'][vault]['perms'][M['account']]=2
active=authcase('verified accepted Member activation',invite,activate,'activate',accept=(M['id'],));authcase('activation missing acceptance',invite,activate,'activate',False)
steps.append(step('authority',active['hash']))
# New signed ordinary secret, edit, delete, restore and invalid maps.
base=copy.deepcopy(active);objs=copy.deepcopy(base['heads'][vault]['objects']);objs[item]=content(vault,1,item,2,1,base['plan'],base['vaults'][vault]['V'],M,t('secret',b'name',b'synthetic value'))
add=snapshot(vault,1,base['plan'],M,objs,base['heads'][vault]);case('Member adds signed secret',steps,'snapshot',add['hash']);steps.append(step('snapshot',add['hash']));base['heads'][vault]=add
for name,kind,plain in [('Member edit',2,t('secret',b'edited',b'value2')),('Member deletion tombstone',3,t('deleted')),('explicit restore is new revision',2,t('secret',b'restored',b'value3'))]:
 objs=copy.deepcopy(base['heads'][vault]['objects']);objs[item]=content(vault,1,item,kind,objs[item]['rev']+1,base['plan'],base['vaults'][vault]['V'],M,plain);sn=snapshot(vault,1,base['plan'],M,objs,base['heads'][vault]);case(name,steps,'snapshot',sn['hash']);steps.append(step('snapshot',sn['hash']));base['heads'][vault]=sn
objs=copy.deepcopy(base['heads'][vault]['objects']);del objs[item];bad=snapshot(vault,1,base['plan'],M,objs,base['heads'][vault]);case('silent item omission',steps,'snapshot',bad['hash'],False)
objs=copy.deepcopy(base['heads'][vault]['objects']);old=objs[item];rev=old['rev']+1;secret=content(vault,1,item,2,rev,base['plan'],base['vaults'][vault]['V'],M,t('secret',b'a',b'b'));deleted=content(vault,1,item,3,rev,base['plan'],base['vaults'][vault]['V'],M,t('deleted'))
raw=[t('content-ref',bytes(16),u(1,1),u(objs[bytes(16)]['rev']),objs[bytes(16)]['hash']),t('content-ref',item,u(2,1),u(rev),secret['hash']),t('content-ref',item,u(3,1),u(rev),deleted['hash'])];bad=snapshot(vault,1,base['plan'],M,objs,base['heads'][vault],raw);case('duplicate item kinds despite sorted tuples',steps,'snapshot',bad['hash'],False)
# Correctly signed authority negatives and valid privileged changes.
authcase('Member cannot self-promote',base,lambda s:(s['roster'][M['account']].update(role=2),s['vaults'][vault]['perms'].update({M['account']:2})),'promote',False,accept=(M['id'],),actor=M)
prom=authcase('Owner promotes with complete accepted grant set',base,lambda s:s['roster'][M['account']].update(role=2),'promote',accept=(M['id'],));authcase('promotion missing acceptance',base,lambda s:s['roster'][M['account']].update(role=2),'promote',False)
# Removal freezes current content and excludes removed grants; stale writer remains signed.
def remove(s):s['roster'][M['account']]['status']=3;s['vaults'][vault]['perms'].pop(M['account']);s['vaults'][vault]['phase']=2
removed=authcase('immediate Member removal/frozen remaining reads',base,remove,'remove');removedsteps=steps+[step('authority',removed['hash'])]
objs=copy.deepcopy(base['heads'][vault]['objects']);objs[item]=content(vault,1,item,2,objs[item]['rev']+1,base['plan'],base['vaults'][vault]['V'],M,t('secret',b'stale',b'removed'));bad=snapshot(vault,1,base['plan'],M,objs,base['heads'][vault]);case('removed writer old-plan append',removedsteps,'snapshot',bad['hash'],False)
# Exact all-current-item rotation; epoch/sequence gaps; partial item subset.
def rotate(s):
 p=policy(2,{O['account']:2});s['vaults'][vault]=p
rotated=copy.deepcopy(removed);rotate(rotated);rot=finish(removed,rotated,'rotate');case('complete atomic rotation current objects',removedsteps,'authority',rot['hash'])
bad=copy.deepcopy(removed);rotate(bad);bad['vaults'][vault]['epoch']=4;bad['vaults'][vault]['commit']=H(t('vault-key-commitment',team,vault,u(4),bad['vaults'][vault]['V']));bad=finish(removed,bad,'rotate',seq=removed['seq']+2);case('signed sequence and epoch jump',removedsteps,'authority',bad['hash'],False)
# Direct signed candidate with missing grant list, full syntax intact.
partial=finish(removed,rotated,'rotate',overrides=lambda p,g,s,a:(p,ls([]),s,a));case('atomic rotation missing required grant',removedsteps,'authority',partial['hash'],False)
# permission downgrade no key loss, permission removal frozen.
def read(s):s['vaults'][vault]['perms'][M['account']]=1
readonly=authcase('writer downgrade retains read without rotation',base,read,'vault-permission');rsteps=steps+[step('authority',readonly['hash'])]
objs=copy.deepcopy(base['heads'][vault]['objects']);objs[item]=content(vault,1,item,2,objs[item]['rev']+1,readonly['plan'],base['vaults'][vault]['V'],M,t('secret',b'no',b'write'));bad=snapshot(vault,1,readonly['plan'],M,objs,base['heads'][vault]);case('read-only signed writer denied',rsteps,'snapshot',bad['hash'],False)
def replace(s):s['roster'][M['account']]['key']=M2['id'];s['vaults'][vault]['phase']=2
replaced=authcase('replacement acceptance/freeze/no historical grant',base,replace,'replace-key',accept=(M2['id'],));authcase('replacement missing acceptance',base,replace,'replace-key',False)
# Inviting and removing another account in one candidate remains invalid even with refs consistent.
def combo(s):s['roster'][A['account']]=member(A,3,1);remove(s)
authcase('invite cannot smuggle unrelated removal',base,combo,'invite',False)
# Explicit transfer and demotion are all Owner-only, not role booleans.
def transfer(s):s['roster'][M['account']]['role']=1;s['roster'][O['account']]['role']=2
trans=authcase('ownership transfer verified accepting recipient',base,transfer,'transfer',accept=(M['id'],));tsteps=steps+[step('authority',trans['hash'])]
def demote(s):s['roster'][O['account']]['role']=3;s['vaults'][vault]['perms'].pop(O['account']);s['vaults'][vault]['phase']=2
dem=copy.deepcopy(trans);demote(dem);dem=finish(trans,dem,'demote',M);case('new Owner demotes former Owner with access loss',tsteps,'authority',dem['hash'])
def delete(s):
 for m in s['roster'].values():m['status']=3
 s['vaults']={}
delstate=copy.deepcopy(base);delete(delstate);deleted=finish(base,delstate,'delete-team');case('terminal team deletion tombstone',steps,'authority',deleted['hash']);case('successor to deleted team',steps+[step('authority',deleted['hash'])],'authority',rot['hash'],False)
# Import always writes a fresh authorized revision and compares both accepted heads.
objs=copy.deepcopy(base['heads'][vault]['objects']);objs[item]=content(vault,1,item,2,objs[item]['rev']+1,base['plan'],base['vaults'][vault]['V'],M,t('secret',b'imported old copy',b'fresh current encryption'));imported=snapshot(vault,1,base['plan'],M,objs,base['heads'][vault])
for name,prefix,ok in [('current authorized import fresh revision',steps,True),('concurrent removal rejects stale import',removedsteps,False),('concurrent rotation rejects stale import',removedsteps+[step('authority',rot['hash'])],False),('concurrent key replacement rejects stale import',steps+[step('authority',replaced['hash'])],False)]:
 op=step('restore',imported['hash']);op.update(expected_authority=base['hash'].hex(),expected_head=base['heads'][vault]['hash'].hex());cases.append({'name':name,'prefix':copy.deepcopy(prefix),'operation':op,'accept':ok})
# Structurally complete and correctly signed rotation with one omitted current item.
partialobjs=copy.deepcopy(rot['heads'][vault]['objects']);partialobjs.pop(item);partialhead=snapshot(vault,2,rot['plan'],O,partialobjs,removed['heads'][vault]);partialauthority=finish(removed,rotated,'rotate',overrides=lambda p,g,s,a:(p,g,ls([t('snapshot-ref',vault,u(2),partialhead['hash'])]),a));case('rotation missing current item despite valid signatures',removedsteps,'authority',partialauthority['hash'],False)
case('valid signed authority rollback is rejected',steps,'authority',gen['hash'],False)
case('conflicting signed successor cannot replace accepted removal',removedsteps,'authority',prom['hash'],False)
competing=next(c['operation']for c in cases if c['name']=='removed writer old-plan append')
op=step('restore',imported['hash']);op.update(expected_authority=base['hash'].hex(),expected_head=base['heads'][vault]['hash'].hex());cases.append({'name':'concurrent content edit rejects stale import head','prefix':steps+[copy.deepcopy(competing)],'operation':op,'accept':False})
# Encrypted recovery/data exports: explicit typed projection, no automatic history grants.
def fs(b):
 pos=len(b'bitbid-team-v1/');n=int.from_bytes(b[pos:pos+2],'big');pos+=2+n;count=int.from_bytes(b[pos:pos+2],'big');pos+=2;out=[]
 for _ in range(count):n=int.from_bytes(b[pos:pos+4],'big');pos+=4;out.append(b[pos:pos+n]);pos+=n
 assert pos==len(b);return out
def entries(b):
 pos=4;out=[]
 for _ in range(int.from_bytes(b[:4],'big')):n=int.from_bytes(b[pos:pos+4],'big');pos+=4;out.append(b[pos:pos+n]);pos+=n
 assert pos==len(b);return out
def payload(h):return fs(fs(bytes.fromhex(records[h.hex()]))[3])[1]
# Existing active privileged offline recipients require grants, not fresh acceptance.
nv2=copy.deepcopy(prom);nv2['vaults'][vault2]=policy(perms={O['account']:2,M['account']:2},v=vault2);new2=finish(prom,nv2,'new-vault');promsteps=steps+[step('authority',prom['hash'])];case('new vault grants all offline active Owner and Admin',promsteps,'authority',new2['hash'])
missing2=finish(prom,nv2,'new-vault',overrides=lambda p,g,s,a:(p,ls([e for e in entries(g)if not(fs(e)[0]==M['account']and fs(e)[2]==vault2)]),s,a));case('new vault missing offline Admin grant',promsteps,'authority',missing2['hash'],False)
passphrase=b'public synthetic qualification passphrase';salt=bytes(range(16));kp=hash_secret_raw(passphrase,salt,3,65536,4,32,Type.ID,19)
R=H(b'PUBLIC-SYNTHETIC-RECOVERY');who=M;nonce=random(24);Phead=t('pass-header',who['account'],u(1),who['id'],u(19,4),u(65536,4),u(3,4),u(4,4),salt,nonce);pw=wire('pass-wrapper',t('pass-wrapper',Phead,crypto_aead_xchacha20poly1305_ietf_encrypt(who['root'],Phead,nonce,kp)))
nonce=random(24);Q=t('recovery-header',who['account'],u(1),who['id'],nonce);Kr=hkdf(R,t('recovery-wrap',who['account'],u(1),who['id']));rw=wire('recovery-wrapper',t('recovery-wrapper',Q,crypto_aead_xchacha20poly1305_ietf_encrypt(who['root'],Q,nonce,Kr)))
nonce=random(24);TH=t('trust-header',who['account'],u(1),u(3),random(32),nonce);trust=t('trust-state',ls([t('team-pin',team,gen['hash'])]),ls([t('peer-pin',O['account'],O['id'],H(t('fingerprint',payload(O['wire']))))]));Kt=hkdf(who['root'],t('trust-wrap',who['account'],u(1)));tw=wire('trust-wrapper',t('trust-wrapper',TH,crypto_aead_xchacha20poly1305_ietf_encrypt(trust,TH,nonce,Kt)))
roots={who['wire'],pw,rw,tw}
projection=set(roots)|{O['wire']}
for op in steps:
 h=bytes.fromhex(op['hash']);projection.add(h)
 if op['kind']=='authority':
  ff=fs(payload(h))
  for ar in entries(ff[3]):projection.add(fs(ar)[2])
  for sr in entries(ff[2]):projection.add(fs(sr)[2])
projection.update(c['hash']for c in base['heads'][vault]['objects'].values());projection.update(g['hash']for g in base['grants']if g['a']==M['account'])
code=t('recovery-code',who['account'],u(1),R);recoverycode='bitbid-recovery1:'+base64.urlsafe_b64encode(code+H(t('recovery-checksum',code))[:16]).decode().rstrip('=')
exports=[]
def exportcase(name,selected,included,ok=True):
 er=ls([t('export-record',h,bytes.fromhex(records[h.hex()]))for h in sorted(included)]);pl=t('export',who['account'],u(1),random(16),ls(selected),er)
 # Do not add the export itself to record lookup (nested exports are forbidden).
 env=t('signed-envelope',who['id'],pl,who['ed'].sign(t('signed-record',b'export',who['id'],pl)).signature);b=t('wire',u(1,2),u(1,2),b'export',env)
 exports.append({'name':name,'wire':b.hex(),'accept':ok,'recovery':R.hex(),'recovery_code':recoverycode,'passphrase':passphrase.hex(),'snapshot':base['heads'][vault]['hash'].hex()if selected else None})
selection=[t('selected-vault',team,vault,u(1),base['heads'][vault]['hash'])]
exportcase('recovery-only exact roots trustseq3 markers',[],roots)
exportcase('selected data exact current projection',selection,projection)
exportcase('recovery-only extra genesis',[],roots|{gen['hash']},False)
exportcase('selected data missing current content',selection,projection-{base['heads'][vault]['objects'][item]['hash']},False)
exportcase('selected data missing signer identity',selection,projection-{O['wire']},False)
exportcase('selected data missing epoch grant',selection,projection-{g['hash']for g in base['grants']if g['a']==M['account']},False)
exportcase('selected data missing authority ancestor',selection,projection-{invite['hash']},False)
exportcase('selected data missing acceptance proof',selection,projection-{fs(e)[2]for e in entries(fs(payload(active['hash']))[3])},False)
exportcase('selected data unreferenced replaced ciphertext',selection,projection|{add['objects'][item]['hash']},False)
exportcase('recovery-only missing recovery wrapper',[],roots-{rw},False)
# Standard/reference primitive values; every expected byte originates outside Rust.
passphrase=b'public synthetic qualification passphrase';salt=bytes(range(16));kp=hash_secret_raw(passphrase,salt,3,65536,4,32,Type.ID,19)
key=bytes(range(32));nonce=bytes(range(24));plain=b'public synthetic xchacha vector';aad=t('test-aad',b'context')
xct=crypto_aead_xchacha20poly1305_ietf_encrypt(plain,aad,nonce,key)
ikm=bytes(range(32));info=b'public independent HPKE';haad=b'grant header';hpt=bytes([99])*32;enc,hct=hpke(O['pk'],info,haad,hpt,ikm)
primitive={'argon2':{'pass':passphrase.hex(),'salt':salt.hex(),'output':kp.hex()},'xchacha':{'key':key.hex(),'nonce':nonce.hex(),'plaintext':plain.hex(),'aad':aad.hex(),'ciphertext':xct.hex()},'hpke':{'private':O['x'].hex(),'public':O['pk'].hex(),'ikm':ikm.hex(),'info':info.hex(),'aad':haad.hex(),'plaintext':hpt.hex(),'enc':enc.hex(),'ciphertext':hct.hex()},'hkdf':{'root':O['root'].hex(),'account':O['account'].hex(),'generation':1,'recipient':O['x'].hex(),'signing':bytes(O['ed']).hex()}}
# Append activation-actor regressions after the original corpus generation. This
# preserves every pre-fix record, case, export and deterministic entropy choice.
activation_case_start=len(cases);activation_export_start=len(exports)
def replace_head(st,v,head):
 out=copy.deepcopy(st);out['heads'][v]=head;f=fs(payload(st['hash']))
 refs=ls([t('snapshot-ref',vv,u(h['epoch']),h['hash'])for vv,h in sorted(out['heads'].items())])
 out['hash']=wire('authority',t('authority',f[0],f[1],refs,f[3]),O);return out
def other_signed_body(st,previous,v,i,signer):
 obj=copy.deepcopy(st['heads'][v]['objects']);original=obj[i]['hash']
 # Re-sign the identical encrypted payload: context, nonce, plaintext, revision
 # and ciphertext remain byte-identical, with only the authenticated signer changed.
 obj[i]['hash']=wire('content',payload(original),signer)
 head=snapshot(v,st['vaults'][v]['epoch'],st['plan'],O,obj,previous['heads'].get(v))
 candidate=replace_head(st,v,head)
 from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
 for h in [original,obj[i]['hash']]:
  env=fs(fs(bytes.fromhex(records[h.hex()]))[3]);keys[env[0]]['ed'].verify_key.verify(t('signed-record',b'content',env[0],env[1]),env[2])
  cf=fs(env[1]);ch=fs(cf[0]);assert crypto_aead_xchacha20poly1305_ietf_decrypt(cf[1],cf[0],ch[7],st['vaults'][v]['V'])==obj[i]['plain']
 assert payload(original)==payload(obj[i]['hash'])
 return candidate
def append_edit(st,v,i,kind,who,plain):
 out=copy.deepcopy(st);objects=copy.deepcopy(st['heads'][v]['objects']);prior=objects.get(i)
 objects[i]=content(v,st['vaults'][v]['epoch'],i,kind,1 if prior is None else prior['rev']+1,st['plan'],st['vaults'][v]['V'],who,plain)
 out['heads'][v]=snapshot(v,st['vaults'][v]['epoch'],st['plan'],who,objects,st['heads'][v]);return out
def selected_case(name,st,v,prior,ok=True):
 included=set(roots)|{O['wire']}
 for op in prior:
  h=bytes.fromhex(op['hash'])
  if op['kind']=='authority':
   included.add(h);ff=fs(payload(h))
   included.update(fs(ar)[2]for ar in entries(ff[3]))
   included.update(fs(sr)[2]for sr in entries(ff[2])if fs(sr)[0]==v)
  elif fs(payload(h))[1]==v:included.add(h)
 head=st['heads'][v];included.add(head['hash']);included.update(c['hash']for c in head['objects'].values())
 included.update(g['hash']for g in st['grants']if g['v']==v and g['a']==M['account'])
 exportcase(name,[t('selected-vault',team,v,u(st['vaults'][v]['epoch']),head['hash'])],included,ok)
 exports[-1]['snapshot']=head['hash'].hex()

# Owner-signed rotation, complete recipient grants, active Member and exact set.
rs=copy.deepcopy(base);rs['vaults'][vault]=policy(2,base['vaults'][vault]['perms']);memberrot=finish(base,rs,'rotate')
case('actor-signed rotation with another eligible Member',steps,'authority',memberrot['hash'])
memberbad=other_signed_body(memberrot,base,vault,item,M)
case('rotation rejects other Member signed replacement body',steps,'authority',memberbad['hash'],False)
for st,name,ok in [(memberrot,'actor-signed rotation selected data',True),(memberbad,'selected rotation rejects other Member signed body',False)]:
 selected_case(name,st,vault,steps+[step('authority',st['hash'])],ok)
# Tombstones and labels are replacement bodies too; label control uses an Admin
# so its negative passes ordinary privileged-label authorization.
dead=append_edit(base,vault,item,3,M,t('deleted'));deadsteps=steps+[step('snapshot',dead['heads'][vault]['hash'])]
ds=copy.deepcopy(dead);ds['vaults'][vault]=policy(2,dead['vaults'][vault]['perms']);deadrot=finish(dead,ds,'rotate')
case('actor-signed rotation preserves tombstone',deadsteps,'authority',deadrot['hash'])
deadbad=other_signed_body(deadrot,dead,vault,item,M);case('rotation rejects other Member signed tombstone',deadsteps,'authority',deadbad['hash'],False)
ps=copy.deepcopy(prom);ps['vaults'][vault]=policy(2,prom['vaults'][vault]['perms']);adminrot=finish(prom,ps,'rotate')
case('actor-signed rotation with another Admin',promsteps,'authority',adminrot['hash'])
adminbad=other_signed_body(adminrot,prom,vault,bytes(16),M);case('rotation rejects other Admin signed replacement label',promsteps,'authority',adminbad['hash'],False)
selected_case('selected rotation rejects other Admin signed label',adminbad,vault,promsteps+[step('authority',adminbad['hash'])],False)
# Existing valid new2 is the exact Owner-signed new-vault control, now paired
# with an Admin-signed label and an otherwise unchanged Owner snapshot/grants.
newbad=other_signed_body(new2,prom,vault2,bytes(16),M)
case('new vault rejects other Admin signed initial label',promsteps,'authority',newbad['hash'],False)
for st,name,ok in [(new2,'actor-signed new vault selected data',True),(newbad,'selected new vault rejects other Admin initial label',False)]:
 selected_case(name,st,vault2,promsteps+[step('authority',st['hash'])],ok)
# Subsequent ordinary operations remain legal under the SAME rotate/new-vault
# plan. No new authority is finalized between these edits and their activation.
rotsteps=steps+[step('authority',memberrot['hash'])];edited=memberrot
for name,kind,plain in [('Member edit under current rotate plan',2,t('secret',b'after rotation',b'Member write')),('Member delete under current rotate plan',3,t('deleted')),('Member restore under current rotate plan',2,t('secret',b'after rotation restore',b'Member write'))]:
 edited=append_edit(edited,vault,item,kind,M,plain);case(name,rotsteps,'snapshot',edited['heads'][vault]['hash']);rotsteps.append(step('snapshot',edited['heads'][vault]['hash']))
selected_case('selected ordinary Member edits under rotate plan',edited,vault,rotsteps)
adminsteps=promsteps+[step('authority',adminrot['hash'])];labeled=append_edit(adminrot,vault,bytes(16),1,M,t('vault-label',b'ordinary Admin label after rotation'))
case('Admin label edit under current rotate plan',adminsteps,'snapshot',labeled['heads'][vault]['hash']);selected_case('selected Admin label edit under rotate plan',labeled,vault,adminsteps+[step('snapshot',labeled['heads'][vault]['hash'])])
newsteps=promsteps+[step('authority',new2['hash'])];labeled=append_edit(new2,vault2,bytes(16),1,M,t('vault-label',b'ordinary Admin label after creation'))
case('Admin label edit under current new-vault plan',newsteps,'snapshot',labeled['heads'][vault2]['hash']);selected_case('selected Admin label edit under new-vault plan',labeled,vault2,newsteps+[step('snapshot',labeled['heads'][vault2]['hash'])])
written=append_edit(new2,vault,item,2,M,t('secret',b'ordinary existing vault edit',b'same new-vault plan'))
case('ordinary content edit under current new-vault plan',newsteps,'snapshot',written['heads'][vault]['hash']);selected_case('selected ordinary content under new-vault plan',written,vault,newsteps+[step('snapshot',written['heads'][vault]['hash'])])
# A selected initial body retained by a later snapshot still needs its original
# activation provenance; checking only terminal-snapshot deltas would miss this.
retained=append_edit(newbad,vault2,item,2,M,t('secret',b'later ordinary secret',b'bad initial label retained'))
selected_case('selected retained initial label rejects other Admin signer',retained,vault2,promsteps+[step('authority',newbad['hash']),step('snapshot',retained['heads'][vault2]['hash'])],False)
ms=copy.deepcopy(base);ms['vaults'][vault2]=policy(perms={O['account']:2,M['account']:2},v=vault2);membernew=finish(base,ms,'new-vault')
case('actor-signed new vault with ordinary Member permission',steps,'authority',membernew['hash']);membersteps=steps+[step('authority',membernew['hash'])];written=membernew
for name,kind,plain in [('Member edit under current new-vault plan',2,t('secret',b'new vault Member edit',b'value')),('Member delete under current new-vault plan',3,t('deleted')),('Member restore under current new-vault plan',2,t('secret',b'new vault Member restore',b'value'))]:
 written=append_edit(written,vault,item,kind,M,plain);case(name,membersteps,'snapshot',written['heads'][vault]['hash']);membersteps.append(step('snapshot',written['heads'][vault]['hash']))
selected_case('selected ordinary Member edits under new-vault plan',written,vault,membersteps)
for c in cases[activation_case_start:]+exports[activation_export_start:]:
 if not c['accept']:c['rejection']='activation content actor'
# Save public synthetic keys for actual grant/content/wrapper decryption checks only.
public_test_material={k['id'].hex():{'root':k['root'].hex(),'x':k['x'].hex(),'account':k['account'].hex(),'generation':k['g']}for k in keys.values()}
corpus={'schema_sha256':'6a9b26878f1192727e8ca6e52a9da449d21d7b8b7c45b827e601de2cd9b66d6a','reference':{p:importlib.metadata.version(p)for p in ['argon2-cffi','PyNaCl','cryptography']},'primitives':primitive,'records':records,'cases':cases,'exports':exports,'synthetic_test_material':public_test_material}
(P/'vectors/reference.json').write_text(json.dumps(corpus,indent=2)+'\n')
print(json.dumps({'records':len(records),'cases':len(cases),'corpus_sha256':H((P/'vectors/reference.json').read_bytes()).hex(),'reference':corpus['reference']},indent=2))
