"""Build two optimized isolated WASM modules; no production manifest edits."""
from pathlib import Path
import subprocess,os,json,hashlib,sys
q=Path(__file__).resolve().parents[1];root=q.parents[2]
for flavor,cap in ([] if '--manifest-only' in sys.argv else [('normal',268435456),('bounded',33554432)]):
 env=os.environ.copy();env['RUSTFLAGS']=f'-C link-arg=--max-memory={cap}'
 subprocess.run(['python3',str(root/'.local/run.py'),'bitsec/qualification/team-vault','build','--locked','--release','--lib','--target','wasm32-unknown-unknown'],env=env,check=True)
 out=q/'web/pkg'/flavor
 subprocess.run([str(root/'.local/bin/wasm-bindgen'),'--target','web','--out-dir',str(out),'--out-name','qualification',str(root/'.local/target/wasm32-unknown-unknown/release/bitbid_team_vault_qualification.wasm')],check=True)
files={str(p.relative_to(q/'web')):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted((q/'web').rglob('*'))if p.is_file() and (p.is_relative_to(q/'web/pkg') or p.name in ['index.html','main.js','worker.js','style.css'])}
manifest={'schema_sha256':'6a9b26878f1192727e8ca6e52a9da449d21d7b8b7c45b827e601de2cd9b66d6a','profile':'argon2id19/m65536/t3/p4/salt16/out32','corpus_sha256':hashlib.sha256((q/'vectors/reference.json').read_bytes()).hexdigest(),'normal_max_bytes':268435456,'bounded_max_bytes':33554432,'files':files}
(q/'web/build.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
