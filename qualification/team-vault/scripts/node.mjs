import fs from 'node:fs/promises';
import {webcrypto} from 'node:crypto';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const dir=new URL('../web/pkg/normal/',import.meta.url), bounded=new URL('../web/pkg/bounded/',import.meta.url);
const api=await import(new URL('qualification.js',dir));const wasm=await api.default({module_or_path:await fs.readFile(new URL('qualification_bg.wasm',dir))});
const result=JSON.parse(api.qualify()),start=performance.now(),kdf=JSON.parse(api.profile_kdf()), kdfMs=performance.now()-start;
const bad=await import(new URL('qualification.js',bounded));const failed=await bad.default({module_or_path:await fs.readFile(new URL('qualification_bg.wasm',bounded))});let allocationRejected=false;try{bad.profile_kdf();}catch(e){if(!String(e).includes('KDF allocation'))throw e;allocationRejected=true;}
if(!allocationRejected)throw Error('bounded allocation succeeded');console.log(JSON.stringify({target:process.version,optimized_wasm:true,result,kdf,kdf_ms:kdfMs,memory:wasm.memory.buffer.byteLength,bounded_memory:failed.memory.buffer.byteLength,allocationRejected}));
