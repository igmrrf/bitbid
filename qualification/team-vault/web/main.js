const $=s=>document.querySelector(s), wait=ms=>new Promise(r=>setTimeout(r,ms));
const metrics={target:'unclassified physical browser',user_agent:navigator.userAgent,timestamp:new Date().toISOString(),events:[],benchmarks:[],errors:[],visibility:[],lifecycle:{},concurrency:{tab_id:crypto.randomUUID()},status:'ready'};
let worker,generation=0,nextId=0,pending=null,activeKdf=null,staleResolve=null,unlocked=false,heartbeat=0,lastBeat=performance.now(),maxGap=0,clockOffset=0,lastActivity=performance.now(),hiddenSince=null,armed=false;
const clock=()=>performance.now()+clockOffset;
function render(){ $('#state').textContent=unlocked?'Synthetic worker operation completed':'Locked';$('#results').textContent=JSON.stringify(metrics,null,2);window.qualificationMetrics=structuredClone(metrics);}
function event(type,details={}){metrics.events.push({type,at:performance.now(),...details});render();}
function lock(reason='manual',retainWorker=false){const start=performance.now();if(!retainWorker)finishHeartbeat(null,'terminated');generation++;unlocked=false;if(pending){pending.reject(Error('cancelled by '+reason));pending=null;}if(!retainWorker){worker?.terminate();worker=null;}metrics.lifecycle.last_lock_ms=performance.now()-start;event('lock',{reason,generation,retained_worker_test_seam:retainWorker});}
function deadlines(now){if(now-lastActivity>=15*60*1000||(hiddenSince!==null&&now-hiddenSince>=5*60*1000)){lock('deadline');return false;}return true;}
// Track actual acknowledged work, including operations outside Run qualification.
// Hidden timer throttling is retained separately and never called foreground coverage.
function sampleHeartbeat(tick=true){
 const now=performance.now(),gap=now-lastBeat;lastBeat=now;
 if(!activeKdf)return;
 if(document.hidden){activeKdf.background_max_ms=Math.max(activeKdf.background_max_ms,gap);if(tick)activeKdf.background_ticks++;}
 else{activeKdf.foreground_max_ms=Math.max(activeKdf.foreground_max_ms,gap);activeKdf.foreground_span_ms+=gap;if(tick)activeKdf.foreground_ticks++;maxGap=Math.max(maxGap,gap);}
}
function finishHeartbeat(message,reason='completed'){
 if(!activeKdf||(message&&message.id!==activeKdf.id))return;
 sampleHeartbeat(false);
 const observation={...activeKdf,visible_at_end:!document.hidden,ended_at:Date.now(),reason};
 if(message)message.heartbeat=observation;
 activeKdf=null;event('kdf-heartbeat',observation);
}
function wire(w){w.onmessage=({data:m})=>{
 if(m.kind==='started'){
  if(m.generation!==generation||pending?.id!==m.id){event('stale-start-rejected',{operation:m.operation});return;}
  if(m.operation==='kdf'){lastBeat=performance.now();activeKdf={id:m.id,started_at:Date.now(),visible_at_start:!document.hidden,foreground_ticks:0,foreground_span_ms:0,foreground_max_ms:0,background_ticks:0,background_max_ms:0};}
  event('worker-started',{operation:m.operation});pending.started?.();return;
 }
 finishHeartbeat(m,m.kind==='failure'?'failure':'completed');
 if(m.generation!==generation||!pending||pending.id!==m.id){metrics.lifecycle.stale_replies_rejected=(metrics.lifecycle.stale_replies_rejected||0)+1;event('stale-reply-rejected',{operation:m.operation});staleResolve?.();staleResolve=null;return;}
 const p=pending;pending=null;if(m.kind==='failure')p.reject(Error(m.error));else p.resolve(m);
 };w.onerror=e=>{finishHeartbeat(null,'worker-error');metrics.errors.push(String(e.message));pending?.reject(Error(e.message));pending=null;render();};}
async function request(kind,options={}){const {started,...message}=options;if(pending)throw Error('duplicate operation rejected');const id=++nextId;return new Promise((resolve,reject)=>{pending={id,resolve,reject,started};try{worker.postMessage({id,generation,kind,...message});}catch(e){pending=null;reject(e);}});}
async function init(flavor='normal'){if(worker)return;worker=new Worker('./worker.js',{type:'module'});wire(worker);const m=await request('init',{flavor});metrics.memory={initial:m.memory,normal_cap:268435456,bounded_cap:33554432};event('worker-ready',{flavor,memory:m.memory});}
async function kdf(){if(!deadlines(clock()))throw Error('expired before operation');await init();lastActivity=clock();const m=await request('kdf');unlocked=true;metrics.benchmarks.push({started_at:m.started_at,ended_at:m.ended_at,heartbeat:m.heartbeat,milliseconds:m.milliseconds,memory_before:m.memory_before,memory_after:m.memory_after,profile:m.result.profile,reference_match:m.result.reference_match});render();return m;}
async function save(){metrics.heartbeat_max_ms=maxGap;metrics.timestamp=new Date().toISOString();render();const res=await fetch('/evidence',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(metrics)});if(!res.ok)throw Error('metrics save '+res.status);$('#summary').textContent='Saved synthetic metrics to local evidence collector.';return res.json();}
async function run(){ $('#run').disabled=true;metrics.status='running';metrics.events=[];metrics.benchmarks=[];metrics.errors=[];metrics.lifecycle={};maxGap=0;lastBeat=performance.now();try{
 lock('fresh qualification');await init();const suite=await request('suite');metrics.suite=suite.result;event('suite-passed',{milliseconds:suite.milliseconds});
 await kdf();await kdf();
 // Duplicate submissions really hit the same pending worker operation.
 let startedResolve;const started=new Promise(r=>startedResolve=r);const first=request('kdf',{started:startedResolve});await started;try{await request('kdf');throw Error('duplicate accepted');}catch(e){if(String(e).includes('duplicate operation rejected'))metrics.lifecycle.duplicate_rejected=true;else throw e;}await first;
 // Cancel after actual worker acknowledgement, while fixed-profile WASM runs.
 let ack;const acknowledged=new Promise(r=>ack=r);const cancelled=request('kdf',{started:ack}).catch(e=>String(e));await acknowledged;await wait(20);const c=performance.now();lock('cancel active KDF');await cancelled;metrics.lifecycle.cancel_ms=performance.now()-c;await init();
 // Real delayed completed reply from old generation, explicit seam retains worker.
 let oldAck;const oldStarted=new Promise(r=>oldAck=r);const staleSeen=new Promise(r=>staleResolve=r);const delayed=request('kdf',{delay:150,started:oldAck}).catch(e=>String(e));await oldStarted;lock('generation stale reply probe',true);await delayed;await Promise.race([staleSeen,wait(31000).then(()=>{throw Error("old worker reply timed out");})]);if(unlocked)throw Error('stale result unlocked state');metrics.lifecycle.stale_did_not_unlock=true;worker.terminate();worker=null;
 // Deadline boundary tests use an explicit injected clock, not elapsed-time claims.
 await init();lastActivity=clock()-15*60*1000;metrics.lifecycle.idle_deadline_locked=!deadlines(clock());await init();lastActivity=clock();hiddenSince=clock()-5*60*1000;metrics.lifecycle.hidden_deadline_locked=!deadlines(clock());hiddenSince=null;lastActivity=clock();
 // A distinct real32MiB-max module must fail its fallible64MiB allocation.
 await init('bounded');try{await request('kdf');throw Error('bounded allocation unexpectedly succeeded');}catch(e){if(String(e).includes('KDF allocation'))metrics.lifecycle.bounded_allocator_failure=true;else throw e;}worker.terminate();worker=null;
 await init();await kdf();metrics.heartbeat_max_ms=maxGap;
 metrics.pass=metrics.suite.pass&&metrics.benchmarks.every(b=>b.milliseconds<=30000&&b.reference_match&&b.memory_after<=268435456&&b.heartbeat.foreground_max_ms<=500)&&maxGap<=500&&metrics.lifecycle.cancel_ms<=250&&metrics.lifecycle.last_lock_ms<=250&&metrics.lifecycle.duplicate_rejected&&metrics.lifecycle.stale_did_not_unlock&&metrics.lifecycle.stale_replies_rejected>0&&metrics.lifecycle.idle_deadline_locked&&metrics.lifecycle.hidden_deadline_locked&&metrics.lifecycle.bounded_allocator_failure;
 metrics.status=metrics.pass?'pass (visibility/two-tab checks separate)':'fail';$('#summary').textContent=metrics.status;await save();
 }catch(e){metrics.errors.push(String(e));metrics.pass=false;metrics.status='fail';$('#summary').textContent=String(e);render();await save().catch(()=>{});}finally{$('#run').disabled=false;}}
setInterval(()=>{sampleHeartbeat();heartbeat++;},50);
document.addEventListener('visibilitychange',()=>{lastBeat=performance.now();metrics.visibility.push({hidden:document.hidden,at:performance.now()});if(document.hidden)hiddenSince=clock();else{if(armed&&hiddenSince!==null){clockOffset+=5*60*1000+1;armed=false;}deadlines(clock());hiddenSince=null;lastActivity=clock();save().catch(()=>{});}render();});
window.addEventListener('error',e=>{metrics.errors.push(String(e.message));render();});window.addEventListener('unhandledrejection',e=>{metrics.errors.push(String(e.reason));render();});
window.addEventListener('pagehide',()=>lock('pagehide/reload'));window.addEventListener('pageshow',()=>{metrics.lifecycle.reload_initial_locked=!unlocked;render();});
$('#agent').textContent=navigator.userAgent;$('#run').onclick=run;$('#kdf').onclick=()=>kdf().then(()=>save()).catch(e=>{$('#summary').textContent=String(e);});$('#lock').onclick=()=>{lock();save().catch(()=>{});};$('#save').onclick=()=>save();$('#visibility').onclick=()=>{armed=true;$('#summary').textContent='Injected deadline armed. Switch to another tab/app, then return; real visibility/resume events will check the deadline.';};
const build=await(await fetch('./build.json')).json();metrics.build=build;$('#build').textContent=build.files['pkg/normal/qualification_bg.wasm'];render();

const channel=new BroadcastChannel('bitbid-qualification-public-probe');let coordinating=false;
channel.onmessage=async({data})=>{try{if(data.kind==='ready'&&coordinating){channel.postMessage({kind:'go'});await concurrentKdf();}else if(data.kind==='go'&&new URL(location.href).searchParams.has('peer'))await concurrentKdf();}catch(e){metrics.errors.push(String(e));render();}};
async function concurrentKdf(){metrics.concurrency.actual_two_tabs=true;metrics.concurrency.start=Date.now();await kdf();metrics.concurrency.end=Date.now();const b=metrics.benchmarks.at(-1);metrics.concurrency.worker_interval={start:b.started_at,end:b.ended_at};metrics.concurrency.foreground_heartbeat=b.heartbeat;metrics.concurrency.foreground_pass=b.heartbeat.foreground_ticks>0?b.heartbeat.foreground_max_ms<=500:null;metrics.concurrency.pass=b.milliseconds<=30000&&b.reference_match&&b.memory_after<=268435456&&(metrics.concurrency.foreground_pass!==false);await save();}
$('#concurrent').onclick=async()=>{try{await init();coordinating=true;const peer=new URL(location.href);peer.searchParams.set('peer','1');window.open(peer,'_blank');$('#summary').textContent='Two owned tabs are coordinating the fixed-profile KDF.';}catch(e){$('#summary').textContent=String(e);}};
if(new URL(location.href).searchParams.has('peer')){await init();channel.postMessage({kind:'ready'});}
