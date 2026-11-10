// Synthetic qualification only. Private work lives in this owned worker.
let api, wasm, flavor;
self.onmessage = async ({data}) => {
 const {id,generation,kind,delay=0}=data;
 try {
  if(kind==='init') {
   flavor=data.flavor||'normal';api=await import(`./pkg/${flavor}/qualification.js`);
   wasm=await api.default();
   self.postMessage({id,generation,kind:'ready',memory:wasm.memory.buffer.byteLength,flavor});return;
  }
  self.postMessage({id,generation,kind:'started',operation:kind});
  let result;
  const before=wasm.memory.buffer.byteLength, start=performance.now(), started_at=Date.now();
  if(kind==='suite') result=JSON.parse(api.qualify());
  else if(kind==='kdf') result=JSON.parse(api.profile_kdf());
  else throw Error('unknown operation');
  const response={id,generation,kind:'result',started_at,ended_at:Date.now(),operation:kind,result,milliseconds:performance.now()-start,memory_before:before,memory_after:wasm.memory.buffer.byteLength,flavor};
  if(delay) setTimeout(()=>self.postMessage(response),delay);else self.postMessage(response);
 } catch(e) {
  self.postMessage({id,generation,kind:'failure',operation:kind,error:String(e),memory:wasm?.memory.buffer.byteLength,flavor});
 }
};
