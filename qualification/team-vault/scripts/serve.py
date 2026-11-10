"""Loopback-only static probe and bounded synthetic-metrics collector."""
from pathlib import Path
from http.server import ThreadingHTTPServer,SimpleHTTPRequestHandler
import argparse,json,hashlib,time
p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--port',type=int,default=0);a=p.parse_args();a.evidence.mkdir(parents=True,exist_ok=True)
web=Path(__file__).resolve().parents[1]/'web'
class Handler(SimpleHTTPRequestHandler):
 def __init__(self,*args,**kw):super().__init__(*args,directory=str(web),**kw)
 def end_headers(self):
  self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'");super().end_headers()
 def do_POST(self):
  if self.path!='/evidence':self.send_error(404);return
  n=int(self.headers.get('Content-Length','0'))
  if not 0<n<=1024*1024:self.send_error(413);return
  try:
   value=json.loads(self.rfile.read(n));assert isinstance(value,dict)
   allowed={'target','build','user_agent','events','suite','benchmarks','heartbeat_max_ms','visibility','errors','lifecycle','concurrency','timestamp','memory','pass','status'}
   assert set(value)<=allowed
   stamp=str(time.time_ns());dest=a.evidence/f'browser-{stamp}.json';dest.write_text(json.dumps(value,indent=2)+'\n')
  except (ValueError,AssertionError):self.send_error(400);return
  self.send_response(200);self.end_headers();self.wfile.write(json.dumps({'saved':dest.name}).encode())
 def log_message(self,fmt,*args):print(fmt%args,flush=True)
s=ThreadingHTTPServer(('127.0.0.1',a.port),Handler);url=f'http://127.0.0.1:{s.server_port}/';(a.evidence/'server.json').write_text(json.dumps({'url':url,'web_root':str(web),'build_sha256':hashlib.sha256((web/'build.json').read_bytes()).hexdigest()},indent=2)+'\n');print(url,flush=True)
try:s.serve_forever()
except KeyboardInterrupt:pass
finally:s.server_close()
