#!/usr/bin/env python3
"""Real selected-list filesystem/order proof. Explicit binary; loopback only."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import sys
sys.dont_write_bytecode = True
from registry_probe import abi, REGISTRY, MNEMONIC


def run(binary, home_env):
    assert os.geteuid() != 0, 'permission cases require a real non-root process'
    observations = []
    requests = []
    action = [lambda: None]
    servers = []
    threads = []
    faults = []
    for label in ['first', 'second']:
        class Handler(http.server.BaseHTTPRequestHandler):
            server_label = label
            def log_message(self, *_args): pass
            def do_POST(self):
                try:
                    body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    requests.append(dict(server=self.server_label, envelope=body))
                    action[0]()
                    payload = json.dumps(dict(result=abi(public=True))).encode()
                    self.send_response(200); self.send_header('Content-Length', str(len(payload))); self.end_headers(); self.wfile.write(payload)
                except Exception as exc:
                    faults.append(repr(exc)); self.send_error(500)
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01})
        thread.start(); servers.append(server); threads.append(thread)
    try:
        with tempfile.TemporaryDirectory(prefix='bitbid-store-list-') as directory:
            root = Path(directory); home = root/'home'
            env = os.environ.copy()
            for name in ['BITBID_HOME','BSEC_HOME','BITBID_PINATA_JWT','BSEC_PINATA_JWT']:
                env.pop(name,None)
            env.update(HOME=str(root), BITBID_E2E='0'); env[home_env]=str(home)
            def cli(*args):
                result = subprocess.run([str(binary),*args],cwd=root,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
                warning = b'Warning: BSEC_HOME is deprecated; use BITBID_HOME. Support ends at 1.0.\n'
                if home_env == 'BSEC_HOME':
                    assert result.stderr.startswith(warning) and result.stderr.count(warning)==1, result.stderr
                    result.stderr=result.stderr[len(warning):]
                else: assert warning not in result.stderr
                return result
            mnemonic=root/'mnemonic'; mnemonic.write_text(MNEMONIC)
            init=cli('init','--no-encryption','--import-mnemonic',str(mnemonic)); assert init.returncode==0,init.stderr
            index=home/'secret_index.json'; config=home/'network-config.json'
            wallet=home/'wallet.json'; wallet_before=(wallet.read_bytes(),stat.S_IMODE(wallet.stat().st_mode))
            def cfg(which=0):
                return dict(network='synthetic',chain_id=31337,rpc_url=f'http://127.0.0.1:{servers[which].server_port}',registry_address=REGISTRY if which==0 else '0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',ipfs=dict(gateway='http://127.0.0.1:1/',pinning_service=None,api_url='http://127.0.0.1:1',pinning_jwt=None))
            def snapshot():
                inventory = {}
                for path in home.iterdir():
                    info = path.lstat()
                    entry = dict(kind=stat.S_IFMT(info.st_mode),mode=stat.S_IMODE(info.st_mode))
                    if stat.S_ISREG(info.st_mode):
                        try: entry['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                        except PermissionError: entry['unreadable'] = True
                    elif stat.S_ISLNK(info.st_mode): entry['target'] = os.readlink(path)
                    inventory[path.name] = entry
                return inventory
            def check(name, expected_ids=(), request_ids=(), failure=False, files=True):
                start=len(requests); before=snapshot()
                out=cli('list','--json','--all')
                assert not faults,faults
                sent=requests[start:]
                ids=[bytes.fromhex(x['envelope']['params'][0]['data'][10:]).rstrip(b'\0').decode() for x in sent]
                assert ids==list(request_ids),(name,ids)
                if failure:
                    assert out.returncode==4 and out.stdout==b'',(name,out)
                    assert out.stderr.endswith(f'Configuration error: invalid {home_env}.\n'.encode()),out.stderr
                else:
                    assert out.returncode==0,(name,out)
                    assert [r['id'] for r in json.loads(out.stdout)]==list(expected_ids),(name,out.stdout)
                after = snapshot()
                assert before.keys()==after.keys(),(name,'entries created/removed',before,after)
                if files: assert before==after,(name,'files/modes changed')
                else:
                    # The trap deliberately rewrites only config/index in the
                    # dynamic cases. Every other entry and every mode is fixed.
                    for filename in before:
                        assert before[filename]['mode']==after[filename]['mode'],(name,filename,'mode changed')
                        if filename not in ['network-config.json','secret_index.json']:
                            assert before[filename]==after[filename],(name,filename,'changed')
                assert (wallet.read_bytes(),stat.S_IMODE(wallet.stat().st_mode))==wallet_before
                observations.append(dict(name=name,exit=out.returncode,stdout=out.stdout.decode(),stderr=out.stderr.decode(),requests=sent,files_before=before,files_unchanged=files,wallet_unchanged=True))
                return sent
            # FIFO config would block if a nonempty network read were done eagerly.
            os.mkfifo(config); index.write_text('{}'); check('empty-index-no-config-or-rpc')
            config.unlink(); config.write_text(json.dumps(cfg()))
            for name,raw in [('malformed-index',b'{bad'),('invalid-utf8-index',b'\xff'),('wrong-schema-index',b'[]'),('invalid-utf8-ignored-index-field',b'{"a-id":{"unknown":"\xff"}}')]:
                index.write_bytes(raw); check(name)
            index.unlink(); check('absent-index')
            index.mkdir(); check('directory-index'); index.rmdir()
            index.write_text('{"z-good":{}}'); index.chmod(0)
            try:
                try: index.read_bytes(); raise AssertionError('OS unexpectedly permitted index read')
                except PermissionError: pass
                check('denied-index-real-access',files=False)
            finally: index.chmod(0o600)
            # Invalid ID stops before RPC even with default config, trapping all I/O locally.
            index.write_text('{"0xzz":{}}')
            for name,raw in [('malformed-config',b'{bad'),('invalid-utf8-config',b'\xff'),('wrong-schema-config',b'{}'),('invalid-utf8-ignored-config-field',json.dumps(dict(cfg(),unknown='SENTINEL')).encode().replace(b'SENTINEL',b'\xff'))]:
                config.write_bytes(raw); check(name)
            config.unlink(); check('absent-config')
            config.mkdir(); check('directory-config'); config.rmdir()
            config.write_text(json.dumps(cfg())); config.chmod(0)
            try:
                try: config.read_bytes(); raise AssertionError('OS unexpectedly permitted config read')
                except PermissionError: pass
                check('denied-config-real-access',files=False)
            finally: config.chmod(0o600)
            # Change both endpoint and registry while answering first ID. Second
            # ID must reload config; a startup snapshot would hit the first trap.
            config.write_text(json.dumps(cfg())); index.write_text('{"b-second":{},"a-first":{}}')
            action[0]=lambda: config.write_text(json.dumps(cfg(1)))
            sent=check('config-reloaded-per-id',('a-first','b-second'),('a-first','b-second'),files=False)
            assert [r['server'] for r in sent]==['first','second'],sent
            assert [r['envelope']['params'][0]['to'] for r in sent]==[REGISTRY,cfg(1)['registry_address']],sent
            # Successful first RPC must revalidate index selection before filters
            # or the next ID. Prove actual directory denial, then restore it.
            action[0]=lambda: home.chmod(0)
            config.write_text(json.dumps(cfg())); index.write_text('{"a-hidden":{"hidden":true},"z-never":{}}')
            start=len(requests)
            try:
                out=cli('list','--json')
                assert out.returncode==4 and out.stdout==b'',out
                assert out.stderr.endswith(f'Configuration error: invalid {home_env}.\n'.encode()),out.stderr
                try: list(home.iterdir()); raise AssertionError('OS unexpectedly permitted directory read')
                except PermissionError: pass
            finally: home.chmod(0o700)
            assert len(requests)==start+1
            assert (wallet.read_bytes(),stat.S_IMODE(wallet.stat().st_mode))==wallet_before
            observations.append(dict(name='post-rpc-index-selection-before-hidden-filter',exit=out.returncode,stdout='',stderr=out.stderr.decode(),requests=requests[start:],real_directory_denial=True,wallet_unchanged=True))
            action[0]=lambda: index.write_bytes(b'\xff')
            config.write_text(json.dumps(cfg()));index.write_text('{"a-first":{}}')
            check('post-rpc-index-decode-fallback',('a-first',),('a-first',),files=False)
            # A selected-path failure is fatal before any config/RPC, no fallback.
            action[0]=lambda:None; home.chmod(0)
            try:
                out=cli('list','--json'); assert out.returncode==4 and out.stdout==b''
                assert out.stderr.endswith(f'Configuration error: invalid {home_env}.\n'.encode()),out.stderr
            finally: home.chmod(0o700)
            observations.append(dict(name='initial-selected-root-denial',exit=out.returncode,stdout='',stderr=out.stderr.decode(),wallet_unchanged=True))
            assert (wallet.read_bytes(),stat.S_IMODE(wallet.stat().st_mode))==wallet_before
        return dict(binary=str(binary),sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),home_env=home_env,uid=os.geteuid(),observations=observations,loopback_only=True,services_stopped=True)
    finally:
        for server in servers: server.shutdown();server.server_close()
        for thread in threads: thread.join(timeout=3);assert not thread.is_alive()

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',required=True,type=Path);parser.add_argument('--home-env',choices=['BITBID_HOME','BSEC_HOME'],default='BITBID_HOME');parser.add_argument('--report',type=Path)
    args=parser.parse_args();result=run(args.binary.resolve(),args.home_env)
    if args.report:args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(f"PASS {len(result['observations'])} actual filesystem/lazy CLI cases; uid {result['uid']}; loopback servers stopped")
