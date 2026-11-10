#!/usr/bin/env python3
"""Canonical-only CLI regression: isolated files, real uid, loopback HTTP/TLS traps.

Pass a release/installed --binary and the native unit --test-binary for exact
Pinata header transport coverage with test-only certificate trust injection.
No system trust store, user home, remote endpoint or real credential is used.
"""
import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import socketserver
import ssl
import stat
import subprocess
import tempfile
import threading

MNEMONIC = 'test test test test test test test test test test test junk'
REGISTRY = '0xabababababababababababababababababababab'


def snapshot(path):
    paths = [path, *path.rglob('*')] if path.is_dir() else [path]
    result = {}
    for item in paths:
        info = item.lstat()
        entry = dict(mode=stat.S_IMODE(info.st_mode), mtime_ns=info.st_mtime_ns,
                     kind=stat.S_IFMT(info.st_mode))
        if item.is_symlink(): entry['target'] = os.readlink(item)
        elif item.is_file(): entry['sha256'] = hashlib.sha256(item.read_bytes()).hexdigest()
        result[str(item.relative_to(path.parent))] = entry
    return result


def run(binary, test_binary, fixture_parent):
    assert os.geteuid() != 0, 'permission assertions require actual nonprivileged uid'
    observations, requests = [], []
    context = [None]

    class Trap(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args): pass
        def do_CONNECT(self):
            requests.append(dict(case=context[0], method='CONNECT', path=self.path,
                                 authorization=self.headers.get('Authorization')))
            self.send_error(502, 'synthetic proxy refuses all remote connections')
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            requests.append(dict(case=context[0], method='POST', path=self.path,
                                 authorization=self.headers.get('Authorization'), bytes=len(body)))
            self.send_error(503, 'synthetic Kubo fails before any chain write')

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Trap)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01})
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}'
    try:
        with tempfile.TemporaryDirectory(prefix='alias-fixtures-', dir=fixture_parent) as name:
            base = Path(name)
            env_base = dict(PATH='/usr/bin:/bin', BITBID_E2E='0', HOME=str(base),
                            HTTP_PROXY=url, HTTPS_PROXY=url, ALL_PROXY=url,
                            NO_PROXY='127.0.0.1,localhost', RUST_BACKTRACE='0')

            def cli(case, root, args, settings=None, expected=None):
                context[0] = case
                env = dict(env_base, HOME=str(root))
                env.update(settings or {})
                start = len(requests)
                command = [str(binary), *args]
                out = subprocess.run(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                     capture_output=True, timeout=20)
                observations.append(dict(case=case, command=command, settings={k: os.fsdecode(v) for k,v in (settings or {}).items()},
                                         status=out.returncode, stdout=out.stdout.decode(errors='replace'),
                                         stderr=out.stderr.decode(errors='replace'), stdout_hex=out.stdout.hex(), stderr_hex=out.stderr.hex(),
                                         requests=requests[start:]))
                if expected is not None: assert out.returncode == expected, observations[-1]
                assert b'deprecated' not in out.stderr, observations[-1]
                assert b'JWT-SENTINEL' not in out.stdout + out.stderr, observations[-1]
                return out, requests[start:]

            def root(label):
                path = base/label; path.mkdir(); return path

            def init(path, home):
                mnemonic = path/'public-mnemonic'; mnemonic.write_text(MNEMONIC)
                out, sent = cli('init-'+path.name, path,
                                ['init','--no-encryption','--import-mnemonic',str(mnemonic)],
                                dict(BITBID_HOME=str(home)), 0)
                assert not sent

            # Old env/default data must never become a wallet, config or cache source.
            for mode in ['legacy-env', 'legacy-default', 'both']:
                path = root(mode); old = path/('.bsec' if mode=='legacy-default' else 'old-root')
                init(path, old)
                (old/'secret_index.json').write_text('{"legacy-only-id":"old"}')
                (old/'ipfs_cache').mkdir(); (old/'ipfs_cache'/'retained').write_bytes(b'old cache')
                (old/'network-config.json').write_text(json.dumps(dict(network='legacy-sentinel',chain_id=31337,
                    rpc_url=url,registry_address=REGISTRY,ipfs=dict(api_url=url,gateway=url,pinning_jwt='LEGACY-JWT-SENTINEL'))))
                old.chmod(0o750); (old/'wallet.json').chmod(0o640)
                before = snapshot(old)
                settings = dict(BSEC_HOME=str(old)) if mode!='legacy-default' else {}
                canonical = path/'canonical-root'
                if mode == 'both':
                    init(path, canonical); settings['BITBID_HOME'] = str(canonical)
                out, sent = cli(mode+'-wallet', path, ['wallet','info','--json'], settings,
                                0 if mode=='both' else 1)
                assert not sent
                if mode != 'both': assert not out.stdout
                out, sent = cli(mode+'-config', path, ['config','--show','--json'], settings, 0)
                assert not sent and b'legacy-sentinel' not in out.stdout
                assert snapshot(old) == before, (mode, 'legacy data/mode/mtime changed')
                observations.append(dict(case=mode+'-legacy-preservation', before=before, after=snapshot(old)))

            path=root('legacy-missing-and-lazy'); retired=path/'retired-missing'
            for args in [['--version'],['--help'],['completion','bash']]:
                cli('lazy-'+args[0],path,args,dict(BITBID_HOME='',BSEC_HOME=str(retired)),0)
                assert not (path/'.bitbid').exists() and not retired.exists()
            out,sent=cli('legacy-missing',path,['wallet','info','--json'],dict(BSEC_HOME=str(retired)),1)
            assert not sent and not retired.exists() and (path/'.bitbid').is_dir()

            # Existing malformed nonce protection remains true for release/installed builds.
            vector_path=Path(__file__).resolve().parents[3]/'bitbid-core/tests/vectors/wallet-codec-v1.json'
            vector=json.loads(vector_path.read_text()); salt,_,cipher=vector['encrypted'].split(':')
            path=root('malformed-wallet'); home=path/'home'; home.mkdir()
            retired=path/'retired'; init(path,retired); retired_before=snapshot(retired)
            for length in [0,1,11,13,24]:
                wallet=home/'wallet.json'
                wallet.write_text(json.dumps(dict(encrypted=True,data=salt+':'+base64.b64encode(bytes(length)).decode()+':'+cipher,last_accessed=1234567891)))
                wallet.chmod(0o640); before=snapshot(wallet)
                out,sent=cli('malformed-nonce-'+str(length),path,['wallet','info','--password',vector['password'],'--json'],dict(BITBID_HOME=str(home),BSEC_HOME=str(retired)),1)
                assert not sent and not out.stdout
                assert out.stderr==b'Warning: Passing passwords via CLI flags may expose credentials in process lists.\nError getting wallet info: Invalid wallet nonce length\n'
                assert snapshot(wallet)==before and snapshot(retired)==retired_before

            # CLI home presence/invalid handling; legacy remains untouched on each failure.
            path = root('invalid-home'); old = path/'old'; init(path, old); before = snapshot(old)
            for kind in ['blank', 'space', 'nonunicode', 'file', 'dangling', 'denied']:
                target = path/kind
                if kind == 'file': target.write_text('unchanged')
                elif kind == 'dangling': target.symlink_to('missing')
                elif kind == 'denied': target.mkdir(); target.chmod(0)
                value = {'blank':'', 'space':' \t ', 'nonunicode':b'\xff\xfe'}.get(kind,str(target))
                for args in [['wallet','info','--json'], ['config','--show','--json'], ['list','--json']]:
                    out,sent=cli('invalid-home-'+kind+'-'+args[0],path,args,
                                 dict(BITBID_HOME=value,BSEC_HOME=str(old)),4)
                    assert out.stdout == b'' and not sent
                    assert out.stderr.endswith(b'Configuration error: invalid BITBID_HOME.\n')
                if kind=='denied': target.chmod(0o700)
                assert snapshot(old)==before

            # Valid canonical symlink still works; default dangling canonical fails closed.
            path=root('home-symlink'); actual=path/'actual'; init(path,actual)
            link=path/'link'; link.symlink_to(actual,target_is_directory=True)
            cli('valid-home-symlink',path,['wallet','info','--json'],dict(BITBID_HOME=str(link)),0)
            (path/'.bitbid').symlink_to('missing'); (path/'.bsec').symlink_to(actual,target_is_directory=True)
            out,sent=cli('dangling-default',path,['wallet','info','--json'],{},4)
            assert not out.stdout and not sent

            # Project negative/control/canonical failure cases; run stays lazy about wallets.
            for kind in ['old-only','both','malformed','dangling','denied','valid-link']:
                path=root('project-'+kind); retired=path/'.bsec.json'
                retired.write_text('{"env_file":"retired.env"}'); retired.chmod(0o640)
                (path/'retired.env').write_text('ALIAS_PROBE=old\n')
                (path/'.env').write_text('ALIAS_PROBE=default\n')
                (path/'canonical.env').write_text('ALIAS_PROBE=canonical\n')
                canonical=path/'.bitbid.json'
                if kind=='malformed': canonical.write_text('malformed')
                elif kind=='dangling': canonical.symlink_to('missing')
                elif kind=='valid-link':
                    (path/'target.json').write_text('{"env_file":"canonical.env"}'); canonical.symlink_to('target.json')
                elif kind!='old-only': canonical.write_text('{"env_file":"canonical.env"}')
                if kind=='denied': canonical.chmod(0)
                before=snapshot(retired)
                failure=kind in ['malformed','dangling','denied']
                out,sent=cli('project-'+kind,path,['run','--','/bin/sh','-c','printf %s "$ALIAS_PROBE"'],{},4 if failure else 0)
                assert not sent and snapshot(retired)==before
                assert out.stdout == (b'' if failure else b'default' if kind=='old-only' else b'canonical'), observations[-1]
                assert not (path/'.bitbid').exists(), 'project run unexpectedly touched wallet root'
                if kind=='denied': canonical.chmod(0o600)

            # Actual release CLI IPFS calls: all nonlocal routes trapped at proxy;
            # Kubo sees no Authorization, retired JWT never even starts Pinata.
            cases=[('old-only',None,'OLD-JWT-SENTINEL',None,False,False),
                   ('canonical','NEW-JWT-SENTINEL',None,None,True,False),
                   ('both','NEW-JWT-SENTINEL','OLD-JWT-SENTINEL',None,True,False),
                   ('blank','','OLD-JWT-SENTINEL',None,False,False),
                   ('config-priority','BAD\nJWT-SENTINEL','OLD-JWT-SENTINEL','CONFIG-JWT-SENTINEL',True,False),
                   ('invalid','BAD\nJWT-SENTINEL','OLD-JWT-SENTINEL',None,False,True),
                   ('nonunicode',b'\xff\xfe','OLD-JWT-SENTINEL',None,False,True)]
            for label,new,old,config,pinata,invalid in cases:
                path=root('jwt-'+label); home=path/'home'; init(path,home)
                (home/'network-config.json').write_text(json.dumps(dict(network='synthetic',chain_id=31337,
                    rpc_url=url,registry_address=REGISTRY,ipfs=dict(api_url=url,gateway=url,pinning_jwt=config))))
                settings=dict(BITBID_HOME=str(home))
                if new is not None: settings['BITBID_PINATA_JWT']=new
                if old is not None: settings['BSEC_PINATA_JWT']=old
                out,sent=cli('jwt-'+label,path,['share','--content','synthetic public fixture','--to','public','--password',''],settings,4)
                assert all(r['authorization'] is None for r in sent)
                assert [r['path'] for r in sent if r['method']=='CONNECT']==(['api.pinata.cloud:443'] if pinata else []),(label,sent)
                assert [r['path'] for r in sent if r['method']=='POST']==([] if invalid else ['/api/v0/add']),(label,sent)
                assert not (home/'secret_index.json').exists()

            if test_binary:
                tls_headers(binary,test_binary,base,observations)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)
    return dict(binary=str(binary),sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),uid=os.geteuid(),
                observations=observations,requests=requests,passed=True)


def tls_headers(binary,test_binary,base,observations):
    """Exact production Pinata request builder over trusted fixture TLS, test-only."""
    cert=base/'fixture-ca.crt'; ca_key=base/'fixture-ca.key'
    leaf=base/'fixture-server.crt'; key=base/'fixture-server.key'; csr=base/'fixture.csr'; config=base/'openssl.cnf'
    config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Bitbid synthetic fixture CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n[server]\nsubjectAltName=DNS:api.pinata.cloud\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    commands=[['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(ca_key),'-out',str(cert),'-config',str(config)],
              ['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(csr),'-subj','/CN=api.pinata.cloud'],
              ['openssl','x509','-req','-in',str(csr),'-CA',str(cert),'-CAkey',str(ca_key),'-CAcreateserial','-out',str(leaf),'-days','1','-extfile',str(config),'-extensions','server']]
    for command in commands: subprocess.run(command,check=True,capture_output=True)
    key.chmod(0o600); ca_key.chmod(0o600)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(leaf,key)
    received=[]; faults=[]
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                self.connection.settimeout(4)
                first=self.rfile.readline(); assert first==b'CONNECT api.pinata.cloud:443 HTTP/1.1\r\n', first
                while self.rfile.readline()!=b'\r\n': pass
                self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n'); self.wfile.flush()
                with tls.wrap_socket(self.connection,server_side=True) as connection:
                    data=b''
                    while b'\r\n\r\n' not in data: data+=connection.recv(4096)
                    header=data.split(b'\r\n\r\n')[0].decode()
                    auth=[line.split(': ',1)[1] for line in header.split('\r\n') if line.lower().startswith('authorization: ')]
                    received.append(dict(request=header.split('\r\n')[0],authorization=auth))
                    body=b'{"IpfsHash":"QmSyntheticFixture123"}'
                    connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
            except Exception as exc: faults.append(repr(exc))
    server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01});thread.start()
    try:
        cases=[('retired',None,'OLD-JWT-SENTINEL',None,None),('new','NEW-JWT-SENTINEL',None,None,'NEW-JWT-SENTINEL'),
               ('both','NEW-JWT-SENTINEL','OLD-JWT-SENTINEL',None,'NEW-JWT-SENTINEL'),
               ('config','BAD\nJWT-SENTINEL','OLD-JWT-SENTINEL','CONFIG-JWT-SENTINEL','CONFIG-JWT-SENTINEL'),
               ('blank','','OLD-JWT-SENTINEL',None,None),('invalid','BAD\nJWT-SENTINEL','OLD-JWT-SENTINEL',None,'INVALID'),
               ('nonunicode',b'\xff\xfe','OLD-JWT-SENTINEL',None,'INVALID')]
        for label,new,old,config,expected in cases:
            env=dict(PATH='/usr/bin:/bin',HOME=str(base),N4_FIXTURE='pinata-transport',N4_CA=str(cert),N4_PROXY=f'http://127.0.0.1:{server.server_address[1]}',
                     N4_EXPECT='Configuration error: invalid Pinata credential.' if expected=='INVALID' else 'DISABLED' if expected is None else 'QmSyntheticFixture123')
            if new is not None: env['BITBID_PINATA_JWT']=new
            if old is not None: env['BSEC_PINATA_JWT']=old
            if config is not None: env['N4_CONFIG']=config
            before=len(received)
            out=subprocess.run([str(test_binary),'compatibility_tests::fixture','--exact','--ignored','--nocapture','--test-threads=1'],cwd=base,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
            assert out.returncode==0,(label,out.stdout,out.stderr,faults)
            observed=received[before:]
            assert not faults, faults
            assert observed==([] if expected in [None,'INVALID'] else [dict(request='POST /pinning/pinFileToIPFS HTTP/1.1',authorization=['Bearer '+expected])]),(label,observed)
            observations.append(dict(case='tls-header-'+label,source='test-only trust/proxy injection; exact production request builder',status=out.returncode,stdout=out.stdout.decode(),stderr=out.stderr.decode(),observed=observed))
    finally:
        server.shutdown();server.server_close();thread.join(timeout=3)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--test-binary',type=Path)
    parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args()
    report=run(args.binary.resolve(),args.test_binary.resolve() if args.test_binary else None,args.report.parent)
    args.report.write_text(json.dumps(report,indent=2))
    print(f"alias removal: {len(report['observations'])} observations passed; uid {report['uid']}; {report['sha256']}")
