#!/usr/bin/env python3
"""Audited synthetic CLI consumer; no chain, IPFS, credentials, or persistent service.
Run with an explicit --binary PATH. --baseline-mode records the old unchecked ABI
panic; every ordinary skip/output/file assertion is identical for both versions.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading

SENDER = '0x52908400098527886E0F7030069857D2E4169EE7'
RECIPIENT = '0xde709f2102306220921060314715629080e2fb77'
REGISTRY = '0xabababababababababababababababababababab'
MNEMONIC = 'test test test test test test test test test test test junk'


def abi(sender=SENDER, recipient=RECIPIENT, public=False, expired=False,
        revoked=False, limited=False):
    words = [int(sender, 16), int(recipient, 16), 352, 7, 3, 9, 2,
             int(revoked), int(public), int(expired), int(limited), 12]
    return '0x' + ''.join(f'{x:064x}' for x in words) + b'QmTestCid123'.hex().ljust(64, '0')


def mutate(data, word, number):
    start = 2 + word * 64
    return data[:start] + f'{number:064x}' + data[start + 64:]


def record(identifier, public=False, sender=SENDER):
    return dict(id=identifier, sender=sender, recipient='public' if public else RECIPIENT,
                content='[Encrypted Payload on IPFS]', content_key='[Encrypted Key]',
                ephemeral_pubkey=None, created_at=7, expires_at=3, max_reads=9,
                read_count=2, hidden=False)


def run(binary, baseline_mode=False):
    observations = []
    requests = []
    faults = []
    replies = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            requests.append(request)
            try:
                assert self.path == '/'
                assert self.headers['Content-Type'] == 'application/json'
                data = request['params'][0]['data']
                assert request == dict(jsonrpc='2.0', id=1, method='eth_call', params=[
                    dict(to=REGISTRY, data=data), 'latest'])
                assert data.startswith('0x6a70f2b7') and len(data) == 74
                identifier = bytes.fromhex(data[10:]).rstrip(b'\x00').decode()
                status, response = replies[identifier]
                if status == 0:  # disconnect the accepted request, without a response
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                payload = response if isinstance(response, bytes) else json.dumps(response).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as exc:
                faults.append(repr(exc))
                self.send_error(500)

    class Service(http.server.HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(3)  # bound shutdown even after an incomplete request
            return connection, address

    server = Service(('127.0.0.1', 0), Handler)
    server.timeout = 0.1
    thread = threading.Thread(name='bsec-registry-probe-http', target=server.serve_forever, kwargs={'poll_interval': 0.01})
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}'
    try:
        with tempfile.TemporaryDirectory(prefix='bsec-registry-probe-') as directory:
            root = Path(directory)
            home = root / 'home'
            env = os.environ.copy()
            env.update(BSEC_HOME=str(home), BSEC_E2E='0')
            mnemonic = root / 'public-synthetic-mnemonic.txt'
            mnemonic.write_text(MNEMONIC)

            def cli(*args):
                return subprocess.run([str(binary), *args], cwd=root, env=env,
                                      stdin=subprocess.DEVNULL, capture_output=True, timeout=30)

            initialized = cli('init', '--no-encryption', '--import-mnemonic', str(mnemonic))
            assert initialized.returncode == 0, initialized.stderr
            wallet = home / 'wallet.json'
            wallet_bytes = wallet.read_bytes()
            wallet_json = json.loads(wallet_bytes)
            assert wallet_json['encrypted'] is False and 'last_accessed' in wallet_json
            # Freeze key bytes and deliberately old timestamps, making rewrites observable.
            wallet_json['last_accessed'] = 123
            wallet_json['data'] = json.dumps(dict(json.loads(wallet_json['data']), last_accessed=124))
            wallet.write_text(json.dumps(wallet_json))
            wallet_bytes = wallet.read_bytes()
            me = json.loads(wallet_json['data'])['address']
            config = dict(network='synthetic', chain_id=31337, rpc_url=url,
                          registry_address=REGISTRY, ipfs=dict(gateway='http://127.0.0.1:1/',
                          pinning_service=None, api_url='http://127.0.0.1:1', pinning_jwt=None))
            config_path = home / 'network-config.json'
            index_path = home / 'secret_index.json'
            config_path.write_text(json.dumps(config))

            def check(name, entries, flags=('--json', '--all'), expected=None, panic=False,
                      raw_index=None, request_ids=None, wallet_failure=False):
                if raw_index is None:
                    index_path.write_text(json.dumps(entries))
                elif raw_index == 'ABSENT':
                    index_path.unlink(missing_ok=True)
                else:
                    index_path.write_text(raw_index)
                before = {p.name: p.read_bytes() for p in home.iterdir() if p.is_file()}
                start = len(requests)
                out = cli('list', *flags)
                sent = requests[start:]
                assert not faults, faults
                if request_ids is None:
                    request_ids = sorted(entries)[:1] if panic and baseline_mode else sorted(entries)
                assert [bytes.fromhex(r['params'][0]['data'][10:]).rstrip(b'\0').decode()
                        for r in sent] == request_ids, (name, sent)
                after = {p.name: p.read_bytes() for p in home.iterdir() if p.is_file()}
                assert before == after, (name, 'list changed files')
                if wallet.exists():
                    assert wallet.read_bytes() == before['wallet.json']
                if wallet_failure:
                    assert out.returncode == 1 and out.stdout == b''
                    assert out.stderr.startswith(b'Error loading wallet:'), out.stderr
                elif panic and baseline_mode:
                    assert out.returncode != 0 and out.stdout == b'', (name, out)
                else:
                    assert out.returncode == 0, (name, out.stderr)
                    if '--json' in flags:
                        assert out.stdout == (json.dumps(expected, indent=2, ensure_ascii=False) + '\n').encode(), (name, out.stdout, expected)
                    else:
                        assert out.stdout == expected.encode(), (name, out.stdout, expected)
                observations.append(dict(name=name, exit=out.returncode,
                    stdout=out.stdout.decode(errors='replace'), requests=sent,
                    files_unchanged=True, wallet_unchanged=True))

            # Multi-record fixture deliberately inserted out of BTreeMap order.
            entries = {x: dict(hidden=x == 'c-hidden', role='synthetic') for x in
                       ['g-revoked', 'b-private', 'a-public', 'e-expired', 'c-hidden', 'f-limit', 'd-mine']}
            replies.update({x: (200, dict(result=abi(public=x != 'b-private',
                sender=me if x == 'd-mine' else SENDER, expired=x == 'e-expired',
                limited=x == 'f-limit', revoked=x == 'g-revoked'))) for x in entries})
            expected = [record(x, public=x != 'b-private', sender=me if x == 'd-mine' else SENDER)
                        for x in sorted(entries)]
            check('valid-json-all', entries, expected=expected)
            text = 'Secrets:\n-------------------\n' + ''.join(
                f"ID: {r['id']}\nSender: {r['sender']}\nRecipient: {r['recipient']}\nCreated: 7\nExpires: 3\nReads: 2/9\n-------------------\n" for r in expected)
            check('valid-text-all', entries, flags=('--all',), expected=text)
            check('default-hidden-and-ownership', entries, flags=('--json',), expected=[r for r in expected if r['id'] not in ['b-private', 'c-hidden']])
            check('all-users-alias', entries, flags=('--json', '--all-users'), expected=expected)
            check('expired-chain-flags', entries, flags=('--json', '--all', '--expired'), expected=expected[4:])
            check('active-chain-flags', entries, flags=('--json', '--all', '--active'), expected=expected[:4])
            check('both-filters', entries, flags=('--json', '--all', '--active', '--expired'), expected=[])
            check('user-case-insensitive', entries, flags=('--json', '--all', '--user', SENDER.lower()), expected=[r for r in expected if r['id'] != 'd-mine'])
            check('private-recipient-user', entries, flags=('--json', '--user', RECIPIENT.upper()), expected=[expected[1]])
            aliases = {'a-public': {}, '0x612d7075626c6963': {}, '0X612d7075626c6963': {}}
            check('original-index-id-aliases', aliases,
                  expected=[record(x, True) for x in sorted(aliases)],
                  request_ids=['a-public'] * 3)
            good = dict(result=abi(public=True))
            malformed = {
                'malformed-json': b'{no', 'provider': {'error': {'code': -1, 'message': 'synthetic'}},
                'provider-null': {'error': None, 'result': abi()}, 'null': {'result': None},
                'missing': {}, 'non-string': {'result': 7}, 'empty': {'result': ''},
                'empty-hex': {'result': '0x'}, 'short': {'result': '0x00'},
                'invalid-hex': {'result': '0xzz'}, 'odd-hex': {'result': '0x1'},
                'invalid-utf8': {'result': abi()[:770] + 'ff' + abi()[772:]},
                'offset-range': {'result': mutate(abi(), 2, 9999)},
                'offset-overflow': {'result': mutate(abi(), 2, 2**64-1)},
                'length-overflow': {'result': mutate(abi(), 11, 2**64-1)},
            }
            for name, bad in malformed.items():
                panic = name in ('offset-overflow', 'length-overflow')
                replies['a-bad'] = (200, bad)
                replies['z-good'] = (200, good)
                check(name + '-mixed', {'z-good': {}, 'a-bad': {}}, expected=[record('z-good', True)], panic=panic)
                check(name + '-all-failed', {'a-bad': {}}, expected=[], panic=panic)
            replies['a-bad'] = (0, None)
            check('disconnect-mixed', {'a-bad': {}, 'z-good': {}}, expected=[record('z-good', True)])
            check('disconnect-all-failed', {'a-bad': {}}, expected=[])
            replies['a-bad'] = (503, good)
            check('http-status-not-rejected', {'a-bad': {}}, expected=[record('a-bad', True)])
            check('absent-index', {}, expected=[], raw_index='ABSENT')
            check('malformed-index', {}, expected=[], raw_index='{no')
            check('empty-text', {}, flags=(), expected='No matching secrets found.\n')
            bad_ids = {'x' * 33: {}, '0xzz': {}, '0x1': {}, 'z-good': {}}
            check('invalid-ids', bad_ids, expected=[record('z-good', True)], request_ids=['z-good'])
            config_path.unlink()
            check('absent-config-no-rewrite', {'0xzz': {}}, expected=[], request_ids=[])
            config_path.write_text('{malformed-config')
            check('malformed-config-no-rewrite', {'0xzz': {}}, expected=[], request_ids=[])
            config_path.write_text(json.dumps(dict(config, registry_address='invalid')))
            check('invalid-registry', {'a-bad': {}}, expected=[], request_ids=[])
            # Connection refusal uses an ephemeral port reserved and closed by this probe.
            with socket.socket() as refused:
                refused.bind(('127.0.0.1', 0))
                refused_port = refused.getsockname()[1]
            config_path.write_text(json.dumps(dict(config, rpc_url=f'http://127.0.0.1:{refused_port}')))
            check('connection-refused', {'a-bad': {}}, expected=[], request_ids=[])
            config_path.write_text(json.dumps(config))
            wallet.write_bytes(b'{broken-wallet')
            check('malformed-wallet', {'a-bad': {}}, wallet_failure=True, request_ids=[])
            wallet.write_bytes(wallet_bytes)
            wallet.unlink()
            check('missing-wallet-existing-home', {'a-bad': {}}, wallet_failure=True, request_ids=[])
            fresh = root / 'missing-home'
            env['BSEC_HOME'] = str(fresh)
            start = len(requests)
            out = cli('list', '--json', '--all')
            assert out.returncode == 1 and not out.stdout and out.stderr.startswith(b'Error loading wallet:')
            assert fresh.is_dir() and not list(fresh.iterdir()) and len(requests) == start
            observations.append(dict(name='missing-home-created', exit=1, stdout='', requests=[], directory_created=True))
            return dict(binary=str(binary), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                        baseline_mode=baseline_mode, probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        service=dict(address=url, pid=os.getpid(), thread=thread.name, ready=True, stopped=True,
                        thread_joined=True, methods=['eth_call']), observations=observations)
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
        assert not thread.is_alive(), 'owned server leaked'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--baseline-mode', action='store_true')
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args()
    result = run(args.binary.resolve(), args.baseline_mode)
    if args.compare:
        before = json.loads(args.compare.read_text())['observations']
        after = result['observations']
        assert len(before) == len(after)
        for left, right in zip(before, after):
            assert left['name'] == right['name']
            if left['name'].startswith(('offset-overflow-', 'length-overflow-')):
                assert right['exit'] == 0  # accepted typed no-panic improvement
            else:
                assert left == right, (left, right)
        result['baseline_comparison'] = 'ordinary outputs, exits, requests, and file effects identical'
    if args.report:
        args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(f"PASS {len(result['observations'])} CLI cases; binary sha256 {result['binary_sha256']}; owned server stopped/joined")


if __name__ == '__main__':
    main()
