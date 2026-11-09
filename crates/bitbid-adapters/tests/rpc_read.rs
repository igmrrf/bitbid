#![cfg(not(target_arch = "wasm32"))]
//! Public consumer over real loopback HTTP; no mocked reqwest implementation.
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use bitbid_adapters::rpc::BlockingRpc;
use bitbid_core::{Rpc, RpcError};
use serde_json::{Value, json};

struct Server {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<(String, Value)>>>,
    stop: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
}
impl Server {
    fn new(status: u16, body: &str, delay: Duration) -> Self {
        Self::with_accept_signal(status, body, delay, None)
    }
    fn with_accept_signal(
        status: u16,
        body: &str,
        delay: Duration,
        accepted: Option<mpsc::Sender<()>>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let (stop, stopped) = mpsc::channel();
        let response = format!(
            "HTTP/1.1 {status} Synthetic\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let thread = thread::spawn(move || {
            loop {
                if stopped.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Darwin inherits the listener's nonblocking mode on accept.
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(3)))
                            .unwrap();
                        if let Some(accepted) = &accepted {
                            accepted.send(()).unwrap();
                        }
                        let mut bytes = Vec::new();
                        let (header_end, length) = loop {
                            let mut chunk = [0; 2048];
                            let n = stream.read(&mut chunk).unwrap();
                            assert!(n > 0);
                            bytes.extend_from_slice(&chunk[..n]);
                            if let Some(start) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
                                let header_end = start + 4;
                                let header = String::from_utf8_lossy(&bytes[..start]);
                                let length: usize = header
                                    .lines()
                                    .find_map(|l| {
                                        l.to_lowercase()
                                            .strip_prefix("content-length: ")
                                            .map(str::parse)
                                    })
                                    .unwrap()
                                    .unwrap();
                                break (header_end, length);
                            }
                        };
                        while bytes.len() < header_end + length {
                            let mut chunk = [0; 2048];
                            let n = stream.read(&mut chunk).unwrap();
                            assert!(n > 0);
                            bytes.extend_from_slice(&chunk[..n]);
                        }
                        let header = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                        let body: Value =
                            serde_json::from_slice(&bytes[header_end..header_end + length])
                                .unwrap();
                        captured.lock().unwrap().push((header, body));
                        if stopped.recv_timeout(delay).is_ok() {
                            break;
                        }
                        // Timeout consumers may close the socket before the response.
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopped.recv_timeout(Duration::from_millis(2)).is_ok() {
                            break;
                        }
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
        });
        Self {
            address,
            requests,
            stop,
            thread: Some(thread),
        }
    }
    fn rpc(&self) -> BlockingRpc {
        BlockingRpc::new(format!("http://{}/", self.address))
    }
    fn assert_request(&self) {
        let requests = self.requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "exactly one attempt, no retries");
        let (header, body) = &requests[0];
        assert!(header.starts_with("POST / HTTP/1.1\r\n"));
        assert!(
            header
                .to_lowercase()
                .contains("content-type: application/json\r\n")
        );
        assert_eq!(
            *body,
            json!({"jsonrpc":"2.0", "id":1, "method":"eth_call", "params":[{"to":"0xabababababababababababababababababababab", "data":"0x6a70f2b76964000000000000000000000000000000000000000000000000000000000000"}, "latest"]})
        );
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        self.thread.take().unwrap().join().unwrap();
    }
}
fn call(rpc: &dyn Rpc) -> Result<Value, RpcError> {
    rpc.call("eth_call", json!([{"to":"0xabababababababababababababababababababab", "data":"0x6a70f2b76964000000000000000000000000000000000000000000000000000000000000"}, "latest"]))
}

#[test]
fn fixture_waits_for_request_bytes_after_accept() {
    let (accepted, signal) = mpsc::channel();
    let server = Server::with_accept_signal(
        200,
        r#"{"result":"0x1234"}"#,
        Duration::ZERO,
        Some(accepted),
    );
    let mut stream = TcpStream::connect(server.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    signal.recv_timeout(Duration::from_secs(3)).unwrap();
    // Deliberately withhold bytes after accept to exercise the fixture's read mode.
    thread::sleep(Duration::from_millis(80));
    let body = json!({"jsonrpc":"2.0", "id":1, "method":"eth_call", "params":[{"to":"0xabababababababababababababababababababab", "data":"0x6a70f2b76964000000000000000000000000000000000000000000000000000000000000"}, "latest"]}).to_string();
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        server.address,
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 Synthetic\r\n"));
    assert!(response.ends_with(r#"{"result":"0x1234"}"#));
    server.assert_request();
}

#[test]
fn public_rpc_consumer_preserves_envelope_result_and_http_status_semantics() {
    fn send_sync_static<T: Send + Sync + 'static>() {}
    send_sync_static::<BlockingRpc>();
    for (status, body, expected) in [
        (200, r#"{"result":"0x1234"}"#, json!("0x1234")),
        (503, r#"{"result":{"nested":7}}"#, json!({"nested":7})),
        (200, r#"{"result":null}"#, Value::Null),
        (200, r#"{}"#, Value::Null),
        (200, r#"[]"#, Value::Null),
    ] {
        let server = Server::new(status, body, Duration::ZERO);
        assert_eq!(call(&server.rpc()).unwrap(), expected);
        server.assert_request();
    }
}

#[test]
fn public_rpc_consumer_distinguishes_provider_decode_and_request_failures() {
    for body in [
        r#"{"error":null,"result":"ignored"}"#,
        r#"{"error":{"code":-1}}"#,
    ] {
        let server = Server::new(500, body, Duration::ZERO);
        assert!(matches!(call(&server.rpc()), Err(RpcError::Provider(_))));
        server.assert_request();
    }
    let server = Server::new(200, "{invalid JSON", Duration::ZERO);
    assert!(matches!(call(&server.rpc()), Err(RpcError::Decode(_))));
    server.assert_request();
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    assert!(matches!(
        call(&BlockingRpc::new(format!("http://{address}"))),
        Err(RpcError::Request(_))
    ));
    assert!(matches!(
        call(&BlockingRpc::new(":invalid-url".into())),
        Err(RpcError::Request(_))
    ));
}

#[test]
fn actual_request_times_out_after_twenty_seconds_without_retry() {
    let server = Server::new(200, r#"{"result":"late"}"#, Duration::from_secs(25));
    let start = Instant::now();
    assert!(matches!(call(&server.rpc()), Err(RpcError::Request(_))));
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(19) && elapsed < Duration::from_secs(24),
        "{elapsed:?}"
    );
    server.assert_request();
    // Drop interrupts the owned server's delay and joins the thread immediately.
}
