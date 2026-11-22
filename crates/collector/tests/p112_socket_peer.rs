// P112 — the five-tuple face: a socket write's fd resolves through
// `/proc` to the connection's socket inode, the inode names the
// connection in `/proc/net/tcp`, and the peer is the canonical sorted
// endpoint pair identical for both directions of one connection
// (ADR-0005). Spec: docs/spec.md#5-collectors.

use agentpcap_collector::resolve_socket_peer;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

#[test]
fn p112_the_socket_fd_resolves_to_the_canonical_pair() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the listener binds");
    let addr = listener.local_addr().expect("the local addr");
    let server = std::thread::spawn(move || {
        let (mut s, _who) = listener.accept().expect("the accept");
        let mut buf = [0u8; 512];
        s.read(&mut buf).unwrap_or(0);
        let _ = s.write_all(b"ok");
    });
    let mut client = TcpStream::connect(addr).expect("the client connects");
    let local = client.local_addr().expect("the client's local face");
    client.write_all(b"ping").expect("the client sends");

    // the client's own fd resolves: its peer pair matches the server face
    // (the namespace face rides the key: `net-<inode>.tcp:...`)
    let client_pid = std::process::id();
    let mut peers = Vec::new();
    // walk the test's own fds: the connected socket lives on some fd
    for fd in 3..64 {
        if let Some(p) = resolve_socket_peer(client_pid, fd).map(|fp| fp.peer) {
            peers.push(p);
        }
    }
    // the listener face carries a 0.0.0.0 remote; the CONNECTED socket
    // carries both endpoints
    let peer = peers
        .iter()
        .find(|p| !p.contains("tcp:0.0.0.0:0"))
        .expect("the client's connected socket resolves to a five-tuple")
        .clone();
    eprintln!("p112 receipt: client local={local} all-peers={peers:?} peer={peer}");
    // the canonical pair sorts the endpoints: both faces of the
    // connection carry one peer string
    let contains_local = peer.contains(&format!("tcp:{}", local));
    let contains_remote = peer.contains(&format!("tcp:{}", addr));
    assert!(
        contains_local && contains_remote,
        "the pair carries both endpoints: {peer}"
    );
    let parts: Vec<&str> = peer.split('=').collect();
    assert_eq!(parts.len(), 2, "the pair face joins the sorted endpoints: {peer}");
    assert!(parts[0] <= parts[1], "the endpoints sort canonically: {peer}");
    // the same connection from the server's direction keys the same
    // pair: the reassembler's socket session keys by this face
}
