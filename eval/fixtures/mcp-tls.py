#!/usr/bin/env python3
# The Streamable-HTTP-shaped TLS fixture for the TLS-boundary cells.
# Spec: docs/spec.md#5-collectors, docs/spec.md#8-modes.
#
#   server mode: python3 mcp-tls.py server <port>  - one TLS JSON-RPC
#   exchange, answering initialize and tools/call on the wrapped
#   socket.
#   client mode: python3 mcp-tls.py client <port> <marker> - the
#   client writes one JSON-RPC line through the wrapped socket.
#
# Both modes ride the host's libssl (SSL_write/SSL_read are the
# uprobe's attach surface). The fixture trusts nothing: it pins the
# self-signed chain only for the lab.

import socket
import ssl
import sys


def server(port, marker):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/tmp/agentpcap-tls-cert.pem", "/tmp/agentpcap-tls-key.pem")
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    print(listener.getsockname()[1], flush=True)
    conn, _ = listener.accept()
    with ctx.wrap_socket(conn, server_side=True) as tls:
        line = tls.recv(4096).decode()
        if marker in line:
            tls.sendall(
                b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18",'
                b'"capabilities":{"tools":{}},"serverInfo":{"name":"tls-server","version":"0"}}}\n'
            )
        # drain one more line if the client sends two
        try:
            more = tls.recv(4096).decode()
        except OSError:
            more = ""
        if "tools/call" in more:
            tls.sendall(
                b'{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"tls-hello"}]}}\n'
            )
            # the writer's fds stay resolvable for the pop window
            import time
            time.sleep(0.4)


def client(port, marker):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port))
    with ctx.wrap_socket(raw) as tls:
        tls.sendall(
            f'{{"jsonrpc":"2.0","id":1,"method":"initialize","params":"{marker}"}}\n'.encode()
        )
        tls.recv(4096)
        tls.sendall(b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch"}}\n')
        tls.recv(4096)
        # the fds stay resolvable for the tap's pop window
        import time
        time.sleep(0.4)


if __name__ == "__main__":
    role = sys.argv[1]
    port = int(sys.argv[2])
    if role == "server":
        server(port, sys.argv[3])
    else:
        client(port, sys.argv[3])
