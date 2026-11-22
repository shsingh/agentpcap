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

import os
import socket
import ssl
import sys

CERT = os.environ.get("AGENTPCAP_TLS_CERT", "/tmp/agentpcap-tls-cert.pem")
KEY = os.environ.get("AGENTPCAP_TLS_KEY", "/tmp/agentpcap-tls-key.pem")


def server(port, marker, http=False, sse=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    print(listener.getsockname()[1], flush=True)
    conn, _ = listener.accept()
    with ctx.wrap_socket(conn, server_side=True) as tls:
        line = tls.recv(4096).decode()
        if http:
            if sse:
                # the SSE reply face: the tool result answers the gated
                # POST as a text/event-stream body, the JSON rides one
                # `data:` line
                data = (
                    b'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text",'
                    b'"text":"tls-' + marker.encode() + b'"}]}}\n\n'
                )
                tls.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: "
                    + str(len(data)).encode()
                    + b"\r\n\r\n" + data
                )
                import time
                time.sleep(0.4)
                return
            # the response frames too: the admission face names the
            # status-line prefix, the body stays the JSON-RPC result
            # the reply rides chunked transfer: the size lines split
            # the JSON, the boundary's decode face concatenates
            body = b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text",'
            tail = f'"text":"tls-{marker}"}}}}'.encode()
            tls.sendall(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                + b"%x\r\n" % len(body) + body + b"\r\n"
                + b"%x\r\n" % len(tail) + tail + b"\r\n"
                + b"0\r\n\r\n"
            )
            more = tls.recv(4096).decode()
            if "tools/call" in more:
                body2 = f'{{"jsonrpc":"2.0","id":2,"result":{{"content":[{{"type":"text","text":"tls-{marker}"}}]}}}}'.encode()
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body2)).encode() + b"\r\n\r\n" + body2)
                import time
                time.sleep(0.4)
            return
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
                f'{{"jsonrpc":"2.0","id":2,"result":{{"content":[{{"type":"text","text":"tls-{marker}"}}]}}}}\n'.encode()
            )
            # the writer's fds stay resolvable for the pop window
            import time
            time.sleep(0.4)


def client(port, marker, http=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port))
    with ctx.wrap_socket(raw) as tls:
        if http:
            # the real HTTPS face: headers and the JSON body ride ONE
            # SSL_write buffer — the tool call must survive the framing
            body = f'{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"fetch","marker":"{marker}"}}}}'
            # a header whose VALUE carries JSON braces: the boundary's
            # header-block bound keeps the parse on the body's braces
            frame = f"POST /mcp HTTP/1.1\r\nHost: localhost\r\nX-Trace-Note: {{\"shaped\":true}}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
            tls.sendall(frame.encode())
            tls.recv(4096)
            import time
            time.sleep(0.4)
            return
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
    marker = sys.argv[3]
    http = len(sys.argv) > 4 and sys.argv[4] in ("http", "sse")
    sse = len(sys.argv) > 4 and sys.argv[4] == "sse"
    if role == "server":
        server(port, marker, http, sse)
    else:
        client(port, marker, http)
