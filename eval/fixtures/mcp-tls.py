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

import json
import os
import queue
import socket
import ssl
import sys
import threading

CERT = os.environ.get("AGENTPCAP_TLS_CERT", "/tmp/agentpcap-tls-cert.pem")
KEY = os.environ.get("AGENTPCAP_TLS_KEY", "/tmp/agentpcap-tls-key.pem")


def _sse_stream(listener, ctx, reply_q, marker):
    """The legacy SSE stream connection: a GET face that delivers the
    `text/event-stream` reply on a SEPARATE SSL connection."""
    stream_conn, _ = listener.accept()
    with ctx.wrap_socket(stream_conn, server_side=True) as tls:
        try:
            tls.recv(4096)  # the GET /sse request line
            first = reply_q.get(timeout=15)
            frame = (
                b'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text",'
                b'"text":"tls-' + marker.encode() + b'"}]}}\n\n'
            )
            tls.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n" + frame
            )
            import time
            time.sleep(0.5)
        except Exception as e:
            print("sse stream face:", e, file=sys.stderr)


def server(port, marker, http=False, sse=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    if sse:
        # the legacy HTTP+SSE contract: the request POSTs on connection
        # one and the replies deliver on a SEPARATE long-lived GET
        # stream (the /sse endpoint). Two TLS connections ride the tap's
        # boundary; the reply rides the GET stream's SSL_write only.
        listener.listen(2)
        print(listener.getsockname()[1], flush=True)
        reply_q: "queue.Queue[bytes]" = queue.Queue()
        conn, _ = listener.accept()
        stream = threading.Thread(target=_sse_stream, args=(listener, ctx, reply_q, marker), daemon=True)
        stream.start()
        with ctx.wrap_socket(conn, server_side=True) as tls:
            line = tls.recv(4096).decode()
            if "tools/call" in line:
                reply_q.put(json.dumps({"id": 1}).encode())
                import time
                time.sleep(0.6)
        return
    listener.listen(1)
    print(listener.getsockname()[1], flush=True)
    conn, _ = listener.accept()
    with ctx.wrap_socket(conn, server_side=True) as tls:
        line = tls.recv(4096).decode()
        if http:
            # the response frames too: the admission face names the
            # status-line prefix, the body stays the JSON-RPC result
            # the reply rides chunked transfer: the size lines split
            # the JSON, the boundary's decode face concatenates
            body = b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","'
            tail = ('"text":"tls-' + marker + '"}]}}').encode()
            tls.sendall(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                + b"%x\r\n" % len(body) + body + b"\r\n"
                + b"%x\r\n" % len(tail) + tail + b"\r\n"
                + b"0\r\n\r\n"
            )
            more = tls.recv(4096).decode()
            if "tools/call" in more:
                body2 = ('{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"tls-' + marker + '"}]}}').encode()
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
                ('{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"tls-' + marker + '"}]}}\n').encode()
            )
            # the writer's fds stay resolvable for the pop window
            import time
            time.sleep(0.4)


def client(port, marker, http=False, sse=False):
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
        client(port, marker, http, sse)
