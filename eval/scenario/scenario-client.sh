#!/bin/sh
# The MCP client for the alpha1 scenario: writes the three framing
# requests into the server FIFO and consumes the responses.
SERVER_FIFO="$1"
CLIENT_FIFO="$2"
LOG="$3"

: > "$LOG"
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"alpha1-client","version":"0"}}}\n' >> "$LOG"
printf '%s\n' "$(sed -n 1p "$LOG")" > "$SERVER_FIFO"

printf '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' >> "$LOG"
printf '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' > "$SERVER_FIFO"

printf '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read","arguments":{"path":"/etc/hostname"}}}\n' >> "$LOG"
printf '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read","arguments":{"path":"/etc/hostname"}}}\n' > "$SERVER_FIFO"

# consume the replies (the server writes them into the client FIFO)
( sleep 4; echo "" > "$CLIENT_FIFO" ) &
RESP=$(head -c 2000 "$CLIENT_FIFO")
printf '%s\n' "$RESP" >> "$LOG"
