#!/bin/sh
# The MCP server for the alpha1 scenario: reads JSON-RPC frames from the
# client FIFO, answers each method on the response FIFO, and logs its
# replies to stdout-captured file via the shell.
# stdin: FIFO f1 (client -> server); each reply goes to FIFO f2.
SERVER_FIFO="$1"
CLIENT_FIFO="$2"

while IFS= read -t 15 -r line; do
  case "$line" in
    *'"method":"initialize"'*|*'"method":"initialize",'*|*'"method": "initialize"'*)
      printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"alpha1-server","version":"0"}}}\n' > "$CLIENT_FIFO"
      ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read","description":"read a file"}]}}\n' > "$CLIENT_FIFO"
      ;;
    *'"method":"tools/call"'*)
      printf '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"hello-from-read"}]}}\n' > "$CLIENT_FIFO"
      ;;
    *)
      printf '{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"unknown"}}\n' > "$CLIENT_FIFO"
      ;;
  esac
done < "$SERVER_FIFO"
