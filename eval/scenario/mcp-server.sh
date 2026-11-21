#!/bin/sh
# The MCP server for the alpha1 scenario: reads JSON-RPC frames from
# stdin (piped by the client process) and answers each method on stdout
# (captured by the test).
while IFS= read -t 20 -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"alpha1-server","version":"0"}}}\n'
      ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read","description":"read a file"}]}}\n'
      ;;
    *'"method":"tools/call"'*)
      printf '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"hello-from-read"}]}}\n'
      ;;
  esac
done
