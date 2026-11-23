#!/usr/bin/env python3
"""The agentpcap evaluation harness (spec section 13).

The harness spawns the real tap per scenario and plays the stdio MCP
exchange through one pipe pair per channel. It consumes only the CLI
surfaces (tap, diff) and never reads tap internals. Harness overhead
stays out of the tap's measurement path: the harness times nothing
inside the tap, and no timing rides inside the tap in any receipt.
"""
