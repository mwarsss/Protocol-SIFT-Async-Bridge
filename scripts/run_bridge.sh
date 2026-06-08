#!/usr/bin/env bash
# Protocol-SIFT-Async-Bridge — Launch script
# Runs the pre-flight check, then starts the MCP server over stdio.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "[*] Running pre-flight checks..."
python3 "$SCRIPT_DIR/verify_env.py"
echo ""

echo "[*] Starting Protocol-SIFT-Async-Bridge (stdio transport)..."
cd "$PROJECT_ROOT"
exec python3 -m server.mcp_vol_server
