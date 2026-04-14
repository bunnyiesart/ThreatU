#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Creating virtual environment..."
python3 -m venv .venv

echo "==> Installing dependencies..."
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -r requirements.txt

echo ""
echo "==> Creating config directory..."
mkdir -p ~/.config/mcp-threatu
if [ ! -f ~/.config/mcp-threatu/config.json ]; then
    cp config.example.json ~/.config/mcp-threatu/config.json
    chmod 600 ~/.config/mcp-threatu/config.json
    echo "    Config created at ~/.config/mcp-threatu/config.json"
    echo "    Fill in your API keys before starting the server."
else
    echo "    Config already exists, skipping."
fi

echo ""
echo "Setup complete."
echo "To verify sources: .venv/bin/python3 -c \"import sys; sys.path.insert(0,'.');from server import *; print(ti_configured_sources())\""
