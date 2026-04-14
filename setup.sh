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
    echo "    Fill in your API keys before use."
else
    echo "    Config already exists, skipping."
fi

echo ""
echo "==> Creating 'threatu' command..."
WRAPPER="$HOME/.local/bin/threatu"
mkdir -p "$HOME/.local/bin"
cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
exec "$(pwd)/.venv/bin/python3" "$(pwd)/cli.py" "\$@"
EOF
chmod +x "$WRAPPER"
echo "    Installed at: $WRAPPER"
echo "    Make sure ~/.local/bin is in your PATH."

echo ""
echo "Setup complete. Run: threatu <ip|hash|domain|url>"
