#!/bin/bash
# dark systemd installation helper
set -euo pipefail

echo "==> Creating dark user and directories..."
sudo useradd -r -m -d /var/lib/dark -s /bin/false dark 2>/dev/null || true
sudo mkdir -p /etc/dark /var/lib/dark
sudo chown dark:dark /var/lib/dark

echo "==> Installing config template..."
if [ ! -f /etc/dark/config.toml ]; then
    sudo cp contrib/config.example.toml /etc/dark/config.toml
    echo "    Edit /etc/dark/config.toml with your settings"
else
    echo "    /etc/dark/config.toml already exists, skipping"
fi

echo "==> Installing systemd service..."
sudo cp contrib/dark.service /etc/systemd/system/dark.service
sudo systemctl daemon-reload

echo "==> Done! Next steps:"
echo "    1. Edit /etc/dark/config.toml"
echo "    2. Copy dark binary to /usr/local/bin/dark"
echo "    3. sudo systemctl enable --now dark"
