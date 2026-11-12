#!/bin/sh
# Generate self-signed SSL cert for local Shadow313 NEXUS dev
# For production: replace with Let's Encrypt or your own cert

SSL_DIR="$(dirname "$0")/ssl"
mkdir -p "$SSL_DIR"
CERT="$SSL_DIR/shadow313.crt"
KEY="$SSL_DIR/shadow313.key"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    echo "✅ SSL cert already exists — skipping generation"
    exit 0
fi

echo "[*] Generating self-signed SSL certificate..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$KEY" \
    -out "$CERT" \
    -subj "/C=CA/ST=Ontario/L=Ottawa/O=Shadow313 NEXUS/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:shadow313.local,IP:127.0.0.1" \
    2>/dev/null
# The nginx container runs as the unprivileged nginx user. This key is only
# for the loopback-bound, self-signed local-development listener; never use
# this generator for a production certificate or private key.
chmod 644 "$KEY"

echo "✅ SSL cert generated: $CERT"
echo "   Valid for: localhost, shadow313.local, 127.0.0.1"
echo "   Expires:   365 days"
echo ""
echo "   To trust in browser (Windows):"
echo "   1. Double-click shadow313.crt"
echo "   2. Install Certificate → Local Machine → Trusted Root CAs"
