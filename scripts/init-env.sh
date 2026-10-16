#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -e .env ]]; then echo '.env already exists; refusing to overwrite encryption keys.'; exit 1; fi
umask 077
cat > .env <<EOF
DB_PASSWORD=$(openssl rand -hex 24)
TOTP_ENCRYPTION_KEY=$(openssl rand -base64 32)
COOKIE_SECURE=false
RP_ID=localhost
RP_ORIGIN=http://localhost:8080
EOF
echo 'Created .env with unique local secrets. Back up the encryption key securely.'
