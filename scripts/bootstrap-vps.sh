#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker Engine + Compose plugin first."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required."
  exit 1
fi

if [[ ! -f .env ]]; then
  read -r -p "MCP domain (DNS A record must already point here): " MCP_DOMAIN
  if [[ -z "$MCP_DOMAIN" ]]; then
    echo "MCP_DOMAIN is required."
    exit 1
  fi

  MSF_PASSWORD="$(openssl rand -hex 16)"
  MCP_AUTH_TOKEN="$(openssl rand -hex 32)"

  cat > .env <<EOF
MCP_DOMAIN=$MCP_DOMAIN
MSF_PASSWORD=$MSF_PASSWORD
MCP_AUTH_TOKEN=$MCP_AUTH_TOKEN
MCP_ALLOW_ACTIVE_ACTIONS=false
MCP_ALLOW_SESSION_CONTROL=false
MCP_ALLOW_PAYLOAD_GENERATION=false
MCP_ALLOW_LISTENER_CONTROL=false
EOF

  chmod 600 .env
  echo "Created .env with random secrets."
else
  echo ".env already exists; keeping existing configuration."
fi

echo "Pulling Metasploit and Caddy images..."
docker compose -f docker-compose.vps.yml --env-file .env pull

echo "Building MCP image..."
docker compose -f docker-compose.vps.yml --env-file .env build --pull metasploit-mcp

echo "Starting stack..."
docker compose -f docker-compose.vps.yml --env-file .env up -d

echo
echo "Stack status:"
docker compose -f docker-compose.vps.yml --env-file .env ps

echo
echo "MCP URL: https://$(grep '^MCP_DOMAIN=' .env | cut -d= -f2-)"
echo
echo "Health check:"
DOMAIN="$(grep '^MCP_DOMAIN=' .env | cut -d= -f2-)"
curl -fsS "https://$DOMAIN/healthz"
echo
