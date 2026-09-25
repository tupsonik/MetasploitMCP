#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."

echo "== MetasploitMCP Codespace setup =="

if ! command -v python >/dev/null 2>&1; then
  echo "Python is required."
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required in this Codespace."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is not available in this Codespace."
  echo "Open a new Codespace terminal and try again."
  exit 1
fi

if [[ ! -d .venv ]]; then
  echo "[1/5] Creating Python virtual environment..."
  python -m venv .venv
fi

echo "[2/5] Installing Python dependencies..."
.venv/bin/python -m pip install --upgrade pip >/dev/null
.venv/bin/pip install -r requirements.txt >/dev/null

if [[ ! -f .codespace.env ]]; then
  echo "[3/5] Generating local Codespace secrets..."
  MSF_PASSWORD="$(openssl rand -hex 16)"
  MCP_AUTH_TOKEN="$(openssl rand -hex 32)"

  cat > .codespace.env <<EOF
MSF_PASSWORD=$MSF_PASSWORD
MCP_AUTH_TOKEN=$MCP_AUTH_TOKEN
EOF
  chmod 600 .codespace.env
else
  echo "[3/5] Reusing existing local Codespace secrets."
  set -a
  # shellcheck disable=SC1091
  source .codespace.env
  set +a
fi

echo "[4/5] Starting Metasploit RPC..."
if docker ps -a --format '{{.Names}}' | grep -qx 'metasploit-rpc-codespace'; then
  if ! docker ps --format '{{.Names}}' | grep -qx 'metasploit-rpc-codespace'; then
    docker start metasploit-rpc-codespace >/dev/null
  fi
else
  docker run -d \
    --name metasploit-rpc-codespace \
    --restart unless-stopped \
    -e HOME=/home/msf \
    -p 127.0.0.1:55553:55553 \
    metasploitframework/metasploit-framework:6.5.5 \
    /usr/src/metasploit-framework/msfrpcd -U msf -P "$MSF_PASSWORD" -S -a 0.0.0.0 -p 55553 -f >/dev/null
fi

echo "Waiting for Metasploit RPC..."
for _ in $(seq 1 60); do
  if docker exec metasploit-rpc-codespace ruby -rsocket -e 's=TCPSocket.new("127.0.0.1",55553); s.close' >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

if ! docker exec metasploit-rpc-codespace ruby -rsocket -e 's=TCPSocket.new("127.0.0.1",55553); s.close' >/dev/null 2>&1; then
  echo "Metasploit RPC did not become ready."
  docker logs --tail 40 metasploit-rpc-codespace || true
  exit 1
fi

echo "[5/5] Starting MCP server..."
pkill -f "MetasploitMCP.py --transport http" >/dev/null 2>&1 || true

export MSF_PASSWORD
export MSF_SERVER=127.0.0.1
export MSF_PORT=55553
export MSF_SSL=false
export MCP_REQUIRE_AUTH=true
export MCP_AUTH_TOKEN
export MCP_ALLOW_ACTIVE_ACTIONS=false
export MCP_ALLOW_SESSION_CONTROL=false
export MCP_ALLOW_PAYLOAD_GENERATION=false
export MCP_ALLOW_LISTENER_CONTROL=false
export PAYLOAD_SAVE_DIR="$PWD/payloads"

mkdir -p "$PAYLOAD_SAVE_DIR"

nohup .venv/bin/python MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085 > .codespace-mcp.log 2>&1 &
echo $! > .codespace-mcp.pid

sleep 3

if ! curl -fsS http://127.0.0.1:8085/healthz >/dev/null; then
  echo "MCP server failed to start."
  tail -n 60 .codespace-mcp.log || true
  exit 1
fi

echo
echo "=============================================="
echo "MetasploitMCP is running on port 8085."
echo "Security: high-impact capabilities are OFF."
echo
echo "MCP bearer token:"
echo "$MCP_AUTH_TOKEN"
echo
echo "Logs: .codespace-mcp.log"
echo "Stop MCP: kill $(cat .codespace-mcp.pid)"
echo "Stop Metasploit: docker stop metasploit-rpc-codespace"
echo "=============================================="
