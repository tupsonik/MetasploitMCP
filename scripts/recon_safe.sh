#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-webgl.greenhost.pw}"

if ! command -v nmap >/dev/null 2>&1; then
  echo "Nmap nie jest zainstalowany — instaluję go w Codespace..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq nmap
fi
OUT="recon-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

echo "[1/3] Nmap TCP service discovery: $TARGET"
nmap -Pn -sV --top-ports 1000 --version-light -T3 "$TARGET" -oN "$OUT/nmap-services.txt"

echo "[2/3] Safe/default Nmap scripts"
nmap -Pn -sV --script "default,safe" -T3 "$TARGET" -oN "$OUT/nmap-safe.txt"

echo "[3/3] HTTP headers (if HTTP/HTTPS are reachable)"
for url in "http://$TARGET" "https://$TARGET"; do
  name=$(printf '%s' "$url" | tr -cd '[:alnum:]')
  curl -k -I --max-time 10 -sS "$url" > "$OUT/$name-headers.txt" 2>&1 || true
done

echo
echo "Gotowe. Wyniki są w: $OUT/"
echo "Nie uruchamia to exploitów, payloadów ani testów destrukcyjnych."
