#!/usr/bin/env sh
set -eu

PORT="${APP_PORT:-8080}"

if [ -n "${APP_CMD:-}" ]; then
  echo "[entrypoint] Running APP_CMD override"
  exec sh -c "$APP_CMD"
fi

if [ -x "/app/app/start.sh" ]; then
  echo "[entrypoint] Found /app/app/start.sh"
  exec /app/app/start.sh
fi

if [ -f "/app/app/main.py" ]; then
  echo "[entrypoint] Found /app/app/main.py"
  exec python /app/app/main.py
fi

if [ -f "/app/app/app.py" ]; then
  echo "[entrypoint] Found /app/app/app.py"
  exec python /app/app/app.py
fi

echo "[entrypoint] No app entrypoint found. Starting a minimal HTTP server on port ${PORT}."
exec python -m http.server "${PORT}"
