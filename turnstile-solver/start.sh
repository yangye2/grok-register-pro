#!/usr/bin/env bash
# Start local Turnstile Solver (host process; reachable by grok-register-pro via docker bridge gateway).
set -euo pipefail
cd "$(dirname "$0")"

HOST="${TURNSTILE_HOST:-0.0.0.0}"
PORT="${TURNSTILE_PORT:-5072}"
THREAD="${TURNSTILE_THREAD:-1}"
BROWSER_TYPE="${TURNSTILE_BROWSER_TYPE:-camoufox}"
LOG_FILE="${TURNSTILE_LOG:-logs/turnstile_solver.log}"

mkdir -p logs keys

# Prefer project venv; create on first run.
if [[ ! -x .venv/bin/python ]]; then
  echo "[turnstile-solver] creating venv..."
  python3 -m venv .venv
  .venv/bin/pip install -U pip setuptools wheel
  .venv/bin/pip install -r requirements.txt
fi

# Browser binaries: same resolver as Docker entrypoint (scripts/resolve_browser_cache.sh).
ROOT_DIR="$(cd .. && pwd)"
# shellcheck disable=SC1091
source "${ROOT_DIR}/scripts/resolve_browser_cache.sh"
apply_browser_cache_env "${ROOT_DIR}"
echo "[turnstile-solver] browser cache=${XDG_CACHE_HOME} playwright=${PLAYWRIGHT_BROWSERS_PATH}"
if [[ "${TURNSTILE_BROWSER_AUTO_FETCH:-1}" != "0" ]]; then
  if [[ -x "${ROOT_DIR}/scripts/fetch_browsers.sh" ]]; then
    echo "[turnstile-solver] ensuring browser binaries..."
    TURNSTILE_PYTHON="$(pwd)/.venv/bin/python" \
      TURNSTILE_BROWSER_TYPE="${BROWSER_TYPE}" \
      "${ROOT_DIR}/scripts/fetch_browsers.sh" || echo "[turnstile-solver] WARN: browser fetch failed" >&2
  else
    # Fallback without helper script
    .venv/bin/python -m camoufox fetch || true
    if [[ "${BROWSER_TYPE}" != "camoufox" || "${TURNSTILE_FETCH_CHROMIUM:-0}" == "1" ]]; then
      .venv/bin/python -m patchright install chromium || true
    fi
  fi
fi

# stop previous instance on same port
if command -v ss >/dev/null 2>&1; then
  old_pid="$(ss -lntp 2>/dev/null | awk -v p=":${PORT}" '$4 ~ p {print}' | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1 || true)"
  if [[ -n "${old_pid:-}" ]]; then
    echo "[turnstile-solver] stopping old pid ${old_pid} on :${PORT}"
    kill "${old_pid}" 2>/dev/null || true
    sleep 1
    kill -9 "${old_pid}" 2>/dev/null || true
  fi
fi
pkill -f "api_solver.py --browser_type .* --port ${PORT}" 2>/dev/null || true
sleep 1

# Per-task proxy is preferred (registration createTask.proxy). Optional
# --proxy + proxies.txt remains as a pool fallback for manual ops.
PROXY_FLAG=""
if [[ "${TURNSTILE_PROXY_SUPPORT:-0}" == "1" || "${TURNSTILE_PROXY_SUPPORT:-}" == "true" ]]; then
  PROXY_FLAG="--proxy"
  echo "[turnstile-solver] proxies.txt fallback enabled (TURNSTILE_PROXY_SUPPORT=1)"
fi

# Keep browsers warm by default (registration reliability).
export TURNSTILE_LAZY="${TURNSTILE_LAZY:-0}"
export TURNSTILE_IDLE_SEC="${TURNSTILE_IDLE_SEC:-0}"

echo "[turnstile-solver] starting ${BROWSER_TYPE} thread=${THREAD} ${HOST}:${PORT} lazy=${TURNSTILE_LAZY} idle=${TURNSTILE_IDLE_SEC}s"
echo "[turnstile-solver] note: registration should pass proxy via createTask; restart after code updates"
# shellcheck disable=SC2086
nohup env TURNSTILE_LAZY="${TURNSTILE_LAZY}" TURNSTILE_IDLE_SEC="${TURNSTILE_IDLE_SEC}" \
  .venv/bin/python api_solver.py \
  --browser_type "${BROWSER_TYPE}" \
  --thread "${THREAD}" \
  --debug \
  --host "${HOST}" \
  --port "${PORT}" \
  ${PROXY_FLAG} \
  >"${LOG_FILE}" 2>&1 &
echo $! > logs/turnstile_solver.pid
echo "[turnstile-solver] pid=$(cat logs/turnstile_solver.pid) log=${LOG_FILE}"

# wait ready
for i in $(seq 1 40); do
  if curl -fsS -m 1 "http://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
    echo "[turnstile-solver] ready http://127.0.0.1:${PORT}"
    exit 0
  fi
  sleep 1
done
echo "[turnstile-solver] WARN: not ready yet; check ${LOG_FILE}" >&2
exit 1
