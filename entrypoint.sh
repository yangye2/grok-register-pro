#!/usr/bin/env bash
# Container entrypoint:
# 1) start inline Turnstile Solver (Camoufox) on 127.0.0.1:5072
# 2) start register-pro API on 0.0.0.0:8788
set -euo pipefail
cd /app

APP_CMD=("python" "register_pro_app.py")
if [[ "$#" -gt 0 ]]; then
  APP_CMD=("$@")
fi

provider="$(echo "${GROK2API_CAPTCHA_PROVIDER:-${CAPTCHA_PROVIDER:-local}}" | tr '[:upper:]' '[:lower:]')"
enable_solver="${GROK2API_INLINE_SOLVER:-1}"
solver_port="${TURNSTILE_PORT:-5072}"
solver_thread="${TURNSTILE_THREAD:-1}"
solver_browser="${TURNSTILE_BROWSER_TYPE:-camoufox}"
solver_host="${TURNSTILE_HOST:-127.0.0.1}"
solver_pid=""

# Persist SQLite / exports on the /data volume (must be mounted by compose)
export GROK_REGISTER_PRO=1
export GROK2API_STORE_BACKEND=file
export GROK2API_REQUIRE_SHARED_STORES=0
export GROK_REGISTER_PRO_HOST="${GROK_REGISTER_PRO_HOST:-0.0.0.0}"
export GROK_REGISTER_PRO_PORT="${GROK_REGISTER_PRO_PORT:-8788}"
export GROK_REGISTER_PRO_DATA_DIR="${GROK_REGISTER_PRO_DATA_DIR:-/data}"
export GROK_REGISTER_PRO_DB="${GROK_REGISTER_PRO_DB:-/data/register_pro.sqlite3}"
export GROK_REGISTER_PRO_OUTPUT_DIR="${GROK_REGISTER_PRO_OUTPUT_DIR:-/data/outputs}"
export GROK2API_AUTH_FILE="${GROK2API_AUTH_FILE:-/data/outputs/grok2api_auth.json}"
export PYTHONPATH="/app/grok-build-auth${PYTHONPATH:+:$PYTHONPATH}"

mkdir -p \
  "${GROK_REGISTER_PRO_DATA_DIR}" \
  "${GROK_REGISTER_PRO_OUTPUT_DIR}" \
  "${GROK_REGISTER_PRO_OUTPUT_DIR}/grok2api_auth" \
  "${GROK_REGISTER_PRO_OUTPUT_DIR}/cpa_auth" \
  "${GROK_REGISTER_PRO_DATA_DIR}/backups" \
  "${GROK_REGISTER_PRO_DATA_DIR}/register_sso" \
  "${GROK_REGISTER_PRO_DATA_DIR}/cache" \
  "${GROK_REGISTER_PRO_DATA_DIR}/cache/ms-playwright" \
  /app/turnstile-solver/logs \
  /app/turnstile-solver/keys

# Browser cache: same resolver as local solver / fetch_browsers (one code path).
# Also seeds incomplete /data/cache addons (esp. UBO) from image bake so a
# failed first-boot download cannot permanently brick captcha solving.
if [[ -f /app/scripts/resolve_browser_cache.sh ]]; then
  # shellcheck disable=SC1091
  source /app/scripts/resolve_browser_cache.sh
  apply_browser_cache_env ""
else
  # Fallback if script missing in older images
  pick_browser_cache() {
    local cand
    for cand in \
      "${XDG_CACHE_HOME:-}" \
      "/opt/browser-cache" \
      "${GROK_REGISTER_PRO_DATA_DIR}/cache"
    do
      [[ -n "$cand" ]] || continue
      if [[ -f "${cand}/camoufox/version.json" ]] \
        || [[ -x "${cand}/camoufox/camoufox-bin" ]] \
        || [[ -d "${cand}/camoufox/browsers/official" ]] \
        || compgen -G "${cand}/camoufox/browsers/official/*" >/dev/null 2>&1; then
        echo "$cand"
        return 0
      fi
    done
    if [[ -d /opt/browser-cache/camoufox ]]; then
      echo "/opt/browser-cache"
    else
      echo "${GROK_REGISTER_PRO_DATA_DIR}/cache"
    fi
  }
  export XDG_CACHE_HOME="$(pick_browser_cache)"
  export PLAYWRIGHT_BROWSERS_PATH="${XDG_CACHE_HOME}/ms-playwright"
  mkdir -p "${XDG_CACHE_HOME}" "${PLAYWRIGHT_BROWSERS_PATH}"
  # Minimal UBO repair even without the shared script (older image fallback).
  if [[ -f /opt/browser-cache/camoufox/addons/UBO/manifest.json ]]; then
    if [[ ! -f "${XDG_CACHE_HOME}/camoufox/addons/UBO/manifest.json" ]]; then
      echo "[entrypoint] repairing incomplete UBO addon from image bake"
      rm -rf "${XDG_CACHE_HOME}/camoufox/addons/UBO"
      mkdir -p "${XDG_CACHE_HOME}/camoufox/addons"
      cp -a /opt/browser-cache/camoufox/addons/UBO "${XDG_CACHE_HOME}/camoufox/addons/UBO"
    fi
  fi
fi
echo "[entrypoint] browser cache=${XDG_CACHE_HOME}"

# Refuse to run if /data is not writable (would silently lose data on ephemeral FS)
if ! touch "${GROK_REGISTER_PRO_DATA_DIR}/.write_test" 2>/dev/null; then
  echo "[entrypoint] ERROR: data dir not writable: ${GROK_REGISTER_PRO_DATA_DIR}" >&2
  echo "[entrypoint] Mount a host volume, e.g. ./data/register_pro:/data" >&2
  exit 1
fi
rm -f "${GROK_REGISTER_PRO_DATA_DIR}/.write_test"

ensure_browsers() {
  # If image already has camoufox, skip download. Otherwise fetch into cache.
  auto="$(echo "${TURNSTILE_BROWSER_AUTO_FETCH:-1}" | tr '[:upper:]' '[:lower:]')"
  if [[ "$auto" == "0" || "$auto" == "false" || "$auto" == "no" || "$auto" == "off" ]]; then
    echo "[entrypoint] browser auto-fetch disabled (TURNSTILE_BROWSER_AUTO_FETCH=0)"
    return 0
  fi
  if [[ ! -x /app/scripts/fetch_browsers.sh ]]; then
    echo "[entrypoint] WARN: scripts/fetch_browsers.sh missing; skip browser fetch" >&2
    return 0
  fi
  echo "[entrypoint] ensuring browser binaries (cache=${XDG_CACHE_HOME})..."
  TURNSTILE_PYTHON="${TURNSTILE_PYTHON:-python}" \
    GROK_REGISTER_PRO_DATA_DIR="${GROK_REGISTER_PRO_DATA_DIR}" \
    XDG_CACHE_HOME="${XDG_CACHE_HOME}" \
    PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH}" \
    TURNSTILE_BROWSER_TYPE="${solver_browser}" \
    /app/scripts/fetch_browsers.sh || echo "[entrypoint] WARN: browser fetch returned non-zero" >&2
}

start_inline_solver() {
  if [[ ! -f /app/turnstile-solver/api_solver.py ]]; then
    echo "[entrypoint] turnstile-solver missing; skip inline solver"
    return 0
  fi
  ensure_browsers
  # Eager browsers by default: keep pool warm. Short idle reclaim caused
  # registration to stall on empty pool ("waiting for admission").
  # Opt-in: TURNSTILE_LAZY=1 and/or TURNSTILE_IDLE_SEC=300+
  export TURNSTILE_LAZY="${TURNSTILE_LAZY:-0}"
  export TURNSTILE_IDLE_SEC="${TURNSTILE_IDLE_SEC:-0}"
  # Prefer native headless; only use Xvfb when explicitly requested.
  use_xvfb="$(echo "${TURNSTILE_USE_XVFB:-0}" | tr '[:upper:]' '[:lower:]')"
  echo "[entrypoint] starting inline turnstile-solver on ${solver_host}:${solver_port} (thread=${solver_thread}, browser=${solver_browser}, lazy=${TURNSTILE_LAZY}, idle=${TURNSTILE_IDLE_SEC}s, xvfb=${use_xvfb})"
  mkdir -p /app/turnstile-solver/logs
  (
    cd /app/turnstile-solver
    # Use system python from the image (packages already installed globally).
    # Do NOT require turnstile-solver/.venv (that is for bare-metal start.sh).
    if [[ "${use_xvfb}" == "1" || "${use_xvfb}" == "true" || "${use_xvfb}" == "yes" || "${use_xvfb}" == "on" ]]; then
      if command -v xvfb-run >/dev/null 2>&1 && command -v xauth >/dev/null 2>&1; then
        exec xvfb-run -a python api_solver.py \
          --browser_type "${solver_browser}" \
          --thread "${solver_thread}" \
          --host "${solver_host}" \
          --port "${solver_port}" \
          --debug
      fi
      echo "[entrypoint] WARN: xvfb/xauth unavailable; falling back to native headless" >&2
    fi
    exec python api_solver.py \
      --browser_type "${solver_browser}" \
      --thread "${solver_thread}" \
      --host "${solver_host}" \
      --port "${solver_port}" \
      --debug
  ) > /app/turnstile-solver/logs/turnstile_solver.log 2>&1 &
  solver_pid=$!
  echo "${solver_pid}" > /app/turnstile-solver/logs/turnstile_solver.pid
  echo "[entrypoint] inline solver pid=${solver_pid}"

  for i in $(seq 1 120); do
    if curl -fsS -m 1 "http://127.0.0.1:${solver_port}/health" >/dev/null 2>&1 \
      || curl -fsS -m 1 "http://127.0.0.1:${solver_port}/" >/dev/null 2>&1; then
      echo "[entrypoint] inline solver ready"
      return 0
    fi
    if ! kill -0 "${solver_pid}" 2>/dev/null; then
      echo "[entrypoint] WARN: inline solver exited early; tail solver log:" >&2
      tail -n 40 /app/turnstile-solver/logs/turnstile_solver.log 2>/dev/null || true
      return 0
    fi
    sleep 1
  done
  echo "[entrypoint] WARN: inline solver not ready after 120s; registration will wait until it is" >&2
}

cleanup() {
  if [[ -n "${solver_pid}" ]] && kill -0 "${solver_pid}" 2>/dev/null; then
    echo "[entrypoint] stopping inline solver pid=${solver_pid}"
    kill "${solver_pid}" 2>/dev/null || true
    sleep 1
    kill -9 "${solver_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if [[ "${provider}" == "local" && "${enable_solver}" != "0" ]]; then
  export GROK2API_CAPTCHA_PROVIDER=local
  export CAPTCHA_PROVIDER=local
  export GROK2API_LOCAL_SOLVER_URL="http://127.0.0.1:${solver_port}"
  export LOCAL_SOLVER_URL="http://127.0.0.1:${solver_port}"
  start_inline_solver
fi

admin_base="${GROK_REGISTER_ADMIN_BASE_PATH:-/admin}"
admin_base="/${admin_base#/}"
admin_base="${admin_base%/}"
if [[ -z "${admin_base}" || "${admin_base}" == "/" ]]; then
  admin_base="/admin"
fi
echo "[entrypoint] data dir=${GROK_REGISTER_PRO_DATA_DIR} db=${GROK_REGISTER_PRO_DB}"
echo "[entrypoint] admin path=${admin_base}"
if [[ -n "${GROK_REGISTER_ADMIN_BOOTSTRAP_PASSWORD:-}" ]]; then
  if [[ "${GROK_REGISTER_ADMIN_FORCE_RESET:-0}" == "1" ]]; then
    echo "[entrypoint] admin password will FORCE-RESET from env"
  else
    echo "[entrypoint] admin bootstrap password provided (used only if unset)"
  fi
fi
echo "[entrypoint] starting app: ${APP_CMD[*]}  (http://${GROK_REGISTER_PRO_HOST}:${GROK_REGISTER_PRO_PORT}${admin_base}/accounts)"
exec "${APP_CMD[@]}"
