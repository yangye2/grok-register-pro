#!/usr/bin/env bash
# Start the local registration/import console backed only by SQLite.
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"

# Prefer project venv so system Python (PEP 668) doesn't break startup.
if [[ -n "${PYTHON:-}" ]]; then
  PY="$PYTHON"
elif [[ -x ".venv/bin/python" ]]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi

if ! command -v "$PY" >/dev/null 2>&1 && [[ ! -x "$PY" ]]; then
  echo "ERROR: Python 3.10+ is required." >&2
  exit 1
fi

if ! "$PY" -c "import fastapi, uvicorn, httpx, curl_cffi" 2>/dev/null; then
  if [[ "$PY" == ".venv/bin/python" || "$PY" == *"/venv/"* || "$PY" == *".venv/"* ]]; then
    "$PY" -m pip install -r requirements.txt
  else
    echo "ERROR: missing deps for $PY. Create .venv and install requirements, or set PYTHON=..." >&2
    exit 1
  fi
fi

export PYTHONPATH="$(pwd)/grok-build-auth${PYTHONPATH:+:$PYTHONPATH}"
export GROK_REGISTER_PRO=1
export GROK2API_STORE_BACKEND=file
export GROK2API_REQUIRE_SHARED_STORES=0

# Align with Docker/server layout: host data dir contents == container /data
# Server: /opt/grok-register-data/register_pro.sqlite3  (mounted at /data)
# Local:  ./data/register_pro/register_pro.sqlite3
export GROK_REGISTER_PRO_DATA_DIR="${GROK_REGISTER_PRO_DATA_DIR:-$(pwd)/data/register_pro}"
export GROK_REGISTER_PRO_DB="${GROK_REGISTER_PRO_DB:-${GROK_REGISTER_PRO_DATA_DIR}/register_pro.sqlite3}"
export GROK_REGISTER_PRO_OUTPUT_DIR="${GROK_REGISTER_PRO_OUTPUT_DIR:-${GROK_REGISTER_PRO_DATA_DIR}/outputs}"
mkdir -p "${GROK_REGISTER_PRO_DATA_DIR}" \
  "${GROK_REGISTER_PRO_OUTPUT_DIR}" \
  "${GROK_REGISTER_PRO_DATA_DIR}/backups" \
  "${GROK_REGISTER_PRO_DATA_DIR}/register_sso" \
  "${GROK_REGISTER_PRO_DATA_DIR}/cache" \
  logs

HOST="${GROK_REGISTER_PRO_HOST:-${HOST:-127.0.0.1}}"
PORT="${GROK_REGISTER_PRO_PORT:-${PORT:-8788}}"
PID_FILE="${GROK_REGISTER_PRO_DATA_DIR}/register_pro.pid"
LOCK_FILE="${GROK_REGISTER_PRO_DATA_DIR}/register_pro.instance.lock"

# Stop leftover instances of THIS project only (same cwd / same data dir / same port).
stop_stale_instances() {
  local pids=""
  # Listeners on our port.
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -tiTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null || true)"
  fi
  # Python processes that are register_pro_app.py and share this project root as cwd.
  local py_pids
  py_pids="$(ps -axo pid=,command= 2>/dev/null | awk '/register_pro_app\.py/ && !/awk/ {print $1}' || true)"
  local pid cwd cmd
  for pid in ${py_pids}; do
    [[ -z "${pid}" ]] && continue
    cwd="$(lsof -a -p "${pid}" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -n1 || true)"
    cmd="$(ps -p "${pid}" -o command= 2>/dev/null || true)"
    case " ${cmd} ${cwd} " in
      *" ${ROOT}/"*|*" ${ROOT} "*|*"${ROOT}/register_pro_app.py"*)
        pids="${pids} ${pid}"
        ;;
    esac
  done
  # Stale pid file.
  if [[ -f "${PID_FILE}" ]]; then
    local old
    old="$(cat "${PID_FILE}" 2>/dev/null || true)"
    if [[ -n "${old}" ]] && kill -0 "${old}" 2>/dev/null; then
      pids="${pids} ${old}"
    else
      rm -f "${PID_FILE}"
    fi
  fi

  local uniq=""
  for pid in ${pids}; do
    case " ${uniq} " in
      *" ${pid} "*) ;;
      *) uniq="${uniq} ${pid}" ;;
    esac
  done
  for pid in ${uniq}; do
    [[ -z "${pid}" ]] && continue
    echo "[start] stopping existing register_pro_app pid=${pid}"
    kill "${pid}" 2>/dev/null || true
  done
  if [[ -n "${uniq// }" ]]; then
    sleep 1
    for pid in ${uniq}; do
      if kill -0 "${pid}" 2>/dev/null; then
        echo "[start] force-kill pid=${pid}"
        kill -9 "${pid}" 2>/dev/null || true
      fi
    done
    sleep 0.3
  fi
  rm -f "${PID_FILE}" "${LOCK_FILE}"
}

if [[ "${GROK_REGISTER_PRO_FORCE_RESTART:-1}" != "0" ]]; then
  stop_stale_instances
fi

# Hard refuse if something is still bound to the port after cleanup.
if command -v lsof >/dev/null 2>&1; then
  still="$(lsof -tiTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "${still}" ]]; then
    echo "ERROR: port ${PORT} still in use by pid(s): ${still}" >&2
    echo "Set GROK_REGISTER_PRO_FORCE_RESTART=1 (default) or free the port manually." >&2
    exit 1
  fi
fi

echo "注册机: http://${HOST}:${PORT}/admin/accounts"
echo "data dir: ${GROK_REGISTER_PRO_DATA_DIR}"
echo "database: ${GROK_REGISTER_PRO_DB}"
export GROK_REGISTER_PRO_HOST="${HOST}"
export GROK_REGISTER_PRO_PORT="${PORT}"
export GROK_REGISTER_PRO_PID_FILE="${PID_FILE}"
export GROK_REGISTER_PRO_LOCK_FILE="${LOCK_FILE}"
exec "$PY" register_pro_app.py
