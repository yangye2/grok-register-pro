#!/usr/bin/env bash
# Dry-run self-check against grok-register-pro admin API.
# Usage:
#   ADMIN_PASSWORD='your-password' ./docs/selfcheck-dryrun.sh
# Optional:
#   BASE=http://127.0.0.1:8788 ADMIN=/admin
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8788}"
ADMIN="${ADMIN:-/admin}"
ADMIN="/${ADMIN#/}"
ADMIN="${ADMIN%/}"
[[ -n "$ADMIN" ]] || ADMIN="/admin"
PASS="${ADMIN_PASSWORD:-${GROK_REGISTER_ADMIN_BOOTSTRAP_PASSWORD:-}}"
COOKIE="$(mktemp)"
trap 'rm -f "$COOKIE"' EXIT

json_pass() {
  if command -v python3 >/dev/null 2>&1; then
    PASS="$PASS" python3 -c 'import json,os; print(json.dumps({"password": os.environ.get("PASS","")}))'
  elif command -v python >/dev/null 2>&1; then
    PASS="$PASS" python -c 'import json,os; print(json.dumps({"password": os.environ.get("PASS","")}))'
  else
    # naive escape
    local p="${PASS//\\/\\\\}"
    p="${p//\"/\\\"}"
    printf '{"password":"%s"}' "$p"
  fi
}

step() { echo; echo "==> $*"; }

step "0 session (public)"
curl -fsS "$BASE$ADMIN/api/session"
echo

if [[ -z "$PASS" ]]; then
  echo "Set ADMIN_PASSWORD to continue authenticated checks." >&2
  exit 0
fi

step "1 login"
curl -fsS -c "$COOKIE" -H 'Content-Type: application/json' \
  -d "$(json_pass)" \
  "$BASE$ADMIN/api/auth/login"
echo

step "2 local-solver status"
curl -fsS -b "$COOKIE" "$BASE$ADMIN/api/local-solver/status"
echo

step "3 registration preflight"
curl -fsS -b "$COOKIE" -H 'Content-Type: application/json' -d '{}' \
  "$BASE$ADMIN/api/accounts/register-email/preflight"
echo

step "4 test-proxy (network; may fail without proxy pool)"
set +e
curl -fsS -b "$COOKIE" -H 'Content-Type: application/json' -d '{}' \
  "$BASE$ADMIN/api/accounts/register-email/test-proxy"
echo
set -e

step "done — review ok/checks above before real registration"