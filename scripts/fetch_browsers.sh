#!/usr/bin/env bash
# Download browser binaries used by the local Turnstile solver.
#
# Default: fetch whatever the installed camoufox/patchright packages want
# (no hard-coded browser version in this repo).
#
# Cache locations (override via env):
#   XDG_CACHE_HOME          -> camoufox cache parent (default: /data/cache or ~/.cache)
#   PLAYWRIGHT_BROWSERS_PATH-> chromium binaries (default: $XDG_CACHE_HOME/ms-playwright)
#
# Optional:
#   TURNSTILE_BROWSER_TYPE=camoufox|chromium|chrome|msedge  (default camoufox)
#   TURNSTILE_BROWSER_FORCE_FETCH=1   re-download even if present
#   TURNSTILE_FETCH_CHROMIUM=1        also fetch chromium when primary is camoufox
set -euo pipefail

PY="${TURNSTILE_PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY="python"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/resolve_browser_cache.sh"
# If caller already exported XDG_CACHE_HOME, keep it; else shared resolve.
if [[ -z "${XDG_CACHE_HOME:-}" ]]; then
  apply_browser_cache_env "${REPO_DIR}"
else
  export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$XDG_CACHE_HOME/ms-playwright}"
  mkdir -p "$XDG_CACHE_HOME" "$PLAYWRIGHT_BROWSERS_PATH"
fi

BROWSER_TYPE="$(echo "${TURNSTILE_BROWSER_TYPE:-camoufox}" | tr '[:upper:]' '[:lower:]')"
FORCE="$(echo "${TURNSTILE_BROWSER_FORCE_FETCH:-0}" | tr '[:upper:]' '[:lower:]')"
FORCE_ON=0
if [[ "$FORCE" == "1" || "$FORCE" == "true" || "$FORCE" == "yes" || "$FORCE" == "on" ]]; then
  FORCE_ON=1
fi

need_camoufox=0
need_chromium=0
case "$BROWSER_TYPE" in
  camoufox) need_camoufox=1 ;;
  chromium|chrome|msedge) need_chromium=1 ;;
  *) need_camoufox=1 ;;
esac
if [[ "${TURNSTILE_FETCH_CHROMIUM:-0}" == "1" ]]; then
  need_chromium=1
fi

camoufox_ready() {
  # New camoufox packages use multiversion layout:
  #   $XDG_CACHE_HOME/camoufox/browsers/official/<ver>/version.json
  # Old ready-check only looked at INSTALL_DIR/version.json and always
  # failed on image-baked browsers → re-downloaded ~600MB every boot.
  "$PY" - <<'PY' 2>/dev/null
from pathlib import Path
from camoufox.pkgman import INSTALL_DIR, Version

try:
    from camoufox.multiversion import get_active_path
except Exception:
    get_active_path = None  # type: ignore

p = Path(INSTALL_DIR)
if not p.exists() or not any(p.iterdir()):
    raise SystemExit(1)

active = None
if get_active_path is not None:
    try:
        active = get_active_path()
    except Exception:
        active = None

# Prefer active multiversion path (browsers/official/<ver>).
# IMPORTANT: "unsupported" (package wants a newer release) must NOT force
# re-fetch. Newer Camoufox builds can break Turnstile; keep the installed
# binary unless TURNSTILE_BROWSER_FORCE_FETCH=1.
if active is not None:
    try:
        ver = Version.from_path(active)
        if ver.is_supported():
            raise SystemExit(0)
        # Present but package-unsupported: still usable pin.
        raise SystemExit(0)
    except SystemExit:
        raise
    except Exception:
        pass

# Legacy flat layout: INSTALL_DIR/version.json
try:
    ver = Version.from_path()
    # Accept present installs even when package marks them unsupported.
    raise SystemExit(0)
except SystemExit:
    raise
except Exception:
    pass

# Last resort: any executable binary means image bake / manual pin is usable.
# Do NOT re-download just because metadata path moved between package versions.
for name in ("camoufox-bin", "camoufox.exe", "camoufox"):
    for bin_path in p.rglob(name):
        if bin_path.is_file():
            raise SystemExit(0)
raise SystemExit(3)
PY
}

chromium_ready() {
  # Presence of any chromium-* dir under PLAYWRIGHT_BROWSERS_PATH is good enough.
  local root="${PLAYWRIGHT_BROWSERS_PATH}"
  [[ -d "$root" ]] || return 1
  compgen -G "$root/chromium-*" >/dev/null 2>&1 || compgen -G "$root/chromium_headless_shell-*" >/dev/null 2>&1
}

echo "[fetch-browsers] cache=$XDG_CACHE_HOME playwright=$PLAYWRIGHT_BROWSERS_PATH type=$BROWSER_TYPE"

if [[ "$need_camoufox" == "1" ]]; then
  if [[ "$FORCE_ON" != "1" ]] && camoufox_ready; then
    ver="$("$PY" - <<'PY'
try:
    from camoufox.pkgman import installed_verstr
    print(installed_verstr())
except Exception:
    try:
        from camoufox.multiversion import get_active_path
        from camoufox.pkgman import Version
        active = get_active_path()
        print(Version.from_path(active).full_string if active else "present")
    except Exception:
        print("present")
PY
)"
    echo "[fetch-browsers] camoufox already present: v${ver}"
  else
    echo "[fetch-browsers] downloading camoufox (version selected by installed camoufox package)..."
    # No hard-coded browser version: package resolves the matching release.
    if ! "$PY" -m camoufox fetch; then
      echo "[fetch-browsers] WARN: camoufox fetch failed" >&2
    else
      ver="$("$PY" - <<'PY'
try:
    from camoufox.pkgman import installed_verstr
    print(installed_verstr())
except Exception:
    print("unknown")
PY
)" || ver="unknown"
      echo "[fetch-browsers] camoufox ready: v${ver}"
    fi
  fi
fi

if [[ "$need_chromium" == "1" ]]; then
  if [[ "$FORCE_ON" != "1" ]] && chromium_ready; then
    echo "[fetch-browsers] chromium already present under $PLAYWRIGHT_BROWSERS_PATH"
  else
    echo "[fetch-browsers] downloading chromium via patchright (package-selected revision)..."
    if ! "$PY" -m patchright install chromium; then
      echo "[fetch-browsers] WARN: patchright chromium install failed" >&2
    else
      echo "[fetch-browsers] chromium ready"
    fi
  fi
fi

echo "[fetch-browsers] done"
