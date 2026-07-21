#!/usr/bin/env bash
# Shared browser-cache resolution for local + Docker.
# Source this file:  source "$ROOT/scripts/resolve_browser_cache.sh"
# Or call:           bash scripts/resolve_browser_cache.sh   (prints path)
#
# Priority (same on every host):
#   1) existing XDG_CACHE_HOME if it already has camoufox
#   2) $GROK_REGISTER_PRO_DATA_DIR/cache  (Docker: /data/cache)
#   3) /opt/browser-cache                  (image bake)
#   4) <repo>/data/register_pro/cache     (source checkout)
#   5) $HOME/.cache
#
# Always sets:
#   XDG_CACHE_HOME
#   PLAYWRIGHT_BROWSERS_PATH=$XDG_CACHE_HOME/ms-playwright

_resolve_browser_cache_has_camoufox() {
  local root="$1"
  [[ -n "$root" ]] || return 1
  # Require real browser payload markers. A residual empty/partial
  # camoufox/addons/UBO tree alone is NOT "ready" — that was the CN first-boot
  # trap that shadowed image bake and left manifest.json missing forever.
  [[ -f "${root}/camoufox/version.json" ]] && return 0
  [[ -d "${root}/camoufox/browsers/official" ]] && return 0
  compgen -G "${root}/camoufox/browsers/official/*" >/dev/null 2>&1 && return 0
  # Linux install layout: binary present
  [[ -x "${root}/camoufox/camoufox-bin" ]] && return 0
  # macOS install layout
  [[ -d "${root}/camoufox/Camoufox.app" ]] && return 0
  return 1
}

# Seed image-baked Camoufox assets into the runtime cache.
# Critical fix: camoufox.addons.maybe_download_addons treats an empty
# addons/UBO/ directory as "already present" and will not re-download.
# On first boot behind bad network that leaves a broken UBO dir under
# /data/cache, every later start fails with "manifest.json is missing".
# Image bake already has complete addons under /opt/browser-cache — copy them.
seed_camoufox_cache_from_image() {
  local src_root="${1:-/opt/browser-cache}"
  local dst_root="${2:-${XDG_CACHE_HOME:-}}"
  local src dst name target
  local seeded=0

  [[ -n "$dst_root" ]] || return 0
  src="${src_root%/}/camoufox"
  dst="${dst_root%/}/camoufox"
  [[ -d "$src" ]] || return 0
  # Same path (runtime already using image bake) — nothing to seed.
  if [[ "$(cd "$src" 2>/dev/null && pwd -P)" == "$(cd "$dst" 2>/dev/null && pwd -P)" ]]; then
    return 0
  fi

  mkdir -p "$dst"

  # If runtime cache lacks a usable browser but image has one, seed the tree.
  if [[ -f "${src}/version.json" && ! -f "${dst}/version.json" ]]; then
    echo "[browser-cache] seeding camoufox browser from ${src_root} → ${dst_root}"
    # Copy contents; do not delete dst first (may already hold partial addons).
    cp -a "${src}/." "${dst}/"
    seeded=1
  fi

  # Always repair incomplete default addons (esp. UBO).
  if [[ -d "${src}/addons" ]]; then
    mkdir -p "${dst}/addons"
    for addon_dir in "${src}/addons"/*; do
      [[ -d "$addon_dir" ]] || continue
      name="$(basename "$addon_dir")"
      target="${dst}/addons/${name}"
      if [[ -f "${target}/manifest.json" ]]; then
        continue
      fi
      if [[ ! -f "${addon_dir}/manifest.json" ]]; then
        echo "[browser-cache] WARN: image addon ${name} also missing manifest.json; skip" >&2
        continue
      fi
      echo "[browser-cache] seeding camoufox addon ${name} from image bake (repair incomplete cache)"
      rm -rf "${target}"
      cp -a "${addon_dir}" "${target}"
      seeded=1
    done
  fi

  if [[ "$seeded" == "1" ]]; then
    echo "[browser-cache] seed complete: ${dst}"
  fi
}

resolve_browser_cache() {
  local repo_dir="${1:-}"
  local cand

  # 1) honor pre-set env if usable
  if [[ -n "${XDG_CACHE_HOME:-}" ]] && _resolve_browser_cache_has_camoufox "${XDG_CACHE_HOME}"; then
    echo "${XDG_CACHE_HOME}"
    return 0
  fi

  # 2) data dir only when it already has a usable camoufox tree.
  #    Do NOT pick empty /data/cache just because /data exists — that used to
  #    shadow the image bake at /opt/browser-cache and force a network re-fetch
  #    (which fails offline / in CN and leaves broken UBO dirs).
  if [[ -n "${GROK_REGISTER_PRO_DATA_DIR:-}" ]]; then
    cand="${GROK_REGISTER_PRO_DATA_DIR}/cache"
    if _resolve_browser_cache_has_camoufox "$cand"; then
      echo "$cand"
      return 0
    fi
  fi

  # 3) image bake path
  if _resolve_browser_cache_has_camoufox "/opt/browser-cache" || [[ -d /opt/browser-cache/camoufox ]]; then
    echo "/opt/browser-cache"
    return 0
  fi

  # 4) writable data cache (first boot without image bake)
  if [[ -n "${GROK_REGISTER_PRO_DATA_DIR:-}" ]]; then
    echo "${GROK_REGISTER_PRO_DATA_DIR}/cache"
    return 0
  fi

  # 5) source-tree data dir (local checkout)
  if [[ -n "$repo_dir" ]]; then
    cand="${repo_dir}/data/register_pro/cache"
    echo "$cand"
    return 0
  fi

  # 6) home cache
  echo "${HOME:-/root}/.cache"
}

apply_browser_cache_env() {
  local repo_dir="${1:-}"
  local chosen
  chosen="$(resolve_browser_cache "$repo_dir")"
  export XDG_CACHE_HOME="$chosen"
  export PLAYWRIGHT_BROWSERS_PATH="${XDG_CACHE_HOME}/ms-playwright"
  mkdir -p "${XDG_CACHE_HOME}" "${PLAYWRIGHT_BROWSERS_PATH}"
  # Repair incomplete volume cache from image bake (UBO / browser binaries).
  seed_camoufox_cache_from_image "/opt/browser-cache" "${XDG_CACHE_HOME}"
}

# When executed directly, print resolved path
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  REPO="$(cd "$(dirname "$0")/.." && pwd)"
  apply_browser_cache_env "$REPO"
  echo "$XDG_CACHE_HOME"
fi
