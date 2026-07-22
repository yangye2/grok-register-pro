"""SQLite-backed storage for the registration-only pro mode.



This module intentionally implements the small subset of the original

``accounts`` contract that ``grok_build_adapter`` needs after a successful

protocol registration: import one OIDC auth payload, persist it, and write

portable auth JSON files.

"""



from __future__ import annotations



import base64

import hashlib

import hmac

import json

import os

import re

import secrets

import sqlite3

import ssl

import time

import urllib.error

import urllib.parse

import urllib.request

from collections import Counter

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from datetime import datetime, timezone

from pathlib import Path

from typing import Any





def looks_like_jwt(value: str | None) -> bool:

    """True when *value* is a 3-part JWT (e.g. mailbox address token mistaken for password)."""

    s = str(value or "").strip()

    if not s.startswith("eyJ") or s.count(".") != 2:

        return False

    parts = s.split(".")

    return all(len(p) >= 8 for p in parts)





def is_plausible_account_password(value: str | None) -> bool:

    """Reject empty / JWT / email-shaped garbage that cannot be an xAI password."""

    s = str(value or "").strip()

    if not s or len(s) < 6 or len(s) > 128:

        return False

    if looks_like_jwt(s):

        return False

    # email:password or pure email dumped into password column

    if "@" in s and "." in s.split("@")[-1] and " " not in s and len(s) > 20:

        # allow passwords that merely contain @ as a character if short-ish

        if s.count("@") == 1 and s.index("@") > 1:

            local, _, domain = s.partition("@")

            if "." in domain and ":" not in s and len(domain) >= 3:

                return False

    return True





ROOT = Path(__file__).resolve().parent


DATA_DIR = Path(
    os.getenv("GROK_REGISTER_PRO_DATA_DIR") or (ROOT / "generated" / "register_pro")
)
DB_PATH = Path(
    os.getenv("GROK_REGISTER_PRO_DB") or (DATA_DIR / "register_pro.sqlite3")
)
OUTPUT_DIR = Path(
    os.getenv("GROK_REGISTER_PRO_OUTPUT_DIR") or (DATA_DIR / "outputs")
)

AUTH_MAP_DIR = OUTPUT_DIR / "grok2api_auth"

CPA_DIR = OUTPUT_DIR / "cpa_auth"

BACKUP_DIR = DATA_DIR / "backups"

GROK2API_PROVIDERS = ("grok_build", "grok_web", "grok_console")

# Grok2API admin list filter values that return non-healthy accounts.

# Verified against /api/admin/v1/accounts?status=... (invalid values 400 invalidFilter).

GROK2API_PROBLEM_STATUSES = (

    "reauthRequired",

    "waitingReset",

    "disabled",

    "cooldown",

    "probing",

)

UPSTREAM_BASE = os.getenv("GROK_CLI_CHAT_PROXY_BASE_URL", "https://cli-chat-proxy.grok.com/v1").rstrip("/")

CLI_VERSION = os.getenv("GROK2API_CLI_VERSION", "0.2.93")

CLIENT_SURFACE = os.getenv("GROK2API_CLIENT_SURFACE", "grok-cli")

CLIENT_IDENTIFIER = os.getenv("GROK2API_CLIENT_IDENTIFIER", "grok-register-pro")



DEFAULT_REGISTRATION_CONFIG: dict[str, Any] = {

    "mail_provider": "moemail",

    "base_url": os.getenv("GROK2API_MOEMAIL_BASE_URL", ""),

    "moemail_base_url": os.getenv("GROK2API_MOEMAIL_BASE_URL", ""),

    "cfmail_base_url": os.getenv("GROK2API_CFMAIL_BASE_URL", ""),

    "api_key": os.getenv("GROK2API_MOEMAIL_API_KEY", ""),

    "moemail_api_key": os.getenv("GROK2API_MOEMAIL_API_KEY", ""),

    "yyds_api_key": os.getenv("GROK2API_YYDS_API_KEY", ""),

    "gptmail_api_key": os.getenv("GROK2API_GPTMAIL_API_KEY", ""),

    "cfmail_api_key": os.getenv("GROK2API_CFMAIL_API_KEY", ""),

    "duckmail_api_key": os.getenv("GROK2API_DUCKMAIL_API_KEY", ""),

    "domain": os.getenv("GROK2API_MOEMAIL_DOMAIN", ""),

    "moemail_domain": os.getenv("GROK2API_MOEMAIL_DOMAIN", ""),

    "yyds_domain": os.getenv("GROK2API_YYDS_DOMAIN", ""),

    "gptmail_domain": os.getenv("GROK2API_GPTMAIL_DOMAIN", ""),

    "cfmail_domain": os.getenv("GROK2API_CFMAIL_DOMAIN", ""),

    "duckmail_domain": os.getenv("GROK2API_DUCKMAIL_DOMAIN", ""),

    "captcha_provider": "local",

    "local_solver_url": "http://127.0.0.1:5072",

    "yescaptcha_key": "",

    "proxy": os.getenv("GROK2API_XAI_PROXY_POOL") or os.getenv("GROK2API_XAI_PROXY", ""),

    "proxy_username": os.getenv("GROK2API_XAI_PROXY_USERNAME", ""),

    "proxy_password": os.getenv("GROK2API_XAI_PROXY_PASSWORD", ""),

    "proxy_strategy": os.getenv("GROK2API_XAI_PROXY_STRATEGY", "round_robin"),

    "prefix": "",

    "expiry_ms": int(os.getenv("GROK2API_MOEMAIL_EXPIRY_MS", "3600000") or 3600000),

    "count": int(os.getenv("GROK2API_REG_COUNT", "1") or 1),

    # Safe defaults: 1 worker / 1 captcha browser / 1 global inflight.

    # Power mode (settings UI) may raise these up to 50.

    "concurrency": int(os.getenv("GROK2API_REG_CONCURRENCY", "1") or 1),

    # Gap between successive worker *submits*. Too low (e.g. 100ms) still lets a

    # full concurrency wave hit mailbox/captcha/device-flow together at startup.

    "stagger_ms": int(os.getenv("GROK2API_REG_STAGGER_MS", "800") or 800),

    "global_inflight": int(os.getenv("GROK2API_REG_GLOBAL_INFLIGHT", "1") or 1),

    "captcha_concurrency": int(os.getenv("GROK2API_CAPTCHA_CONCURRENCY", "1") or 1),

    # Power mode gate: when false, normalize forces concurrency knobs back to 1.

    "power_mode": str(os.getenv("GROK2API_REG_POWER_MODE", "0") or "0").strip().lower()

        in {"1", "true", "yes", "on"},

    # New OIDC tokens often 403 for a short settle window; default 30s.

    "probe_delay_sec": 30,

    # When true, registration writes credentials and counts as success without model probe.

    # Useful for bulk runs where probe latency dominates; accounts stay status=registered.

    "skip_probe": False,

    # When true, stop after SSO cookie is obtained — do not run device-flow conversion

    # into Grok2API/CPA auth. Accounts stay status=sso_pending until manual convert.

    "sso_only": False,

    # When true, local Turnstile (Camoufox) uses the same proxy as the

    # registration job so CF sees one egress. When false, captcha is Proxyless

    # (server egress) while protocol HTTP still uses the job proxy.

    "captcha_use_proxy": True,

    # Outmail (Outlook pool + anonymous temp mailbox) ? same keys as grok-register.

    "outmail_api_base": os.getenv("GROK2API_OUTMAIL_API_BASE", ""),

    "outmail_api_key": os.getenv("GROK2API_OUTMAIL_API_KEY", ""),

    "outmail_session_cookie": os.getenv("GROK2API_OUTMAIL_SESSION_COOKIE", ""),

    "outmail_proxy": os.getenv("GROK2API_OUTMAIL_PROXY", ""),

    "outmail_plus_alias": True,

    "outmail_plus_alias_count": 1,

    "outmail_alias_suffix_len": 6,

    "outmail_fetch_top": 10,

    "outmail_poll_interval_sec": 5,

    "outmail_poll_timeout_sec": 180,

    "outmail_since_padding_sec": 30,

    "outmail_from_filter": "x.ai",

    "outmail_subject_filter": "xAI",

    "outmail_group_id": "",

    "outmail_anonymous_enabled": False,

    "outmail_anonymous_provider": "cloudflare",

    "outmail_anonymous_domain": "",

    "outmail_anonymous_username_prefix": "",

    "outmail_anonymous_password": "",

    "outmail_anonymous_delete_after": False,

    "outmail_exclude_used": True,

    "outmail_used_file": "outmail_used_mailboxes.txt",

}



# Single remote backend: Grok2API and CPA are mutually exclusive.

# Auto-import + remote-status pull both follow this switch.

REMOTE_BACKENDS = ("grok2api", "cpa")

DEFAULT_REMOTE_BACKEND = str(os.getenv("GROK_REGISTER_REMOTE_BACKEND", "") or "").strip().lower()



DEFAULT_GROK2API_CONFIG: dict[str, Any] = {

    "base_url": os.getenv("GROK2API_IMPORT_BASE_URL", ""),

    "username": os.getenv("GROK2API_IMPORT_USERNAME", ""),

    "password": os.getenv("GROK2API_IMPORT_PASSWORD", ""),

    "upload_mode": "build_auth_files",

    "limit": 1000,

    # Kept for UI compatibility only — registration auto-upload is immediate (no grouping).

    "upload_batch_size": int(os.getenv("GROK2API_UPLOAD_BATCH_SIZE", "50") or 50),

    # Register path: after each registration probe pass (immediate).

    "auto_upload_after_probe": False,

    # Relogin path: after relogin probe pass (immediate). Default off so CPA/Grok2API

    # mutual exclusion is not pre-broken by a checked box on both sides.

    "auto_upload_after_relogin": False,

}



DEFAULT_CPA_CONFIG: dict[str, Any] = {

    "base_url": os.getenv("GROK_REGISTER_PRO_CPA_BASE_URL", ""),

    "management_key": os.getenv("GROK_REGISTER_PRO_CPA_MANAGEMENT_KEY", ""),

    "limit": 1000,

    "auto_upload_after_probe": False,

    "auto_upload_after_relogin": False,

    # grok-register cpa_export.upload_cpa_auth_to_cloud knobs

    "upload_timeout": int(os.getenv("GROK_REGISTER_PRO_CPA_UPLOAD_TIMEOUT", "30") or 30),

    "upload_retries": int(os.getenv("GROK_REGISTER_PRO_CPA_UPLOAD_RETRIES", "3") or 3),

}



DEFAULT_SUB2API_CONFIG: dict[str, Any] = {

    "api_base": os.getenv("GROK2API_SUB2API_API_BASE", "") or os.getenv("SUB2API_API_BASE", ""),

    "api_key": os.getenv("GROK2API_SUB2API_API_KEY", "") or os.getenv("SUB2API_API_KEY", ""),

    "upload_enabled": True,

    "auto_upload_after_probe": False,

    "auto_upload_after_relogin": False,

    "timeout": int(os.getenv("GROK2API_SUB2API_UPLOAD_TIMEOUT", "30") or 30),

    "retries": int(os.getenv("GROK2API_SUB2API_UPLOAD_RETRIES", "3") or 3),

    "platform": "grok",

    "account_type": "oauth",

    "account_concurrency": 1,

    "account_priority": 1,

    "account_load_factor": 10,

    "account_rate_multiplier": 1.0,

    "account_group_ids": "",

    "default_proxy": "",

    "local_export": False,

    "local_export_dir": "",

    "limit": 1000,

}





DEFAULT_RELOGIN_CONFIG: dict[str, Any] = {

    "concurrency": int(os.getenv("GROK2API_RELOGIN_CONCURRENCY", "2") or 2),

    "stagger_ms": int(os.getenv("GROK2API_RELOGIN_STAGGER_MS", "200") or 200),

    "captcha_provider": "local",

    "yescaptcha_key": "",

    "local_solver_url": "http://127.0.0.1:5072",

    "proxy": os.getenv("GROK2API_RELOGIN_PROXY_POOL") or os.getenv("GROK2API_RELOGIN_PROXY", ""),

    "proxy_username": os.getenv("GROK2API_RELOGIN_PROXY_USERNAME", ""),

    "proxy_password": os.getenv("GROK2API_RELOGIN_PROXY_PASSWORD", ""),

    "proxy_strategy": os.getenv("GROK2API_RELOGIN_PROXY_STRATEGY", "round_robin"),

    # When true and relogin proxy pool is empty, reuse registration proxy pool.

    "use_registration_proxy_fallback": True,

    "probe_model": "grok-4.5",

}



ADMIN_AUTH_KEY = "admin_auth"

ADMIN_SESSION_SECRET_KEY = "admin_session_secret"

ADMIN_HASH_ITERATIONS = 210_000

# Min admin password length (login/setup + change-password share this).

ADMIN_PASSWORD_MIN_LEN = max(6, int(os.getenv("GROK_REGISTER_ADMIN_PASSWORD_MIN_LEN", "10") or 10))



# Auto registration schedule + failure fallback + system throttle policy.

DEFAULT_SCHEDULE_POLICY: dict[str, Any] = {

    "enabled": False,

    # interval minutes between auto batches (when no batch running)

    "interval_min": 30,

    # how many accounts each scheduled batch tries to register

    "batch_count": 10,

    # only run inside local hour window [start, end); end can be < start for overnight

    "window_start_hour": 0,

    "window_end_hour": 24,

    # max concurrent scheduled batches overlap guard is always on (skip if running)

    "skip_if_running": True,

    # failure fallback switches

    "fallback_enabled": True,

    "rotate_proxy_on_fail": True,

    "rotate_domain_on_fail": True,

    "rotate_mail_provider_on_fail": False,

    # after N consecutive failures in a rolling window, apply throttle

    "fail_threshold": 3,

    "fail_window_sec": 300,

    # throttle steps applied on pressure/fail streak

    "min_concurrency": 1,

    "min_global_inflight": 1,

    "min_probe_delay_sec": 5,

    "concurrency_step_down": 1,

    "global_inflight_step_down": 1,

    "probe_delay_step_up": 1,

    # system resource guard (host process view inside container)

    "sys_guard_enabled": True,

    "cpu_high_pct": 85,

    "mem_high_pct": 88,

    "cpu_critical_pct": 95,

    "mem_critical_pct": 95,

    # cooldown between auto throttle actions

    "throttle_cooldown_sec": 60,

    # restore toward baseline when healthy for this long

    "recover_after_sec": 300,

    "recover_step_up": 1,

}





def normalize_schedule_policy(raw: dict[str, Any] | None) -> dict[str, Any]:

    src = {**DEFAULT_SCHEDULE_POLICY, **(raw or {})}

    out: dict[str, Any] = {}

    for key, default in DEFAULT_SCHEDULE_POLICY.items():

        val = src.get(key, default)

        if isinstance(default, bool):

            if isinstance(val, str):

                out[key] = val.strip().lower() in {"1", "true", "yes", "on"}

            else:

                out[key] = bool(val)

        elif isinstance(default, int):

            try:

                n = int(val)

            except (TypeError, ValueError):

                n = int(default)

            out[key] = n

        else:

            out[key] = val if val is not None else default

    out["interval_min"] = max(1, min(24 * 60, int(out["interval_min"])))

    out["batch_count"] = max(1, min(1000, int(out["batch_count"])))

    out["window_start_hour"] = max(0, min(23, int(out["window_start_hour"])))

    out["window_end_hour"] = max(0, min(24, int(out["window_end_hour"])))

    out["fail_threshold"] = max(1, min(50, int(out["fail_threshold"])))

    out["fail_window_sec"] = max(30, min(3600, int(out["fail_window_sec"])))

    out["min_concurrency"] = max(1, min(20, int(out["min_concurrency"])))

    out["min_global_inflight"] = max(1, min(64, int(out["min_global_inflight"])))

    out["min_probe_delay_sec"] = max(0, min(600, int(out["min_probe_delay_sec"])))

    out["concurrency_step_down"] = max(1, min(10, int(out["concurrency_step_down"])))

    out["global_inflight_step_down"] = max(1, min(16, int(out["global_inflight_step_down"])))

    out["probe_delay_step_up"] = max(0, min(120, int(out["probe_delay_step_up"])))

    out["cpu_high_pct"] = max(20, min(99, int(out["cpu_high_pct"])))

    out["mem_high_pct"] = max(20, min(99, int(out["mem_high_pct"])))

    out["cpu_critical_pct"] = max(out["cpu_high_pct"], min(99, int(out["cpu_critical_pct"])))

    out["mem_critical_pct"] = max(out["mem_high_pct"], min(99, int(out["mem_critical_pct"])))

    out["throttle_cooldown_sec"] = max(10, min(1800, int(out["throttle_cooldown_sec"])))

    out["recover_after_sec"] = max(30, min(7200, int(out["recover_after_sec"])))

    out["recover_step_up"] = max(1, min(10, int(out["recover_step_up"])))

    return out





def get_schedule_policy() -> dict[str, Any]:

    return normalize_schedule_policy(_json_setting("schedule_policy") or {})





def set_schedule_policy(patch: dict[str, Any] | None, *, replace: bool = False) -> dict[str, Any]:

    base = {} if replace else (_json_setting("schedule_policy") or {})

    merged = {**base, **(patch or {})}

    cfg = normalize_schedule_policy(merged)

    _set_json_setting("schedule_policy", cfg)

    return cfg





def get_schedule_runtime() -> dict[str, Any]:

    raw = _json_setting("schedule_runtime") or {}

    if not isinstance(raw, dict):

        raw = {}

    return {

        "last_tick_at": float(raw.get("last_tick_at") or 0),

        "last_start_at": float(raw.get("last_start_at") or 0),

        "last_batch_id": str(raw.get("last_batch_id") or ""),

        "last_batch_settled": int(raw.get("last_batch_settled") or 0),

        "last_error": str(raw.get("last_error") or ""),

        "last_action": str(raw.get("last_action") or ""),

        "last_throttle_at": float(raw.get("last_throttle_at") or 0),

        "last_recover_at": float(raw.get("last_recover_at") or 0),

        "baseline_concurrency": int(raw.get("baseline_concurrency") or 0),

        "baseline_global_inflight": int(raw.get("baseline_global_inflight") or 0),

        "baseline_probe_delay_sec": int(raw.get("baseline_probe_delay_sec") or 0),

        "baseline_seeded": int(raw.get("baseline_seeded") or 0),

        "fail_events": list(raw.get("fail_events") or [])[-50:],

        "domain_index": int(raw.get("domain_index") or 0),

        "proxy_index": int(raw.get("proxy_index") or 0),

        "mail_provider_index": int(raw.get("mail_provider_index") or 0),

        "sticky_proxy": str(raw.get("sticky_proxy") or ""),

        "sticky_domain": str(raw.get("sticky_domain") or ""),

        "healthy_since": float(raw.get("healthy_since") or 0),

    }





def set_schedule_runtime(patch: dict[str, Any] | None) -> dict[str, Any]:

    cur = get_schedule_runtime()

    merged = {**cur, **(patch or {})}

    # keep fail_events bounded

    events = list(merged.get("fail_events") or [])

    merged["fail_events"] = events[-50:]

    _set_json_setting("schedule_runtime", merged)

    return get_schedule_runtime()





def note_schedule_failure(reason: str = "") -> dict[str, Any]:

    rt = get_schedule_runtime()

    events = list(rt.get("fail_events") or [])

    events.append({"at": time.time(), "reason": str(reason or "")[:200]})

    return set_schedule_runtime({"fail_events": events[-50:], "last_error": str(reason or "")[:300]})





def note_schedule_success() -> dict[str, Any]:

    return set_schedule_runtime({"last_error": "", "fail_events": []})





def _cpu_count() -> int:

    try:

        n = os.cpu_count() or 1

    except Exception:

        n = 1

    return max(1, int(n))





def sample_system_load() -> dict[str, Any]:

    """Best-effort host/container load sample without extra deps.



    Returns cpu_pct / mem_pct in 0..100. Missing values stay 0 with ok=False

    so callers can skip the system guard instead of crashing the tick.

    """

    out: dict[str, Any] = {

        "ok": False,

        "cpu_pct": 0.0,

        "mem_pct": 0.0,

        "load1": 0.0,

        "load5": 0.0,

        "load15": 0.0,

        "mem_total_mb": 0,

        "mem_used_mb": 0,

        "source": "",

    }

    sources: list[str] = []

    # CPU: loadavg / cores → approximate utilization (capped 100).

    try:

        load1, load5, load15 = os.getloadavg()

        cores = float(_cpu_count())

        out["load1"] = float(load1)

        out["load5"] = float(load5)

        out["load15"] = float(load15)

        out["cpu_pct"] = max(0.0, min(100.0, (float(load1) / cores) * 100.0))

        sources.append("loadavg")

    except (AttributeError, OSError):

        pass



    # Memory: Linux /proc/meminfo first (Docker containers include this).

    mem_ok = False

    try:

        info: dict[str, int] = {}

        with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as fh:

            for line in fh:

                if ":" not in line:

                    continue

                key, raw = line.split(":", 1)

                parts = raw.strip().split()

                if not parts:

                    continue

                try:

                    # values are kB

                    info[key.strip()] = int(parts[0])

                except (TypeError, ValueError):

                    continue

        total = int(info.get("MemTotal") or 0)

        available = int(info.get("MemAvailable") or 0)

        if total > 0:

            if available <= 0:

                free = int(info.get("MemFree") or 0)

                buffers = int(info.get("Buffers") or 0)

                cached = int(info.get("Cached") or 0)

                available = free + buffers + cached

            used = max(0, total - available)

            out["mem_total_mb"] = int(total / 1024)

            out["mem_used_mb"] = int(used / 1024)

            out["mem_pct"] = max(0.0, min(100.0, (used / float(total)) * 100.0))

            mem_ok = True

            sources.append("proc_meminfo")

    except Exception:

        mem_ok = False



    # macOS fallback via `vm_stat` (best-effort, only if /proc missing).

    if not mem_ok:

        try:

            import subprocess



            raw = subprocess.check_output(["vm_stat"], text=True, timeout=2.0)

            page_size = 4096

            stats: dict[str, int] = {}

            for line in raw.splitlines():

                if ":" not in line:

                    continue

                key, val = line.split(":", 1)

                digits = "".join(ch for ch in val if ch.isdigit())

                if digits:

                    stats[key.strip()] = int(digits)

                if "page size of" in line.lower():

                    maybe = "".join(ch for ch in line if ch.isdigit())

                    if maybe:

                        page_size = int(maybe)

            free = int(stats.get("Pages free") or 0)

            inactive = int(stats.get("Pages inactive") or 0)

            speculative = int(stats.get("Pages speculative") or 0)

            active = int(stats.get("Pages active") or 0)

            wired = int(stats.get("Pages wired down") or stats.get("Pages wired") or 0)

            compressed = int(stats.get("Pages occupied by compressor") or 0)

            total_pages = free + inactive + speculative + active + wired + compressed

            if total_pages > 0:

                used_pages = active + wired + compressed

                total_b = total_pages * page_size

                used_b = used_pages * page_size

                out["mem_total_mb"] = int(total_b / (1024 * 1024))

                out["mem_used_mb"] = int(used_b / (1024 * 1024))

                out["mem_pct"] = max(0.0, min(100.0, (used_b / float(total_b)) * 100.0))

                mem_ok = True

                sources.append("vm_stat")

        except Exception:

            pass



    out["ok"] = bool(sources)

    out["source"] = "+".join(sources) if sources else "unavailable"

    return out





def count_recent_failures(runtime: dict[str, Any] | None = None, *, window_sec: int = 300) -> int:

    rt = runtime if isinstance(runtime, dict) else get_schedule_runtime()

    now = time.time()

    window = max(30, int(window_sec or 300))

    n = 0

    for item in list(rt.get("fail_events") or []):

        try:

            at = float(item.get("at") or 0)

        except (TypeError, ValueError, AttributeError):

            continue

        if at > 0 and (now - at) <= window:

            n += 1

    return n





# Domain list separators: ASCII + CJK punctuation + whitespace / pipes.

# Must stay in sync with grok_build_adapter._domain_pool.

_DOMAIN_SPLIT_RE = re.compile(r"[\s,;|，、；]+")





def _domain_list_from_text(raw: str | None) -> list[str]:

    text = str(raw or "")

    if not text.strip():

        return []

    out: list[str] = []

    seen: set[str] = set()

    for part in _DOMAIN_SPLIT_RE.split(text):

        dom = part.strip().lstrip("@").strip(".").lower()

        if not dom or dom in seen:

            continue

        seen.add(dom)

        out.append(dom)

    return out





def _mail_provider_key_slot(provider: str) -> str:

    return {

        "moemail": "moemail_api_key",

        "yyds": "yyds_api_key",

        "gptmail": "gptmail_api_key",

        "cfmail": "cfmail_api_key",

        "duckmail": "duckmail_api_key",

        "outmail": "outmail_api_key",

    }.get(provider, "moemail_api_key")





def _mail_provider_domain_slot(provider: str) -> str:

    return {

        "moemail": "moemail_domain",

        "yyds": "yyds_domain",

        "gptmail": "gptmail_domain",

        "cfmail": "cfmail_domain",

        "duckmail": "duckmail_domain",

        "outmail": "outmail_anonymous_domain",

    }.get(provider, "moemail_domain")





def _configured_mail_providers(reg_cfg: dict[str, Any] | None = None) -> list[str]:

    cfg = reg_cfg if isinstance(reg_cfg, dict) else get_registration_config(include_secrets=True)

    order = ["moemail", "yyds", "gptmail", "cfmail", "duckmail", "outmail"]

    out: list[str] = []

    for prov in order:

        key = str(cfg.get(_mail_provider_key_slot(prov)) or "").strip()

        # DuckMail public domains work without API key.

        # Outmail can auth via session cookie without API key.

        if key or prov == "duckmail":

            out.append(prov)

        elif prov == "outmail" and (

            str(cfg.get("outmail_session_cookie") or "").strip()

            or str(cfg.get("outmail_api_base") or "").strip()

        ):

            out.append(prov)

    # Always keep the active provider even if key temporarily empty (user may use env).

    active = str(cfg.get("mail_provider") or "moemail").strip().lower() or "moemail"

    if active not in out:

        out.insert(0, active)

    return out





def ensure_schedule_baseline(

    runtime: dict[str, Any] | None = None,

    reg_cfg: dict[str, Any] | None = None,

) -> dict[str, Any]:

    """Capture user-facing concurrency knobs once so throttle can recover later."""

    rt = runtime if isinstance(runtime, dict) else get_schedule_runtime()

    cfg = reg_cfg if isinstance(reg_cfg, dict) else get_registration_config(include_secrets=False)

    if int(rt.get("baseline_seeded") or 0):

        return rt

    return set_schedule_runtime(

        {

            "baseline_concurrency": int(cfg.get("concurrency") or 10),

            "baseline_global_inflight": int(cfg.get("global_inflight") or 16),

            "baseline_probe_delay_sec": int(cfg.get("probe_delay_sec") or 30),

            "baseline_seeded": 1,

        }

    )





def refresh_schedule_baseline_from_config(reg_cfg: dict[str, Any] | None = None) -> dict[str, Any]:

    """Call when the user manually saves registration config — re-anchor recover target."""

    cfg = reg_cfg if isinstance(reg_cfg, dict) else get_registration_config(include_secrets=False)

    return set_schedule_runtime(

        {

            "baseline_concurrency": int(cfg.get("concurrency") or 10),

            "baseline_global_inflight": int(cfg.get("global_inflight") or 16),

            "baseline_probe_delay_sec": int(cfg.get("probe_delay_sec") or 30),

            "baseline_seeded": 1,

        }

    )





def _in_schedule_window(policy: dict[str, Any], *, now_ts: float | None = None) -> bool:

    start = int(policy.get("window_start_hour") or 0)

    end = int(policy.get("window_end_hour") or 24)

    if start == end:

        return True

    local = time.localtime(now_ts if now_ts is not None else time.time())

    hour = int(local.tm_hour)

    if start < end:

        return start <= hour < end

    # Overnight window, e.g. 22 → 6

    return hour >= start or hour < end





def _registration_running_now() -> bool:

    """True when adapter still has a non-terminal registration batch/session."""

    try:

        import grok_build_adapter as _adapter



        listed = _adapter.list_registration_sessions()

    except Exception:

        return False

    live_statuses = {

        "running",

        "starting",

        "stopping",

        "registering",

        "probing",

        "waiting_solver",

        "solving_turnstile",

        "queued",

    }

    for b in list(listed.get("batches") or []):

        st = str(b.get("status") or b.get("batch_status") or "").lower()

        if st in live_statuses:

            return True

    for s in list(listed.get("sessions") or []):

        st = str(s.get("status") or "").lower()

        if st in live_statuses:

            return True

    return False





def _batch_outcome(batch_id: str) -> dict[str, Any]:

    """Inspect a finished (or still-running) batch for schedule bookkeeping."""

    bid = str(batch_id or "").strip()

    if not bid:

        return {"ok": False, "terminal": False, "success": 0, "failed": 0, "status": ""}

    try:

        import grok_build_adapter as _adapter



        batch = _adapter.get_registration_batch(bid)

    except Exception as exc:  # noqa: BLE001

        return {

            "ok": False,

            "terminal": False,

            "success": 0,

            "failed": 0,

            "status": "error",

            "error": str(exc)[:200],

        }

    if not batch:

        return {"ok": False, "terminal": True, "success": 0, "failed": 0, "status": "missing"}

    st = str(batch.get("status") or batch.get("batch_status") or "").lower()

    success = int(batch.get("success") or batch.get("imported") or batch.get("ok") or 0)

    failed = int(batch.get("failed") or batch.get("fail") or 0)

    # Some adapters expose nested stats.

    try:

        success = max(success, int(batch.get("ok_count") or 0))

    except (TypeError, ValueError):

        pass

    terminal = st in {

        "done",

        "completed",

        "success",

        "imported",

        "partial",

        "failed",

        "error",

        "stopped",

        "cancelled",

        "interrupted",

    } or int(batch.get("running") or 0) == 0 and st not in {"", "running", "starting", "stopping"}

    # If adapter still reports running count, treat as non-terminal.

    try:

        if int(batch.get("running") or 0) > 0:

            terminal = False

    except (TypeError, ValueError):

        pass

    good = success > 0 and st not in {"failed", "error", "cancelled", "stopped", "interrupted"}

    return {

        "ok": good,

        "terminal": bool(terminal),

        "success": success,

        "failed": failed,

        "status": st or "unknown",

        "batch": batch,

    }





def apply_schedule_throttle(

    reason: str = "",

    *,

    critical: bool = False,

    policy: dict[str, Any] | None = None,

    force: bool = False,

) -> dict[str, Any]:

    """Step down concurrency / inflight and stretch probe delay."""

    pol = normalize_schedule_policy(policy or get_schedule_policy())

    rt = ensure_schedule_baseline()

    now = time.time()

    cooldown = int(pol.get("throttle_cooldown_sec") or 60)

    last = float(rt.get("last_throttle_at") or 0)

    if not force and last > 0 and (now - last) < cooldown:

        return {

            "ok": True,

            "throttled": False,

            "skipped": "cooldown",

            "runtime": rt,

            "actions": [],

        }



    cfg = get_registration_config(include_secrets=True)

    cur_c = int(cfg.get("concurrency") or 10)

    cur_g = int(cfg.get("global_inflight") or 16)

    cur_p = int(cfg.get("probe_delay_sec") or 30)

    min_c = int(pol.get("min_concurrency") or 1)

    min_g = int(pol.get("min_global_inflight") or 1)

    # probe_delay floor is the *minimum wait* we keep when throttling (not a max).

    # When stepping up delay we also respect this as lower bound of the new value.

    step_c = int(pol.get("concurrency_step_down") or 1)

    step_g = int(pol.get("global_inflight_step_down") or 1)

    step_p = int(pol.get("probe_delay_step_up") or 1)

    if critical:

        step_c = max(step_c, step_c * 2)

        step_g = max(step_g, step_g * 2)

        step_p = max(step_p, step_p * 2)



    new_c = max(min_c, cur_c - step_c)

    new_g = max(min_g, cur_g - step_g)

    new_p = min(600, max(cur_p, int(pol.get("min_probe_delay_sec") or 5)) + step_p)



    actions: list[str] = []

    patch: dict[str, Any] = {}

    if new_c < cur_c:

        patch["concurrency"] = new_c

        actions.append(f"concurrency {cur_c}→{new_c}")

    if new_g < cur_g:

        patch["global_inflight"] = new_g

        actions.append(f"global_inflight {cur_g}→{new_g}")

    if new_p > cur_p:

        patch["probe_delay_sec"] = new_p

        actions.append(f"probe_delay {cur_p}s→{new_p}s")



    if not patch:

        return {

            "ok": True,

            "throttled": False,

            "skipped": "already_at_floor",

            "runtime": rt,

            "actions": [],

            "config": cfg,

        }



    new_cfg = set_registration_config(patch, replace=False)

    action_text = "；".join(actions)

    why = str(reason or ("critical" if critical else "throttle"))[:200]

    rt = set_schedule_runtime(

        {

            "last_throttle_at": now,

            "last_action": f"throttle: {action_text} ({why})",

            "healthy_since": 0,

        }

    )

    return {

        "ok": True,

        "throttled": True,

        "critical": bool(critical),

        "actions": actions,

        "reason": why,

        "config": new_cfg,

        "runtime": rt,

    }





def maybe_recover_schedule(

    *,

    policy: dict[str, Any] | None = None,

    force: bool = False,

) -> dict[str, Any]:

    """Step concurrency knobs back toward the saved baseline when healthy."""

    pol = normalize_schedule_policy(policy or get_schedule_policy())

    rt = ensure_schedule_baseline()

    now = time.time()

    baseline_c = int(rt.get("baseline_concurrency") or 0)

    baseline_g = int(rt.get("baseline_global_inflight") or 0)

    baseline_p = int(rt.get("baseline_probe_delay_sec") or 0)

    if baseline_c <= 0 and baseline_g <= 0:

        return {"ok": True, "recovered": False, "skipped": "no_baseline", "runtime": rt}



    cfg = get_registration_config(include_secrets=True)

    cur_c = int(cfg.get("concurrency") or 10)

    cur_g = int(cfg.get("global_inflight") or 16)

    cur_p = int(cfg.get("probe_delay_sec") or 30)

    need = (

        (baseline_c > 0 and cur_c < baseline_c)

        or (baseline_g > 0 and cur_g < baseline_g)

        or (cur_p > baseline_p)

    )

    if not need:

        if not rt.get("healthy_since"):

            rt = set_schedule_runtime({"healthy_since": now})

        return {"ok": True, "recovered": False, "skipped": "at_baseline", "runtime": rt, "config": cfg}



    healthy_since = float(rt.get("healthy_since") or 0)

    if healthy_since <= 0:

        rt = set_schedule_runtime({"healthy_since": now})

        return {"ok": True, "recovered": False, "skipped": "health_timer_started", "runtime": rt}



    recover_after = int(pol.get("recover_after_sec") or 300)

    if not force and (now - healthy_since) < recover_after:

        return {

            "ok": True,

            "recovered": False,

            "skipped": "waiting_health_window",

            "wait_sec": int(recover_after - (now - healthy_since)),

            "runtime": rt,

        }



    step = int(pol.get("recover_step_up") or 1)

    patch: dict[str, Any] = {}

    actions: list[str] = []

    if baseline_c > 0 and cur_c < baseline_c:

        new_c = min(baseline_c, cur_c + step)

        if new_c > cur_c:

            patch["concurrency"] = new_c

            actions.append(f"concurrency {cur_c}→{new_c}")

    if baseline_g > 0 and cur_g < baseline_g:

        new_g = min(baseline_g, cur_g + max(1, step))

        if new_g > cur_g:

            patch["global_inflight"] = new_g

            actions.append(f"global_inflight {cur_g}→{new_g}")

    if cur_p > baseline_p:

        # Walk probe delay back down toward baseline.

        new_p = max(baseline_p, cur_p - max(1, int(pol.get("probe_delay_step_up") or 1)))

        if new_p < cur_p:

            patch["probe_delay_sec"] = new_p

            actions.append(f"probe_delay {cur_p}s→{new_p}s")



    if not patch:

        return {"ok": True, "recovered": False, "skipped": "nothing_to_change", "runtime": rt}



    new_cfg = set_registration_config(patch, replace=False)

    rt = set_schedule_runtime(

        {

            "last_recover_at": now,

            "last_action": "recover: " + "；".join(actions),

            # Keep healthy_since so next step can continue after another window,

            # unless we fully reached baseline.

            "healthy_since": now

            if (

                int(new_cfg.get("concurrency") or 0) >= baseline_c

                and int(new_cfg.get("global_inflight") or 0) >= baseline_g

                and int(new_cfg.get("probe_delay_sec") or 0) <= baseline_p

            )

            else healthy_since,

        }

    )

    return {

        "ok": True,

        "recovered": True,

        "actions": actions,

        "config": new_cfg,

        "runtime": rt,

    }





def reset_schedule_throttle() -> dict[str, Any]:

    """Restore registration knobs to baseline and clear fail streak."""

    rt = ensure_schedule_baseline()

    baseline_c = int(rt.get("baseline_concurrency") or 0)

    baseline_g = int(rt.get("baseline_global_inflight") or 0)

    baseline_p = int(rt.get("baseline_probe_delay_sec") or 30)

    patch: dict[str, Any] = {}

    if baseline_c > 0:

        patch["concurrency"] = baseline_c

    if baseline_g > 0:

        patch["global_inflight"] = baseline_g

    patch["probe_delay_sec"] = max(0, baseline_p)

    cfg = set_registration_config(patch, replace=False) if patch else get_registration_config(include_secrets=True)

    rt = set_schedule_runtime(

        {

            "fail_events": [],

            "last_error": "",

            "last_action": "reset_throttle",

            "last_throttle_at": 0,

            "healthy_since": time.time(),

            "sticky_domain": "",

            "sticky_proxy": "",

        }

    )

    return {"ok": True, "config": cfg, "runtime": rt}





def rotate_registration_resources(

    *,

    rotate_proxy: bool = False,

    rotate_domain: bool = False,

    rotate_mail_provider: bool = False,

    reason: str = "",

) -> dict[str, Any]:

    """Advance proxy/domain/mail-provider indices and pin sticky overrides for next batch."""

    cfg = get_registration_config(include_secrets=True)

    rt = get_schedule_runtime()

    actions: list[str] = []

    runtime_patch: dict[str, Any] = {}

    reg_patch: dict[str, Any] = {}



    if rotate_proxy:

        try:

            from proxy_pool import parse_proxy_pool



            pool = parse_proxy_pool(

                str(cfg.get("proxy") or ""),

                username=str(cfg.get("proxy_username") or "") or None,

                password=str(cfg.get("proxy_password") or "") or None,

                fallback_env=True,

            )

        except Exception:

            pool = []

        if pool:

            idx = (int(rt.get("proxy_index") or 0) + 1) % len(pool)

            runtime_patch["proxy_index"] = idx

            runtime_patch["sticky_proxy"] = pool[idx]

            actions.append(f"proxy→#{idx + 1}/{len(pool)}")

        else:

            actions.append("proxy_pool_empty")



    if rotate_domain:

        domains = _domain_list_from_text(str(cfg.get("domain") or ""))

        if domains:

            idx = (int(rt.get("domain_index") or 0) + 1) % len(domains)

            picked = domains[idx]

            runtime_patch["domain_index"] = idx

            runtime_patch["sticky_domain"] = picked

            # Keep the full multi-domain pool in registration_config; only pin

            # sticky_domain for the next scheduled batch.

            actions.append(f"domain→{picked}")

        else:

            # Empty domain means provider auto-pick; just bump index as a signal.

            runtime_patch["domain_index"] = int(rt.get("domain_index") or 0) + 1

            runtime_patch["sticky_domain"] = ""

            actions.append("domain_auto")



    if rotate_mail_provider:

        providers = _configured_mail_providers(cfg)

        if len(providers) > 1:

            cur = str(cfg.get("mail_provider") or providers[0]).strip().lower()

            try:

                cur_i = providers.index(cur)

            except ValueError:

                cur_i = 0

            idx = (cur_i + 1) % len(providers)

            nxt = providers[idx]

            runtime_patch["mail_provider_index"] = idx

            reg_patch["mail_provider"] = nxt

            # Switch unified domain/api_key view to the next provider's slots.

            reg_patch["domain"] = str(cfg.get(_mail_provider_domain_slot(nxt)) or "")

            reg_patch["api_key"] = str(cfg.get(_mail_provider_key_slot(nxt)) or "")

            actions.append(f"mail_provider→{nxt}")

        else:

            actions.append("mail_provider_single")



    new_cfg = set_registration_config(reg_patch, replace=False) if reg_patch else cfg

    why = str(reason or "rotate")[:160]

    runtime_patch["last_action"] = "rotate: " + ("；".join(actions) if actions else "noop") + f" ({why})"

    new_rt = set_schedule_runtime(runtime_patch)

    return {

        "ok": True,

        "actions": actions,

        "config": new_cfg,

        "runtime": new_rt,

        "sticky_proxy": str(new_rt.get("sticky_proxy") or runtime_patch.get("sticky_proxy") or ""),

        "sticky_domain": str(new_rt.get("sticky_domain") or runtime_patch.get("sticky_domain") or ""),

    }





def resolve_schedule_registration_overrides() -> dict[str, Any]:

    """Build start_registration kwargs from current config + sticky rotation state."""

    cfg = get_registration_config(include_secrets=True)

    rt = get_schedule_runtime()

    sticky_proxy = str(rt.get("sticky_proxy") or "").strip()

    sticky_domain = str(rt.get("sticky_domain") or "").strip()

    proxy = sticky_proxy or str(cfg.get("proxy") or "")

    domain = sticky_domain or str(cfg.get("domain") or "")

    # When a sticky proxy is pinned, force sticky strategy so the whole batch

    # uses that egress until the next rotation.

    strategy = "sticky" if sticky_proxy else str(cfg.get("proxy_strategy") or "round_robin")

    return {

        "proxy": proxy or None,

        "proxy_username": str(cfg.get("proxy_username") or "") or None,

        "proxy_password": str(cfg.get("proxy_password") or "") or None,

        "proxy_strategy": strategy or None,

        "moemail_api_key": str(cfg.get("api_key") or "") or None,

        "moemail_base_url": str(cfg.get("base_url") or "") or None,

        "prefix": str(cfg.get("prefix") or "") or None,

        "domain": domain or None,

        "expiry_ms": cfg.get("expiry_ms"),

        "mail_provider": str(cfg.get("mail_provider") or "moemail") or None,

        "captcha_provider": "local",

        "local_solver_url": str(cfg.get("local_solver_url") or "http://127.0.0.1:5072"),

        "yescaptcha_key": "",

        "count": int(cfg.get("count") or 1),

        "concurrency": int(cfg.get("concurrency") or 10),

        "stagger_ms": int(cfg.get("stagger_ms") or 800),

        "probe_delay_sec": int(cfg.get("probe_delay_sec") or 30),

        "skip_probe": bool(cfg.get("skip_probe")),

        "sso_only": bool(cfg.get("sso_only")),

        "global_inflight": int(cfg.get("global_inflight") or 16),

        "captcha_concurrency": int(cfg.get("captcha_concurrency") or 1),

        "captcha_use_proxy": bool(cfg.get("captcha_use_proxy", True)),

    }





def get_schedule_status() -> dict[str, Any]:

    policy = get_schedule_policy()

    runtime = get_schedule_runtime()

    reg = get_registration_config(include_secrets=False)

    sys_load = sample_system_load()

    recent_fails = count_recent_failures(runtime, window_sec=int(policy.get("fail_window_sec") or 300))

    interval = max(1, int(policy.get("interval_min") or 30))

    last_start = float(runtime.get("last_start_at") or 0)

    next_due = (last_start + interval * 60.0) if last_start > 0 else 0.0

    return {

        "ok": True,

        "policy": policy,

        "runtime": runtime,

        "system": sys_load,

        "registration": {

            "concurrency": int(reg.get("concurrency") or 10),

            "global_inflight": int(reg.get("global_inflight") or 16),

            "global_inflight_active": int(reg.get("global_inflight_active") or 0),

            "probe_delay_sec": int(reg.get("probe_delay_sec") or 30),

            "skip_probe": bool(reg.get("skip_probe")),

            "mail_provider": str(reg.get("mail_provider") or ""),

            "domain": str(reg.get("domain") or ""),

            "proxy_strategy": str(reg.get("proxy_strategy") or ""),

        },

        "baseline": {

            "concurrency": int(runtime.get("baseline_concurrency") or 0),

            "global_inflight": int(runtime.get("baseline_global_inflight") or 0),

            "probe_delay_sec": int(runtime.get("baseline_probe_delay_sec") or 0),

        },

        "recent_failures": recent_fails,

        "registration_running": _registration_running_now(),

        "in_window": _in_schedule_window(policy),

        "next_due_at": next_due,

        "seconds_to_next": max(0, int(next_due - time.time())) if next_due > 0 else None,

    }





def evaluate_schedule_tick(

    *,

    start_fn: Any | None = None,

    force: bool = False,

    now_ts: float | None = None,

) -> dict[str, Any]:

    """One scheduler tick: observe last batch, guard system, maybe start a batch.



    ``start_fn`` should accept the kwargs from ``resolve_schedule_registration_overrides``

    (with count overridden by policy.batch_count) and return a dict like

    ``start_registration`` (``ok``, ``batch_id`` / ``id``, ``error``).

    """

    now = float(now_ts if now_ts is not None else time.time())

    policy = get_schedule_policy()

    runtime = ensure_schedule_baseline()

    set_schedule_runtime({"last_tick_at": now})

    actions: list[dict[str, Any]] = []

    sys_load = sample_system_load()



    # 1) Close out previous scheduled batch if it finished.

    last_bid = str(runtime.get("last_batch_id") or "").strip()

    last_settled = bool(runtime.get("last_batch_settled"))

    if last_bid and not last_settled:

        outcome = _batch_outcome(last_bid)

        if outcome.get("terminal"):

            if outcome.get("ok"):

                note_schedule_success()

                set_schedule_runtime(

                    {

                        "last_batch_settled": 1,

                        "last_action": f"batch_ok {last_bid} success={outcome.get('success')}",

                        "healthy_since": float(runtime.get("healthy_since") or 0) or now,

                    }

                )

                actions.append({"type": "batch_ok", "batch_id": last_bid, **{k: outcome[k] for k in ("success", "failed", "status")}})

            else:

                note_schedule_failure(

                    f"batch {last_bid} status={outcome.get('status')} success={outcome.get('success')} failed={outcome.get('failed')}"

                )

                set_schedule_runtime({"last_batch_settled": 1})

                actions.append(

                    {

                        "type": "batch_fail",

                        "batch_id": last_bid,

                        "status": outcome.get("status"),

                        "success": outcome.get("success"),

                        "failed": outcome.get("failed"),

                    }

                )

                if policy.get("fallback_enabled"):

                    rot = rotate_registration_resources(

                        rotate_proxy=bool(policy.get("rotate_proxy_on_fail")),

                        rotate_domain=bool(policy.get("rotate_domain_on_fail")),

                        rotate_mail_provider=bool(policy.get("rotate_mail_provider_on_fail")),

                        reason=f"batch_fail:{outcome.get('status')}",

                    )

                    actions.append({"type": "rotate", "actions": rot.get("actions") or []})

                    recent = count_recent_failures(window_sec=int(policy.get("fail_window_sec") or 300))

                    if recent >= int(policy.get("fail_threshold") or 3):

                        th = apply_schedule_throttle(

                            reason=f"fail_streak={recent}",

                            critical=False,

                            policy=policy,

                        )

                        actions.append({"type": "throttle", **{k: th.get(k) for k in ("throttled", "actions", "skipped")}})



    # 2) System resource guard.

    # IMPORTANT:

    # - When schedule is disabled, this tick must NOT rewrite the user's saved

    #   concurrency / global_inflight. That permanently turns "threads=10" into

    #   "threads=1" mid-run on shared hosts (e.g. CLIProxyAPI eating CPU) and

    #   makes manual batches look frozen after a few successes.

    # - Persist throttle/recover only for enabled auto-schedule mode.

    # - Critical still blocks *scheduled* auto-starts; manual /admin 开始 is

    #   unaffected because it does not go through this tick.

    running = _registration_running_now()

    schedule_on = bool(policy.get("enabled"))

    if policy.get("sys_guard_enabled") and sys_load.get("ok"):

        cpu = float(sys_load.get("cpu_pct") or 0)

        mem = float(sys_load.get("mem_pct") or 0)

        cpu_hi = float(policy.get("cpu_high_pct") or 85)

        mem_hi = float(policy.get("mem_high_pct") or 88)

        cpu_crit = float(policy.get("cpu_critical_pct") or 95)

        mem_crit = float(policy.get("mem_critical_pct") or 95)

        critical = cpu >= cpu_crit or mem >= mem_crit

        high = cpu >= cpu_hi or mem >= mem_hi

        if critical or high:

            if schedule_on:

                th = apply_schedule_throttle(

                    reason=f"sys cpu={cpu:.0f}% mem={mem:.0f}%",

                    critical=critical,

                    policy=policy,

                )

                actions.append(

                    {

                        "type": "sys_guard",

                        "critical": critical,

                        "cpu_pct": cpu,

                        "mem_pct": mem,

                        "throttled": th.get("throttled"),

                        "throttle_actions": th.get("actions") or [],

                        "skipped": th.get("skipped"),

                        "persist": True,

                    }

                )

            else:

                # Observe only — keep manual power-mode knobs intact.

                set_schedule_runtime(

                    {

                        "last_action": (

                            f"sys_{'critical' if critical else 'high'}_observe "

                            f"cpu={cpu:.0f}% mem={mem:.0f}% (manual mode, no persist)"

                        ),

                        "healthy_since": 0 if critical else float(

                            (get_schedule_runtime() or {}).get("healthy_since") or 0

                        ),

                    }

                )

                actions.append(

                    {

                        "type": "sys_guard",

                        "critical": critical,

                        "cpu_pct": cpu,

                        "mem_pct": mem,

                        "throttled": False,

                        "throttle_actions": [],

                        "skipped": "manual_mode_no_persist",

                        "persist": False,

                    }

                )

            if critical and schedule_on and not force:

                set_schedule_runtime(

                    {

                        "last_action": f"sys_critical_pause cpu={cpu:.0f}% mem={mem:.0f}%",

                        "healthy_since": 0,

                    }

                )

                return {

                    "ok": True,

                    "started": False,

                    "skipped": "sys_critical",

                    "actions": actions,

                    "system": sys_load,

                    "status": get_schedule_status(),

                }

        elif not high and schedule_on:

            # Only recover auto-schedule knobs when schedule is enabled.

            recent = count_recent_failures(window_sec=int(policy.get("fail_window_sec") or 300))

            if recent < int(policy.get("fail_threshold") or 3):

                rec = maybe_recover_schedule(policy=policy)

                if rec.get("recovered"):

                    actions.append({"type": "recover", "actions": rec.get("actions") or []})



    # 3) Decide whether to start a scheduled batch.

    if not policy.get("enabled") and not force:

        return {

            "ok": True,

            "started": False,

            "skipped": "disabled",

            "actions": actions,

            "system": sys_load,

            "status": get_schedule_status(),

        }



    if not _in_schedule_window(policy, now_ts=now) and not force:

        return {

            "ok": True,

            "started": False,

            "skipped": "outside_window",

            "actions": actions,

            "system": sys_load,

            "status": get_schedule_status(),

        }



    # Even "run now" refuses to stack on a live batch when skip_if_running is on.

    if policy.get("skip_if_running") and running:

        return {

            "ok": True,

            "started": False,

            "skipped": "already_running",

            "actions": actions,

            "system": sys_load,

            "status": get_schedule_status(),

        }



    runtime = get_schedule_runtime()

    interval_sec = max(1, int(policy.get("interval_min") or 30)) * 60

    last_start = float(runtime.get("last_start_at") or 0)

    if not force and last_start > 0 and (now - last_start) < interval_sec:

        return {

            "ok": True,

            "started": False,

            "skipped": "interval",

            "wait_sec": int(interval_sec - (now - last_start)),

            "actions": actions,

            "system": sys_load,

            "status": get_schedule_status(),

        }



    if start_fn is None:

        return {

            "ok": False,

            "started": False,

            "skipped": "no_start_fn",

            "error": "start_fn is required to launch a scheduled batch",

            "actions": actions,

            "system": sys_load,

            "status": get_schedule_status(),

        }



    overrides = resolve_schedule_registration_overrides()

    overrides["count"] = max(1, int(policy.get("batch_count") or 1))

    # Apply global inflight cap before workers start.

    try:

        import grok_build_adapter as _adapter



        _adapter.set_global_reg_inflight_limit(overrides.get("global_inflight"))

    except Exception:

        pass



    try:

        result = start_fn(**{k: v for k, v in overrides.items() if k != "global_inflight"})

    except TypeError:

        # Some start_fn implementations may not accept every kwarg.

        try:

            result = start_fn(

                count=overrides.get("count"),

                concurrency=overrides.get("concurrency"),

                proxy=overrides.get("proxy"),

                proxy_username=overrides.get("proxy_username"),

                proxy_password=overrides.get("proxy_password"),

                proxy_strategy=overrides.get("proxy_strategy"),

                domain=overrides.get("domain"),

                mail_provider=overrides.get("mail_provider"),

                moemail_api_key=overrides.get("moemail_api_key"),

                moemail_base_url=overrides.get("moemail_base_url"),

                stagger_ms=overrides.get("stagger_ms"),

                probe_delay_sec=overrides.get("probe_delay_sec"),

                skip_probe=overrides.get("skip_probe"),

                sso_only=overrides.get("sso_only"),

            )

        except Exception as exc:  # noqa: BLE001

            note_schedule_failure(f"start_exception: {exc}")

            set_schedule_runtime({"last_action": f"start_error: {exc}"[:240]})

            return {

                "ok": False,

                "started": False,

                "error": str(exc)[:300],

                "actions": actions,

                "system": sys_load,

                "status": get_schedule_status(),

            }

    except Exception as exc:  # noqa: BLE001

        note_schedule_failure(f"start_exception: {exc}")

        set_schedule_runtime({"last_action": f"start_error: {exc}"[:240]})

        return {

            "ok": False,

            "started": False,

            "error": str(exc)[:300],

            "actions": actions,

            "system": sys_load,

            "status": get_schedule_status(),

        }



    if not isinstance(result, dict):

        result = {"ok": bool(result), "result": result}



    if not result.get("ok"):

        err = str(result.get("error") or "start failed")[:300]

        note_schedule_failure(err)

        set_schedule_runtime({"last_action": f"start_failed: {err}"[:240]})

        if policy.get("fallback_enabled"):

            rot = rotate_registration_resources(

                rotate_proxy=bool(policy.get("rotate_proxy_on_fail")),

                rotate_domain=bool(policy.get("rotate_domain_on_fail")),

                rotate_mail_provider=bool(policy.get("rotate_mail_provider_on_fail")),

                reason="start_failed",

            )

            actions.append({"type": "rotate", "actions": rot.get("actions") or []})

        return {

            "ok": False,

            "started": False,

            "error": err,

            "result": result,

            "actions": actions,

            "system": sys_load,

            "status": get_schedule_status(),

        }



    batch_id = str(result.get("batch_id") or result.get("id") or "")

    set_schedule_runtime(

        {

            "last_start_at": now,

            "last_batch_id": batch_id,

            "last_batch_settled": 0,

            "last_error": "",

            "last_action": f"started batch={batch_id} count={overrides.get('count')}",

        }

    )

    actions.append({"type": "started", "batch_id": batch_id, "count": overrides.get("count")})

    return {

        "ok": True,

        "started": True,

        "batch_id": batch_id,

        "result": result,

        "actions": actions,

        "system": sys_load,

        "status": get_schedule_status(),

    }





def _urlopen(req: urllib.request.Request, *, timeout: float | int):

    try:

        import certifi

    except ImportError as exc:

        raise RuntimeError("certifi is required for HTTPS requests; install project requirements") from exc

    context = ssl.create_default_context(cafile=certifi.where())

    return urllib.request.urlopen(req, timeout=timeout, context=context)





def is_safe_outbound_url(

    url: str,

    *,

    allow_http: bool = False,

    allow_private: bool | None = None,

) -> tuple[bool, str]:

    """Validate admin-configured outbound base URLs (SSRF guard).



    Returns (ok, reason).

    Defaults (server-friendly):

      - https preferred; http allowed via GROK_REGISTER_ALLOW_HTTP_URLS=1

      - private / loopback hosts ALLOWED by default (Docker/LAN Grok2API/CPA)

      - cloud metadata hosts still blocked

    Set GROK_REGISTER_ALLOW_PRIVATE_URLS=0 to forbid private targets.

    """

    text = str(url or "").strip()

    if not text:

        return False, "地址为空"

    try:

        parsed = urllib.parse.urlsplit(text)

    except Exception:

        return False, "地址无法解析"

    scheme = (parsed.scheme or "").lower()

    if scheme not in {"https", "http"}:

        return False, "仅允许 http:// 或 https://"

    if scheme == "http" and not allow_http:

        if os.getenv("GROK_REGISTER_ALLOW_HTTP_URLS", "").strip().lower() not in {

            "1",

            "true",

            "yes",

            "on",

        }:

            return False, "默认仅允许 https://（如需 http 设 GROK_REGISTER_ALLOW_HTTP_URLS=1）"

    host = (parsed.hostname or "").strip().lower()

    if not host:

        return False, "缺少主机名"



    def _private_allowed() -> bool:

        if allow_private is not None:

            return bool(allow_private)

        # Default ALLOW private/LAN so Docker/internal Grok2API works out of the box.

        # Opt-out with GROK_REGISTER_ALLOW_PRIVATE_URLS=0.

        raw = os.getenv("GROK_REGISTER_ALLOW_PRIVATE_URLS")

        if raw is None or str(raw).strip() == "":

            return True

        return str(raw).strip().lower() in {"1", "true", "yes", "on"}



    # Always block cloud metadata endpoints even when private is allowed.

    if host in {"metadata", "metadata.google.internal"} or host.endswith(".internal"):

        if host in {"metadata", "metadata.google.internal"} or host == "metadata.google.internal":

            return False, "禁止 metadata 主机"

        # bare "*.internal" is often corp DNS — only block explicit metadata names above.



    if host in {"metadata.google.internal", "metadata"}:

        return False, "禁止 metadata 主机"

    # Link-local metadata IP

    if host in {"169.254.169.254", "fd00:ec2::254"}:

        return False, "禁止云 metadata 地址"



    private_ok = _private_allowed()

    if host in {"localhost", "0.0.0.0"} or host.endswith(".localhost") or host.startswith("127."):

        if not private_ok:

            return False, "禁止指向本机地址（可设 GROK_REGISTER_ALLOW_PRIVATE_URLS=1）"

        return True, ""



    try:

        import ipaddress



        ip = ipaddress.ip_address(host)

        if ip.exploded == "169.254.169.254" or str(ip) == "169.254.169.254":

            return False, "禁止云 metadata 地址"

        if not private_ok and (

            ip.is_private

            or ip.is_loopback

            or ip.is_link_local

            or ip.is_reserved

            or ip.is_multicast

            or ip.is_unspecified

        ):

            return False, f"禁止私网/保留地址 {host}"

    except ValueError:

        if host in {"host.docker.internal", "gateway.docker.internal"} and not private_ok:

            return False, "禁止 docker 内部主机名"

    return True, ""





def require_safe_outbound_url(url: str, *, label: str = "地址") -> str:

    """Normalize + validate; raise ValueError when unsafe."""

    text = str(url or "").strip().rstrip("/")

    if not text:

        return ""

    ok, reason = is_safe_outbound_url(text)

    if not ok:

        raise ValueError(f"{label}不安全：{reason}")

    return text





def _connect() -> sqlite3.Connection:

    # Ensure parent always exists — "unable to open database file" is often a missing dir.

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    # timeout: wait for locks instead of failing immediately under concurrent readers/writers.

    conn = sqlite3.connect(str(DB_PATH), timeout=30.0, check_same_thread=False)

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=WAL")

    conn.execute("PRAGMA busy_timeout=30000")

    conn.execute("PRAGMA synchronous=NORMAL")

    conn.execute("PRAGMA foreign_keys=ON")

    return conn





def init_db() -> None:

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    AUTH_MAP_DIR.mkdir(parents=True, exist_ok=True)

    CPA_DIR.mkdir(parents=True, exist_ok=True)

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    (DATA_DIR / "register_sso").mkdir(parents=True, exist_ok=True)

    with _connect() as conn:

        conn.execute(

            """

            CREATE TABLE IF NOT EXISTS settings (

              key TEXT PRIMARY KEY,

              value TEXT NOT NULL,

              updated_at REAL NOT NULL

            )

            """

        )

        conn.execute(

            """

            CREATE TABLE IF NOT EXISTS accounts (

              email TEXT PRIMARY KEY,

              password TEXT,

              sso TEXT,

              auth_key TEXT NOT NULL,

              user_id TEXT,

              access_token TEXT,

              refresh_token TEXT,

              id_token TEXT,

              expires_at TEXT,

              oidc_issuer TEXT,

              oidc_client_id TEXT,

              grok2api_auth_path TEXT,

              cpa_auth_path TEXT,

              grok2api_auth_json TEXT,

              cpa_auth_json TEXT,

              status TEXT NOT NULL DEFAULT 'registered',

              batch_id TEXT,

              session_id TEXT,

              last_probe_json TEXT,

              last_probe_at REAL,

              created_at REAL NOT NULL,

              updated_at REAL NOT NULL,

              raw_json TEXT NOT NULL

            )

            """

        )

        conn.execute(

            """

            CREATE TABLE IF NOT EXISTS remote_accounts (

              provider TEXT NOT NULL,

              remote_id TEXT NOT NULL,

              email TEXT NOT NULL,

              classification TEXT NOT NULL DEFAULT '',

              http_status INTEGER,

              action TEXT NOT NULL DEFAULT '',

              reason TEXT NOT NULL DEFAULT '',

              auth_status TEXT NOT NULL DEFAULT '',

              disabled INTEGER,

              model TEXT NOT NULL DEFAULT '',

              raw_json TEXT NOT NULL DEFAULT '',

              seen_at REAL NOT NULL,

              PRIMARY KEY(provider, remote_id)

            )

            """

        )

        conn.execute(

            """

            CREATE TABLE IF NOT EXISTS account_recycle_bin (

              email TEXT PRIMARY KEY,

              account_json TEXT NOT NULL,

              deleted_at REAL NOT NULL,

              backup_path TEXT NOT NULL DEFAULT '',

              source TEXT NOT NULL DEFAULT 'delete',

              restore_count INTEGER NOT NULL DEFAULT 0

            )

            """

        )

        conn.execute(

            """

            CREATE TABLE IF NOT EXISTS unassigned_sso (

              token_hash TEXT PRIMARY KEY,

              sso TEXT NOT NULL,

              source TEXT NOT NULL,

              created_at REAL NOT NULL

            )

            """

        )

        _ensure_account_columns(conn)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts_updated ON accounts(updated_at)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts_batch ON accounts(batch_id)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_remote_accounts_email ON remote_accounts(email)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_remote_accounts_action ON remote_accounts(action)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_remote_accounts_email_seen ON remote_accounts(email, seen_at)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts_email_lower ON accounts(email)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_account_recycle_deleted ON account_recycle_bin(deleted_at)")





def _ensure_account_columns(conn: sqlite3.Connection) -> None:

    rows = conn.execute("PRAGMA table_info(accounts)").fetchall()

    columns = {str(r["name"]) for r in rows}

    if "last_probe_json" not in columns:

        conn.execute("ALTER TABLE accounts ADD COLUMN last_probe_json TEXT")

    if "last_probe_at" not in columns:

        conn.execute("ALTER TABLE accounts ADD COLUMN last_probe_at REAL")

    if "relogin_requested_at" not in columns:

        conn.execute("ALTER TABLE accounts ADD COLUMN relogin_requested_at REAL")

    if "relogin_status" not in columns:

        conn.execute("ALTER TABLE accounts ADD COLUMN relogin_status TEXT NOT NULL DEFAULT ''")

    if "grok2api_auth_json" not in columns:

        conn.execute("ALTER TABLE accounts ADD COLUMN grok2api_auth_json TEXT")

        conn.execute(

            """

            UPDATE accounts

            SET grok2api_auth_json = raw_json

            WHERE raw_json IS NOT NULL AND raw_json != ''

              AND (grok2api_auth_json IS NULL OR grok2api_auth_json = '')

            """

        )

    if "cpa_auth_json" not in columns:

        conn.execute("ALTER TABLE accounts ADD COLUMN cpa_auth_json TEXT")

    # One-shot: rewrite legacy CLI auth-map rows into Grok2API import documents.

    # Safe to re-run — only touches rows that still look like the old map.

    try:

        legacy_rows = conn.execute(

            """

            SELECT email, access_token, refresh_token, id_token, expires_at,

                   oidc_client_id, user_id, grok2api_auth_json

            FROM accounts

            WHERE access_token IS NOT NULL AND access_token != ''

              AND (

                grok2api_auth_json IS NULL OR grok2api_auth_json = ''

                OR grok2api_auth_json LIKE '%"auth_mode"%'

                OR grok2api_auth_json LIKE '%https://auth.x.ai::%'

              )

            """

        ).fetchall()

        now_ts = time.time()

        for row in legacy_rows:

            email = str(row["email"] or "").strip().lower()

            if not email:

                continue

            raw = str(row["grok2api_auth_json"] or "").strip()

            # Already canonical?

            if raw:

                try:

                    parsed = json.loads(raw)

                    if (

                        isinstance(parsed, dict)

                        and parsed.get("provider") == "grok_build"

                        and parsed.get("access_token")

                        and "key" not in parsed

                        and "accounts" not in parsed

                    ):

                        continue

                except Exception:

                    pass

            doc = _build_grok2api_auth_document(

                {

                    "access_token": row["access_token"] or "",

                    "refresh_token": row["refresh_token"] or "",

                    "id_token": row["id_token"] or "",

                    "expires_at": row["expires_at"] or "",

                    "oidc_client_id": row["oidc_client_id"] or "",

                    "user_id": row["user_id"] or "",

                    "email": email,

                },

                email,

            )

            if not doc.get("access_token") and not doc.get("refresh_token"):

                continue

            conn.execute(

                "UPDATE accounts SET grok2api_auth_json = ?, updated_at = ? WHERE email = ?",

                (json.dumps(doc, ensure_ascii=False), now_ts, email),

            )

            # Do not write auth files during migration; export path materializes them.

    except Exception as exc:  # noqa: BLE001

        print(f"[register-pro] grok2api_auth_json migration skip: {exc}")





    if "cpa_pushed" not in columns:

        conn.execute("ALTER TABLE accounts ADD COLUMN cpa_pushed INTEGER NOT NULL DEFAULT 0")

    if "cpa_pushed_at" not in columns:

        conn.execute("ALTER TABLE accounts ADD COLUMN cpa_pushed_at REAL")

    if "sub2_pushed" not in columns:

        conn.execute("ALTER TABLE accounts ADD COLUMN sub2_pushed INTEGER NOT NULL DEFAULT 0")

    if "sub2_pushed_at" not in columns:

        conn.execute("ALTER TABLE accounts ADD COLUMN sub2_pushed_at REAL")

    if "grok2api_pushed" not in columns:

        conn.execute("ALTER TABLE accounts ADD COLUMN grok2api_pushed INTEGER NOT NULL DEFAULT 0")

    if "grok2api_pushed_at" not in columns:

        conn.execute("ALTER TABLE accounts ADD COLUMN grok2api_pushed_at REAL")



def _json_setting(key: str) -> Any | None:

    init_db()

    with _connect() as conn:

        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()

    if not row:

        return None

    return json.loads(str(row["value"]))





def _set_json_setting(key: str, value: Any) -> None:

    init_db()

    with _connect() as conn:

        conn.execute(

            """

            INSERT INTO settings(key, value, updated_at)

            VALUES (?, ?, ?)

            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at

            """,

            (key, json.dumps(value, ensure_ascii=False), time.time()),

        )





def _admin_password_hash(password: str, salt: str) -> str:

    digest = hashlib.pbkdf2_hmac(

        "sha256",

        password.encode("utf-8"),

        salt.encode("utf-8"),

        ADMIN_HASH_ITERATIONS,

    )

    return base64.urlsafe_b64encode(digest).decode("ascii")





def admin_auth_state() -> dict[str, Any]:

    data = _json_setting(ADMIN_AUTH_KEY) or {}

    return {

        "setup_required": not bool(data.get("password_hash")),

        "updated_at": data.get("updated_at"),

        "password_version": int(data.get("password_version") or 0),

        "min_password_len": ADMIN_PASSWORD_MIN_LEN,

    }





def set_admin_password(password: str, *, rotate_sessions: bool = True) -> dict[str, Any]:

    """Set/replace admin password.



    When *rotate_sessions* is True (default), the session HMAC secret is rotated

    so every existing browser cookie is invalidated immediately.

    """

    password = str(password or "")

    if len(password) < ADMIN_PASSWORD_MIN_LEN:

        raise ValueError(f"管理员密码至少 {ADMIN_PASSWORD_MIN_LEN} 位")

    prev = _json_setting(ADMIN_AUTH_KEY) or {}

    try:

        prev_ver = int(prev.get("password_version") or 0)

    except (TypeError, ValueError):

        prev_ver = 0

    salt = secrets.token_urlsafe(18)

    data = {

        "salt": salt,

        "password_hash": _admin_password_hash(password, salt),

        "iterations": ADMIN_HASH_ITERATIONS,

        "password_version": prev_ver + 1,

        "updated_at": time.time(),

    }

    _set_json_setting(ADMIN_AUTH_KEY, data)

    if rotate_sessions:

        rotate_admin_session_secret()

    return admin_auth_state()





def verify_admin_password(password: str) -> bool:

    data = _json_setting(ADMIN_AUTH_KEY) or {}

    password_hash = str(data.get("password_hash") or "")

    salt = str(data.get("salt") or "")

    if not password_hash or not salt:

        return False

    candidate = _admin_password_hash(str(password or ""), salt)

    return hmac.compare_digest(candidate, password_hash)





def admin_password_version() -> int:

    data = _json_setting(ADMIN_AUTH_KEY) or {}

    try:

        return int(data.get("password_version") or 0)

    except (TypeError, ValueError):

        return 0





def admin_session_secret() -> str:

    secret = _json_setting(ADMIN_SESSION_SECRET_KEY)

    if isinstance(secret, str) and len(secret) >= 32:

        return secret

    secret = secrets.token_urlsafe(48)

    _set_json_setting(ADMIN_SESSION_SECRET_KEY, secret)

    return secret





def rotate_admin_session_secret() -> str:

    """Issue a new session HMAC secret — all existing cookies become invalid."""

    secret = secrets.token_urlsafe(48)

    _set_json_setting(ADMIN_SESSION_SECRET_KEY, secret)

    return secret





def maybe_bootstrap_admin_password() -> dict[str, Any]:

    """Create or force-reset admin password from env.



    Env vars (first match wins):

      GROK_REGISTER_ADMIN_BOOTSTRAP_PASSWORD

      ADMIN_BOOTSTRAP_PASSWORD



    Force reset (even if password already set):

      GROK_REGISTER_ADMIN_FORCE_RESET=1

      ADMIN_FORCE_RESET=1

    """

    bootstrap = (

        os.getenv("GROK_REGISTER_ADMIN_BOOTSTRAP_PASSWORD")

        or os.getenv("ADMIN_BOOTSTRAP_PASSWORD")

        or ""

    ).strip()

    force = (

        os.getenv("GROK_REGISTER_ADMIN_FORCE_RESET")

        or os.getenv("ADMIN_FORCE_RESET")

        or ""

    ).strip().lower() in {"1", "true", "yes", "on"}



    state = admin_auth_state()

    already = not bool(state.get("setup_required"))

    if already and not force:

        return {"bootstrapped": False, "reset": False, "reason": "already_set"}

    if not bootstrap:

        return {

            "bootstrapped": False,

            "reset": False,

            "reason": "no_env" if not already else "force_without_password",

        }

    if len(bootstrap) < ADMIN_PASSWORD_MIN_LEN:

        raise RuntimeError(

            f"GROK_REGISTER_ADMIN_BOOTSTRAP_PASSWORD 至少 {ADMIN_PASSWORD_MIN_LEN} 位"

        )

    set_admin_password(bootstrap, rotate_sessions=True)

    return {

        "bootstrapped": not already,

        "reset": already and force,

        "reason": "reset" if already and force else "ok",

    }





def _clamp_int(value: Any, default: int, lo: int, hi: int) -> int:

    try:

        n = int(value)

    except (TypeError, ValueError):

        n = default

    return max(lo, min(hi, n))





def _normalize_domain_text(value: Any) -> str:

    """Canonical multi-domain storage: comma-separated single line.



    Historically joined with newlines, but the admin UI uses a single-line

    ``<input>`` which drops/collapses newlines on reload — multi-domain

    configs then looked like the commas "disappeared" and domains glued

    together. Comma + space is editable and round-trips cleanly.

    Accepts ASCII/CJK separators on input.

    """

    return ", ".join(_domain_list_from_text(str(value or "")))





def normalize_registration_config(raw: dict[str, Any] | None) -> dict[str, Any]:

    src = {**DEFAULT_REGISTRATION_CONFIG, **(raw or {})}

    mail = str(src.get("mail_provider") or "moemail").strip().lower()

    if mail in {"outlook", "outlookemail"}:

        mail = "outmail"

    if mail not in {"moemail", "yyds", "gptmail", "cfmail", "duckmail", "outmail"}:

        mail = "moemail"

    # Local captcha only — YesCaptcha UI/config removed.

    captcha = "local"

    strategy = str(src.get("proxy_strategy") or "round_robin").strip().lower().replace("-", "_")

    if strategy in {"rr", "round", "roundrobin"}:

        strategy = "round_robin"

    elif strategy in {"rand"}:

        strategy = "random"

    elif strategy in {"first", "fixed"}:

        strategy = "sticky"

    elif strategy not in {"round_robin", "random", "sticky"}:

        strategy = "round_robin"



    cfg = {k: ("" if v is None else v) for k, v in src.items()}

    cfg["mail_provider"] = mail

    cfg["captcha_provider"] = captcha

    cfg["yescaptcha_key"] = ""

    cfg["local_solver_url"] = "http://127.0.0.1:5072"

    cfg["proxy_strategy"] = strategy

    cfg["count"] = _clamp_int(cfg.get("count"), 1, 1, 10000)

    cfg["stagger_ms"] = _clamp_int(cfg.get("stagger_ms"), 800, 0, 10000)

    # Power mode: allow multi-browser / multi-thread. Safe mode locks to 1/1/1.

    def _as_bool(v, default=False):

        if isinstance(v, bool):

            return v

        if v is None:

            return default

        return str(v).strip().lower() in {"1", "true", "yes", "on"}

    power = _as_bool(src.get("power_mode"), False)

    cfg["power_mode"] = power

    if power:

        cfg["concurrency"] = _clamp_int(cfg.get("concurrency"), 1, 1, 50)

        cfg["global_inflight"] = _clamp_int(cfg.get("global_inflight"), 1, 1, 64)

        cfg["captcha_concurrency"] = _clamp_int(cfg.get("captcha_concurrency"), 1, 1, 50)

    else:

        cfg["concurrency"] = 1

        cfg["global_inflight"] = 1

        cfg["captcha_concurrency"] = 1

    cfg["captcha_concurrency_auto"] = False

    # Default 30s settle after registration. Explicit 0 is still allowed.

    if cfg.get("probe_delay_sec") in (None, ""):

        cfg["probe_delay_sec"] = 30

    cfg["probe_delay_sec"] = _clamp_int(cfg.get("probe_delay_sec"), 30, 0, 600)

    cfg["skip_probe"] = _as_bool(src.get("skip_probe"), False)

    cfg["sso_only"] = _as_bool(src.get("sso_only"), False)

    # SSO-only already skips device-flow + probe; keep flags consistent.

    if cfg["sso_only"]:

        cfg["skip_probe"] = True

    # Default ON: keep captcha egress aligned with registration proxy pool.

    cfg["captcha_use_proxy"] = _as_bool(src.get("captcha_use_proxy"), True)

    cfg["expiry_ms"] = _clamp_int(cfg.get("expiry_ms"), 3600000, 0, 259200000)



    key_slot = {

        "moemail": "moemail_api_key",

        "yyds": "yyds_api_key",

        "gptmail": "gptmail_api_key",

        "cfmail": "cfmail_api_key",

        "duckmail": "duckmail_api_key",

        "outmail": "outmail_api_key",

    }[mail]

    domain_slot = {

        "moemail": "moemail_domain",

        "yyds": "yyds_domain",

        "gptmail": "gptmail_domain",

        "cfmail": "cfmail_domain",

        "duckmail": "duckmail_domain",

        "outmail": "outmail_anonymous_domain",

    }[mail]

    # Unified api_key is only a write alias for the active provider slot.

    # Never invent a key for provider B from a leftover unified api_key that

    # actually belonged to provider A — only promote when the active slot is

    # empty AND api_key is non-empty (fresh form submit for that provider).

    api_key_val = str(cfg.get("api_key") or "").strip()

    slot_val = str(cfg.get(key_slot) or "").strip()

    if api_key_val and not slot_val:

        cfg[key_slot] = api_key_val

        slot_val = api_key_val

    elif api_key_val and slot_val and api_key_val != slot_val:

        # Explicit unified field wins on same-provider form submit

        # (registrationPayload always sends both with the same value).

        cfg[key_slot] = api_key_val

        slot_val = api_key_val

    cfg["api_key"] = slot_val

    # Mirror unified "domain" into the active provider slot, but never let an
    # empty unified field wipe an explicit provider slot (e.g. outmail_anonymous_domain
    # filled while #domain is blank, or vice versa).
    if "domain" in (raw or {}):
        domain_val = _normalize_domain_text(cfg.get("domain"))
        if domain_val:
            cfg[domain_slot] = domain_val
        elif not str(cfg.get(domain_slot) or "").strip():
            cfg[domain_slot] = ""

    # Prefer the provider-specific slot; fall back to unified domain.
    cfg["domain"] = _normalize_domain_text(
        cfg.get(domain_slot) or cfg.get("domain") or ""
    )
    if cfg["domain"]:
        cfg[domain_slot] = cfg["domain"]



    if mail == "yyds":

        cfg["base_url"] = "https://maliapi.215.im"

    elif mail == "gptmail":

        cfg["base_url"] = "https://mail.chatgpt.org.uk"

    elif mail == "duckmail":

        cfg["base_url"] = "https://api.duckmail.sbs"

    elif mail == "cfmail":

        if cfg.get("base_url"):

            cfg["cfmail_base_url"] = str(cfg.get("base_url") or "").strip().rstrip("/")

        cfg["base_url"] = str(cfg.get("cfmail_base_url") or "").strip().rstrip("/")

        cfg["cfmail_base_url"] = cfg["base_url"]

    elif mail == "outmail":

        if cfg.get("base_url"):

            cfg["outmail_api_base"] = str(cfg.get("base_url") or "").strip().rstrip("/")

        cfg["base_url"] = str(cfg.get("outmail_api_base") or "").strip().rstrip("/")

        cfg["outmail_api_base"] = cfg["base_url"]

    else:

        if cfg.get("base_url"):

            cfg["moemail_base_url"] = str(cfg.get("base_url") or "").strip().rstrip("/")

        cfg["base_url"] = str(cfg.get("moemail_base_url") or "").strip().rstrip("/")



    cfg["local_solver_url"] = "http://127.0.0.1:5072"



    # Outmail bool/int clamps (mirror grok-register console defaults).

    def _as_bool_om(v, default=False):

        if isinstance(v, bool):

            return v

        if v is None:

            return default

        return str(v).strip().lower() in {"1", "true", "yes", "on"}



    cfg["outmail_api_base"] = str(cfg.get("outmail_api_base") or "").strip().rstrip("/")

    cfg["outmail_api_key"] = str(cfg.get("outmail_api_key") or "").strip()

    cfg["outmail_session_cookie"] = str(cfg.get("outmail_session_cookie") or "").strip()

    cfg["outmail_proxy"] = str(cfg.get("outmail_proxy") or "").strip()

    cfg["outmail_plus_alias"] = _as_bool_om(cfg.get("outmail_plus_alias"), True)

    cfg["outmail_plus_alias_count"] = _clamp_int(cfg.get("outmail_plus_alias_count"), 1, 1, 1000)

    cfg["outmail_alias_suffix_len"] = _clamp_int(cfg.get("outmail_alias_suffix_len"), 6, 2, 32)

    cfg["outmail_fetch_top"] = _clamp_int(cfg.get("outmail_fetch_top"), 10, 1, 50)

    cfg["outmail_poll_interval_sec"] = _clamp_int(cfg.get("outmail_poll_interval_sec"), 5, 1, 60)

    cfg["outmail_poll_timeout_sec"] = _clamp_int(cfg.get("outmail_poll_timeout_sec"), 180, 30, 600)

    cfg["outmail_since_padding_sec"] = _clamp_int(cfg.get("outmail_since_padding_sec"), 30, 0, 300)

    cfg["outmail_from_filter"] = str(cfg.get("outmail_from_filter") or "x.ai")

    cfg["outmail_subject_filter"] = str(cfg.get("outmail_subject_filter") or "xAI")

    cfg["outmail_group_id"] = str(cfg.get("outmail_group_id") or "").strip()

    cfg["outmail_anonymous_enabled"] = _as_bool_om(cfg.get("outmail_anonymous_enabled"), False)

    cfg["outmail_anonymous_provider"] = str(cfg.get("outmail_anonymous_provider") or "cloudflare").strip().lower() or "cloudflare"

    # Keep outmail anonymous domain normalized + mirrored with unified domain.
    # Explicit outmail_anonymous_domain wins when both are present.
    _om_dom = _normalize_domain_text(
        cfg.get("outmail_anonymous_domain") or cfg.get("domain") or ""
    )
    cfg["outmail_anonymous_domain"] = _om_dom
    if mail == "outmail":
        cfg["domain"] = _om_dom

    cfg["outmail_anonymous_username_prefix"] = str(cfg.get("outmail_anonymous_username_prefix") or "").strip()

    cfg["outmail_anonymous_password"] = str(cfg.get("outmail_anonymous_password") or "").strip()

    cfg["outmail_anonymous_delete_after"] = _as_bool_om(cfg.get("outmail_anonymous_delete_after"), False)

    cfg["outmail_exclude_used"] = _as_bool_om(cfg.get("outmail_exclude_used"), True)

    used_file = str(cfg.get("outmail_used_file") or "outmail_used_mailboxes.txt").strip() or "outmail_used_mailboxes.txt"

    cfg["outmail_used_file"] = used_file

    if mail == "outmail":

        # Keep unified api_key / base_url mirrored for preflight UI.

        if cfg.get("outmail_api_key") and not str(cfg.get("api_key") or "").strip():

            cfg["api_key"] = cfg["outmail_api_key"]

        if cfg.get("outmail_api_base") and not str(cfg.get("base_url") or "").strip():

            cfg["base_url"] = cfg["outmail_api_base"]

        elif str(cfg.get("base_url") or "").strip() and not cfg.get("outmail_api_base"):

            cfg["outmail_api_base"] = str(cfg.get("base_url") or "").strip().rstrip("/")

        if str(cfg.get("api_key") or "").strip() and not cfg.get("outmail_api_key"):

            cfg["outmail_api_key"] = str(cfg.get("api_key") or "").strip()



    return cfg





# Never let a blank form field wipe a previously saved secret / mail slot.

# Accidental empty overwrite was the main cause of "mailbox config disappeared

# after rebuild / start registration without Save".

_REG_PROTECT_EMPTY_KEYS = frozenset(

    {

        "api_key",

        "moemail_api_key",

        "yyds_api_key",

        "gptmail_api_key",

        "cfmail_api_key",

        "duckmail_api_key",

        "outmail_api_key",

        "outmail_session_cookie",

        "outmail_api_base",

        "outmail_proxy",

        "outmail_anonymous_password",

        "yescaptcha_key",

        "proxy_password",

        "proxy_username",

        "proxy",

        "domain",

        "moemail_domain",

        "yyds_domain",

        "gptmail_domain",

        "cfmail_domain",

        "duckmail_domain",

        "base_url",

        "moemail_base_url",

        "cfmail_base_url",

        "duckmail_base_url",

        "prefix",

    }

)





def _is_blank_config_value(value: Any) -> bool:

    if value is None:

        return True

    if isinstance(value, str):

        s = value.strip()

        if not s:

            return True

        # Masked password/key from UI must never be written back.

        if set(s) <= {"*"}:

            return True

    return False





def set_registration_config(patch: dict[str, Any] | None, *, replace: bool = False) -> dict[str, Any]:

    base = {} if replace else (_json_setting("registration_config") or {})

    incoming = dict(patch or {})

    if not replace:

        cleaned: dict[str, Any] = {}

        for key, value in incoming.items():

            if value is None:

                continue

            if _is_blank_config_value(value) and key in _REG_PROTECT_EMPTY_KEYS:

                # Keep previously saved non-empty value.

                if str(base.get(key) or "").strip():

                    continue

            cleaned[key] = value

        incoming = cleaned

    merged = {**base, **incoming}

    cfg = normalize_registration_config(merged)

    _set_json_setting("registration_config", cfg)

    # Apply runtime admission caps immediately so next job uses the new values.

    try:

        import grok_build_adapter as _adapter



        applied = _adapter.set_global_reg_inflight_limit(cfg.get("global_inflight"))

        cfg["global_inflight"] = applied

        cfg["global_inflight_active"] = _adapter.get_global_reg_inflight_active()

        cap = _adapter.set_local_captcha_concurrency(cfg.get("captcha_concurrency"))

        cfg["captcha_concurrency"] = cap

        cfg["captcha_active"] = _adapter.get_local_captcha_active()

    except Exception:

        pass

    return cfg





def get_registration_config(*, include_secrets: bool = True) -> dict[str, Any]:

    cfg = normalize_registration_config(_json_setting("registration_config") or {})

    # Live admission counters for UI.

    # IMPORTANT: do NOT overwrite saved captcha_concurrency / global_inflight with

    # in-memory adapter defaults (they start at 1/16 on process boot). Always push

    # the DB/normalized values into the adapter, then report live active counts.

    try:

        import grok_build_adapter as _adapter



        applied_g = _adapter.set_global_reg_inflight_limit(cfg.get("global_inflight"))

        applied_c = _adapter.set_local_captcha_concurrency(cfg.get("captcha_concurrency"))

        cfg["global_inflight"] = applied_g

        cfg["captcha_concurrency"] = applied_c

        cfg["global_inflight_active"] = _adapter.get_global_reg_inflight_active()

        cfg["captcha_active"] = _adapter.get_local_captcha_active()

    except Exception:

        cfg.setdefault("global_inflight_active", 0)

        cfg.setdefault("captcha_active", 0)

    if include_secrets:

        return cfg

    public = dict(cfg)

    for key in (

        "api_key",

        "moemail_api_key",

        "yyds_api_key",

        "gptmail_api_key",

        "cfmail_api_key",

        "duckmail_api_key",

        "outmail_api_key",

        "outmail_session_cookie",

        "outmail_anonymous_password",

        "proxy_password",

    ):

        public[f"{key}_set"] = bool(public.get(key))

        public[key] = "********" if public.get(key) else ""

    return public





# Probe proxy rotation state (registration proxy pool, round-robin).

_probe_proxy_rr = 0





def resolve_probe_proxy_url() -> str:

    """Pick next proxy from the saved registration proxy pool (round-robin).



    Registration form proxy pool is the single source of truth for both

    protocol registration and probe/health checks.

    """

    global _probe_proxy_rr

    try:

        from proxy_pool import parse_proxy_pool, pick_proxy



        reg = get_registration_config(include_secrets=True)

        pool = parse_proxy_pool(

            reg.get("proxy") or "",

            username=reg.get("proxy_username") or None,

            password=reg.get("proxy_password") or None,

            fallback_env=True,

        )

        if not pool:

            return ""

        # Always round-robin across the pool for probe fairness.

        idx = int(_probe_proxy_rr)

        _probe_proxy_rr = (idx + 1) % max(1, len(pool))

        return pick_proxy(pool, strategy="round_robin", index=idx) or ""

    except Exception:

        return ""





def resolve_registration_inputs(overrides: dict[str, Any] | None) -> dict[str, Any]:

    """Merge UI overrides onto saved config without blanking secrets.



    Empty strings / masked ``****`` never wipe previously saved mail keys,

    domains, proxy, or passwords. Only non-empty overrides win.

    """

    base = get_registration_config(include_secrets=True)

    merged = dict(base)

    ov = dict(overrides or {})

    target_mail = str(ov.get("mail_provider") or merged.get("mail_provider") or "moemail").strip().lower()



    # Provider switch: clear *unified* display fields only (not per-provider slots).

    # Per-provider keys/domains stay in their own slots so switching back restores them.

    if "mail_provider" in ov and target_mail != str(base.get("mail_provider") or "").strip().lower():

        merged["api_key"] = ""

        merged["domain"] = ""

        merged["base_url"] = ""



    for key, value in ov.items():

        if value is None:

            continue

        if _is_blank_config_value(value):

            # Never clear protected config via empty form fields.

            if key in _REG_PROTECT_EMPTY_KEYS:

                continue

            # Non-protected blank: still skip so defaults stay.

            continue

        merged[key] = value

    return normalize_registration_config(merged)





def normalize_remote_backend(raw: Any = None) -> str:

    text = str(raw or "").strip().lower().replace("-", "_")

    if text in {"g2", "g2api", "grok", "grok_2api", "grok2", "grok2_api"}:

        text = "grok2api"

    if text in {"cliproxy", "cliproxyapi", "cli_proxy", "cli_proxy_api", "cpamc"}:

        text = "cpa"

    if text in REMOTE_BACKENDS:

        return text

    return ""





def get_remote_backend(*, resolve: bool = True) -> str:

    """Return the exclusive remote backend: ``grok2api`` | ``cpa`` | ``""``.



    When ``resolve`` is True and no explicit switch is stored, infer from which

    side has auto-import enabled **and** is fully configured. CPA wins only when

    it is the sole ready/auto side (matches the old grok_reg inspection workflow).

    """

    stored = normalize_remote_backend(_json_setting("remote_backend"))

    if stored:

        return stored

    if not resolve:

        return normalize_remote_backend(DEFAULT_REMOTE_BACKEND)

    env_default = normalize_remote_backend(DEFAULT_REMOTE_BACKEND)

    if env_default:

        return env_default

    try:

        gcfg = normalize_grok2api_config(_json_setting("grok2api_config") or {})

    except Exception:

        gcfg = dict(DEFAULT_GROK2API_CONFIG)

    try:

        ccfg = normalize_cpa_config(_json_setting("cpa_config") or {})

    except Exception:

        ccfg = dict(DEFAULT_CPA_CONFIG)

    g_auto = bool(gcfg.get("auto_upload_after_probe") or gcfg.get("auto_upload_after_relogin"))

    c_auto = bool(ccfg.get("auto_upload_after_probe") or ccfg.get("auto_upload_after_relogin"))

    g_ready = bool(gcfg.get("base_url") and gcfg.get("username") and gcfg.get("password"))

    c_ready = bool(ccfg.get("base_url") and ccfg.get("management_key"))

    g_active = g_auto and g_ready

    c_active = c_auto and c_ready

    if c_active and not g_active:

        return "cpa"

    if g_active and not c_active:

        return "grok2api"

    # Neither auto-active: fall back to whichever connection is ready.

    if c_ready and not g_ready:

        return "cpa"

    if g_ready and not c_ready:

        return "grok2api"

    # Both auto-active or both ready without a pin — prefer Grok2API for parity

    # with previous default (auto_upload_after_relogin=True). Operator should pin.

    if g_active or g_ready:

        return "grok2api"

    if c_active or c_ready:

        return "cpa"

    return ""





def set_remote_backend(backend: str | None) -> str:

    value = normalize_remote_backend(backend)

    if value and value not in REMOTE_BACKENDS:

        raise ValueError("远端对接只能是 grok2api 或 cpa")

    _set_json_setting("remote_backend", value)

    # Enforce mutual exclusion on auto-import flags.

    if value == "grok2api":

        cbase = dict(_json_setting("cpa_config") or {})

        if cbase.get("auto_upload_after_probe") or cbase.get("auto_upload_after_relogin"):

            cbase["auto_upload_after_probe"] = False

            cbase["auto_upload_after_relogin"] = False

            _set_json_setting("cpa_config", normalize_cpa_config(cbase))

    elif value == "cpa":

        gbase = dict(_json_setting("grok2api_config") or {})

        if gbase.get("auto_upload_after_probe") or gbase.get("auto_upload_after_relogin"):

            gbase["auto_upload_after_probe"] = False

            gbase["auto_upload_after_relogin"] = False

            _set_json_setting("grok2api_config", normalize_grok2api_config(gbase))

    return value





def _disable_other_backend_auto(backend: str) -> None:

    """When one backend enables auto-import, force the other off + pin switch."""

    backend = normalize_remote_backend(backend)

    if backend not in REMOTE_BACKENDS:

        return

    _set_json_setting("remote_backend", backend)

    if backend == "grok2api":

        cbase = dict(_json_setting("cpa_config") or {})

        if cbase.get("auto_upload_after_probe") or cbase.get("auto_upload_after_relogin"):

            cbase["auto_upload_after_probe"] = False

            cbase["auto_upload_after_relogin"] = False

            _set_json_setting("cpa_config", normalize_cpa_config(cbase))

    else:

        gbase = dict(_json_setting("grok2api_config") or {})

        if gbase.get("auto_upload_after_probe") or gbase.get("auto_upload_after_relogin"):

            gbase["auto_upload_after_probe"] = False

            gbase["auto_upload_after_relogin"] = False

            _set_json_setting("grok2api_config", normalize_grok2api_config(gbase))





def normalize_grok2api_config(raw: dict[str, Any] | None) -> dict[str, Any]:

    src = {**DEFAULT_GROK2API_CONFIG, **(raw or {})}

    mode = str(src.get("upload_mode") or "build_auth_files").strip().lower()

    if mode not in {"build_auth_files", "web_sso"}:

        mode = "build_auth_files"

    try:

        limit = int(src.get("limit") or 1000)

    except (TypeError, ValueError):

        limit = 1000

    limit = max(1, min(5000, limit))

    return {

        "base_url": _normalize_origin(str(src.get("base_url") or "")),

        "username": str(src.get("username") or "").strip(),

        "password": str(src.get("password") or ""),

        "upload_mode": mode,

        "limit": limit,

        "upload_batch_size": _clamp_int(src.get("upload_batch_size"), 50, 1, 200),

        "auto_upload_after_probe": bool(src.get("auto_upload_after_probe")),

        "auto_upload_after_relogin": bool(src.get("auto_upload_after_relogin", False)),

    }





def _mask_auto_by_remote_pin(cfg: dict[str, Any], side: str) -> dict[str, Any]:

    """If exclusive remote_backend is the other side, present auto flags as off."""

    pin = get_remote_backend(resolve=False)

    out = dict(cfg)

    if pin and pin != side:

        out["auto_upload_after_probe"] = False

        out["auto_upload_after_relogin"] = False

    return out





def get_grok2api_config(*, include_password: bool = True) -> dict[str, Any]:

    cfg = _mask_auto_by_remote_pin(normalize_grok2api_config(_json_setting("grok2api_config") or {}), "grok2api")

    if include_password:

        return cfg

    public = dict(cfg)

    public["password_set"] = bool(public.get("password"))

    public["password"] = "********" if public.get("password") else ""

    return public





def set_grok2api_config(patch: dict[str, Any] | None, *, replace: bool = False) -> dict[str, Any]:

    base = {} if replace else (_json_setting("grok2api_config") or {})

    patch = dict(patch or {})

    # UI reloads password as ******** when masked; never persist the mask.

    pwd = str(patch.get("password") or "")

    if (not pwd.strip()) or set(pwd.strip()) == {"*"} or pwd.strip() == "********":

        if "password" in patch:

            if str(base.get("password") or "").strip():

                patch["password"] = base.get("password")

            else:

                patch.pop("password", None)

    merged = {**base, **patch}

    cfg = normalize_grok2api_config(merged)

    if not cfg["base_url"]:

        raise ValueError("Grok2API 地址不能为空")

    if not cfg["username"]:

        raise ValueError("Grok2API 管理员账号不能为空")

    # Password required only when none stored yet.

    if not str(cfg.get("password") or "").strip():

        raise ValueError("Grok2API 管理员密码不能为空（保存后刷新若显示 ****，请重新输入真实密码再保存）")

    _set_json_setting("grok2api_config", cfg)

    # Mutual exclusion: enabling Grok2API auto-import pins backend and disables CPA auto.

    if cfg.get("auto_upload_after_probe") or cfg.get("auto_upload_after_relogin"):

        _disable_other_backend_auto("grok2api")

    elif get_remote_backend(resolve=False) == "" and cfg.get("base_url"):

        # First successful Grok2API save without explicit backend → pin if CPA empty.

        ccfg = normalize_cpa_config(_json_setting("cpa_config") or {})

        if not (ccfg.get("base_url") and ccfg.get("management_key")):

            _set_json_setting("remote_backend", "grok2api")

    return cfg







def _cpa_upload_timeout(value: Any) -> int:

    try:

        n = int(value)

    except (TypeError, ValueError):

        n = 30

    return max(5, min(180, n))





def _cpa_upload_retries(value: Any) -> int:

    try:

        n = int(value)

    except (TypeError, ValueError):

        n = 3

    return max(1, min(10, n))





def normalize_cpa_config(raw: dict[str, Any] | None) -> dict[str, Any]:

    src = {**DEFAULT_CPA_CONFIG, **(raw or {})}

    try:

        limit = int(src.get("limit") or 1000)

    except (TypeError, ValueError):

        limit = 1000

    limit = max(1, min(5000, limit))

    base_raw = str(src.get("base_url") or "").strip()

    # Accept management UI URLs like

    # https://cpa.example/management.html#/plugin-pages/grok-inspection/0

    # and reduce them to origin (scheme + host).

    try:

        base_url = _normalize_origin(base_raw) if base_raw else ""

    except ValueError:

        # Fall back: strip path/hash manually then re-validate.

        parsed = urllib.parse.urlsplit(base_raw)

        if parsed.scheme and parsed.netloc:

            base_url = _normalize_origin(

                urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))

            )

        else:

            raise

    return {

        "base_url": base_url,

        "management_key": str(src.get("management_key") or ""),

        "limit": limit,

        "auto_upload_after_probe": bool(src.get("auto_upload_after_probe")),

        "auto_upload_after_relogin": bool(src.get("auto_upload_after_relogin", False)),

        "upload_timeout": _cpa_upload_timeout(src.get("upload_timeout")),

        "upload_retries": _cpa_upload_retries(src.get("upload_retries")),

    }





def get_cpa_config(*, include_key: bool = True) -> dict[str, Any]:

    cfg = _mask_auto_by_remote_pin(normalize_cpa_config(_json_setting("cpa_config") or {}), "cpa")

    if include_key:

        return cfg

    public = dict(cfg)

    public["management_key_set"] = bool(public.get("management_key"))

    public["management_key"] = "********" if public.get("management_key") else ""

    return public





def set_cpa_config(patch: dict[str, Any] | None, *, replace: bool = False) -> dict[str, Any]:

    base = {} if replace else (_json_setting("cpa_config") or {})

    patch = dict(patch or {})

    key = str(patch.get("management_key") or "")

    if (not key.strip()) or set(key.strip()) == {"*"} or key.strip() == "********":

        if "management_key" in patch:

            if str(base.get("management_key") or "").strip():

                patch["management_key"] = base.get("management_key")

            else:

                patch.pop("management_key", None)

    merged = {**base, **patch}

    cfg = normalize_cpa_config(merged)

    if not cfg["base_url"]:

        raise ValueError("CPA 地址不能为空（可填 management.html 完整链接，会自动取域名）")

    if not str(cfg.get("management_key") or "").strip():

        raise ValueError("CPA 管理密钥不能为空（保存后刷新若显示 ****，请重新输入真实密钥再保存）")

    _set_json_setting("cpa_config", cfg)

    if cfg.get("auto_upload_after_probe") or cfg.get("auto_upload_after_relogin"):

        _disable_other_backend_auto("cpa")

    elif get_remote_backend(resolve=False) == "" and cfg.get("base_url"):

        gcfg = normalize_grok2api_config(_json_setting("grok2api_config") or {})

        if not (gcfg.get("base_url") and gcfg.get("username") and gcfg.get("password")):

            _set_json_setting("remote_backend", "cpa")

    return cfg





def normalize_relogin_config(raw: dict[str, Any] | None) -> dict[str, Any]:

    src = {**DEFAULT_RELOGIN_CONFIG, **(raw or {})}

    strategy = str(src.get("proxy_strategy") or "round_robin").strip().lower().replace("-", "_")

    if strategy in {"rr", "round", "roundrobin"}:

        strategy = "round_robin"

    elif strategy in {"rand"}:

        strategy = "random"

    elif strategy in {"first", "fixed"}:

        strategy = "sticky"

    elif strategy not in {"round_robin", "random", "sticky"}:

        strategy = "round_robin"

    model = str(src.get("probe_model") or "grok-4.5").strip() or "grok-4.5"

    return {

        "concurrency": _clamp_int(src.get("concurrency"), 2, 1, 10),

        "stagger_ms": _clamp_int(src.get("stagger_ms"), 200, 0, 60000),

        # Local captcha only — YesCaptcha UI/config removed.

        "captcha_provider": "local",

        "yescaptcha_key": "",

        "local_solver_url": "http://127.0.0.1:5072",

        "proxy": str(src.get("proxy") or "").strip(),

        "proxy_username": str(src.get("proxy_username") or "").strip(),

        "proxy_password": str(src.get("proxy_password") or ""),

        "proxy_strategy": strategy,

        "use_registration_proxy_fallback": bool(src.get("use_registration_proxy_fallback", True)),

        "probe_model": model,

    }





def get_relogin_config(*, include_secrets: bool = True) -> dict[str, Any]:

    cfg = normalize_relogin_config(_json_setting("relogin_config") or {})

    if include_secrets:

        return cfg

    public = dict(cfg)

    public["proxy_password_set"] = bool(public.get("proxy_password"))

    public["proxy_password"] = "********" if public.get("proxy_password") else ""

    return public





def set_relogin_config(patch: dict[str, Any] | None, *, replace: bool = False) -> dict[str, Any]:

    base = {} if replace else (_json_setting("relogin_config") or {})

    merged = {**base, **(patch or {})}

    # Keep existing secrets when UI sends masked placeholders.

    if str(merged.get("proxy_password") or "") in {"", "********"} and "proxy_password" in base:

        merged["proxy_password"] = base.get("proxy_password") or ""

    cfg = normalize_relogin_config(merged)

    _set_json_setting("relogin_config", cfg)

    return cfg





def resolve_relogin_runtime_config() -> dict[str, Any]:

    """Merge relogin settings with optional registration proxy fallback. Local captcha only."""

    relogin = get_relogin_config(include_secrets=True)

    reg = get_registration_config(include_secrets=True)

    out = dict(relogin)

    out["captcha_provider"] = "local"

    out["yescaptcha_key"] = ""

    out["local_solver_url"] = str(reg.get("local_solver_url") or "http://127.0.0.1:5072")



    if not str(out.get("proxy") or "").strip() and out.get("use_registration_proxy_fallback"):

        out["proxy"] = str(reg.get("proxy") or "")

        out["proxy_username"] = str(reg.get("proxy_username") or "")

        out["proxy_password"] = str(reg.get("proxy_password") or "")

        out["proxy_strategy"] = str(reg.get("proxy_strategy") or out.get("proxy_strategy") or "round_robin")

    return out





def _upload_emails_to_remotes(

    emails: list[str],

    *,

    mode: str = "probe",

    grok2api_token: str | None = None,

    require_probe: bool = True,

) -> dict[str, Any]:

    """Upload the given emails to the active exclusive remote backend.



    Grok2API and CPA are mutually exclusive — only the pinned remote_backend

    (or the side with auto-import enabled) runs. The other is always skipped.



    mode:

      - "probe": only remotes with auto_upload_after_probe=True (registration path)

      - "relogin": only remotes with auto_upload_after_relogin=True (relogin batch path)



    ``grok2api_token``: optional pre-fetched admin token so multi-batch sync does

    not re-login for every chunk.



    ``require_probe``: when False (skip-probe bulk mode), import any local account

    that has usable credentials without requiring a successful model probe.

    """

    clean = sorted({str(e or "").strip().lower() for e in (emails or []) if str(e or "").strip()})

    backend = get_remote_backend(resolve=True)

    out: dict[str, Any] = {

        "ok": True,

        "emails": clean,

        "grok2api": None,

        "cpa": None,

        "skipped": [],

        "mode": mode,

        "backend": backend or "",

        "require_probe": bool(require_probe),

    }

    if not clean:

        out["ok"] = False

        out["skipped"].append("no emails")

        return out



    flag_key = "auto_upload_after_relogin" if mode == "relogin" else "auto_upload_after_probe"

    skip_tag = "relogin" if mode == "relogin" else "probe"



    # Grok2API (skipped entirely when backend is cpa)

    if backend == "cpa":

        out["skipped"].append("grok2api skipped: remote_backend=cpa")

    else:

        try:

            gcfg = get_grok2api_config(include_password=True)

            g_enabled = bool(gcfg.get(flag_key)) and (backend in {"", "grok2api"})

            g_ready = bool(gcfg.get("base_url") and gcfg.get("username") and gcfg.get("password"))

            if g_enabled and g_ready:

                upload_mode = str(gcfg.get("upload_mode") or "build_auth_files")

                limit = max(len(clean), int(gcfg.get("limit") or len(clean)))

                # Default auto path requires probe-passed accounts; skip-probe bulk can relax.

                if upload_mode == "web_sso":

                    result = upload_grok2api_sso(

                        gcfg, limit=limit, emails=clean, require_probe=require_probe

                    )

                else:

                    result = upload_grok2api_auth_files(

                        gcfg,

                        limit=limit,

                        emails=clean,

                        require_probe=require_probe,

                        access_token=grok2api_token,

                    )

                out["grok2api"] = result

                if not result.get("ok"):

                    out["ok"] = False

                else:

                    marked = result.get("emails") if isinstance(result.get("emails"), list) else clean

                    try:

                        mark_local_remote_imported(

                            marked,

                            provider="grok_build",

                            reason=f"auto_upload_{skip_tag}",

                        )

                    except Exception:

                        pass

                    try:

                        mark_accounts_pushed(marked, grok2api=True)

                    except Exception:

                        pass

            elif g_enabled and not g_ready:

                out["grok2api"] = {"ok": False, "error": "Grok2API 连接未配置完整"}

                out["ok"] = False

            else:

                out["skipped"].append(f"grok2api auto {skip_tag} off")

        except Exception as exc:  # noqa: BLE001

            out["grok2api"] = {"ok": False, "error": str(exc)[:300]}

            out["ok"] = False



    # CPA (skipped entirely when backend is grok2api)

    if backend == "grok2api":

        out["skipped"].append("cpa skipped: remote_backend=grok2api")

    else:

        try:

            ccfg = get_cpa_config(include_key=True)

            c_enabled = bool(ccfg.get(flag_key)) and (backend in {"", "cpa"})

            c_ready = bool(ccfg.get("base_url") and ccfg.get("management_key"))

            if c_enabled and c_ready:

                limit = max(len(clean), int(ccfg.get("limit") or len(clean)))

                result = upload_cpa_auth_files(

                    ccfg, limit=limit, emails=clean, require_probe=require_probe,

                    skip_already_pushed=True,

                )

                out["cpa"] = result

                if not result.get("ok"):

                    out["ok"] = False

                else:

                    marked = result.get("emails") if isinstance(result.get("emails"), list) else clean

                    try:

                        mark_local_remote_imported(

                            marked,

                            provider="cpa",

                            reason=f"auto_upload_{skip_tag}",

                        )

                    except Exception:

                        pass

                    try:

                        mark_accounts_pushed(marked, cpa=True)

                    except Exception:

                        pass

            elif c_enabled and not c_ready:

                out["cpa"] = {"ok": False, "error": "CPA 连接未配置完整"}

                out["ok"] = False

            else:

                out["skipped"].append(f"cpa auto {skip_tag} off")

        except Exception as exc:  # noqa: BLE001

            out["cpa"] = {"ok": False, "error": str(exc)[:300]}

            out["ok"] = False



    # Sub2API push (independent of Grok2API/CPA exclusive backend; needs CPA auth JSON)

    try:

        scfg = get_sub2api_config(include_key=True)

        s_enabled = bool(scfg.get(flag_key)) and bool(scfg.get("upload_enabled", True))

        s_ready = bool(scfg.get("api_base") and scfg.get("api_key"))

        if s_enabled and s_ready:

            s_limit = max(len(clean), int(scfg.get("limit") or len(clean)))

            s_result = upload_sub2api_auth_files(

                scfg,

                limit=s_limit,

                emails=clean,

                require_probe=require_probe,

                skip_already_pushed=True,

            )

            out["sub2api"] = s_result

            if not s_result.get("ok") and int(s_result.get("uploaded") or 0) <= 0:

                # do not fail whole batch solely on sub2 partial issues if something uploaded

                if s_result.get("error") and not s_result.get("uploaded"):

                    out["ok"] = False

        elif s_enabled and not s_ready:

            out["sub2api"] = {"ok": False, "error": "Sub2API config incomplete"}

        else:

            out["skipped"].append(f"sub2api auto {skip_tag} off")

    except Exception as exc:  # noqa: BLE001

        out["sub2api"] = {"ok": False, "error": str(exc)[:300]}



    return out





def auto_upload_after_probe(emails: list[str]) -> dict[str, Any]:

    """Legacy single-shot probe upload (kept for compatibility).



    Prefer ``sync_accounts_after_probe`` for batch/group uploads.

    """

    return _upload_emails_to_remotes(emails, mode="probe")





def _chunked_sync_accounts(

    emails: list[str],

    *,

    mode: str,

    batch_size: int | None = None,

    on_progress=None,

    should_stop=None,

    require_probe: bool = True,

) -> dict[str, Any]:

    """Upload emails in chunks to remotes enabled for ``mode``.



    Logs in to Grok2API once and reuses the token across chunks. Optional

    ``should_stop`` aborts between batches (used when operator stops relogin).



    ``require_probe=False`` allows skip-probe bulk mode to push credentials that

    were never model-probed.

    """

    clean: list[str] = []

    seen: set[str] = set()

    for email in emails or []:

        key = str(email or "").strip().lower()

        if not key or key in seen:

            continue

        seen.add(key)

        clean.append(key)



    gcfg = get_grok2api_config(include_password=True)

    # Prefer an explicit batch_size; otherwise use saved config.

    # Historical default was 1 (one HTTP call per account) which is extremely

    # slow even on the same VPS. Floor auto-sync to 20 when leftover is 1.

    raw_size = batch_size if batch_size is not None else gcfg.get("upload_batch_size")

    try:

        raw_n = int(raw_size if raw_size is not None else 50)

    except (TypeError, ValueError):

        raw_n = 50

    if batch_size is None and raw_n <= 1:

        raw_n = 50

    size = _clamp_int(raw_n, 50, 1, 200)

    out: dict[str, Any] = {

        "ok": True,

        "emails": clean,

        "total": len(clean),

        "batch_size": size,

        "batches": [],

        "uploaded": 0,

        "failed_batches": 0,

        "skipped": [],

        "mode": mode,

        "require_probe": bool(require_probe),

    }

    if not clean:

        out["skipped"].append("no emails")

        return out



    flag_key = "auto_upload_after_relogin" if mode == "relogin" else "auto_upload_after_probe"

    ccfg = get_cpa_config(include_key=True)

    g_on = bool(gcfg.get(flag_key)) and bool(

        gcfg.get("base_url") and gcfg.get("username") and gcfg.get("password")

    )

    c_on = bool(ccfg.get(flag_key)) and bool(

        ccfg.get("base_url") and ccfg.get("management_key")

    )

    if not g_on and not c_on:

        out["skipped"].append(f"no remote enabled for {mode} sync")

        return out



    # One login for the whole multi-batch sync (huge win vs login-per-account).

    grok_token: str | None = None

    if g_on:

        try:

            grok_token = grok2api_login(gcfg["base_url"], gcfg["username"], gcfg["password"])

        except Exception as exc:  # noqa: BLE001

            # Fall back to per-batch login inside upload helper.

            grok_token = None

            if callable(on_progress):

                on_progress(

                    {

                        "kind": "sync",

                        "message": f"Grok2API 预登录失败，将按批重试登录：{str(exc)[:120]}",

                    }

                )



    total_batches = (len(clean) + size - 1) // size

    for i in range(0, len(clean), size):

        if callable(should_stop) and should_stop():

            out["ok"] = False

            out["stopped"] = True

            out["skipped"].append("stopped_mid_sync")

            if callable(on_progress):

                on_progress(

                    {

                        "kind": "sync",

                        "message": f"已停止同步（完成 {out['uploaded']}/{len(clean)}）",

                    }

                )

            break

        chunk = clean[i : i + size]

        batch_no = (i // size) + 1

        if callable(on_progress):

            on_progress(

                {

                    "kind": "sync",

                    "message": f"正在同步远端 {batch_no}/{total_batches}（{len(chunk)} 个账号）",

                    "batch": batch_no,

                    "total_batches": total_batches,

                    "emails": chunk,

                }

            )

        try:

            result = _upload_emails_to_remotes(

                chunk,

                mode=mode,

                grok2api_token=grok_token,

                require_probe=require_probe,

            )

        except Exception as exc:  # noqa: BLE001

            result = {"ok": False, "error": str(exc)[:300], "emails": chunk}

        batch_view = {

            "batch": batch_no,

            "count": len(chunk),

            "emails": chunk,

            "ok": bool(result.get("ok")),

            "grok2api": result.get("grok2api"),

            "cpa": result.get("cpa"),

            "error": result.get("error"),

            "skipped": result.get("skipped") or [],

        }

        out["batches"].append(batch_view)

        if result.get("ok"):

            out["uploaded"] += len(chunk)

        else:

            out["failed_batches"] += 1

            out["ok"] = False

    return out





def sync_accounts_after_probe(

    emails: list[str],

    *,

    batch_size: int | None = None,

    on_progress=None,

    should_stop=None,

    require_probe: bool = True,

) -> dict[str, Any]:

    """Batch-sync registration accounts (chunked upload).



    ``require_probe=False`` is used when registration skipped model probe.

    """

    return _chunked_sync_accounts(

        emails,

        mode="probe",

        batch_size=batch_size,

        on_progress=on_progress,

        should_stop=should_stop,

        require_probe=require_probe,

    )





def sync_accounts_after_relogin(

    emails: list[str],

    *,

    batch_size: int | None = None,

    on_progress=None,

    should_stop=None,

) -> dict[str, Any]:

    """Batch-sync relogin probe-passed accounts (chunked upload)."""

    return _chunked_sync_accounts(

        emails,

        mode="relogin",

        batch_size=batch_size,

        on_progress=on_progress,

        should_stop=should_stop,

    )





def _normalize_origin(raw: str) -> str:

    text = str(raw or "").strip()

    if not text:

        return ""

    parsed = urllib.parse.urlsplit(text)

    if not parsed.scheme or not parsed.netloc:

        raise ValueError("地址必须包含 http:// 或 https://")

    origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")

    ok, reason = is_safe_outbound_url(origin)

    if not ok:

        raise ValueError(f"地址不安全：{reason}")

    return origin





def _is_cloudflare_block(raw: str) -> bool:

    text = str(raw or "").lower()

    return (

        "error code: 1010" in text

        or "error code 1010" in text

        or "cf-ray" in text

        or "cloudflare" in text and ("attention required" in text or "blocked" in text)

        or "just a moment" in text

    )





def grok2api_login(base_url: str, username: str, password: str) -> str:

    pwd = str(password or "")

    if not pwd.strip() or set(pwd.strip()) == {"*"} or pwd.strip() == "********":

        raise ValueError(

            "Grok2API 管理员密码无效（空或仍是 **** 掩码）。"

            "请在设置里重新输入真实密码并保存后再导入"

        )

    safe_base = require_safe_outbound_url(base_url, label="Grok2API 地址")

    body = json.dumps({"username": username, "password": pwd}).encode()

    req = urllib.request.Request(

        safe_base.rstrip("/") + "/api/admin/v1/auth/login",

        data=body,

        headers={

            "Content-Type": "application/json",

            "Accept": "application/json",

            "User-Agent": f"grok-register-pro/{CLI_VERSION}",

        },

        method="POST",

    )

    try:

        with _urlopen(req, timeout=30) as resp:

            payload = json.loads(resp.read())

    except urllib.error.HTTPError as exc:

        raw = exc.read().decode("utf-8", "replace")[:300]

        code = int(exc.code)

        if _is_cloudflare_block(raw):

            raise RuntimeError(

                f"Grok2API 登录被 Cloudflare 拦截 HTTP {code}（error 1010 / bot fight）。"

                f" 请改用内网/直连地址，或在 CF 放行 /api/admin。详情：{raw}"

            ) from exc

        if code in {401, 403}:

            raise RuntimeError(

                f"Grok2API 登录被拒绝 HTTP {code}：账号/密码错误，或密码曾被保存成 **** 掩码。"

                f" 请打开设置重新输入真实密码并点保存。详情：{raw}"

            ) from exc

        raise RuntimeError(f"Grok2API 登录失败 HTTP {code}: {raw}") from exc

    token = (((payload.get("data") or {}).get("tokens") or {}).get("accessToken"))

    if not token:

        raise RuntimeError("Grok2API 登录成功但响应里没有 accessToken")

    return str(token)





def test_grok2api_login(config: dict[str, Any] | None = None) -> dict[str, Any]:

    cfg = normalize_grok2api_config(config or get_grok2api_config(include_password=True))

    token = grok2api_login(cfg["base_url"], cfg["username"], cfg["password"])

    return {"ok": True, "base_url": cfg["base_url"], "username": cfg["username"], "token_hint": token[:12] + "..."}





def _build_multipart_parts(parts: list[tuple[str, bytes, str]], boundary: str) -> bytes:

    chunks: list[bytes] = []

    for filename, content, content_type in parts:

        chunks.append(

            (

                f"--{boundary}\r\n"

                f'Content-Disposition: form-data; name="files"; filename="{filename}"\r\n'

                f"Content-Type: {content_type}\r\n\r\n"

            ).encode()

            + content

            + b"\r\n"

        )

    chunks.append(f"--{boundary}--\r\n".encode())

    return b"".join(chunks)





def _build_multipart(files: list[Path], boundary: str) -> bytes:

    return _build_multipart_parts(

        [(path.name, path.read_bytes(), "application/json") for path in files],

        boundary,

    )





def _build_multipart_auth_parts(parts: list[tuple[str, bytes]], boundary: str) -> bytes:

    return _build_multipart_parts(

        [(filename, content, "application/json") for filename, content in parts],

        boundary,

    )





def _parse_sse_complete(text: str) -> dict[str, Any]:

    event = "message"

    data_lines: list[str] = []

    complete: dict[str, Any] = {}



    def dispatch() -> None:

        nonlocal event, data_lines, complete

        if not data_lines:

            event = "message"

            return

        raw = "\n".join(data_lines).strip()

        data_lines = []

        payload = json.loads(raw)

        if event == "error":

            raise RuntimeError(payload)

        if event == "complete" and isinstance(payload, dict):

            complete = payload

        event = "message"



    for line in text.splitlines():

        if not line.strip():

            dispatch()

            continue

        if line.startswith("event:"):

            event = line[6:].strip() or "message"

        elif line.startswith("data:"):

            data_lines.append(line[5:].strip())

    dispatch()

    return complete





def _read_grok2api_import_response(response) -> dict[str, Any]:

    """Read an import SSE stream only until its terminal ``complete`` event."""

    content_type = str(response.headers.get("Content-Type") or "").lower()

    if "text/event-stream" not in content_type:

        text = response.read().decode("utf-8", "replace")

        try:

            payload = json.loads(text)

        except json.JSONDecodeError:

            payload = _parse_sse_complete(text)

        if isinstance(payload, dict):

            return payload

        raise RuntimeError("Grok2API 导入响应格式无效")



    event = "message"

    data_lines: list[str] = []



    def dispatch() -> dict[str, Any] | None:

        nonlocal event, data_lines

        if not data_lines:

            event = "message"

            return None

        raw = "\n".join(data_lines).strip()

        data_lines = []

        payload = json.loads(raw)

        if event == "error":

            if isinstance(payload, dict):

                code = str(payload.get("code") or payload.get("error") or "importError")

                message = str(payload.get("message") or payload.get("detail") or payload)

                raise RuntimeError(f"Grok2API 导入失败 [{code}]: {message}")

            raise RuntimeError(f"Grok2API 导入失败: {payload}")

        event_name = event

        event = "message"

        return payload if event_name == "complete" and isinstance(payload, dict) else None



    # Bound wait so a stuck SSE from the remote admin UI cannot hang the local

    # register-pro request forever (browser then looks "stuck at 准备导入").

    deadline = time.time() + 90.0

    for raw_line in response:

        if time.time() > deadline:

            raise RuntimeError("Grok2API 导入超时（90s 内未收到 complete 事件）")

        line = raw_line.decode("utf-8", "replace").rstrip("\r\n")

        if not line:

            complete = dispatch()

            if complete is not None:

                return complete

        elif line.startswith("event:"):

            event = line[6:].strip() or "message"

        elif line.startswith("data:"):

            data_lines.append(line[5:].strip())



    complete = dispatch()

    if complete is not None:

        return complete

    raise RuntimeError("Grok2API 导入连接已结束，但未返回完成结果")





def normalize_grok2api_providers(raw: Any = None) -> list[str]:

    if raw is None or raw == "" or raw == "all":

        return list(GROK2API_PROVIDERS)

    if isinstance(raw, str):

        values = [part.strip() for part in raw.split(",") if part.strip()]

    else:

        values = [str(part).strip() for part in raw if str(part).strip()]

    bad = sorted(set(values) - set(GROK2API_PROVIDERS))

    if bad:

        raise ValueError("未知 Grok2API 来源: " + ", ".join(bad))

    return values or list(GROK2API_PROVIDERS)





def classify_grok2api_account(item: dict[str, Any]) -> dict[str, Any]:

    email = str(item.get("email") or item.get("name") or "").strip().lower()

    auth_status = str(item.get("authStatus") or "").strip()

    auth_status_lower = auth_status.lower()

    quota = item.get("quota") if isinstance(item.get("quota"), dict) else {}

    quota_status = str(quota.get("status") or "").strip().lower()

    enabled = bool(item.get("enabled"))

    refresh_failures = int(item.get("refreshFailureCount") or 0)

    failure_count = int(item.get("failureCount") or 0)



    classification = "healthy"

    http_status: int | None = 200

    action = "keep"

    reason = "active"



    if "reauth" in auth_status_lower or auth_status_lower in {

        "expired",

        "invalid",

        "unauthorized",

        "refresh_failed",

        "token_expired",

    }:

        classification = "reauth"

        http_status = 401

        action = "relogin"

        reason = auth_status or "credential requires re-login"

    elif auth_status and auth_status_lower != "active":

        classification = "probe_error"

        http_status = None

        action = "inspect"

        reason = auth_status

    elif quota_status in {"waitingreset", "waiting_reset", "exhausted"}:

        classification = "quota_exhausted"

        http_status = 429

        action = "wait"

        reason = quota_status

    elif refresh_failures > 0:

        classification = "reauth"

        http_status = 401

        action = "relogin"

        reason = f"refresh failures={refresh_failures}"

    elif failure_count > 0:

        classification = "probe_error"

        http_status = 500

        action = "inspect"

        reason = f"failure count={failure_count}"

    elif not enabled:

        classification = "disabled"

        http_status = None

        action = "enable_or_ignore"

        reason = "disabled"



    return {

        "email": email,

        "classification": classification,

        "http_status": http_status,

        "action": action,

        "reason": reason,

        "model": str(item.get("model") or ""),

        "disabled": int(not enabled),

        "auth_status": auth_status,

        "remote_id": str(item.get("id") or item.get("authIndex") or email or ""),

    }





def _grok2api_get_json(base_url: str, token: str, path: str, query: dict[str, Any], *, timeout: float) -> dict[str, Any]:

    url = base_url.rstrip("/") + path

    if query:

        url += "?" + urllib.parse.urlencode(query)

    req = urllib.request.Request(

        url,

        headers={"Accept": "application/json", "Authorization": "Bearer " + token},

        method="GET",

    )

    with _urlopen(req, timeout=timeout) as resp:

        payload = json.loads(resp.read())

    if not isinstance(payload, dict):

        raise RuntimeError("Grok2API 返回的账号列表不是 JSON 对象")

    return payload





def _fetch_grok2api_accounts_page(

    cfg: dict[str, Any],

    token: str,

    *,

    provider: str,

    page: int,

    page_size: int,

    timeout: float,

    status: str | None = None,

) -> tuple[list[dict[str, Any]], int, int]:

    query: dict[str, Any] = {

        "provider": provider,

        "page": page,

        "pageSize": page_size,

    }

    if status:

        query["status"] = status

    payload = _grok2api_get_json(

        cfg["base_url"],

        token,

        "/api/admin/v1/accounts",

        query,

        timeout=timeout,

    )

    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload

    batch = data.get("items") if isinstance(data, dict) else []

    if not isinstance(batch, list):

        raise RuntimeError("Grok2API 账号列表 items 字段格式异常")

    items = [row for row in batch if isinstance(row, dict)]

    total = int(data.get("total") or len(items)) if isinstance(data, dict) else len(items)

    current_page_size = int(data.get("pageSize") or page_size) if isinstance(data, dict) else page_size

    return items, total, current_page_size





def _fetch_grok2api_provider_accounts(

    cfg: dict[str, Any],

    token: str,

    provider: str,

    *,

    page_size: int,

    timeout: float,

    statuses: list[str] | tuple[str, ...] | None = None,

) -> list[dict[str, Any]]:

    """Page through admin account list.



    When ``statuses`` is set, only those server-side filters are requested

    (e.g. reauthRequired / waitingReset). Otherwise the full provider list is

    mirrored page by page.

    """

    if not statuses:

        page = 1

        items: list[dict[str, Any]] = []

        while True:

            batch, total, current_page_size = _fetch_grok2api_accounts_page(

                cfg,

                token,

                provider=provider,

                page=page,

                page_size=page_size,

                timeout=timeout,

            )

            items.extend(batch)

            if page * current_page_size >= total or not batch:

                break

            page += 1

        return items



    # Problem-only mode: one filtered crawl per status, de-duped by remote id.

    merged: list[dict[str, Any]] = []

    seen: set[str] = set()

    for status in statuses:

        status = str(status or "").strip()

        if not status:

            continue

        page = 1

        while True:

            batch, total, current_page_size = _fetch_grok2api_accounts_page(

                cfg,

                token,

                provider=provider,

                page=page,

                page_size=page_size,

                timeout=timeout,

                status=status,

            )

            for row in batch:

                rid = str(row.get("id") or row.get("authIndex") or row.get("email") or "").strip().lower()

                if not rid or rid in seen:

                    continue

                seen.add(rid)

                merged.append(row)

            if page * current_page_size >= total or not batch:

                break

            page += 1

    return merged





def fetch_grok2api_accounts_summary(

    config: dict[str, Any] | None = None,

    *,

    token: str | None = None,

    timeout: float = 20.0,

) -> dict[str, Any]:

    """Lightweight remote counters from ``GET /api/admin/v1/accounts/summary``."""

    cfg = normalize_grok2api_config(config or get_grok2api_config(include_password=True))

    auth = token or grok2api_login(cfg["base_url"], cfg["username"], cfg["password"])

    payload = _grok2api_get_json(

        cfg["base_url"],

        auth,

        "/api/admin/v1/accounts/summary",

        {},

        timeout=timeout,

    )

    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload

    return data if isinstance(data, dict) else {}





def _upsert_remote_account_row(

    conn: sqlite3.Connection,

    *,

    provider: str,

    classified: dict[str, Any],

    raw: dict[str, Any] | None,

    seen_at: float,

    mode_norm: str,

) -> bool:

    email = str(classified.get("email") or "").strip().lower()

    remote_id = str(classified.get("remote_id") or email or f"row-{seen_at}").strip()

    if not email:

        return False

    conn.execute(

        """

        INSERT INTO remote_accounts(

          provider, remote_id, email, classification, http_status, action, reason,

          auth_status, disabled, model, raw_json, seen_at

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

        ON CONFLICT(provider, remote_id) DO UPDATE SET

          email = excluded.email,

          classification = excluded.classification,

          http_status = excluded.http_status,

          action = excluded.action,

          reason = excluded.reason,

          auth_status = excluded.auth_status,

          disabled = excluded.disabled,

          model = excluded.model,

          raw_json = excluded.raw_json,

          seen_at = excluded.seen_at

        """,

        (

            provider,

            remote_id,

            email,

            str(classified.get("classification") or ""),

            classified.get("http_status"),

            str(classified.get("action") or ""),

            str(classified.get("reason") or ""),

            str(classified.get("auth_status") or ""),

            classified.get("disabled"),

            str(classified.get("model") or ""),

            json.dumps(raw if isinstance(raw, dict) else (classified or {}), ensure_ascii=False),

            seen_at,

        ),

    )

    # Real remote row supersedes any local-upload marker for the same email.

    conn.execute(

        """

        DELETE FROM remote_accounts

        WHERE provider = ?

          AND lower(email) = ?

          AND remote_id != ?

          AND (

            remote_id LIKE 'local-upload::%'

            OR lower(IFNULL(reason, '')) LIKE 'local_upload%'

            OR lower(IFNULL(reason, '')) LIKE 'manual_upload%'

            OR lower(IFNULL(reason, '')) LIKE 'auto_upload%'

          )

        """,

        (provider, email, remote_id),

    )

    if mode_norm == "problems":

        # Problem row wins over a previous local healthy marker for the same email.

        conn.execute(

            """

            DELETE FROM remote_accounts

            WHERE provider = ?

              AND lower(email) = ?

              AND remote_id != ?

              AND (

                lower(IFNULL(classification, '')) = 'healthy'

                OR lower(IFNULL(action, '')) IN ('keep', 'ok', 'active')

              )

            """,

            (provider, email, remote_id),

        )

    return True





def _clear_remote_provider_cache(conn: sqlite3.Connection, provider: str, *, mode_norm: str) -> None:

    if mode_norm == "full":

        # Wipe remote mirror, but KEEP local-upload / auto-import markers.

        conn.execute(

            """

            DELETE FROM remote_accounts

            WHERE provider = ?

              AND remote_id NOT LIKE 'local-upload::%'

              AND lower(IFNULL(reason, '')) NOT LIKE 'local_upload%'

              AND lower(IFNULL(reason, '')) NOT LIKE 'manual_upload%'

              AND lower(IFNULL(reason, '')) NOT LIKE 'auto_upload%'

            """,

            (provider,),

        )

    else:

        # Drop stale problem rows only. Healthy / local-import rows stay.

        conn.execute(

            """

            DELETE FROM remote_accounts

            WHERE provider = ?

              AND NOT (

                lower(IFNULL(classification, '')) = 'healthy'

                OR lower(IFNULL(action, '')) IN ('keep', 'ok', 'active')

              )

              AND remote_id NOT LIKE 'local-upload::%'

              AND lower(IFNULL(reason, '')) NOT LIKE 'local_upload%'

              AND lower(IFNULL(reason, '')) NOT LIKE 'manual_upload%'

              AND lower(IFNULL(reason, '')) NOT LIKE 'auto_upload%'

            """,

            (provider,),

        )





def _record_remote_accounts(

    provider: str,

    rows: list[dict[str, Any]],

    *,

    seen_at: float,

    mode: str = "full",

) -> int:

    """Write remote account rows for one Grok2API provider."""

    init_db()

    mode_norm = str(mode or "full").strip().lower()

    if mode_norm in {"all", "full", "mirror", "complete"}:

        mode_norm = "full"

    else:

        mode_norm = "problems"



    written = 0

    with _connect() as conn:

        _clear_remote_provider_cache(conn, provider, mode_norm=mode_norm)

        for item in rows:

            classified = classify_grok2api_account(item)

            if _upsert_remote_account_row(

                conn,

                provider=provider,

                classified=classified,

                raw=item,

                seen_at=seen_at,

                mode_norm=mode_norm,

            ):

                written += 1

    return written





def _record_classified_remote_accounts(

    provider: str,

    rows: list[dict[str, Any]],

    *,

    seen_at: float,

    mode: str = "full",

) -> int:

    """Write already-classified remote rows (CPA grok-inspection / custom)."""

    init_db()

    mode_norm = str(mode or "full").strip().lower()

    if mode_norm in {"all", "full", "mirror", "complete"}:

        mode_norm = "full"

    else:

        mode_norm = "problems"

    written = 0

    with _connect() as conn:

        _clear_remote_provider_cache(conn, provider, mode_norm=mode_norm)

        for item in rows:

            if not isinstance(item, dict):

                continue

            # Accept either pre-classified shape or raw inspection rows.

            if item.get("classification") or item.get("action") or item.get("http_status") is not None:

                classified = {

                    "email": str(item.get("email") or item.get("name") or "").strip().lower(),

                    "classification": str(item.get("classification") or ""),

                    "http_status": item.get("http_status"),

                    "action": str(item.get("action") or ""),

                    "reason": str(item.get("reason") or item.get("status_message") or ""),

                    "auth_status": str(item.get("auth_status") or item.get("authStatus") or ""),

                    "disabled": item.get("disabled"),

                    "model": str(item.get("model") or ""),

                    "remote_id": str(

                        item.get("remote_id")

                        or item.get("auth_index")

                        or item.get("file_name")

                        or item.get("file_id")

                        or item.get("email")

                        or item.get("name")

                        or ""

                    ),

                }

            else:

                classified = classify_cpa_inspection_result(item)

            if _upsert_remote_account_row(

                conn,

                provider=provider,

                classified=classified,

                raw=item,

                seen_at=seen_at,

                mode_norm=mode_norm,

            ):

                written += 1

    return written





def classify_cpa_inspection_result(row: dict[str, Any]) -> dict[str, Any]:

    """Map CPA grok-inspection plugin result → remote_accounts shape."""

    email = str(row.get("email") or row.get("name") or "").strip().lower()

    classification = str(row.get("classification") or "").strip().lower()

    reason = str(row.get("reason") or row.get("status_message") or row.get("message") or "").strip()

    action_raw = str(row.get("action") or "").strip().lower()

    model = str(row.get("model") or "").strip()

    file_name = str(row.get("file_name") or row.get("file_id") or row.get("auth_index") or "").strip()

    disabled = row.get("disabled")

    try:

        http_status = int(row.get("http_status") or 0) or None

    except Exception:

        http_status = None



    # Normalize common plugin labels.

    if classification in {"ok", "active", "good", "pass", "passed"}:

        classification = "healthy"

    if classification in {"need_reauth", "need-reauth", "relogin", "unauthorized", "token_expired"}:

        classification = "reauth"

    if classification in {"quota", "rate_limit", "ratelimited", "waiting_reset", "waitingreset"}:

        classification = "quota_exhausted"

    if classification in {"error", "fail", "failed", "probe-error"}:

        classification = "probe_error"

    if not classification:

        if http_status == 401:

            classification = "reauth"

        elif http_status == 403:

            classification = "permission_denied"

        elif http_status == 429:

            classification = "quota_exhausted"

        elif http_status is not None and http_status >= 500:

            classification = "probe_error"

        elif http_status in (None, 200):

            classification = "healthy"

        else:

            classification = f"http_{http_status}"



    if action_raw in {"keep", "ok", "active", "relogin", "wait", "inspect", "enable_or_ignore"}:

        action = action_raw if action_raw != "ok" else "keep"

    elif classification == "healthy":

        action = "keep"

    elif classification == "reauth":

        action = "relogin"

    elif classification == "quota_exhausted":

        action = "wait"

    elif classification == "disabled":

        action = "enable_or_ignore"

    else:

        action = "inspect"



    if classification == "reauth" and http_status is None:

        http_status = 401

    if classification == "quota_exhausted" and http_status is None:

        http_status = 429

    if classification == "permission_denied" and http_status is None:

        http_status = 403



    return {

        "email": email,

        "classification": classification or "unknown",

        "http_status": http_status,

        "action": action,

        "reason": reason or classification or "inspection",

        "auth_status": str(row.get("auth_status") or row.get("authStatus") or classification or ""),

        "disabled": None if disabled is None else int(bool(disabled)),

        "model": model,

        "remote_id": file_name or email or f"cpa-{hash(email) & 0xFFFFFFFF:x}",

    }



def _is_remote_problem_classified(row: dict[str, Any]) -> bool:
    action = str(row.get("action") or "").strip().lower()
    classification = str(row.get("classification") or "").strip().lower()
    try:
        http_status = int(row.get("http_status") or 0)
    except Exception:
        http_status = 0
    if action in {"keep", "ok", "active"} or classification == "healthy" or http_status == 200:
        return False
    return bool(action or classification or http_status)



def _collect_problem_emails(rows: list[dict[str, Any]]) -> list[str]:
    """Extract unique problem emails from classified remote rows."""
    emails: list[str] = []
    seen: set[str] = set()
    for row in rows or []:
        if not isinstance(row, dict) or not _is_remote_problem_classified(row):
            continue
        email = str(row.get("email") or row.get("name") or "").strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            continue
        if email in seen:
            continue
        seen.add(email)
        emails.append(email)
    return emails


def _auto_restore_problem_accounts_from_recycle(
    rows: list[dict[str, Any]],
    *,
    source: str = "cpa_remote",
) -> dict[str, Any]:
    """When CPA reports problem accounts, restore matching soft-deleted local rows first."""
    emails = _collect_problem_emails(rows)
    if not emails:
        return {
            "ok": True,
            "restored": 0,
            "overwritten": 0,
            "requested": 0,
            "candidates": 0,
            "emails": [],
            "source": source,
        }
    init_db()
    candidates: list[str] = []
    with _connect() as conn:
        for email in emails:
            exists = conn.execute(
                "SELECT 1 FROM accounts WHERE lower(email) = ? LIMIT 1",
                (email,),
            ).fetchone()
            if exists:
                continue
            recycled = conn.execute(
                "SELECT 1 FROM account_recycle_bin WHERE lower(email) = ? LIMIT 1",
                (email,),
            ).fetchone()
            if recycled:
                candidates.append(email)
    if not candidates:
        return {
            "ok": True,
            "restored": 0,
            "overwritten": 0,
            "requested": len(emails),
            "candidates": 0,
            "emails": [],
            "source": source,
        }
    result = restore_accounts_from_recycle(
        candidates,
        restore_all=False,
        overwrite=False,
    )
    result = dict(result or {})
    result["source"] = source
    result["candidates"] = len(candidates)
    result["requested"] = len(emails)
    return result


def _create_cpa_remote_placeholder_accounts(rows: list[dict[str, Any]], *, source: str) -> int:
    """Deprecated: no longer create remote_only local placeholders for CPA remote problems.

    Kept as a no-op for backward compatibility. CPA sync restores from recycle bin when
    possible and leaves unmatched remote problems as remote-only status rows.
    """
    return 0


def sync_grok2api_remote_status(

    config: dict[str, Any] | None = None,

    *,

    providers: Any = None,

    page_size: int = 200,

    timeout: float = 45.0,

    mode: str = "problems",

) -> dict[str, Any]:

    """Pull Grok2API account status into local ``remote_accounts``.



    ``mode``:

      - ``problems`` (default): only server-filtered abnormal accounts

        (reauthRequired / waitingReset / disabled / cooldown / probing).

        Uses ``/api/admin/v1/accounts?status=...`` — not the full inventory.

      - ``full``: page through every account for selected providers (slow).

    """

    cfg = normalize_grok2api_config(config or get_grok2api_config(include_password=True))

    selected = normalize_grok2api_providers(providers)

    page_size = max(1, min(500, int(page_size or 200)))

    mode_norm = str(mode or "problems").strip().lower()

    if mode_norm in {"all", "full", "mirror", "complete"}:

        mode_norm = "full"

    else:

        mode_norm = "problems"

    token = grok2api_login(cfg["base_url"], cfg["username"], cfg["password"])

    seen_at = time.time()

    counts: Counter[str] = Counter()

    provider_counts: dict[str, int] = {}

    problem_statuses = list(GROK2API_PROBLEM_STATUSES) if mode_norm == "problems" else None



    remote_summary: dict[str, Any] = {}

    if mode_norm == "problems":

        try:

            remote_summary = fetch_grok2api_accounts_summary(cfg, token=token, timeout=min(20.0, timeout))

        except Exception:

            remote_summary = {}



    # Prefer summary to skip empty providers / empty problem buckets.

    active_providers = list(selected)

    active_statuses = list(problem_statuses or [])

    if mode_norm == "problems" and remote_summary:

        prov_map = remote_summary.get("providers") if isinstance(remote_summary.get("providers"), dict) else {}

        if prov_map:

            filtered = []

            for p in active_providers:

                meta = prov_map.get(p) if isinstance(prov_map.get(p), dict) else {}

                total_p = int(meta.get("total") or 0)

                available_p = int(meta.get("available") or 0)

                # Keep provider if it has any non-available accounts, or summary is incomplete.

                if total_p <= 0:

                    continue

                if available_p >= total_p and int(remote_summary.get("attention") or 0) == 0 and int(remote_summary.get("recovering") or 0) == 0:

                    # Still pull disabled/reauth filters — summary available may include

                    # waitingReset as non-available; only skip truly empty providers.

                    pass

                filtered.append(p)

            if filtered:

                active_providers = filtered

        # Drop status filters the summary already reports as zero.

        issues = remote_summary.get("issues") if isinstance(remote_summary.get("issues"), dict) else {}

        recovery = remote_summary.get("recovery") if isinstance(remote_summary.get("recovery"), dict) else {}

        status_hint = {

            "reauthRequired": int(issues.get("reauthRequired") or 0),

            "disabled": int(issues.get("disabled") or 0),

            "waitingReset": int(recovery.get("waitingReset") or remote_summary.get("recovering") or 0),

            "cooldown": int(recovery.get("cooldown") or 0),

            "probing": int(recovery.get("probing") or 0),

        }

        # Only skip when summary explicitly gave us the counters (keys present).

        if issues or recovery:

            kept = []

            for st in active_statuses:

                if st in status_hint and status_hint[st] <= 0:

                    continue

                kept.append(st)

            # Always keep at least reauthRequired + waitingReset if summary attention/recovering > 0

            # but counters missing — safety net already handled by status_hint defaults.

            if kept:

                active_statuses = kept



    for provider in active_providers:

        items = _fetch_grok2api_provider_accounts(

            cfg,

            token,

            provider,

            page_size=page_size,

            timeout=timeout,

            statuses=active_statuses if mode_norm == "problems" else None,

        )

        provider_counts[provider] = _record_remote_accounts(

            provider, items, seen_at=seen_at, mode=mode_norm

        )

        for item in items:

            row = classify_grok2api_account(item)

            counts["total"] += 1

            counts[f"classification:{row.get('classification') or 'unknown'}"] += 1

            counts[f"action:{row.get('action') or 'unknown'}"] += 1

            counts[f"http:{row.get('http_status') or 'unknown'}"] += 1

    # Providers skipped by summary: full mode wipes them; problems mode only clears

    # stale problem rows and keeps healthy / local-upload markers.

    for provider in selected:

        if provider in provider_counts:

            continue

        provider_counts[provider] = _record_remote_accounts(

            provider, [], seen_at=seen_at, mode=mode_norm

        )



    with _connect() as conn:

        local_total = int(conn.execute("SELECT COUNT(*) AS n FROM accounts").fetchone()["n"])

        matched = int(

            conn.execute(

                """

                SELECT COUNT(DISTINCT a.email) AS n

                FROM accounts a

                JOIN remote_accounts r ON lower(r.email) = lower(a.email)

                """

            ).fetchone()["n"]

        )

        remote_only_failures = int(

            conn.execute(

                """

                SELECT COUNT(*) AS n

                FROM remote_accounts r

                LEFT JOIN accounts a ON lower(a.email) = lower(r.email)

                WHERE a.email IS NULL AND (r.action != 'keep' OR COALESCE(r.http_status, 200) != 200)

                """

            ).fetchone()["n"]

        )



    pulled_total = int(counts["total"])

    # In problems mode local cache only holds abnormal rows; prefer the lightweight

    # summary total for "远端一共有多少账号" so the UI does not look like 366 is all.

    inventory_total = pulled_total

    if mode_norm == "problems" and remote_summary:

        try:

            inventory_total = int(remote_summary.get("total") or pulled_total)

        except (TypeError, ValueError):

            inventory_total = pulled_total



    summary = {

        "ok": True,

        "base_url": cfg["base_url"],

        "providers": selected,

        "mode": mode_norm,

        "problem_statuses": list(active_statuses if mode_norm == "problems" else []),

        "provider_counts": provider_counts,

        "counts": dict(sorted(counts.items())),

        # Rows actually written to remote_accounts this pull.

        "remote_total": pulled_total,

        "problem_total": pulled_total if mode_norm == "problems" else None,

        # Full remote inventory size when summary is available.

        "remote_inventory_total": inventory_total,

        "remote_summary": {

            "total": remote_summary.get("total"),

            "available": remote_summary.get("available"),

            "attention": remote_summary.get("attention"),

            "recovering": remote_summary.get("recovering"),

            "issues": remote_summary.get("issues"),

            "recovery": remote_summary.get("recovery"),

            "providers": remote_summary.get("providers"),

        }

        if remote_summary

        else None,

        "local_total": local_total,

        "matched_local": matched,

        "remote_only_failures": remote_only_failures,

        "seen_at": seen_at,

    }

    _set_json_setting("grok2api_last_remote_sync", summary)

    # Rebuild lightweight dashboard cache once after remote pull — not on every list.

    try:

        summary["stats"] = refresh_account_dashboard_stats()

    except Exception:

        pass

    return summary





def mark_local_remote_imported(

    emails: list[str] | str,

    *,

    provider: str = "grok_build",

    reason: str = "local_upload_ok",

) -> dict[str, Any]:

    """After a successful remote upload, mark accounts as imported in the local cache.



    UI remote column uses ``remote_accounts``:

      - missing row after a remote sync ⇒ 「未导入」

      - healthy/keep row ⇒ 「已导入/正常」



    Upload success previously did not write this cache, so freshly registered

    accounts stayed 「未导入」 until the next full remote pull found them.

    """

    if isinstance(emails, str):

        items = [emails]

    else:

        items = list(emails or [])

    clean = sorted({str(e or "").strip().lower() for e in items if str(e or "").strip()})

    if not clean:

        return {"ok": True, "updated": 0, "emails": []}

    now = time.time()

    prov = str(provider or "grok_build").strip() or "grok_build"

    why = str(reason or "local_upload_ok")[:120]

    upserted = 0

    with _connect() as conn:

        for email in clean:

            remote_id = f"local-upload::{email}"

            # Prefer updating any existing row for this email/provider; else insert.

            existing = conn.execute(

                """

                SELECT remote_id FROM remote_accounts

                WHERE provider = ? AND lower(email) = ?

                ORDER BY seen_at DESC LIMIT 1

                """,

                (prov, email),

            ).fetchone()

            if existing:

                rid = str(existing["remote_id"] or remote_id)

                conn.execute(

                    """

                    UPDATE remote_accounts

                    SET classification = 'healthy',

                        http_status = 200,

                        action = 'keep',

                        reason = ?,

                        auth_status = 'active',

                        disabled = 0,

                        seen_at = ?

                    WHERE provider = ? AND remote_id = ?

                    """,

                    (why, now, prov, rid),

                )

            else:

                conn.execute(

                    """

                    INSERT INTO remote_accounts(

                      provider, remote_id, email, classification, http_status, action, reason,

                      auth_status, disabled, model, raw_json, seen_at

                    )

                    VALUES (?, ?, ?, 'healthy', 200, 'keep', ?, 'active', 0, '', '{}', ?)

                    ON CONFLICT(provider, remote_id) DO UPDATE SET

                      email = excluded.email,

                      classification = 'healthy',

                      http_status = 200,

                      action = 'keep',

                      reason = excluded.reason,

                      auth_status = 'active',

                      disabled = 0,

                      seen_at = excluded.seen_at

                    """,

                    (prov, remote_id, email, why, now),

                )

            upserted += 1

    try:

        refresh_account_dashboard_stats()

    except Exception:

        pass

    return {"ok": True, "updated": upserted, "emails": clean, "provider": prov}







def mark_accounts_pushed(

    emails: list[str] | str,

    *,

    cpa: bool = False,

    sub2: bool = False,

    grok2api: bool = False,

) -> dict[str, Any]:

    """Mark local accounts as already pushed to CPA / Sub2API / Grok2API."""

    if isinstance(emails, str):

        emails = [emails]

    clean = sorted({str(e or "").strip().lower() for e in (emails or []) if str(e or "").strip()})

    if not clean or not (cpa or sub2 or grok2api):

        return {"ok": True, "updated": 0, "emails": clean}

    init_db()

    now = time.time()

    sets: list[str] = []

    args: list[Any] = []

    if cpa:

        sets.append("cpa_pushed = 1")

        sets.append("cpa_pushed_at = ?")

        args.append(now)

    if sub2:

        sets.append("sub2_pushed = 1")

        sets.append("sub2_pushed_at = ?")

        args.append(now)

    if grok2api:

        sets.append("grok2api_pushed = 1")

        sets.append("grok2api_pushed_at = ?")

        args.append(now)

    sets.append("updated_at = ?")

    args.append(now)

    placeholders = ",".join("?" for _ in clean)

    sql = f"UPDATE accounts SET {', '.join(sets)} WHERE lower(email) IN ({placeholders})"

    with _connect() as conn:

        cur = conn.execute(sql, [*args, *clean])

        updated = int(cur.rowcount or 0)

    return {"ok": True, "updated": updated, "emails": clean}





def normalize_sub2api_config(raw: dict[str, Any] | None) -> dict[str, Any]:

    src = {**DEFAULT_SUB2API_CONFIG, **(raw or {})}



    def _as_bool(v, default=False):

        if isinstance(v, bool):

            return v

        if v is None:

            return default

        return str(v).strip().lower() in {"1", "true", "yes", "on"}



    out = dict(src)

    out["api_base"] = str(out.get("api_base") or "").strip().rstrip("/")

    out["api_key"] = str(out.get("api_key") or "").strip()

    out["upload_enabled"] = _as_bool(out.get("upload_enabled"), True)

    out["auto_upload_after_probe"] = _as_bool(out.get("auto_upload_after_probe"), False)

    out["auto_upload_after_relogin"] = _as_bool(out.get("auto_upload_after_relogin"), False)

    out["timeout"] = _clamp_int(out.get("timeout"), 30, 5, 180)

    out["retries"] = _clamp_int(out.get("retries"), 3, 1, 10)

    out["platform"] = str(out.get("platform") or "grok").strip() or "grok"

    out["account_type"] = str(out.get("account_type") or "oauth").strip() or "oauth"

    out["account_concurrency"] = _clamp_int(out.get("account_concurrency"), 1, 1, 200)

    out["account_priority"] = _clamp_int(out.get("account_priority"), 1, 0, 1000)

    out["account_load_factor"] = _clamp_int(out.get("account_load_factor"), 10, 1, 10000)

    try:

        out["account_rate_multiplier"] = float(out.get("account_rate_multiplier") or 1.0)

    except (TypeError, ValueError):

        out["account_rate_multiplier"] = 1.0

    out["account_group_ids"] = str(out.get("account_group_ids") or "").strip()

    out["default_proxy"] = str(out.get("default_proxy") or "").strip()

    out["local_export"] = _as_bool(out.get("local_export"), False)

    out["local_export_dir"] = str(out.get("local_export_dir") or "").strip()

    out["limit"] = _clamp_int(out.get("limit"), 1000, 1, 5000)

    return out





def get_sub2api_config(*, include_key: bool = True) -> dict[str, Any]:

    cfg = normalize_sub2api_config(_json_setting("sub2api_config") or {})

    if include_key:

        return cfg

    public = dict(cfg)

    public["api_key_set"] = bool(public.get("api_key"))

    public["api_key"] = "********" if public.get("api_key") else ""

    return public





def set_sub2api_config(patch: dict[str, Any] | None, *, replace: bool = False) -> dict[str, Any]:

    base = {} if replace else (_json_setting("sub2api_config") or {})

    incoming = dict(patch or {})

    if not replace:

        key = incoming.get("api_key")

        if key is None or (isinstance(key, str) and (not key.strip() or set(key.strip()) <= {"*"})):

            incoming.pop("api_key", None)

    merged = {**base, **incoming}

    cfg = normalize_sub2api_config(merged)

    _set_json_setting("sub2api_config", cfg)

    return cfg





def test_sub2api_remote(config: dict[str, Any] | None = None) -> dict[str, Any]:

    """Lightweight connectivity check against Sub2API admin API."""

    cfg = normalize_sub2api_config(config or get_sub2api_config(include_key=True))

    base = str(cfg.get("api_base") or "").strip().rstrip("/")

    key = str(cfg.get("api_key") or "").strip()

    if not base:

        return {"ok": False, "error": "Sub2API api_base is empty"}

    if not key:

        return {"ok": False, "error": "Sub2API api_base is empty"}

    url = base + "/api/v1/admin/accounts"

    req = urllib.request.Request(

        url + "?page=1&page_size=1",

        headers={"x-api-key": key, "Accept": "application/json"},

        method="GET",

    )

    try:

        with _urlopen(req, timeout=float(cfg.get("timeout") or 30)) as resp:

            status = int(resp.status)

            body = resp.read(500).decode("utf-8", "replace")

        if status >= 400:

            return {"ok": False, "error": f"HTTP {status}: {body[:200]}", "status": status}

        return {"ok": True, "status": status, "message": "Sub2API connection ok", "preview": body[:120]}

    except Exception as exc:  # noqa: BLE001

        return {"ok": False, "error": str(exc)[:300]}





def _build_sub2api_push_cfg(cfg: dict[str, Any]) -> dict[str, Any]:

    """Map pro sub2 config ? cpa_to_sub2api expected keys."""

    return {

        "sub2api_upload_enabled": True,

        "sub2api_export_enabled": bool(cfg.get("local_export")),

        "sub2api_api_base": str(cfg.get("api_base") or "").strip(),

        "sub2api_api_key": str(cfg.get("api_key") or "").strip(),

        "sub2api_upload_timeout": int(cfg.get("timeout") or 30),

        "sub2api_upload_retries": int(cfg.get("retries") or 3),

        "sub2api_platform": str(cfg.get("platform") or "grok"),

        "sub2api_account_type": str(cfg.get("account_type") or "oauth"),

        "sub2api_account_concurrency": int(cfg.get("account_concurrency") or 1),

        "sub2api_account_priority": int(cfg.get("account_priority") or 1),

        "sub2api_account_load_factor": int(cfg.get("account_load_factor") or 10),

        "sub2api_account_rate_multiplier": float(cfg.get("account_rate_multiplier") or 1.0),

        "sub2api_account_group_ids": str(cfg.get("account_group_ids") or ""),

        "sub2api_default_proxy": str(cfg.get("default_proxy") or ""),

        "sub2api_local_export": bool(cfg.get("local_export")),

        "sub2api_local_export_dir": str(cfg.get("local_export_dir") or ""),

    }





def upload_sub2api_auth_files(

    config: dict[str, Any] | None = None,

    *,

    limit: int = 1000,

    emails: list[str] | None = None,

    require_probe: bool = True,

    skip_already_pushed: bool = True,

) -> dict[str, Any]:

    """Push CPA auth payloads to Sub2API; mark accounts sub2_pushed on success."""

    cfg = normalize_sub2api_config(config or get_sub2api_config(include_key=True))

    if not cfg.get("upload_enabled", True):

        return {"ok": False, "error": "Sub2API push disabled", "uploaded": 0, "files": 0}

    if not str(cfg.get("api_base") or "").strip():

        return {"ok": False, "error": "Sub2API api_base is empty", "uploaded": 0, "files": 0}

    if not str(cfg.get("api_key") or "").strip():

        return {"ok": False, "error": "Sub2API api_key is empty", "uploaded": 0, "files": 0}



    approved, skipped = _verified_remote_import_emails(

        emails, limit=limit, require_probe=require_probe

    )

    if skip_already_pushed and approved:

        init_db()

        with _connect() as conn:

            rows = conn.execute(

                "SELECT lower(email) AS e, IFNULL(sub2_pushed, 0) AS p FROM accounts "

                "WHERE lower(email) IN (" + ",".join("?" for _ in approved) + ")",

                approved,

            ).fetchall()

        already = {str(r["e"]) for r in rows if int(r["p"] or 0)}

        if already:

            skipped = list(skipped) + [

                {"email": e, "reason": "already_sub2_pushed"} for e in approved if e in already

            ]

            approved = [e for e in approved if e not in already]



    parts = list_cpa_auth_parts(limit=limit, emails=approved)

    if not parts:

        return {

            "ok": False,

            "error": "没有可推送的 CPA Auth" if not require_probe else "没有通过测活的 CPA Auth 可推送",

            "files": 0,

            "uploaded": 0,

            "skipped": len(skipped),

            "skipped_accounts": skipped[:100],

        }



    try:

        import cpa_to_sub2api as sub_mod  # type: ignore

    except Exception as exc:  # noqa: BLE001

        return {"ok": False, "error": f"无法加载 cpa_to_sub2api: {exc}", "uploaded": 0, "files": 0}



    push_cfg = _build_sub2api_push_cfg(cfg)

    results: list[dict[str, Any]] = []

    ok_emails: list[str] = []

    for filename, payload in parts:

        raw = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode("utf-8")

        email_hint = ""

        auth_doc: dict[str, Any] | None = None

        try:

            auth_doc = json.loads(raw.decode("utf-8"))

            if isinstance(auth_doc, dict):

                email_hint = str(

                    auth_doc.get("email")

                    or auth_doc.get("Email")

                    or (auth_doc.get("credentials") or {}).get("email")

                    or ""

                ).strip().lower()

        except Exception:

            auth_doc = None

        if not email_hint:

            email_hint = (

                filename.replace("xai-", "").replace(".json", "").replace("_at_", "@").lower()

            )

        try:

            res = sub_mod.upload_cpa_auth_to_sub2api(auth_doc if auth_doc is not None else raw, push_cfg)

        except Exception as exc:  # noqa: BLE001

            res = {"ok": False, "error": str(exc)[:300]}

        ok = bool(isinstance(res, dict) and res.get("ok"))

        results.append({"filename": filename, "email": email_hint, "ok": ok, "result": res})

        if ok and email_hint:

            ok_emails.append(email_hint)



    ok_count = sum(1 for r in results if r.get("ok"))

    if ok_emails:

        try:

            mark_accounts_pushed(ok_emails, sub2=True)

        except Exception:

            pass

        try:

            mark_local_remote_imported(ok_emails, provider="sub2api", reason="upload_sub2api")

        except Exception:

            pass



    summary = {

        "ok": ok_count > 0 and ok_count == len(results),

        "files": len(parts),

        "uploaded": ok_count,

        "failed": len(results) - ok_count,

        "skipped": len(skipped),

        "skipped_accounts": skipped[:100],

        "results": results[:50],

        "emails": ok_emails,

        "api_base": cfg.get("api_base"),

    }

    _set_json_setting(

        "sub2api_last_upload",

        {

            "at": time.time(),

            "files": len(parts),

            "uploaded": ok_count,

            "failed": len(results) - ok_count,

            "api_base": cfg.get("api_base"),

        },

    )

    return summary





def mark_local_relogin_resolved(emails: list[str] | str) -> dict[str, Any]:

    """After a successful local relogin + probe, mark account as locally relogged.



    - accounts.status becomes ``relogged`` (本地优先展示「已重登」)

    - stale remote_accounts reauth/relogin rows are cleared to healthy

    Next remote pull may re-assert 需重登 if upstream still says so.

    """

    if isinstance(emails, str):

        items = [emails]

    else:

        items = list(emails or [])

    clean = sorted({str(e or "").strip().lower() for e in items if str(e or "").strip()})

    if not clean:

        return {"ok": True, "updated": 0, "emails": []}

    now = time.time()

    placeholders = ",".join("?" for _ in clean)

    with _connect() as conn:

        # Prefer local success: flip any cached remote reauth/relogin rows to healthy.

        cur = conn.execute(

            f"""

            UPDATE remote_accounts

            SET classification = 'healthy',

                http_status = 200,

                action = 'keep',

                reason = 'local_relogin_resolved',

                auth_status = 'active',

                seen_at = ?

            WHERE lower(email) IN ({placeholders})

              AND (

                lower(IFNULL(action,'')) LIKE '%relogin%'

                OR lower(IFNULL(classification,'')) IN ('reauth','relogin')

                OR IFNULL(http_status,0) IN (401,403)

              )

            """,

            [now, *clean],

        )

        remote_updated = int(cur.rowcount or 0)

        # Distinct local status so UI can show 「已重登」 instead of stale 需重登.

        conn.execute(

            f"""

            UPDATE accounts

            SET status = 'relogged',

                relogin_status = 'resolved',

                relogin_requested_at = ?,

                updated_at = ?

            WHERE lower(email) IN ({placeholders})

            """,

            [now, now, *clean],

        )

    # Cheap cache patch: drop resolved emails from 需重登 counter without full recompute.

    try:

        _patch_dashboard_stats_after_local_relogin(len(clean), remote_updated)

    except Exception:

        try:

            refresh_account_dashboard_stats()

        except Exception:

            pass

    return {"ok": True, "updated": remote_updated, "emails": clean}





def _latest_remote_by_email(conn: sqlite3.Connection, emails: list[str]) -> dict[str, dict[str, Any]]:

    if not emails:

        return {}

    placeholders = ",".join("?" for _ in emails)

    rows = conn.execute(

        f"""

        SELECT r.*

        FROM remote_accounts r

        WHERE lower(r.email) IN ({placeholders})

        ORDER BY r.seen_at DESC

        """,

        [email.lower() for email in emails],

    ).fetchall()

    priority = {

        "relogin": 0,

        "probe_error": 1,

        "quota_exhausted": 2,

        "disabled": 3,

        "healthy": 9,

    }

    out: dict[str, dict[str, Any]] = {}

    for row in rows:

        item = dict(row)

        email = str(item.get("email") or "").lower()

        current = out.get(email)

        if not current:

            out[email] = item

            continue

        old_rank = priority.get(str(current.get("classification") or ""), 5)

        new_rank = priority.get(str(item.get("classification") or ""), 5)

        if new_rank < old_rank:

            out[email] = item

    return out





def list_grok2api_auth_files(limit: int = 1000) -> list[Path]:

    init_db()

    limit = max(1, min(5000, int(limit or 1000)))

    with _connect() as conn:

        rows = conn.execute(

            """

            SELECT grok2api_auth_path

            FROM accounts

            WHERE grok2api_auth_path IS NOT NULL AND grok2api_auth_path != ''

            ORDER BY updated_at DESC

            LIMIT ?

            """,

            (limit,),

        ).fetchall()

    files: list[Path] = []

    seen: set[str] = set()

    for row in rows:

        path = Path(str(row["grok2api_auth_path"]))

        key = str(path)

        if key in seen or not path.is_file():

            continue

        seen.add(key)

        files.append(path)

    return files





def _auth_part_filename(email: str, *, cpa: bool = False) -> str:

    safe = _safe_name(email)

    return f"xai-{safe}.json" if cpa else f"{safe}.json"





def _auth_parts(

    *,

    limit: int,

    json_column: str,

    path_column: str,

    cpa: bool = False,

    emails: list[str] | None = None,

) -> list[tuple[str, bytes]]:

    init_db()

    limit = max(1, min(5000, int(limit or 1000)))

    clean = sorted({str(email or "").strip().lower() for email in (emails or []) if str(email or "").strip()})

    where = [f"({json_column} IS NOT NULL AND {json_column} != '') OR ({path_column} IS NOT NULL AND {path_column} != '')"]

    args: list[Any] = []

    if clean:

        where.append("lower(email) IN (" + ",".join("?" for _ in clean) + ")")

        args.extend(clean)

    with _connect() as conn:

        rows = conn.execute(

            f"""

            SELECT email, {json_column} AS auth_json, {path_column} AS auth_path

            FROM accounts

            WHERE {' AND '.join('(' + clause + ')' for clause in where)}

            ORDER BY updated_at DESC

            LIMIT ?

            """,

            [*args, limit],

        ).fetchall()



    parts: list[tuple[str, bytes]] = []

    seen: set[str] = set()

    for row in rows:

        email = str(row["email"] or "")

        filename = _auth_part_filename(email, cpa=cpa)

        if filename in seen:

            continue

        content = str(row["auth_json"] or "").strip()

        if content:

            payload = json.dumps(json.loads(content), ensure_ascii=False, indent=2).encode("utf-8") + b"\n"

        else:

            path = Path(str(row["auth_path"] or ""))

            if not path.is_file():

                continue

            payload = path.read_bytes()

            filename = path.name or filename

        seen.add(filename)

        parts.append((filename, payload))

    return parts





def _to_grok2api_import_document(raw: str | dict[str, Any], *, email_hint: str = "") -> dict[str, Any]:

    """Convert local auth storage into Grok2API ``accounts/import`` JSON.



    Grok2API expects either:

      {"provider":"grok_build","access_token":"...","refresh_token":"...","email":"..."}

    or:

      {"accounts":[ ... same fields ... ]}



    Local pro storage historically saved an internal map keyed by auth_key

    (``{ "https://auth.x.ai::client::user": {key, refresh_token, ...} }``), which

    the remote importer rejects with ``authImportFailed``.

    """

    if isinstance(raw, str):

        text = raw.strip()

        if not text:

            raise ValueError("empty auth json")

        data = json.loads(text)

    else:

        data = dict(raw or {})



    # Already in Grok2API batch shape.

    if isinstance(data.get("accounts"), list):

        return data



    # Flat single-account shape already compatible.

    if any(k in data for k in ("access_token", "refresh_token", "provider")) and "key" not in data:

        entry = {

            "provider": str(data.get("provider") or "grok_build"),

            "name": str(data.get("name") or data.get("email") or email_hint or "account"),

            "client_id": str(data.get("client_id") or data.get("oidc_client_id") or ""),

            "access_token": str(data.get("access_token") or data.get("key") or ""),

            "refresh_token": str(data.get("refresh_token") or ""),

            "id_token": str(data.get("id_token") or ""),

            "token_type": str(data.get("token_type") or "Bearer"),

            "expires_at": str(data.get("expires_at") or ""),

            "email": str(data.get("email") or email_hint or ""),

            "user_id": str(data.get("user_id") or data.get("principal_id") or data.get("sub") or ""),

        }

        return entry



    # Internal auth_map: {auth_key: entry, ...} — convert first/only entry.

    candidates: list[dict[str, Any]] = []

    if all(isinstance(v, dict) for v in data.values()) and data:

        for _key, value in data.items():

            if isinstance(value, dict):

                candidates.append(value)

    elif isinstance(data, dict):

        candidates.append(data)



    if not candidates:

        raise ValueError("unsupported auth json shape")



    accounts: list[dict[str, Any]] = []

    for item in candidates:

        access = str(item.get("access_token") or item.get("key") or "").strip()

        refresh = str(item.get("refresh_token") or "").strip()

        if not access and not refresh:

            continue

        email = str(item.get("email") or email_hint or "").strip()

        accounts.append(

            {

                "provider": "grok_build",

                "name": email or str(item.get("user_id") or item.get("principal_id") or "account"),

                "client_id": str(item.get("oidc_client_id") or item.get("client_id") or ""),

                "access_token": access,

                "refresh_token": refresh,

                "id_token": str(item.get("id_token") or ""),

                "token_type": "Bearer",

                "expires_at": str(item.get("expires_at") or ""),

                "email": email,

                "user_id": str(item.get("user_id") or item.get("principal_id") or item.get("sub") or ""),

            }

        )

    if not accounts:

        raise ValueError("auth json has no access_token/refresh_token")

    if len(accounts) == 1:

        return accounts[0]

    return {"accounts": accounts}





def list_grok2api_auth_parts(limit: int = 1000, *, emails: list[str] | None = None) -> list[tuple[str, bytes]]:

    """Export/upload parts from ``grok2api_auth_json`` (Grok2API format).



    Prefer the DB column as-is. Legacy auth-map rows are converted on the fly

    and rewritten back so the column stays canonical.

    """

    init_db()

    limit = max(1, min(5000, int(limit or 1000)))

    clean = sorted({str(email or "").strip().lower() for email in (emails or []) if str(email or "").strip()})

    where = [

        "(grok2api_auth_json IS NOT NULL AND grok2api_auth_json != '')"

        " OR (access_token IS NOT NULL AND access_token != '')"

        " OR (grok2api_auth_path IS NOT NULL AND grok2api_auth_path != '')"

    ]

    args: list[Any] = []

    if clean:

        where.append("lower(email) IN (" + ",".join("?" for _ in clean) + ")")

        args.extend(clean)

    with _connect() as conn:

        rows = conn.execute(

            f"""

            SELECT email, access_token, refresh_token, id_token, expires_at,

                   oidc_client_id, user_id, grok2api_auth_json, grok2api_auth_path

            FROM accounts

            WHERE {' AND '.join('(' + clause + ')' for clause in where)}

            ORDER BY updated_at DESC

            LIMIT ?

            """,

            [*args, limit],

        ).fetchall()



    out: list[tuple[str, bytes]] = []

    seen: set[str] = set()

    for row in rows:

        email = str(row["email"] or "").strip().lower()

        if not email or email in seen:

            continue

        filename = _auth_part_filename(email, cpa=False)

        doc: dict[str, Any] | None = None



        raw_json = str(row["grok2api_auth_json"] or "").strip()

        if raw_json:

            try:

                parsed = json.loads(raw_json)

                # Canonical shape already has provider + access_token.

                if isinstance(parsed, dict) and (

                    parsed.get("provider") == "grok_build"

                    or (parsed.get("access_token") and "key" not in parsed and "accounts" not in parsed)

                ):

                    doc = _to_grok2api_import_document(parsed, email_hint=email)

                else:

                    doc = _to_grok2api_import_document(parsed, email_hint=email)

                    # Rewrite legacy map into the column so next export is direct.

                    try:

                        with _connect() as conn:

                            conn.execute(

                                "UPDATE accounts SET grok2api_auth_json = ?, updated_at = ? WHERE email = ?",

                                (json.dumps(doc, ensure_ascii=False), time.time(), email),

                            )

                    except Exception:

                        pass

            except Exception as exc:  # noqa: BLE001

                print(f"[register-pro] grok2api_auth_json parse fail {email}: {exc}")



        if doc is None:

            # Construct from account columns — source of truth.

            access = str(row["access_token"] or "").strip()

            refresh = str(row["refresh_token"] or "").strip()

            if not access and not refresh:

                path = Path(str(row["grok2api_auth_path"] or ""))

                if path.is_file():

                    try:

                        doc = _to_grok2api_import_document(

                            path.read_text(encoding="utf-8"), email_hint=email

                        )

                    except Exception as exc:  # noqa: BLE001

                        print(f"[register-pro] skip file {path}: {exc}")

                        continue

                else:

                    continue

            else:

                doc = _build_grok2api_auth_document(

                    {

                        "access_token": access,

                        "refresh_token": refresh,

                        "id_token": row["id_token"] or "",

                        "expires_at": row["expires_at"] or "",

                        "oidc_client_id": row["oidc_client_id"] or "",

                        "user_id": row["user_id"] or "",

                        "email": email,

                    },

                    email,

                )

                try:

                    with _connect() as conn:

                        conn.execute(

                            "UPDATE accounts SET grok2api_auth_json = ?, updated_at = ? WHERE email = ?",

                            (json.dumps(doc, ensure_ascii=False), time.time(), email),

                        )

                except Exception:

                    pass



        body = json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"

        seen.add(email)

        out.append((filename, body))

    return out





def list_cpa_auth_parts(limit: int = 1000, *, emails: list[str] | None = None) -> list[tuple[str, bytes]]:

    return _auth_parts(

        limit=limit,

        json_column="cpa_auth_json",

        path_column="cpa_auth_path",

        cpa=True,

        emails=emails,

    )






def list_sub2api_export_parts(
    limit: int = 1000,
    *,
    emails: list[str] | None = None,
    config: dict[str, Any] | None = None,
) -> list[tuple[str, bytes]]:
    """Build Sub2API import JSON parts from local CPA auth for selected/all accounts."""
    cfg = normalize_sub2api_config(config or get_sub2api_config(include_key=True))
    parts = list_cpa_auth_parts(limit=limit, emails=emails)
    if not parts:
        return []
    try:
        import cpa_to_sub2api as sub_mod  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"无法加载 cpa_to_sub2api: {exc}") from exc

    push_cfg = _build_sub2api_push_cfg(cfg)
    push = sub_mod.get_sub2api_push_settings(push_cfg)
    out: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for filename, payload in parts:
        raw = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode("utf-8")
        auth_doc: dict[str, Any] | None = None
        email_hint = ""
        try:
            parsed = json.loads(raw.decode("utf-8"))
            if isinstance(parsed, dict):
                auth_doc = parsed
                email_hint = str(
                    parsed.get("email")
                    or parsed.get("Email")
                    or (parsed.get("credentials") or {}).get("email")
                    or ""
                ).strip().lower()
        except Exception:
            auth_doc = None
        if not email_hint:
            email_hint = (
                str(filename or "")
                .replace("xai-", "")
                .replace(".json", "")
                .replace("_at_", "@")
                .strip()
                .lower()
            )
        if not isinstance(auth_doc, dict):
            continue
        if email_hint and not auth_doc.get("email"):
            auth_doc = {**auth_doc, "email": email_hint}
        try:
            bundle = sub_mod.build_sub2api_export_bundle([auth_doc], push)
        except Exception:
            continue
        safe = re.sub(r"[^a-zA-Z0-9@._-]+", "-", email_hint or "unknown").strip("-") or "unknown"
        name = f"sub2api-account-xai-{safe}.json"
        if name in seen:
            stem, suffix = os.path.splitext(name)
            name = f"{stem}-{len(seen) + 1}{suffix or '.json'}"
        seen.add(name)
        out.append((name, (json.dumps(bundle, ensure_ascii=False, indent=2) + "\n").encode("utf-8")))
    return out


def export_sub2api_bundle(
    limit: int = 1000,
    *,
    emails: list[str] | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one combined Sub2API export bundle (accounts + proxies)."""
    cfg = normalize_sub2api_config(config or get_sub2api_config(include_key=True))
    parts = list_cpa_auth_parts(limit=limit, emails=emails)
    if not parts:
        return {"ok": False, "count": 0, "bundle": None, "error": "没有可导出的 CPA Auth"}
    try:
        import cpa_to_sub2api as sub_mod  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "count": 0, "bundle": None, "error": f"无法加载 cpa_to_sub2api: {exc}"}
    push = sub_mod.get_sub2api_push_settings(_build_sub2api_push_cfg(cfg))
    auth_items: list[dict[str, Any]] = []
    for filename, payload in parts:
        raw = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode("utf-8")
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            continue
        if not isinstance(parsed, dict):
            continue
        email_hint = str(
            parsed.get("email")
            or parsed.get("Email")
            or (parsed.get("credentials") or {}).get("email")
            or ""
        ).strip().lower()
        if not email_hint:
            email_hint = (
                str(filename or "").replace("xai-", "").replace(".json", "").replace("_at_", "@").strip().lower()
            )
        if email_hint and not parsed.get("email"):
            parsed = {**parsed, "email": email_hint}
        auth_items.append(parsed)
    if not auth_items:
        return {"ok": False, "count": 0, "bundle": None, "error": "CPA Auth 无法解析为 Sub2 格式"}
    try:
        bundle = sub_mod.build_sub2api_export_bundle(auth_items, push)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "count": 0, "bundle": None, "error": str(exc)[:300]}
    return {"ok": True, "count": len(auth_items), "bundle": bundle}


def _verified_remote_import_emails(

    emails: list[str] | None,

    *,

    limit: int,

    require_probe: bool = True,

) -> tuple[list[str], list[dict[str, str]]]:

    """Select local accounts eligible for remote import.



    ``require_probe``:

      - True  (registration / relogin auto-upload): must be probe-passed.

      - False (manual Grok2API / CPA import): any local account with usable

        credentials can be imported; probe is NOT required.

    """

    init_db()

    requested = sorted(

        {str(email or "").strip().lower() for email in (emails or []) if str(email or "").strip()}

    )

    where = ""

    args: list[Any] = []

    if requested:

        where = "WHERE lower(email) IN (" + ",".join("?" for _ in requested) + ")"

        args.extend(requested)

    with _connect() as conn:

        rows = conn.execute(

            f"""

            SELECT email, status, last_probe_json, access_token, refresh_token, sso

            FROM accounts {where}

            ORDER BY updated_at DESC

            """,

            args,

        ).fetchall()



    found: dict[str, sqlite3.Row] = {str(row["email"]).lower(): row for row in rows}

    approved: list[str] = []

    skipped: list[dict[str, str]] = []

    candidates = requested or list(found)

    for email in candidates:

        row = found.get(email)

        if not row:

            skipped.append({"email": email, "reason": "本地不存在"})

            continue

        has_cred = bool(

            str(row["access_token"] or "").strip()

            or str(row["refresh_token"] or "").strip()

            or str(row["sso"] or "").strip()

        )

        if not has_cred:

            skipped.append({"email": email, "reason": "缺少可用凭证"})

            continue

        if not require_probe:

            # Manual import: operator explicitly selected these accounts.

            approved.append(email)

            continue

        probe: dict[str, Any] = {}

        try:

            probe = json.loads(str(row["last_probe_json"] or ""))

        except (TypeError, ValueError, json.JSONDecodeError):

            pass

        if str(row["status"] or "") == "active" and probe.get("ok") is True:

            approved.append(email)

        elif not probe:

            skipped.append({"email": email, "reason": "尚未测活"})

        else:

            skipped.append({"email": email, "reason": "测活未通过"})

    return approved[: max(1, min(5000, int(limit or 1000)))], skipped





def list_cpa_auth_files(limit: int = 1000) -> list[Path]:

    init_db()

    limit = max(1, min(5000, int(limit or 1000)))

    with _connect() as conn:

        rows = conn.execute(

            """

            SELECT cpa_auth_path

            FROM accounts

            WHERE cpa_auth_path IS NOT NULL AND cpa_auth_path != ''

            ORDER BY updated_at DESC

            LIMIT ?

            """,

            (limit,),

        ).fetchall()

    files: list[Path] = []

    seen: set[str] = set()

    for row in rows:

        path = Path(str(row["cpa_auth_path"]))

        key = str(path)

        if key in seen or not path.is_file():

            continue

        seen.add(key)

        files.append(path)

    return files





def _cpa_cloud_management_base(value: str) -> str:

    """Normalize CPA management API base (same as grok-register cpa_export).



    Accepts origin, full management UI URL, or already-suffixed ``.../v0/management``.

    Always returns ``{origin}/v0/management``.

    """

    base = (value or "").strip().rstrip("/")

    if not base:

        return ""

    if not re.match(r"^https?://", base, re.IGNORECASE):

        base = f"http://{base}"

    # Strip management UI paths / hash leftovers before rebuilding.

    try:

        parsed = urllib.parse.urlsplit(base)

        if parsed.scheme and parsed.netloc:

            base = f"{parsed.scheme}://{parsed.netloc}"

    except Exception:

        pass

    base = re.sub(r"/v0/management/?$", "", base, flags=re.IGNORECASE).rstrip("/")

    return f"{base}/v0/management"





def _cpa_response_preview(text: str, limit: int = 300) -> str:

    raw = str(text or "").strip()

    if not raw:

        return ""

    if len(raw) <= limit:

        return raw

    return raw[:limit]





def _post_cpa_bytes(url: str, data: bytes, headers: dict[str, str], timeout: float) -> tuple[int, str]:

    """Legacy urllib POST helper (kept for non-upload CPA probes)."""

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    try:

        with _urlopen(req, timeout=timeout) as resp:

            body = resp.read().decode("utf-8", errors="replace")

            return int(resp.status), body

    except urllib.error.HTTPError as exc:

        body = exc.read().decode("utf-8", errors="replace")

        return int(exc.code), body





def _upload_cpa_auth_part(

    filename: str,

    payload: bytes,

    cfg: dict[str, Any],

    *,

    timeout: float | None = None,

) -> dict[str, Any]:

    """Upload one CPA auth JSON to remote CPA management (grok-register compatible).



    Endpoint: ``POST {base}/v0/management/auth-files``

    Auth: ``Authorization: Bearer {management_key}``

    Body: multipart field ``file`` (application/json) ? same as

    ``cpa_export.upload_cpa_auth_to_cloud``.

    """

    api_base = _cpa_cloud_management_base(str(cfg.get("base_url") or ""))

    key = str(cfg.get("management_key") or "").strip()

    if not api_base:

        return {"ok": False, "error": "missing_api_base", "name": filename}

    if not key:

        return {"ok": False, "error": "missing_management_key", "name": filename}



    try:

        to = float(timeout if timeout is not None else cfg.get("upload_timeout") or 30)

    except (TypeError, ValueError):

        to = 30.0

    to = max(5.0, min(180.0, to))

    try:

        retries = int(cfg.get("upload_retries") or 3)

    except (TypeError, ValueError):

        retries = 3

    retries = max(1, min(10, retries))



    url = f"{api_base}/auth-files"

    raw = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode("utf-8")

    last_error = "upload_failed"



    # Prefer requests (same stack as grok-register) for correct multipart boundaries.

    try:

        import requests as _req  # type: ignore

    except Exception:

        _req = None



    for attempt in range(1, retries + 1):

        try:

            if _req is not None:

                resp = _req.post(

                    url,

                    headers={"Authorization": f"Bearer {key}"},

                    files={"file": (filename, raw, "application/json")},

                    timeout=to,

                )

                status = int(resp.status_code)

                body = resp.text or ""

                preview = _cpa_response_preview(body, 300)

                if 200 <= status < 300:

                    try:

                        payload_json: Any = resp.json()

                    except Exception:

                        payload_json = {"raw": preview}

                    return {

                        "ok": True,

                        "method": "requests-multipart",

                        "status": status,

                        "status_code": status,

                        "name": filename,

                        "response": payload_json,

                        "url": url,

                    }

                last_error = f"HTTP {status}: {preview}"

                if status not in {408, 429, 500, 502, 503, 504} or attempt == retries:

                    return {

                        "ok": False,

                        "method": "requests-multipart",

                        "status": status,

                        "status_code": status,

                        "name": filename,

                        "error": last_error,

                        "url": url,

                    }

            else:

                # urllib fallback when requests is unavailable

                boundary = f"----register-pro-cpa-{int(time.time() * 1000)}-{attempt}"

                crlf = "\r\n"

                head = (

                    f"--{boundary}{crlf}"

                    f'Content-Disposition: form-data; name="file"; filename="{filename}"{crlf}'

                    f"Content-Type: application/json{crlf}{crlf}"

                ).encode("utf-8")

                tail = f"{crlf}--{boundary}--{crlf}".encode("utf-8")

                multipart = head + raw + tail

                status, body = _post_cpa_bytes(

                    url,

                    multipart,

                    {

                        "Authorization": f"Bearer {key}",

                        "Content-Type": f"multipart/form-data; boundary={boundary}",

                    },

                    to,

                )

                preview = _cpa_response_preview(body, 300)

                if 200 <= status < 300:

                    return {

                        "ok": True,

                        "method": "urllib-multipart",

                        "status": status,

                        "status_code": status,

                        "name": filename,

                        "url": url,

                    }

                last_error = f"HTTP {status}: {preview}"

                if status not in {408, 429, 500, 502, 503, 504} or attempt == retries:

                    return {

                        "ok": False,

                        "method": "urllib-multipart",

                        "status": status,

                        "status_code": status,

                        "name": filename,

                        "error": last_error,

                        "url": url,

                    }

        except Exception as exc:  # noqa: BLE001

            last_error = str(exc)[:300]

            if attempt == retries:

                return {

                    "ok": False,

                    "name": filename,

                    "error": last_error,

                    "url": url,

                }

        time.sleep(min(2 * attempt, 8))

    return {"ok": False, "name": filename, "error": last_error, "url": url}





def _upload_cpa_auth_file(path: Path, cfg: dict[str, Any], *, timeout: float | None = None) -> dict[str, Any]:

    """Upload a local CPA auth file path (grok-register compatible)."""

    path = Path(path)

    return _upload_cpa_auth_part(path.name, path.read_bytes(), cfg, timeout=timeout)





def _cpa_management_headers(cfg: dict[str, Any]) -> dict[str, str]:

    return {

        "Accept": "application/json",

        "Authorization": "Bearer " + str(cfg.get("management_key") or "").strip(),

        "User-Agent": f"grok-register-pro/{CLI_VERSION}",

    }





def fetch_cpa_grok_inspection_status(

    config: dict[str, Any] | None = None,

    *,

    include_results: bool = True,

    timeout: float = 45.0,

) -> dict[str, Any]:

    """GET CPA plugin ``/v0/management/plugins/grok-inspection/status``.



    Accepts management.html UI URLs; origin is already normalized in config.

    """

    cfg = normalize_cpa_config(config or get_cpa_config(include_key=True))

    if not cfg["base_url"]:

        raise ValueError("CPA 地址不能为空（可填 management.html 完整链接，会自动取域名）")

    if not cfg["management_key"]:

        raise ValueError("CPA 管理密钥不能为空")

    flag = "1" if include_results else "0"

    url = (

        cfg["base_url"].rstrip("/")

        + f"/v0/management/plugins/grok-inspection/status?include_results={flag}"

    )

    req = urllib.request.Request(url, headers=_cpa_management_headers(cfg), method="GET")

    try:

        with _urlopen(req, timeout=timeout) as resp:

            raw = resp.read().decode("utf-8", errors="replace")

            status = int(resp.status)

    except urllib.error.HTTPError as exc:

        raw = exc.read().decode("utf-8", errors="replace")

        status = int(exc.code)

        if _is_cloudflare_block(raw):

            raise RuntimeError(

                f"CPA grok-inspection 被 Cloudflare 拦截 HTTP {status}。"

                f" 请改用内网/直连地址。详情：{raw[:300]}"

            ) from exc

        if status in {401, 403}:

            raise RuntimeError(

                f"CPA 管理密钥被拒绝 HTTP {status}（检查 management key 是否正确，"

                f"不是 Grok2API 账号密码）。详情：{raw[:300]}"

            ) from exc

        raise RuntimeError(f"CPA grok-inspection 拉取失败 HTTP {status}: {raw[:300]}") from exc

    if status >= 400:

        raise RuntimeError(f"CPA grok-inspection 拉取失败 HTTP {status}: {raw[:300]}")

    try:

        payload = json.loads(raw) if raw else {}

    except Exception as exc:

        raise RuntimeError(f"CPA grok-inspection 返回非 JSON: {raw[:200]}") from exc

    if not isinstance(payload, dict):

        raise RuntimeError("CPA grok-inspection 返回格式无效")

    # Some builds wrap under data.

    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload

    return data if isinstance(data, dict) else payload





def test_cpa_remote(config: dict[str, Any] | None = None) -> dict[str, Any]:

    cfg = normalize_cpa_config(config or get_cpa_config(include_key=True))

    status_payload = fetch_cpa_grok_inspection_status(

        cfg, include_results=False, timeout=30.0

    )

    return {

        "ok": True,

        "base_url": cfg["base_url"],

        "plugin": "grok-inspection",

        "done": status_payload.get("done"),

        "total": status_payload.get("total"),

        "running": status_payload.get("running"),

        "finished_at": status_payload.get("finished_at"),

    }





def sync_cpa_remote_status(

    config: dict[str, Any] | None = None,

    *,

    mode: str = "problems",

    timeout: float = 45.0,

) -> dict[str, Any]:

    """Pull CPA grok-inspection results into local ``remote_accounts`` (provider=cpa).



    Same classification vocabulary as Grok2API so the accounts UI 远端状态 column

    works unchanged. ``mode``:

      - problems: only non-healthy rows (default, cheap)

      - full: write every inspection result

    """

    cfg = normalize_cpa_config(config or get_cpa_config(include_key=True))

    mode_norm = str(mode or "problems").strip().lower()

    if mode_norm in {"all", "full", "mirror", "complete"}:

        mode_norm = "full"

    else:

        mode_norm = "problems"



    status_payload = fetch_cpa_grok_inspection_status(

        cfg, include_results=True, timeout=timeout

    )

    raw_results = status_payload.get("results") or status_payload.get("items") or []

    if not isinstance(raw_results, list):

        raw_results = []



    classified_rows: list[dict[str, Any]] = []

    counts: Counter[str] = Counter()

    for row in raw_results:

        if not isinstance(row, dict):

            continue

        classified = classify_cpa_inspection_result(row)

        if not classified.get("email"):

            counts["skipped_no_email"] += 1

            continue

        cls = str(classified.get("classification") or "unknown")

        if mode_norm == "problems" and cls == "healthy":

            counts["skipped_healthy"] += 1

            continue

        # Keep raw fields for debugging.

        classified_rows.append({**row, **classified})

        counts["total"] += 1

        counts[f"classification:{cls}"] += 1

        counts[f"action:{classified.get('action') or 'unknown'}"] += 1

        counts[f"http:{classified.get('http_status') or 'unknown'}"] += 1



    seen_at = time.time()

    written = _record_classified_remote_accounts(

        "cpa", classified_rows, seen_at=seen_at, mode=mode_norm

    )



    recycle_restore = _auto_restore_problem_accounts_from_recycle(
        classified_rows, source=f"cpa_remote_status:{mode_norm}"
    )
    restored_from_recycle = int(
        (recycle_restore.get("restored") or 0) + (recycle_restore.get("overwritten") or 0)
    )

    # Do not create remote_only local placeholders for CPA-missing emails.
    # Prefer recycle-bin restore above; remaining remote-only failures stay as remote status.
    generated_local_accounts = 0



    with _connect() as conn:

        local_total = int(conn.execute("SELECT COUNT(*) AS n FROM accounts").fetchone()["n"])

        matched = int(

            conn.execute(

                """

                SELECT COUNT(DISTINCT a.email) AS n

                FROM accounts a

                JOIN remote_accounts r ON lower(r.email) = lower(a.email)

                WHERE r.provider = 'cpa'

                """

            ).fetchone()["n"]

        )

        remote_only_failures = int(

            conn.execute(

                """

                SELECT COUNT(*) AS n

                FROM remote_accounts r

                LEFT JOIN accounts a ON lower(a.email) = lower(r.email)

                WHERE r.provider = 'cpa'

                  AND a.email IS NULL

                  AND (r.action != 'keep' OR COALESCE(r.http_status, 200) != 200)

                """

            ).fetchone()["n"]

        )



    inventory_total = int(status_payload.get("total") or counts["total"] or written)

    summary = {

        "ok": True,

        "backend": "cpa",

        "base_url": cfg["base_url"],

        "plugin": "grok-inspection",

        "mode": mode_norm,

        "provider_counts": {"cpa": written},

        "counts": dict(sorted(counts.items())),

        "remote_total": written,

        "problem_total": written if mode_norm == "problems" else None,

        "remote_inventory_total": inventory_total,

        "remote_summary": {

            "total": status_payload.get("total"),

            "done": status_payload.get("done"),

            "running": status_payload.get("running"),

            "finished_at": status_payload.get("finished_at"),

            "store_path": status_payload.get("store_path"),

        },

        "local_total": local_total,

        "matched_local": matched,

        "remote_only_failures": remote_only_failures,

        "generated_local_accounts": generated_local_accounts,
        "restored_from_recycle": restored_from_recycle,
        "recycle_restore": recycle_restore,
        "seen_at": seen_at,

    }

    _set_json_setting("cpa_last_remote_sync", summary)

    try:

        summary["stats"] = refresh_account_dashboard_stats()

    except Exception:

        pass

    return summary





def sync_remote_status(

    *,

    mode: str = "problems",

    providers: Any = None,

    page_size: int = 200,

    timeout: float = 45.0,

    backend: str | None = None,

) -> dict[str, Any]:

    """Unified remote-status pull. Routes to Grok2API or CPA by exclusive backend."""

    chosen = normalize_remote_backend(backend) or get_remote_backend(resolve=True)

    if not chosen:

        raise ValueError(

            "未选择远端对接（Grok2API / CPA 互斥）。"

            "请在设置里保存其中一个，或勾选其自动导入以锁定后端。"

        )

    if chosen == "cpa":

        return sync_cpa_remote_status(mode=mode, timeout=timeout)

    result = sync_grok2api_remote_status(

        providers=providers,

        page_size=page_size,

        timeout=timeout,

        mode=mode,

    )

    if isinstance(result, dict):

        result.setdefault("backend", "grok2api")

    return result





def upload_cpa_auth_files(

    config: dict[str, Any] | None = None,

    *,

    limit: int = 1000,

    emails: list[str] | None = None,

    require_probe: bool = True,

    skip_already_pushed: bool = False,

) -> dict[str, Any]:

    cfg = normalize_cpa_config(config or get_cpa_config(include_key=True))

    if not cfg["base_url"]:

        raise ValueError("CPA 地址不能为空")

    if not cfg["management_key"]:

        raise ValueError("CPA 管理密钥不能为空")

    approved, skipped = _verified_remote_import_emails(

        emails, limit=limit, require_probe=require_probe

    )

    if skip_already_pushed and approved:

        init_db()

        with _connect() as conn:

            rows = conn.execute(

                "SELECT lower(email) AS e, IFNULL(cpa_pushed, 0) AS p FROM accounts "

                "WHERE lower(email) IN (" + ",".join("?" for _ in approved) + ")",

                approved,

            ).fetchall()

        already = {str(r["e"]) for r in rows if int(r["p"] or 0)}

        if already:

            skipped = list(skipped) + [

                {"email": e, "reason": "already_cpa_pushed"} for e in approved if e in already

            ]

            approved = [e for e in approved if e not in already]

    parts = list_cpa_auth_parts(limit=limit, emails=approved)

    if not parts:

        return {

            "ok": False,

            "error": "没有可导入的 CPA Auth" if not require_probe else "没有通过测活的 CPA Auth 可导入",

            "files": 0,

            "skipped": len(skipped),

            "skipped_accounts": skipped[:100],

        }

    results = []

    for filename, payload in parts:

        item = _upload_cpa_auth_part(filename, payload, cfg)

        # attach email hint for UI / push flags

        email_hint = ""

        try:

            doc = json.loads(payload.decode("utf-8") if isinstance(payload, (bytes, bytearray)) else payload)

            if isinstance(doc, dict):

                email_hint = str(doc.get("email") or "").strip().lower()

        except Exception:

            email_hint = ""

        if not email_hint:

            email_hint = (

                filename.replace("xai-", "").replace(".json", "").replace("_at_", "@").lower()

            )

        item["email"] = email_hint

        item["name"] = filename

        results.append(item)

    ok_count = sum(1 for item in results if item.get("ok"))

    ok_emails = sorted({

        str(item.get("email") or "").strip().lower()

        for item in results

        if item.get("ok") and str(item.get("email") or "").strip()

    })

    result = {

        "ok": ok_count == len(results) and ok_count > 0,

        "base_url": cfg["base_url"],

        "management_base": _cpa_cloud_management_base(str(cfg.get("base_url") or "")),

        "files": len(parts),

        "uploaded": ok_count,

        "failed": len(results) - ok_count,

        "skipped": len(skipped),

        "skipped_accounts": skipped[:100],

        "results": results[:50],

        "emails": ok_emails or approved,

    }

    if ok_emails:

        try:

            mark_local_remote_imported(

                ok_emails,

                provider="cpa",

                reason="manual_upload_cpa",

            )

        except Exception:

            pass

        try:

            mark_accounts_pushed(ok_emails, cpa=True)

        except Exception:

            pass

    _set_json_setting(

        "cpa_last_upload",

        {

            "at": time.time(),

            "files": len(parts),

            "uploaded": ok_count,

            "failed": len(results) - ok_count,

            "base_url": cfg["base_url"],

        },

    )

    return result





def upload_grok2api_auth_files(

    config: dict[str, Any] | None = None,

    *,

    limit: int = 1000,

    emails: list[str] | None = None,

    require_probe: bool = True,

    access_token: str | None = None,

) -> dict[str, Any]:

    cfg = normalize_grok2api_config(config or get_grok2api_config(include_password=True))

    approved, skipped = _verified_remote_import_emails(

        emails, limit=limit, require_probe=require_probe

    )

    parts = list_grok2api_auth_parts(limit=limit, emails=approved)

    if not parts:

        return {

            "ok": False,

            "error": "没有可导入的 Grok2API Auth" if not require_probe else "没有通过测活的 Grok2API Auth 可导入",

            "files": 0,

            "skipped": len(skipped),

            "skipped_accounts": skipped[:100],

        }

    token = (access_token or "").strip() or grok2api_login(cfg["base_url"], cfg["username"], cfg["password"])

    boundary = "----register-pro-grok2api-" + str(int(time.time()))

    body = _build_multipart_auth_parts(parts, boundary)

    req = urllib.request.Request(

        cfg["base_url"].rstrip("/") + "/api/admin/v1/accounts/import",

        data=body,

        headers={

            "Authorization": "Bearer " + token,

            "Content-Type": "multipart/form-data; boundary=" + boundary,

            "Content-Length": str(len(body)),

        },

        method="POST",

    )

    try:

        with _urlopen(req, timeout=45) as resp:

            status = int(resp.status)

            if status < 400:

                result = _read_grok2api_import_response(resp)

            else:

                raw = resp.read()

    except urllib.error.HTTPError as exc:

        raw = exc.read()

        status = int(exc.code)

    if status >= 400:

        text = raw.decode("utf-8", "replace")

        raise RuntimeError(f"Grok2API 导入失败 HTTP {status}: {text[:500]}")

    result.update(

        {

            "ok": True,

            "files": len(parts),

            "base_url": cfg["base_url"],

            "skipped": len(skipped),

            "skipped_accounts": skipped[:100],

            "emails": approved,

        }

    )

    try:

        mark_local_remote_imported(

            approved,

            provider="grok_build",

            reason="manual_upload_auth_files",

        )

    except Exception:

        pass

    try:

        mark_accounts_pushed(approved, grok2api=True)

    except Exception:

        pass

    _set_json_setting(

        "grok2api_last_upload",

        {

            "at": time.time(),

            "files": len(parts),

            "base_url": cfg["base_url"],

            "result": result,

        },

    )

    return result





def list_grok2api_sso_lines(limit: int = 1000, *, emails: list[str] | None = None) -> list[str]:

    init_db()

    limit = max(1, min(5000, int(limit or 1000)))

    clean = sorted({str(email or "").strip().lower() for email in (emails or []) if str(email or "").strip()})

    where = ["sso IS NOT NULL", "sso != ''"]

    args: list[Any] = []

    if clean:

        where.append("lower(email) IN (" + ",".join("?" for _ in clean) + ")")

        args.extend(clean)

    with _connect() as conn:

        rows = conn.execute(

            """

            SELECT sso

            FROM accounts

            WHERE """ + " AND ".join(where) + """

            ORDER BY updated_at DESC

            LIMIT ?

            """,

            [*args, limit],

        ).fetchall()

    lines: list[str] = []

    seen: set[str] = set()

    for row in rows:

        sso = str(row["sso"] or "").strip()

        if not sso or sso in seen:

            continue

        seen.add(sso)

        lines.append(sso)

    return lines





def upload_grok2api_sso(

    config: dict[str, Any] | None = None,

    *,

    limit: int = 1000,

    emails: list[str] | None = None,

    require_probe: bool = True,

) -> dict[str, Any]:

    cfg = normalize_grok2api_config(config or get_grok2api_config(include_password=True))

    approved, skipped = _verified_remote_import_emails(

        emails, limit=limit, require_probe=require_probe

    )

    lines = list_grok2api_sso_lines(limit=limit, emails=approved)

    if not lines:

        return {

            "ok": False,

            "error": "没有可导入的 SSO" if not require_probe else "没有通过测活的 SSO 可导入",

            "sso": 0,

            "skipped": len(skipped),

            "skipped_accounts": skipped[:100],

        }

    token = grok2api_login(cfg["base_url"], cfg["username"], cfg["password"])

    boundary = "----register-pro-grok2api-sso-" + str(int(time.time()))

    filename = "register-pro-sso-" + time.strftime("%Y%m%d-%H%M%S", time.localtime()) + ".txt"

    body = _build_multipart_parts(

        [(filename, ("\n".join(lines) + "\n").encode("utf-8"), "text/plain; charset=utf-8")],

        boundary,

    )

    req = urllib.request.Request(

        cfg["base_url"].rstrip("/") + "/api/admin/v1/accounts/web/import",

        data=body,

        headers={

            "Authorization": "Bearer " + token,

            "Content-Type": "multipart/form-data; boundary=" + boundary,

            "Content-Length": str(len(body)),

        },

        method="POST",

    )

    try:

        with _urlopen(req, timeout=45) as resp:

            status = int(resp.status)

            if status < 400:

                result = _read_grok2api_import_response(resp)

            else:

                raw = resp.read()

    except urllib.error.HTTPError as exc:

        raw = exc.read()

        status = int(exc.code)

    if status >= 400:

        text = raw.decode("utf-8", "replace")

        raise RuntimeError(f"Grok2API SSO 导入失败 HTTP {status}: {text[:500]}")

    result.update(

        {

            "ok": True,

            "sso": len(lines),

            "base_url": cfg["base_url"],

            "filename": filename,

            "skipped": len(skipped),

            "skipped_accounts": skipped[:100],

            "emails": approved,

        }

    )

    try:

        mark_local_remote_imported(

            approved,

            provider="grok_build",

            reason="manual_upload_sso",

        )

    except Exception:

        pass

    _set_json_setting(

        "grok2api_last_upload",

        {

            "at": time.time(),

            "mode": "web_sso",

            "sso": len(lines),

            "base_url": cfg["base_url"],

            "result": result,

        },

    )

    return result





def _safe_name(value: str) -> str:

    s = re.sub(r"[^A-Za-z0-9_.@+-]+", "_", value.strip())

    return s[:180] or f"account_{int(time.time())}"





def _jwt_payload(token: str) -> dict[str, Any]:

    try:

        parts = token.split(".")

        if len(parts) < 2:

            return {}

        padded = parts[1] + "=" * (-len(parts[1]) % 4)

        raw = base64.urlsafe_b64decode(padded.encode("ascii"))

        data = json.loads(raw.decode("utf-8"))

        return data if isinstance(data, dict) else {}

    except Exception:

        return {}





def _iso_from_expires_at(value: Any) -> str:

    if value is None or value == "":

        return ""

    if isinstance(value, (int, float)):

        return datetime.fromtimestamp(float(value), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    text = str(value)

    if text.isdigit():

        return datetime.fromtimestamp(float(text), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return text





def _unix_from_expires_at(value: Any) -> int | None:

    if value is None or value == "":

        return None

    if isinstance(value, (int, float)):

        return int(value)

    text = str(value).strip()

    if text.isdigit():

        return int(text)

    try:

        return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())

    except ValueError:

        return None





def _auth_key(entry: dict[str, Any]) -> str:

    issuer = str(entry.get("oidc_issuer") or "https://auth.x.ai").rstrip("/")

    client_id = str(entry.get("oidc_client_id") or "")

    user_id = str(entry.get("user_id") or entry.get("principal_id") or entry.get("email") or "")

    return "::".join(x for x in (issuer, client_id, user_id) if x)





def _build_grok2api_auth_document(entry: dict[str, Any], email: str) -> dict[str, Any]:

    """Canonical Grok2API ``/accounts/import`` document stored in SQLite.



    Built from account columns / OIDC entry — not the old CLI auth-map shape.

    """

    access = str(entry.get("access_token") or entry.get("key") or "").strip()

    refresh = str(entry.get("refresh_token") or "").strip()

    user_id = str(entry.get("user_id") or entry.get("principal_id") or entry.get("sub") or "").strip()

    email_n = str(entry.get("email") or email or "").strip().lower()

    return {

        "provider": "grok_build",

        "name": email_n or user_id or "account",

        "client_id": str(entry.get("oidc_client_id") or entry.get("client_id") or "").strip(),

        "access_token": access,

        "refresh_token": refresh,

        "id_token": str(entry.get("id_token") or "").strip(),

        "token_type": "Bearer",

        "expires_at": str(entry.get("expires_at") or ""),

        "email": email_n,

        "user_id": user_id,

    }





def _build_auth_payloads(entry: dict[str, Any], email: str) -> tuple[dict[str, Any], dict[str, Any]]:

    """Return (grok2api_auth_document, cpa_record)."""

    grok2api_doc = _build_grok2api_auth_document(entry, email)

    exp_unix = _unix_from_expires_at(entry.get("expires_at"))

    cpa_record = {

        "type": "xai",

        "auth_kind": "oauth",

        "email": email,

        "sub": entry.get("user_id") or entry.get("principal_id") or "",

        "access_token": entry.get("key") or entry.get("access_token") or "",

        "refresh_token": entry.get("refresh_token") or "",

        "id_token": entry.get("id_token") or "",

        "token_type": "Bearer",

        "expires_in": None,

        "expired": _iso_from_expires_at(exp_unix),

        "last_refresh": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),

        "redirect_uri": "",

        "token_endpoint": "https://auth.x.ai/oauth2/token",

        "base_url": "https://cli-chat-proxy.grok.com/v1",

        "disabled": False,

        "headers": {

            "User-Agent": "grok-cli",

            "X-Client-Name": "grok-cli",

        },

    }

    return grok2api_doc, cpa_record





def _write_auth_files(

    grok2api_doc: dict[str, Any], cpa_record: dict[str, Any], email: str

) -> tuple[Path, Path]:

    """Materialize auth JSON files for export only (not on registration)."""

    safe = _safe_name(email)

    AUTH_MAP_DIR.mkdir(parents=True, exist_ok=True)

    CPA_DIR.mkdir(parents=True, exist_ok=True)



    auth_path = AUTH_MAP_DIR / f"{safe}.json"

    auth_path.write_text(

        json.dumps(grok2api_doc, ensure_ascii=False, indent=2) + "\n",

        encoding="utf-8",

    )



    cpa_path = CPA_DIR / f"xai-{safe}.json"

    cpa_path.write_text(json.dumps(cpa_record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    return auth_path, cpa_path





def materialize_auth_export_files(

    *,

    limit: int = 5000,

    emails: list[str] | None = None,

) -> dict[str, Any]:

    """Write grok2api + CPA auth JSON files from SQLite for download/export."""

    init_db()

    grok_parts = list_grok2api_auth_parts(limit=limit, emails=emails)

    cpa_parts = list_cpa_auth_parts(limit=limit, emails=emails)

    AUTH_MAP_DIR.mkdir(parents=True, exist_ok=True)

    CPA_DIR.mkdir(parents=True, exist_ok=True)

    written_g = 0

    written_c = 0

    for filename, body in grok_parts:

        path = AUTH_MAP_DIR / filename

        path.write_bytes(body)

        written_g += 1

    for filename, body in cpa_parts:

        path = CPA_DIR / filename

        path.write_bytes(body)

        written_c += 1

    return {

        "ok": True,

        "grok2api_files": written_g,

        "cpa_files": written_c,

        "grok2api_dir": str(AUTH_MAP_DIR),

        "cpa_dir": str(CPA_DIR),

    }





def import_auth_payload(raw: str | dict[str, Any], *, merge: bool = True) -> dict[str, Any]:

    if isinstance(raw, str):

        parsed = json.loads(raw) if raw.strip().startswith("{") else {"key": raw.strip()}

    else:

        parsed = dict(raw or {})

    token = parsed.get("key") or parsed.get("access_token") or parsed.get("token")

    if not isinstance(token, str) or not token.strip():

        return {"ok": False, "error": "missing access token"}



    access_payload = _jwt_payload(token)

    id_payload = _jwt_payload(str(parsed.get("id_token") or ""))

    email = str(parsed.get("email") or id_payload.get("email") or access_payload.get("email") or "").strip().lower()

    if not email:

        return {"ok": False, "error": "missing email"}



    now = time.time()

    entry = {

        "key": token,

        "auth_mode": parsed.get("auth_mode") or "oidc",

        "create_time": parsed.get("create_time") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),

        "user_id": parsed.get("user_id") or access_payload.get("sub") or access_payload.get("principal_id") or id_payload.get("sub") or "",

        "email": email,

        "principal_type": parsed.get("principal_type") or access_payload.get("principal_type") or "User",

        "principal_id": parsed.get("principal_id") or access_payload.get("principal_id") or access_payload.get("sub") or "",

        "refresh_token": parsed.get("refresh_token") or "",

        "id_token": parsed.get("id_token") or "",

        "expires_at": _iso_from_expires_at(parsed.get("expires_at")),

        "oidc_issuer": parsed.get("oidc_issuer") or "https://auth.x.ai",

        "oidc_client_id": parsed.get("oidc_client_id") or "",

    }

    grok2api_doc, cpa_record = _build_auth_payloads(entry, email)

    # Store export documents in SQLite only. Files are materialized on export/upload.

    auth_json = json.dumps(grok2api_doc, ensure_ascii=False)

    cpa_json = json.dumps(cpa_record, ensure_ascii=False)

    password_raw = str(parsed.get("registration_password") or parsed.get("password") or "")

    # Never persist mailbox JWTs / garbage as the account password.

    password = password_raw if is_plausible_account_password(password_raw) else ""

    sso = str(parsed.get("sso") or "")

    auth_key = _auth_key(entry)



    init_db()

    with _connect() as conn:

        existing = conn.execute(

            "SELECT created_at, password FROM accounts WHERE email = ?",

            (email,),

        ).fetchone()

        created_at = float(existing["created_at"]) if existing else now

        # Keep a previously stored good password when the incoming payload has none.

        if not password and existing is not None:

            prev = str(existing["password"] or "")

            if is_plausible_account_password(prev):

                password = prev

        conn.execute(

            """

            INSERT INTO accounts(

              email, password, sso, auth_key, user_id, access_token, refresh_token, id_token,

              expires_at, oidc_issuer, oidc_client_id, grok2api_auth_path, cpa_auth_path,

              grok2api_auth_json, cpa_auth_json, status, batch_id, session_id, created_at, updated_at, raw_json

            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(email) DO UPDATE SET

              password = CASE

                WHEN excluded.password != '' THEN excluded.password

                ELSE accounts.password

              END,

              sso = excluded.sso,

              auth_key = excluded.auth_key,

              user_id = excluded.user_id,

              access_token = excluded.access_token,

              refresh_token = excluded.refresh_token,

              id_token = excluded.id_token,

              expires_at = excluded.expires_at,

              oidc_issuer = excluded.oidc_issuer,

              oidc_client_id = excluded.oidc_client_id,

              grok2api_auth_json = excluded.grok2api_auth_json,

              cpa_auth_json = excluded.cpa_auth_json,

              status = excluded.status,

              batch_id = excluded.batch_id,

              session_id = excluded.session_id,

              updated_at = excluded.updated_at,

              raw_json = excluded.raw_json

            """,

            (

                email,

                password,

                sso,

                auth_key,

                entry.get("user_id") or "",

                token,

                entry.get("refresh_token") or "",

                entry.get("id_token") or "",

                entry.get("expires_at") or "",

                entry.get("oidc_issuer") or "",

                entry.get("oidc_client_id") or "",

                "",  # no on-disk path at registration time

                "",

                auth_json,

                cpa_json,

                "registered",

                str(parsed.get("batch_id") or ""),

                str(parsed.get("session_id") or ""),

                created_at,

                now,

                auth_json,

            ),

        )



    return {

        "ok": True,

        "storage": "sqlite",

        "message": "已保存；导出 Auth / 导入远端时再生成文件",

        "imported": [{"id": auth_key, "email": email, "expires_at": entry.get("expires_at"), "has_refresh_token": bool(entry.get("refresh_token"))}],

        "count": 1,

        "total_accounts": account_count(),

        "auth_file": "",

        "cpa_auth_file": "",

        "merged": bool(merge),

    }





def import_local_credentials(records: list[dict[str, Any]], *, source: str) -> dict[str, Any]:

    """Merge local email/password/SSO records without fabricating OAuth data."""

    now = time.time()

    created = 0

    updated = 0

    skipped = 0

    init_db()

    with _connect() as conn:

        for raw in records:

            email = str(raw.get("email") or "").strip().lower()

            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):

                skipped += 1

                continue

            password_raw = str(raw.get("password") or "")

            password = password_raw if is_plausible_account_password(password_raw) else ""

            sso = str(raw.get("sso") or "")

            # If importer put a JWT/email token into password, and sso is empty,

            # do not treat the JWT as sso either — caller must supply real fields.

            existing = conn.execute(

                "SELECT email, access_token, status, created_at, password FROM accounts WHERE email = ?",

                (email,),

            ).fetchone()

            if existing:

                updated += 1

                created_at = float(existing["created_at"])

                status = str(existing["status"] or "registered")

                if not password:

                    prev = str(existing["password"] or "")

                    if is_plausible_account_password(prev):

                        password = prev

            else:

                created += 1

                created_at = now

                status = "sso_pending" if sso else "credentials_only"

            payload = json.dumps(

                {

                    "source": source,

                    "email": email,

                    "has_password": bool(password),

                    "has_sso": bool(sso),

                    "rejected_password_shape": bool(password_raw) and not is_plausible_account_password(password_raw),

                },

                ensure_ascii=False,

            )

            conn.execute(

                """

                INSERT INTO accounts(

                  email, password, sso, auth_key, user_id, access_token, refresh_token, id_token,

                  expires_at, oidc_issuer, oidc_client_id, grok2api_auth_path, cpa_auth_path,

                  grok2api_auth_json, cpa_auth_json, status, batch_id, session_id, created_at, updated_at, raw_json

                )

                VALUES (?, ?, ?, ?, '', '', '', '', '', '', '', '', '', '', '', ?, '', '', ?, ?, ?)

                ON CONFLICT(email) DO UPDATE SET

                  password = CASE

                    WHEN excluded.password != '' THEN excluded.password

                    ELSE accounts.password

                  END,

                  sso = CASE WHEN excluded.sso != '' THEN excluded.sso ELSE accounts.sso END,

                  updated_at = excluded.updated_at,

                  raw_json = excluded.raw_json

                """,

                (

                    email,

                    password,

                    sso,

                    f"local::{email}",

                    status,

                    created_at,

                    now,

                    payload,

                ),

            )

    return {"ok": True, "created": created, "updated": updated, "skipped": skipped, "total": created + updated}





def account_credentials(emails: list[str]) -> list[dict[str, Any]]:

    """Return password + current auth snapshot for relogin/rollback."""

    clean = sorted({str(email or "").strip().lower() for email in emails if str(email or "").strip()})

    if not clean:

        return []

    init_db()

    with _connect() as conn:

        rows = conn.execute(

            """

            SELECT email, password, sso, access_token, refresh_token, id_token,

                   expires_at, oidc_issuer, oidc_client_id, status,

                   grok2api_auth_json, cpa_auth_json, auth_key, user_id

            FROM accounts

            WHERE lower(email) IN (""" + ",".join("?" for _ in clean) + ")",

            clean,

        ).fetchall()

    out: list[dict[str, Any]] = []

    for row in rows:

        out.append(

            {

                "email": str(row["email"] or ""),

                "password": str(row["password"] or ""),

                "sso": str(row["sso"] or ""),

                "access_token": str(row["access_token"] or ""),

                "refresh_token": str(row["refresh_token"] or ""),

                "id_token": str(row["id_token"] or ""),

                "expires_at": str(row["expires_at"] or ""),

                "oidc_issuer": str(row["oidc_issuer"] or ""),

                "oidc_client_id": str(row["oidc_client_id"] or ""),

                "status": str(row["status"] or ""),

                "grok2api_auth_json": str(row["grok2api_auth_json"] or ""),

                "cpa_auth_json": str(row["cpa_auth_json"] or ""),

                "auth_key": str(row["auth_key"] or ""),

                "user_id": str(row["user_id"] or ""),

            }

        )

    return out





def restore_account_snapshot(snapshot: dict[str, Any]) -> None:

    """Roll back an account to a previous auth snapshot after failed relogin/probe."""

    email = str((snapshot or {}).get("email") or "").strip().lower()

    if not email:

        return

    init_db()

    now = time.time()

    with _connect() as conn:

        conn.execute(

            """

            UPDATE accounts SET

              sso = ?,

              access_token = ?,

              refresh_token = ?,

              id_token = ?,

              expires_at = ?,

              oidc_issuer = ?,

              oidc_client_id = ?,

              status = ?,

              grok2api_auth_json = ?,

              cpa_auth_json = ?,

              auth_key = ?,

              user_id = ?,

              updated_at = ?

            WHERE lower(email) = ?

            """,

            (

                str(snapshot.get("sso") or ""),

                str(snapshot.get("access_token") or ""),

                str(snapshot.get("refresh_token") or ""),

                str(snapshot.get("id_token") or ""),

                str(snapshot.get("expires_at") or ""),

                str(snapshot.get("oidc_issuer") or ""),

                str(snapshot.get("oidc_client_id") or ""),

                str(snapshot.get("status") or "registered"),

                str(snapshot.get("grok2api_auth_json") or ""),

                str(snapshot.get("cpa_auth_json") or ""),

                str(snapshot.get("auth_key") or ""),

                str(snapshot.get("user_id") or ""),

                now,

                email,

            ),

        )





def import_unassigned_sso(tokens: list[str], *, source: str) -> dict[str, Any]:

    """Persist SSO values that have no trustworthy email association yet."""

    inserted = 0

    duplicates = 0

    init_db()

    with _connect() as conn:

        for raw in tokens:

            sso = str(raw or "").strip()

            if not sso:

                continue

            token_hash = hashlib.sha256(sso.encode("utf-8")).hexdigest()

            cursor = conn.execute(

                "INSERT OR IGNORE INTO unassigned_sso(token_hash, sso, source, created_at) VALUES (?, ?, ?, ?)",

                (token_hash, sso, source, time.time()),

            )

            if cursor.rowcount:

                inserted += 1

            else:

                duplicates += 1

    return {"ok": True, "inserted": inserted, "duplicates": duplicates, "total": inserted + duplicates}





def account_count() -> int:

    init_db()

    with _connect() as conn:

        row = conn.execute("SELECT COUNT(*) AS n FROM accounts").fetchone()

    return int(row["n"] if row else 0)





def _account_list_query(

    *,

    q: str = "",

    sort: str = "newest",

    status: str = "",

    probe: str = "",

    remote: str = "",

) -> tuple[str, list[Any], str, str, float]:

    """Shared filter/sort SQL for list_accounts / list_account_emails.



    Returns (where_sql, args, remote_join, order_sql, remote_synced_at).

    """

    where_parts: list[str] = []

    args: list[Any] = []

    if q.strip():

        where_parts.append("(a.email LIKE ? OR a.auth_key LIKE ? OR IFNULL(a.batch_id,'') LIKE ?)")

        like = f"%{q.strip()}%"

        args.extend([like, like, like])



    # Local status filter: exact DB status column (plus a few aliases).

    status_key = str(status or "").strip().lower()

    if status_key:

        if status_key in {"active", "ok", "imported"}:

            where_parts.append("lower(IFNULL(a.status,'')) IN ('active','ok','imported')")

        elif status_key == "failed":

            # Generic "失败" = any failed-like status, including probe_failed.

            where_parts.append(

                "(lower(IFNULL(a.status,'')) LIKE '%fail%' OR lower(IFNULL(a.status,'')) LIKE '%error%')"

            )

        elif status_key == "probe_failed":

            where_parts.append("lower(IFNULL(a.status,'')) = 'probe_failed'")

        elif status_key == "disabled":

            where_parts.append("lower(IFNULL(a.status,'')) LIKE 'disabled%'")

        elif status_key == "registered":

            where_parts.append("lower(IFNULL(a.status,'')) = 'registered'")

        elif status_key == "credentials_only":

            where_parts.append("lower(IFNULL(a.status,'')) = 'credentials_only'")

        elif status_key in {"relogged", "relogin_ok", "local_relogged"}:

            where_parts.append("lower(IFNULL(a.status,'')) = 'relogged'")

        else:

            where_parts.append("lower(IFNULL(a.status,'')) = ?")

            args.append(status_key)



    # Probe filter: only last_probe_json result (independent of status column).

    probe_key = str(probe or "").strip().lower()

    if probe_key in {"ok", "failed", "untested"}:

        if probe_key == "ok":

            where_parts.append(

                "(json_valid(a.last_probe_json) AND json_extract(a.last_probe_json,'$.ok') = 1)"

            )

        elif probe_key == "failed":

            where_parts.append(

                "("

                " json_valid(a.last_probe_json) AND ("

                "   json_extract(a.last_probe_json,'$.ok') = 0 "

                "   OR IFNULL(json_extract(a.last_probe_json,'$.error'),'') != '' "

                "   OR CAST(IFNULL(json_extract(a.last_probe_json,'$.status_code'),0) AS INTEGER) >= 400"

                " )"

                ")"

            )

        else:  # untested

            where_parts.append(

                "("

                " a.last_probe_json IS NULL OR a.last_probe_json = '' "

                " OR NOT json_valid(a.last_probe_json) "

                " OR ("

                "   json_extract(a.last_probe_json,'$.ok') IS NULL "

                "   AND IFNULL(json_extract(a.last_probe_json,'$.error'),'') = '' "

                "   AND CAST(IFNULL(json_extract(a.last_probe_json,'$.status_code'),0) AS INTEGER) < 400"

                " )"

                ")"

            )



    remote_key = str(remote or "").strip().lower()

    remote_join = (

        "LEFT JOIN ("

        "  SELECT r1.* FROM remote_accounts r1 "

        "  INNER JOIN ("

        "    SELECT lower(email) AS e, MAX(seen_at) AS max_seen FROM remote_accounts GROUP BY lower(email)"

        "  ) r2 ON lower(r1.email)=r2.e AND r1.seen_at=r2.max_seen"

        ") r ON lower(a.email)=lower(r.email)"

    )

    remote_sync = _json_setting("grok2api_last_remote_sync") or {}

    remote_synced_at = float(remote_sync.get("seen_at") or 0) if isinstance(remote_sync, dict) else 0.0

    # problems mode only caches abnormal remote rows; missing join ⇒ treat as healthy.

    remote_mode = str((remote_sync or {}).get("mode") or "full").strip().lower()

    problems_cache = remote_mode in {"problems", "problem", "failed", "abnormal"}

    if remote_key:

        if remote_key == "not_synced":

            # Only matches when remote status has never been pulled.

            if remote_synced_at:

                where_parts.append("1=0")

            # else: all rows are not_synced (no extra predicate)

        elif remote_key == "not_imported":

            # Full-mirror only: "local has no remote row". In problems mode the

            # cache intentionally omits healthy remotes, so this filter is N/A.

            if remote_synced_at and not problems_cache:

                where_parts.append("r.email IS NULL")

            else:

                where_parts.append("1=0")

        elif remote_key == "ok":

            if problems_cache:

                # No problem row (or explicitly healthy) ⇒ remote OK.

                where_parts.append(

                    "("

                    " r.email IS NULL "

                    " OR lower(IFNULL(r.action,'')) IN ('keep','ok','active') "

                    " OR lower(IFNULL(r.classification,'')) = 'healthy' "

                    " OR IFNULL(r.http_status,0) = 200"

                    ")"

                )

            else:

                where_parts.append(

                    "("

                    " lower(IFNULL(r.action,'')) IN ('keep','ok','active') "

                    " OR lower(IFNULL(r.classification,'')) = 'healthy' "

                    " OR IFNULL(r.http_status,0) = 200"

                    ")"

                )

        elif remote_key == "relogin":

            where_parts.append(

                "("

                " lower(IFNULL(r.action,'')) LIKE '%relogin%' "

                " OR IFNULL(r.http_status,0) IN (401,403)"

                ")"

            )

        elif remote_key == "wait":

            where_parts.append(

                "("

                " lower(IFNULL(r.action,'')) IN ('wait','waiting','waitingreset') "

                " OR lower(IFNULL(r.classification,'')) LIKE '%wait%' "

                " OR IFNULL(r.http_status,0) = 429"

                ")"

            )

        elif remote_key == "failed":

            where_parts.append(

                "("

                " lower(IFNULL(r.action,'')) LIKE '%fail%' "

                " OR lower(IFNULL(r.action,'')) LIKE '%error%' "

                " OR (IFNULL(r.http_status,0) >= 400 AND IFNULL(r.http_status,0) NOT IN (401,403,429))"

                ")"

            )

        else:

            where_parts.append("lower(IFNULL(r.action,'')) = ?")

            args.append(remote_key)



    where_sql = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

    sort_key = str(sort or "newest").strip().lower()

    order = {

        "newest": "a.updated_at DESC",

        "oldest": "a.updated_at ASC",

        "email_asc": "a.email COLLATE NOCASE ASC",

        "email_desc": "a.email COLLATE NOCASE DESC",

        "status_asc": "a.status COLLATE NOCASE ASC, a.updated_at DESC",

        "status_desc": "a.status COLLATE NOCASE DESC, a.updated_at DESC",

        "probe_asc": "IFNULL(json_extract(a.last_probe_json,'$.ok'), -1) ASC, a.updated_at DESC",

        "probe_desc": "IFNULL(json_extract(a.last_probe_json,'$.ok'), -1) DESC, a.updated_at DESC",

        "created_at_asc": "a.created_at ASC",

        "created_at_desc": "a.created_at DESC",

        "expires_at_asc": "a.expires_at ASC",

        "expires_at_desc": "a.expires_at DESC",

        "remote_asc": "IFNULL(r.action,'') COLLATE NOCASE ASC, a.updated_at DESC",

        "remote_desc": "IFNULL(r.action,'') COLLATE NOCASE DESC, a.updated_at DESC",

    }.get(sort_key, "a.updated_at DESC")

    return where_sql, args, remote_join, order, remote_synced_at





def list_account_emails(

    *,

    q: str = "",

    sort: str = "newest",

    status: str = "",

    probe: str = "",

    remote: str = "",

    limit: int = 20000,

) -> dict[str, Any]:

    """Return emails matching the same filters as list_accounts (no pagination)."""

    init_db()

    where_sql, args, remote_join, order, _remote_synced_at = _account_list_query(

        q=q, sort=sort, status=status, probe=probe, remote=remote

    )

    need_remote = bool(str(remote or "").strip()) or str(sort or "").lower().startswith("remote_")

    join_sql = remote_join if need_remote else ""

    cap = max(1, min(50000, int(limit or 20000)))

    with _connect() as conn:

        total = int(

            conn.execute(

                f"SELECT COUNT(*) AS n FROM accounts a {join_sql} {where_sql}",

                args,

            ).fetchone()["n"]

        )

        rows = conn.execute(

            f"SELECT a.email AS email FROM accounts a {join_sql} {where_sql} ORDER BY {order} LIMIT ?",

            [*args, cap],

        ).fetchall()

    emails = [

        str(row["email"] or "").strip().lower()

        for row in rows

        if str(row["email"] or "").strip()

    ]

    # De-dupe while preserving SQL order (important for "select filtered" UX).

    seen: set[str] = set()

    ordered: list[str] = []

    for email in emails:

        if email in seen:

            continue

        seen.add(email)

        ordered.append(email)

    return {

        "ok": True,

        "emails": ordered,

        "total": total,

        "returned": len(ordered),

        "truncated": total > len(ordered),

    }





def list_accounts(

    *,

    page: int = 1,

    page_size: int = 25,

    q: str = "",

    sort: str = "newest",

    status: str = "",

    probe: str = "",

    remote: str = "",

) -> dict[str, Any]:

    """List accounts with DB-wide filters/sort/pagination.



    Filter values match table badges / SQLite fields:

      - status: active | registered | probe_failed | credentials_only | disabled | ...

      - probe:  ok | failed | untested

      - remote: not_imported | not_synced | relogin | wait | failed | ok



    Performance:

      - remote JOIN is only used when filtering/sorting by remote fields.

      - default list path is accounts-only + per-page remote lookup.

      - dashboard stats are cache-only.

    """

    init_db()

    page = max(1, int(page or 1))

    page_size = max(1, min(5000, int(page_size or 25)))

    offset = (page - 1) * page_size



    where_sql, args, remote_join, order, remote_synced_at = _account_list_query(

        q=q, sort=sort, status=status, probe=probe, remote=remote

    )

    need_remote = bool(str(remote or "").strip()) or str(sort or "").lower().startswith("remote_")

    join_sql = remote_join if need_remote else ""

    remote_sync = _json_setting("grok2api_last_remote_sync") or {}

    remote_mode = str((remote_sync or {}).get("mode") or "full").strip().lower()

    problems_cache = remote_mode in {"problems", "problem", "failed", "abnormal"}



    with _connect() as conn:

        total = int(

            conn.execute(

                f"SELECT COUNT(*) AS n FROM accounts a {join_sql} {where_sql}",

                args,

            ).fetchone()["n"]

        )

        rows = conn.execute(

            f"SELECT a.* FROM accounts a {join_sql} {where_sql} ORDER BY {order} LIMIT ? OFFSET ?",

            [*args, page_size, offset],

        ).fetchall()

        remote_by_email = _latest_remote_by_email(conn, [str(row["email"]) for row in rows])



    accounts = []

    for row in rows:

        item = dict(row)

        item["id"] = item.get("auth_key")

        item["auth_mode"] = "oidc"

        item["enabled"] = True

        item["expired"] = False

        grok2api_auth_path = str(item.get("grok2api_auth_path") or "")

        cpa_auth_path = str(item.get("cpa_auth_path") or "")

        has_sso = bool(str(item.get("sso") or "").strip())

        item["auth_data"] = {

            "sso": has_sso,

            "grok2api": bool(item.get("grok2api_auth_json") or grok2api_auth_path),

            "cpa": bool(item.get("cpa_auth_json") or cpa_auth_path),

            "grok2api_name": Path(grok2api_auth_path).name if grok2api_auth_path else _auth_part_filename(str(item.get("email") or "")),

            "cpa_name": Path(cpa_auth_path).name if cpa_auth_path else _auth_part_filename(str(item.get("email") or ""), cpa=True),

        }

        item["push_flags"] = {

            "cpa_pushed": bool(int(item.get("cpa_pushed") or 0)),

            "cpa_pushed_at": item.get("cpa_pushed_at"),

            "sub2_pushed": bool(int(item.get("sub2_pushed") or 0)),

            "sub2_pushed_at": item.get("sub2_pushed_at"),

            "grok2api_pushed": bool(int(item.get("grok2api_pushed") or 0)),

            "grok2api_pushed_at": item.get("grok2api_pushed_at"),

        }

        item["_pool"] = {

            "id": item.get("auth_key"),

            "enabled": True,

            "pool_status": item.get("status") or "registered",

            "source": "register_pro",

        }

        item.pop("password", None)

        item.pop("access_token", None)

        item.pop("refresh_token", None)

        item.pop("id_token", None)

        item.pop("sso", None)

        item.pop("raw_json", None)

        item.pop("grok2api_auth_json", None)

        item.pop("cpa_auth_json", None)

        item.pop("grok2api_auth_path", None)

        item.pop("cpa_auth_path", None)

        item["last_probe"] = json.loads(item["last_probe_json"]) if item.get("last_probe_json") else None

        item.pop("last_probe_json", None)

        remote_row = remote_by_email.get(str(item.get("email") or "").lower())

        # Remote column semantics (single source of truth for the UI):

        #   - never pulled          → not_synced（未同步）

        #   - full mirror, no row   → not_imported（未导入）

        #   - problems cache, no row→ keep/healthy（已导入/正常，异常才有行）

        #   - has remote row        → use that row's action/classification

        if remote_row:

            item["remote"] = {

                "provider": remote_row.get("provider"),

                "classification": remote_row.get("classification"),

                "http_status": remote_row.get("http_status"),

                "action": remote_row.get("action"),

                "reason": remote_row.get("reason"),

                "auth_status": remote_row.get("auth_status"),

                "seen_at": remote_row.get("seen_at"),

            }

        elif not remote_synced_at:

            item["remote"] = {

                "classification": "not_synced",

                "action": "not_synced",

                "reason": "",

            }

        elif problems_cache:

            item["remote"] = {

                "classification": "healthy",

                "action": "keep",

                "reason": "assumed_ok_problems_cache",

                "http_status": 200,

                "seen_at": remote_synced_at,

            }

        else:

            item["remote"] = {

                "classification": "not_imported",

                "action": "not_imported",

                "reason": "",

                "seen_at": remote_synced_at,

            }

        accounts.append(item)

    total_pages = max(1, (total + page_size - 1) // page_size)

    # Read cached stats only — never recompute heavy remote joins on list/page.

    stats = get_account_dashboard_stats(refresh=False)

    return {

        "ok": True,

        "accounts": accounts,

        "total": total,

        "account_count": total,

        "page": page,

        "page_size": page_size,

        "total_pages": total_pages,

        "sort": sort,

        "store_source": "sqlite",

        "store_backend": "sqlite",

        "auth_file_role": "export",

        "pool": {"mode": "round_robin", "total": total, "live": total, "enabled": total},

        "stats": stats,

    }






def export_account_txt_lines(
    emails: list[str] | None = None,
    *,
    require_selected: bool = True,
) -> list[str]:
    """Export account lines as ``email----password----sso`` (grok-register style).

    When *emails* is non-empty, only those accounts are exported.
    When empty and *require_selected* is True, returns [] (caller should 400).
    When empty and *require_selected* is False, exports all accounts that have
    email or sso.
    """
    init_db()
    clean = sorted(
        {
            str(e or "").strip().lower()
            for e in (emails or [])
            if str(e or "").strip()
        }
    )
    if not clean and require_selected:
        return []
    where = ["1=1"]
    args: list[Any] = []
    if clean:
        where.append("lower(email) IN (" + ",".join("?" for _ in clean) + ")")
        args.extend(clean)
    sql = (
        "SELECT email, password, sso FROM accounts WHERE "
        + " AND ".join(where)
        + " ORDER BY updated_at DESC"
    )
    with _connect() as conn:
        rows = conn.execute(sql, args).fetchall()
    lines: list[str] = []
    for row in rows:
        email = str(row["email"] or "").strip()
        password = str(row["password"] or "").strip()
        sso = str(row["sso"] or "").strip()
        if not email and not sso:
            continue
        lines.append(f"{email}----{password}----{sso}")
    return lines


def export_sso_rows(

    *,

    batch_id: str = "",

    status: list[str] | None = None,

    emails: list[str] | None = None,

) -> list[dict[str, Any]]:

    init_db()

    where = ["sso IS NOT NULL", "sso != ''"]

    args: list[Any] = []

    if batch_id.strip():

        where.append("batch_id = ?")

        args.append(batch_id.strip())

    if status:

        placeholders = ",".join("?" for _ in status)

        where.append(f"status IN ({placeholders})")

        args.extend(status)

    clean_emails = sorted(

        {

            str(e or "").strip().lower()

            for e in (emails or [])

            if str(e or "").strip()

        }

    )

    if clean_emails:

        placeholders = ",".join("?" for _ in clean_emails)

        where.append(f"lower(email) IN ({placeholders})")

        args.extend(clean_emails)

    sql = (

        "SELECT email, password, sso, status, batch_id, session_id, updated_at "

        f"FROM accounts WHERE {' AND '.join(where)} ORDER BY updated_at DESC"

    )

    with _connect() as conn:

        rows = conn.execute(sql, args).fetchall()

    return [dict(r) for r in rows]





def import_sso_only_account(

    *,

    email: str,

    password: str = "",

    sso: str,

    batch_id: str = "",

    session_id: str = "",

) -> dict[str, Any]:

    """Persist email/password/SSO without device-flow OAuth conversion."""

    email_n = str(email or "").strip().lower()

    sso_n = str(sso or "").strip()

    if not email_n or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email_n):

        return {"ok": False, "error": "missing/invalid email"}

    if not sso_n:

        return {"ok": False, "error": "missing sso"}

    password_n = password if is_plausible_account_password(password) else ""

    now = time.time()

    payload = json.dumps(

        {

            "source": "register_sso_only",

            "email": email_n,

            "has_password": bool(password_n),

            "has_sso": True,

            "sso_only": True,

        },

        ensure_ascii=False,

    )

    init_db()

    with _connect() as conn:

        existing = conn.execute(

            "SELECT created_at, password, status FROM accounts WHERE email = ?",

            (email_n,),

        ).fetchone()

        if existing:

            created_at = float(existing["created_at"] or now)

            if not password_n:

                prev = str(existing["password"] or "")

                if is_plausible_account_password(prev):

                    password_n = prev

        else:

            created_at = now

        conn.execute(

            """

            INSERT INTO accounts(

              email, password, sso, auth_key, user_id, access_token, refresh_token, id_token,

              expires_at, oidc_issuer, oidc_client_id, grok2api_auth_path, cpa_auth_path,

              grok2api_auth_json, cpa_auth_json, status, batch_id, session_id, created_at, updated_at, raw_json

            )

            VALUES (?, ?, ?, ?, '', '', '', '', '', '', '', '', '', '', '', 'sso_pending', ?, ?, ?, ?, ?)

            ON CONFLICT(email) DO UPDATE SET

              password = CASE

                WHEN excluded.password != '' THEN excluded.password

                ELSE accounts.password

              END,

              sso = excluded.sso,

              status = CASE

                WHEN IFNULL(accounts.access_token, '') = ''

                  AND IFNULL(accounts.grok2api_auth_json, '') = ''

                  AND IFNULL(accounts.cpa_auth_json, '') = ''

                THEN 'sso_pending'

                ELSE accounts.status

              END,

              batch_id = CASE WHEN excluded.batch_id != '' THEN excluded.batch_id ELSE accounts.batch_id END,

              session_id = CASE WHEN excluded.session_id != '' THEN excluded.session_id ELSE accounts.session_id END,

              updated_at = excluded.updated_at,

              raw_json = excluded.raw_json

            """,

            (

                email_n,

                password_n,

                sso_n,

                f"sso::{email_n}",

                str(batch_id or ""),

                str(session_id or ""),

                created_at,

                now,

                payload,

            ),

        )

    return {

        "ok": True,

        "email": email_n,

        "status": "sso_pending",

        "imported": [{"id": f"sso::{email_n}", "email": email_n, "sso_only": True}],

        "count": 1,

    }





def convert_sso_accounts_to_auth(

    emails: list[str],

    *,

    concurrency: int = 2,

    force: bool = False,

) -> dict[str, Any]:

    """Convert selected SSO-only (or SSO-bearing) accounts into Grok2API/CPA auth.



    Runs device-flow via ``sso_to_auth_json`` for each account that has an SSO

    cookie. By default skips rows that already have both auth documents unless

    ``force`` is true.

    """

    from concurrent.futures import ThreadPoolExecutor, as_completed



    clean = sorted(

        {str(e or "").strip().lower() for e in (emails or []) if str(e or "").strip()}

    )

    if not clean:

        return {"ok": False, "error": "未选择账号", "results": [], "converted": 0, "failed": 0, "skipped": 0}



    init_db()

    with _connect() as conn:

        placeholders = ",".join("?" for _ in clean)

        rows = conn.execute(

            f"""

            SELECT email, password, sso, access_token, grok2api_auth_json, cpa_auth_json, status

            FROM accounts

            WHERE lower(email) IN ({placeholders})

            """,

            clean,

        ).fetchall()

    by_email = {str(r["email"] or "").strip().lower(): dict(r) for r in rows}



    results: list[dict[str, Any]] = []

    todo: list[dict[str, Any]] = []

    for email in clean:

        row = by_email.get(email)

        if not row:

            results.append({"email": email, "ok": False, "error": "账号不存在", "skipped": True})

            continue

        sso = str(row.get("sso") or "").strip()

        if not sso:

            results.append({"email": email, "ok": False, "error": "无 SSO，无法转换", "skipped": True})

            continue

        has_auth = bool(str(row.get("grok2api_auth_json") or "").strip()) and bool(

            str(row.get("cpa_auth_json") or "").strip()

        )

        if has_auth and not force:

            results.append(

                {

                    "email": email,

                    "ok": True,

                    "skipped": True,

                    "error": "",

                    "message": "已有 Auth/CPA，已跳过（可 force 重转）",

                }

            )

            continue

        todo.append({"email": email, "sso": sso, "password": str(row.get("password") or "")})



    def _one(item: dict[str, Any]) -> dict[str, Any]:

        email = item["email"]

        sso = item["sso"]

        password = item.get("password") or ""

        try:

            import sso_to_auth_json as sso_import



            token = sso_import.sso_to_token(sso)

            if not token or not token.get("access_token"):

                return {

                    "email": email,

                    "ok": False,

                    "error": "SSO→OAuth 转换失败（device-flow）",

                }

            _key, entry = sso_import.token_to_auth_entry(token, email=email)

            imported = import_auth_payload(

                {

                    "key": entry["key"],

                    "auth_mode": entry.get("auth_mode", "oidc"),

                    "email": entry.get("email") or email,

                    "refresh_token": entry.get("refresh_token", ""),

                    "id_token": token.get("id_token", ""),

                    "expires_at": entry.get("expires_at"),

                    "oidc_issuer": entry.get("oidc_issuer", "https://auth.x.ai"),

                    "oidc_client_id": entry.get("oidc_client_id", ""),

                    "registration_password": password,

                    "sso": sso,

                },

                merge=True,

            )

            if not imported.get("ok"):

                return {

                    "email": email,

                    "ok": False,

                    "error": str(imported.get("error") or "写入 Auth 失败"),

                }

            return {

                "email": email,

                "ok": True,

                "status": "registered",

                "message": "已转换为 Grok2API/CPA Auth",

                "has_refresh_token": bool(token.get("refresh_token")),

            }

        except Exception as exc:  # noqa: BLE001

            return {"email": email, "ok": False, "error": str(exc)[:300]}



    workers = max(1, min(8, int(concurrency or 2), len(todo) or 1))

    if todo:

        with ThreadPoolExecutor(max_workers=workers) as pool:

            futs = {pool.submit(_one, item): item["email"] for item in todo}

            for fut in as_completed(futs):

                try:

                    results.append(fut.result())

                except Exception as exc:  # noqa: BLE001

                    results.append(

                        {"email": futs[fut], "ok": False, "error": str(exc)[:300]}

                    )



    converted = sum(1 for r in results if r.get("ok") and not r.get("skipped"))

    skipped = sum(1 for r in results if r.get("skipped"))

    failed = sum(1 for r in results if not r.get("ok") and not r.get("skipped"))

    return {

        "ok": failed == 0,

        "converted": converted,

        "failed": failed,

        "skipped": skipped,

        "total": len(clean),

        "concurrency": workers,

        "results": sorted(results, key=lambda x: str(x.get("email") or "")),

        "message": f"转换完成：成功 {converted}，跳过 {skipped}，失败 {failed}",

    }





def _probe_body(model: str) -> dict[str, Any]:

    return {

        "model": model,

        "messages": [{"role": "user", "content": "ping"}],

        "stream": True,

        "max_tokens": 8,

        "max_completion_tokens": 8,

    }





def _upstream_headers(token: str, model: str) -> dict[str, str]:

    """Match the Grok CLI request shape used by the original health probe."""

    return {

        "Content-Type": "application/json",

        "Authorization": f"Bearer {token}",

        "X-XAI-Token-Auth": "xai-grok-cli",

        "x-grok-model-override": model,

        "x-grok-client-version": CLI_VERSION,

        "x-grok-client-surface": CLIENT_SURFACE,

        "x-grok-client-identifier": CLIENT_IDENTIFIER,

        "User-Agent": f"grok-cli/{CLI_VERSION}",

        "Accept": "text/event-stream, application/json",

    }





def _probe_once(

    token: str,

    *,

    model: str,

    timeout: float,

    proxy: str | None = None,

) -> dict[str, Any]:

    """Single chat/completions probe attempt. Returns status/error/latency fields."""

    t0 = time.time()

    headers = _upstream_headers(token, model)

    body = json.dumps(_probe_body(model)).encode("utf-8")

    url = f"{UPSTREAM_BASE}/chat/completions"

    out: dict[str, Any] = {"probed_at": t0}



    # Prefer curl_cffi (browser-like TLS) when available; optional proxy stickiness.

    try:

        from curl_cffi import requests as curl_requests  # type: ignore

    except Exception:

        curl_requests = None



    if curl_requests is not None:

        try:

            kwargs: dict[str, Any] = {

                "headers": headers,

                "data": body,

                "timeout": timeout,

                "allow_redirects": False,

                "impersonate": "chrome",

            }

            if proxy:

                kwargs["proxies"] = {"http": proxy, "https": proxy}

            resp = curl_requests.post(url, **kwargs)

            raw = (resp.text or "")[:4096]

            code = int(resp.status_code)

            if 200 <= code < 300:

                out.update(

                    {

                        "ok": True,

                        "available": True,

                        "status_code": code,

                        "stream_ok": "data:" in raw or bool(raw),

                        "latency_ms": int((time.time() - t0) * 1000),

                        "transport": "curl_cffi",

                    }

                )

            else:

                out.update(

                    {

                        "ok": False,

                        "available": False,

                        "status_code": code,

                        "error": raw[:800] or f"HTTP {code}",

                        "latency_ms": int((time.time() - t0) * 1000),

                        "transport": "curl_cffi",

                    }

                )

            if proxy:

                out["proxy_enabled"] = True

            return out

        except Exception as exc:  # noqa: BLE001

            # Fall through to urllib so a curl_cffi glitch is not fatal.

            out["curl_cffi_error"] = str(exc)[:200]



    req = urllib.request.Request(url, data=body, headers=headers, method="POST")

    try:

        with _urlopen(req, timeout=timeout) as resp:

            raw = resp.read(4096).decode("utf-8", "replace")

            out.update(

                {

                    "ok": 200 <= int(resp.status) < 300,

                    "available": 200 <= int(resp.status) < 300,

                    "status_code": int(resp.status),

                    "stream_ok": "data:" in raw or bool(raw),

                    "latency_ms": int((time.time() - t0) * 1000),

                    "transport": "urllib",

                }

            )

    except urllib.error.HTTPError as exc:

        body_txt = exc.read(4096).decode("utf-8", "replace")

        out.update(

            {

                "ok": False,

                "available": False,

                "status_code": int(exc.code),

                "error": body_txt[:800] or str(exc),

                "latency_ms": int((time.time() - t0) * 1000),

                "transport": "urllib",

            }

        )

    except Exception as exc:  # noqa: BLE001

        out.update(

            {

                "ok": False,

                "available": False,

                "error": str(exc)[:800],

                "latency_ms": int((time.time() - t0) * 1000),

                "transport": "urllib",

            }

        )

    if proxy:

        out["proxy_enabled"] = True

    return out





def _is_transient_probe_denial(result: dict[str, Any]) -> bool:

    """True when upstream is still settling a brand-new OIDC session."""

    code = int(result.get("status_code") or 0)

    err = str(result.get("error") or "").lower()

    if code == 403 and (

        "permission-denied" in err

        or "access to the chat endpoint is denied" in err

        or "permissiondenied" in err

    ):

        return True

    if code == 401 and "no auth context" in err:

        return True

    return False





def _resolve_probe_proxy() -> str:

    """Probe uses the registration proxy pool (round-robin)."""

    try:

        return resolve_probe_proxy_url() or ""

    except Exception:

        return ""





def probe_access_token(

    token: str,

    *,

    email: str = "",

    model: str = "grok-4.5",

    timeout: float = 45.0,

    retries: int = 3,

    retry_delay_sec: float = 8.0,

    proxy: str | None = None,

    persist: bool = False,

) -> dict[str, Any]:

    """Probe a raw access token without requiring it to already be in SQLite.



    Used by relogin: verify the fresh credential first, only then write DB.

    When persist=True and email is set, also saves probe result onto that account.

    """

    access = str(token or "").strip()

    if not access:

        return {

            "ok": False,

            "available": False,

            "email": email or None,

            "model": model,

            "error": "missing access_token",

            "probed_at": time.time(),

        }

    proxy_url = (proxy if proxy is not None else _resolve_probe_proxy() or "").strip() or None

    attempts = max(1, int(retries or 1))

    delay = max(0.0, float(retry_delay_sec or 0.0))

    result: dict[str, Any] = {

        "ok": False,

        "available": False,

        "email": email or None,

        "model": model,

        "probed_at": time.time(),

    }

    for attempt in range(1, attempts + 1):

        attempt_result = _probe_once(access, model=model, timeout=timeout, proxy=proxy_url)

        result.update(attempt_result)

        result["attempt"] = attempt

        result["proxy"] = bool(proxy_url)

        if result.get("ok"):

            # Successful retry must not keep the previous attempt's error body.

            result.pop("error", None)

            result.pop("curl_cffi_error", None)

            break

        if attempt < attempts and _is_transient_probe_denial(result):

            time.sleep(delay * attempt)

            continue

        break

    if persist and email:

        _save_probe_result(str(email).strip().lower(), result)

    return result





def probe_account(

    identifier: str,

    *,

    model: str = "grok-4.5",

    timeout: float = 45.0,

    retries: int = 3,

    retry_delay_sec: float = 8.0,

    proxy: str | None = None,

) -> dict[str, Any]:

    """Probe one SQLite account with the same upstream shape as the Grok CLI proxy.



    Newly minted OIDC tokens often return 403 permission-denied for a short

    settle window. We retry those transient denials instead of immediately

    marking the account probe_failed / blocking Grok2API import.

    """

    init_db()

    ident = str(identifier or "").strip()

    if not ident:

        return {"ok": False, "error": "missing account identifier"}

    with _connect() as conn:

        row = conn.execute(

            "SELECT * FROM accounts WHERE email = ? OR auth_key = ?",

            (ident, ident),

        ).fetchone()

    if not row:

        return {"ok": False, "error": f"account not found: {ident}"}



    account = dict(row)

    token = str(account.get("access_token") or "")

    if not token:

        result = {

            "ok": False,

            "available": False,

            "email": account.get("email"),

            "model": model,

            "error": "missing access_token",

            "probed_at": time.time(),

        }

        _save_probe_result(str(account["email"]), result)

        return result



    # Single proxy source: explicit arg, else registration proxy pool (round-robin).

    proxy_url = (proxy if proxy is not None else _resolve_probe_proxy() or "").strip() or None

    effective_proxy = proxy_url

    attempts = max(1, int(retries or 1))

    delay = max(0.0, float(retry_delay_sec or 0.0))

    result: dict[str, Any] = {

        "ok": False,

        "available": False,

        "email": account.get("email"),

        "auth_key": account.get("auth_key"),

        "model": model,

        "probed_at": time.time(),

    }

    for attempt in range(1, attempts + 1):

        attempt_result = _probe_once(

            token, model=model, timeout=timeout, proxy=effective_proxy

        )

        result.update(attempt_result)

        result["attempt"] = attempt

        result["proxy"] = bool(proxy_url)

        if result.get("ok"):

            # Successful retry must not keep the previous attempt's error body.

            result.pop("error", None)

            result.pop("curl_cffi_error", None)

            break

        if attempt < attempts and _is_transient_probe_denial(result):

            # Brand-new tokens settle server-side; wait and retry.

            time.sleep(delay * attempt)

            continue

        break



    _save_probe_result(str(account["email"]), result)

    return result





def _run_probe_batch(

    emails: list[str],

    *,

    model: str,

    concurrency: int,

    cooldown_ms: int,

    should_stop=None,

    on_progress=None,

) -> dict[str, Any]:

    clean: list[str] = []

    seen: set[str] = set()

    for email in emails:

        key = str(email or "").strip().lower()

        if not key or key in seen:

            continue

        seen.add(key)

        clean.append(key)

    if not clean:

        return {"ok": 0, "fail": 0, "count": 0, "results": []}



    workers = max(1, min(10, int(concurrency or 2), len(clean)))

    cooldown = max(0.0, min(60.0, float(cooldown_ms or 0) / 1000.0))

    results: list[dict[str, Any]] = []

    next_index = 0

    stopped = False



    def stop_requested() -> bool:

        return bool(callable(should_stop) and should_stop())



    def progress() -> None:

        if callable(on_progress):

            on_progress({"done": len(results), "total": len(clean), "ok": sum(1 for item in results if item.get("ok"))})



    with ThreadPoolExecutor(max_workers=workers) as executor:

        futures: dict[Any, str] = {}

        last_started = 0.0

        while next_index < len(clean) or futures:

            while next_index < len(clean) and len(futures) < workers:

                if stop_requested():

                    stopped = True

                    break

                remaining_wait = cooldown - (time.monotonic() - last_started) if last_started else 0.0

                while remaining_wait > 0:

                    if stop_requested():

                        stopped = True

                        break

                    time.sleep(min(0.1, remaining_wait))

                    remaining_wait = cooldown - (time.monotonic() - last_started)

                if stopped:

                    break

                email = clean[next_index]

                next_index += 1

                futures[executor.submit(probe_account, email, model=model)] = email

                last_started = time.monotonic()

            if not futures:

                break

            done, _ = wait(futures, return_when=FIRST_COMPLETED)

            for future in done:

                futures.pop(future, None)

                results.append(future.result())

                progress()

            if stopped and not futures:

                break

    ok = sum(1 for r in results if r.get("ok"))

    return {

        "ok": ok,

        "fail": len(results) - ok,

        "count": len(results),

        "concurrency": workers,

        "cooldown_ms": int(cooldown * 1000),

        "results": results,

        "stopped": stopped,

        "requested": len(clean),

    }





def probe_account_list(

    emails: list[str],

    *,

    model: str = "grok-4.5",

    concurrency: int = 2,

    cooldown_ms: int = 1000,

    should_stop=None,

    on_progress=None,

) -> dict[str, Any]:

    return _run_probe_batch(

        emails,

        model=model,

        concurrency=concurrency,

        cooldown_ms=cooldown_ms,

        should_stop=should_stop,

        on_progress=on_progress,

    )





def probe_accounts(

    *,

    model: str = "grok-4.5",

    limit: int = 20,

    concurrency: int = 2,

    cooldown_ms: int = 1000,

    should_stop=None,

    on_progress=None,

) -> dict[str, Any]:

    init_db()

    limit = max(1, min(200, int(limit or 20)))

    workers = max(1, min(10, int(concurrency or 2), limit))

    cooldown = max(0.0, min(60.0, float(cooldown_ms or 0) / 1000.0))

    with _connect() as conn:

        rows = conn.execute(

            "SELECT email FROM accounts ORDER BY updated_at DESC LIMIT ?",

            (limit,),

        ).fetchall()

    emails = [str(r["email"]) for r in rows]

    return _run_probe_batch(

        emails,

        model=model,

        concurrency=workers,

        cooldown_ms=int(cooldown * 1000),

        should_stop=should_stop,

        on_progress=on_progress,

    )





def delete_accounts(emails: list[str], *, backup: bool = True, recycle: bool = True) -> dict[str, Any]:

    clean: list[str] = []

    seen: set[str] = set()

    for email in emails or []:

        key = str(email or "").strip().lower()

        if not key or key in seen:

            continue

        seen.add(key)

        clean.append(key)

    if not clean:

        return {"ok": False, "deleted": 0, "error": "未选择账号"}



    init_db()

    placeholders = ",".join("?" for _ in clean)

    now = int(time.time())

    deleted_at = time.time()

    backup_path = ""

    with _connect() as conn:

        rows = conn.execute(

            f"SELECT * FROM accounts WHERE lower(email) IN ({placeholders})",

            clean,

        ).fetchall()

        backup_rows = [dict(row) for row in rows]

        if backup and backup_rows:

            BACKUP_DIR.mkdir(parents=True, exist_ok=True)

            path = BACKUP_DIR / f"accounts_delete_{now}.json"

            path.write_text(

                json.dumps(

                    {"deleted_at": now, "count": len(backup_rows), "accounts": backup_rows},

                    ensure_ascii=False,

                    indent=2,

                )

                + "\n",

                encoding="utf-8",

            )

            backup_path = str(path)

        recycled = 0
        if recycle and backup_rows:
            for row in backup_rows:
                email = str(row.get("email") or "").strip().lower()
                if not email:
                    continue
                conn.execute(
                    """
                    INSERT INTO account_recycle_bin(email, account_json, deleted_at, backup_path, source, restore_count)
                    VALUES (?, ?, ?, ?, 'delete', 0)
                    ON CONFLICT(email) DO UPDATE SET
                      account_json = excluded.account_json,
                      deleted_at = excluded.deleted_at,
                      backup_path = excluded.backup_path,
                      source = excluded.source
                    """,
                    (email, json.dumps(row, ensure_ascii=False), deleted_at, backup_path),
                )
                recycled += 1

        conn.execute(

            f"DELETE FROM accounts WHERE lower(email) IN ({placeholders})",

            clean,

        )

    return {

        "ok": True,

        "deleted": len(backup_rows),

        "requested": len(clean),

        "backup_path": backup_path,

        "recycled": recycled if recycle else 0,

        "soft_deleted": bool(recycle),

    }





def discard_accounts(emails: list[str]) -> dict[str, Any]:

    """Hard-drop registration leftovers (probe fail) without writing backup files."""

    return delete_accounts(emails, backup=False, recycle=False)





def list_account_delete_backups(limit: int = 20) -> dict[str, Any]:
    init_db()
    cap = max(1, min(200, int(limit or 20)))
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = []
    paths = sorted(BACKUP_DIR.glob("accounts_delete_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in paths[:cap]:
        meta: dict[str, Any] = {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                meta = data
        except Exception:
            meta = {}
        stat = path.stat()
        items.append(
            {
                "name": path.name,
                "path": str(path),
                "count": int(meta.get("count") or 0),
                "deleted_at": meta.get("deleted_at"),
                "size": stat.st_size,
                "mtime": stat.st_mtime,
            }
        )
    return {"ok": True, "backups": items, "count": len(items), "backup_dir": str(BACKUP_DIR)}


def _resolve_account_backup_path(backup_path: str | None) -> Path:
    raw = str(backup_path or "").strip().strip("\"'")
    if not raw:
        backups = list_account_delete_backups(limit=1).get("backups") or []
        if not backups:
            raise FileNotFoundError("未找到账号删除备份文件")
        raw = str(backups[0].get("path") or "")
    path = Path(raw)
    if not path.is_absolute():
        path = BACKUP_DIR / path.name
    resolved = path.resolve()
    backup_root = BACKUP_DIR.resolve()
    try:
        resolved.relative_to(backup_root)
    except ValueError as exc:
        raise ValueError("只能恢复备份目录内的账号删除备份文件") from exc
    if not resolved.exists() or not resolved.is_file():
        raise FileNotFoundError(f"备份文件不存在：{resolved}")
    if resolved.suffix.lower() != ".json" or not resolved.name.startswith("accounts_delete_"):
        raise ValueError("备份文件名必须是 accounts_delete_*.json")
    return resolved


def restore_accounts_from_backup(backup_path: str | None = None, *, overwrite: bool = False) -> dict[str, Any]:
    init_db()
    path = _resolve_account_backup_path(backup_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"备份文件 JSON 解析失败：{exc}") from exc
    rows = payload.get("accounts") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise ValueError("备份文件格式无效：缺少 accounts 数组")

    now = time.time()
    restored = 0
    skipped_existing = 0
    skipped_invalid = 0
    overwritten = 0
    touched_emails: list[str] = []
    with _connect() as conn:
        columns = [str(row["name"]) for row in conn.execute("PRAGMA table_info(accounts)").fetchall()]
        insert_cols = list(columns)
        placeholders = ",".join("?" for _ in insert_cols)
        col_sql = ",".join(insert_cols)
        if overwrite:
            update_cols = [c for c in insert_cols if c != "email"]
            conflict_sql = "DO UPDATE SET " + ", ".join(f"{c}=excluded.{c}" for c in update_cols)
        else:
            conflict_sql = "DO NOTHING"
        sql = f"INSERT INTO accounts({col_sql}) VALUES ({placeholders}) ON CONFLICT(email) {conflict_sql}"

        for raw in rows:
            if not isinstance(raw, dict):
                skipped_invalid += 1
                continue
            email = str(raw.get("email") or "").strip().lower()
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                skipped_invalid += 1
                continue
            exists = conn.execute("SELECT 1 FROM accounts WHERE lower(email)=? LIMIT 1", (email,)).fetchone()
            if exists and not overwrite:
                skipped_existing += 1
                continue
            record = {key: raw.get(key) for key in insert_cols}
            record["email"] = email
            record["auth_key"] = str(record.get("auth_key") or f"restore::{email}")
            record["status"] = str(record.get("status") or "registered")
            record["created_at"] = float(record.get("created_at") or now)
            record["updated_at"] = now
            if record.get("raw_json") is None:
                record["raw_json"] = json.dumps(
                    {"source": "restore_backup", "backup": path.name, "email": email},
                    ensure_ascii=False,
                )
            for key in insert_cols:
                if record.get(key) is None:
                    record[key] = 0 if key in {"created_at", "updated_at", "cpa_pushed", "sub2_pushed", "grok2api_pushed"} else ""
            conn.execute(sql, [record.get(c) for c in insert_cols])
            if exists:
                overwritten += 1
            else:
                restored += 1
            touched_emails.append(email)
        removed_from_recycle = 0
        if touched_emails:
            placeholders_del = ",".join("?" for _ in touched_emails)
            cur = conn.execute(
                f"DELETE FROM account_recycle_bin WHERE lower(email) IN ({placeholders_del})",
                touched_emails,
            )
            removed_from_recycle = int(cur.rowcount or 0)
    return {
        "ok": True,
        "backup_path": str(path),
        "restored": restored,
        "overwritten": overwritten,
        "skipped_existing": skipped_existing,
        "skipped_invalid": skipped_invalid,
        "removed_from_recycle": removed_from_recycle,
        "total": len(rows),
        "overwrite": bool(overwrite),
    }


def list_account_recycle_bin(limit: int = 100) -> dict[str, Any]:
    init_db()
    cap = max(1, min(1000, int(limit or 100)))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT email, account_json, deleted_at, backup_path, source, restore_count
            FROM account_recycle_bin
            ORDER BY deleted_at DESC
            LIMIT ?
            """,
            (cap,),
        ).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        raw: dict[str, Any] = {}
        try:
            parsed = json.loads(str(row["account_json"] or "{}"))
            if isinstance(parsed, dict):
                raw = parsed
        except Exception:
            raw = {}
        items.append(
            {
                "email": str(row["email"] or ""),
                "status": str(raw.get("status") or ""),
                "auth_key": str(raw.get("auth_key") or ""),
                "deleted_at": row["deleted_at"],
                "backup_path": str(row["backup_path"] or ""),
                "source": str(row["source"] or ""),
                "restore_count": int(row["restore_count"] or 0),
                "has_password": bool(str(raw.get("password") or "")),
                "has_sso": bool(str(raw.get("sso") or "")),
                "has_cpa": bool(str(raw.get("cpa_auth_json") or raw.get("cpa_auth_path") or "")),
                "has_grok2api": bool(str(raw.get("grok2api_auth_json") or raw.get("grok2api_auth_path") or "")),
            }
        )
    return {"ok": True, "items": items, "count": len(items), "limit": cap}


def restore_accounts_from_recycle(
    emails: list[str] | None = None,
    *,
    restore_all: bool = False,
    overwrite: bool = False,
) -> dict[str, Any]:
    init_db()
    clean = sorted({str(email or "").strip().lower() for email in (emails or []) if str(email or "").strip()})
    if not clean and not restore_all:
        return {"ok": False, "restored": 0, "error": "未选择回收站账号"}

    now = time.time()
    restored = 0
    overwritten = 0
    skipped_existing = 0
    skipped_invalid = 0
    requested = 0
    restored_emails: list[str] = []
    with _connect() as conn:
        if restore_all:
            recycle_rows = conn.execute(
                "SELECT email, account_json FROM account_recycle_bin ORDER BY deleted_at DESC"
            ).fetchall()
        else:
            placeholders = ",".join("?" for _ in clean)
            recycle_rows = conn.execute(
                f"SELECT email, account_json FROM account_recycle_bin WHERE lower(email) IN ({placeholders})",
                clean,
            ).fetchall()
        requested = len(recycle_rows)
        columns = [str(row["name"]) for row in conn.execute("PRAGMA table_info(accounts)").fetchall()]
        insert_cols = list(columns)
        placeholders = ",".join("?" for _ in insert_cols)
        col_sql = ",".join(insert_cols)
        if overwrite:
            update_cols = [c for c in insert_cols if c != "email"]
            conflict_sql = "DO UPDATE SET " + ", ".join(f"{c}=excluded.{c}" for c in update_cols)
        else:
            conflict_sql = "DO NOTHING"
        sql = f"INSERT INTO accounts({col_sql}) VALUES ({placeholders}) ON CONFLICT(email) {conflict_sql}"

        for row in recycle_rows:
            try:
                raw = json.loads(str(row["account_json"] or "{}"))
            except Exception:
                raw = {}
            if not isinstance(raw, dict):
                skipped_invalid += 1
                continue
            email = str(raw.get("email") or row["email"] or "").strip().lower()
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                skipped_invalid += 1
                continue
            exists = conn.execute("SELECT 1 FROM accounts WHERE lower(email)=? LIMIT 1", (email,)).fetchone()
            if exists and not overwrite:
                skipped_existing += 1
                continue
            record = {key: raw.get(key) for key in insert_cols}
            record["email"] = email
            record["auth_key"] = str(record.get("auth_key") or f"restore::{email}")
            record["status"] = str(record.get("status") or "registered")
            record["created_at"] = float(record.get("created_at") or now)
            record["updated_at"] = now
            if record.get("raw_json") is None:
                record["raw_json"] = json.dumps(
                    {"source": "restore_recycle", "email": email},
                    ensure_ascii=False,
                )
            for key in insert_cols:
                if record.get(key) is None:
                    record[key] = 0 if key in {"created_at", "updated_at", "cpa_pushed", "sub2_pushed", "grok2api_pushed"} else ""
            conn.execute(sql, [record.get(c) for c in insert_cols])
            conn.execute("DELETE FROM account_recycle_bin WHERE lower(email)=?", (email,))
            restored_emails.append(email)
            if exists:
                overwritten += 1
            else:
                restored += 1
    return {
        "ok": True,
        "restored": restored,
        "overwritten": overwritten,
        "skipped_existing": skipped_existing,
        "skipped_invalid": skipped_invalid,
        "requested": requested,
        "emails": restored_emails,
        "overwrite": bool(overwrite),
        "restore_all": bool(restore_all),
    }



def purge_accounts_from_recycle(
    emails: list[str] | None = None,
    *,
    purge_all: bool = False,
) -> dict[str, Any]:
    """Permanently remove soft-deleted accounts from recycle bin."""
    init_db()
    clean = sorted({str(email or "").strip().lower() for email in (emails or []) if str(email or "").strip()})
    if not clean and not purge_all:
        return {"ok": False, "purged": 0, "error": "未选择回收站账号"}
    with _connect() as conn:
        if purge_all:
            cur = conn.execute("DELETE FROM account_recycle_bin")
        else:
            placeholders = ",".join("?" for _ in clean)
            cur = conn.execute(
                f"DELETE FROM account_recycle_bin WHERE lower(email) IN ({placeholders})",
                clean,
            )
        purged = int(cur.rowcount or 0)
    return {
        "ok": True,
        "purged": purged,
        "requested": 0 if purge_all else len(clean),
        "purge_all": bool(purge_all),
    }


def _save_probe_result(email: str, result: dict[str, Any]) -> None:

    # Do not clobber explicit local relogin success status with generic "active".

    status = "active" if result.get("ok") else "probe_failed"

    now = time.time()

    with _connect() as conn:

        if result.get("ok"):

            conn.execute(

                """

                UPDATE accounts

                SET status = CASE

                      WHEN lower(IFNULL(status,'')) = 'relogged' THEN status

                      ELSE ?

                    END,

                    last_probe_json = ?,

                    last_probe_at = ?,

                    updated_at = ?

                WHERE email = ?

                """,

                (status, json.dumps(result, ensure_ascii=False), now, now, email),

            )

        else:

            conn.execute(

                """

                UPDATE accounts

                SET status = ?, last_probe_json = ?, last_probe_at = ?, updated_at = ?

                WHERE email = ?

                """,

                (status, json.dumps(result, ensure_ascii=False), now, now, email),

            )





def _empty_dashboard_stats() -> dict[str, Any]:

    return {

        "ok": True,

        "local_total": 0,

        "remote_total": 0,

        "remote_relogin": 0,

        "remote_failed": 0,

        "remote_only_failures": 0,

        "matched_local": 0,

        "remote_synced_at": None,

        "remote_synced": False,

        "store_source": "sqlite",

        "cached": True,

    }





def _patch_dashboard_stats_after_local_relogin(resolved_count: int, remote_rows_cleared: int) -> None:

    """Adjust cached 需重登 counter after local relogin success — O(1), no JOIN."""

    cached = _json_setting("account_dashboard_stats")

    if not isinstance(cached, dict):

        return

    out = dict(cached)

    out["local_total"] = account_count()

    drop = max(0, int(resolved_count or 0))

    out["remote_relogin"] = max(0, int(out.get("remote_relogin") or 0) - drop)

    # cleared remote rows may also reduce generic failure noise slightly; keep conservative.

    _ = remote_rows_cleared

    out["updated_at"] = time.time()

    out["cached"] = True

    _set_json_setting("account_dashboard_stats", out)





def refresh_account_dashboard_stats() -> dict[str, Any]:

    """Recompute dashboard counters once and persist them.



    Call after remote pull (and optionally after bulk mutations). List endpoints

    must NOT call this on every page load.

    """

    init_db()

    remote_sync = _json_setting("grok2api_last_remote_sync") or {}

    remote_synced_at = float(remote_sync.get("seen_at") or 0) if isinstance(remote_sync, dict) else 0.0

    with _connect() as conn:

        # Ensure index-friendly comparisons; avoid nested MAX(seen_at) subqueries per row.

        conn.execute("CREATE INDEX IF NOT EXISTS idx_remote_accounts_email_seen ON remote_accounts(email, seen_at)")

        local_total = int(conn.execute("SELECT COUNT(*) AS n FROM accounts").fetchone()["n"])

        remote_total = int(conn.execute("SELECT COUNT(*) AS n FROM remote_accounts").fetchone()["n"])

        # Materialize latest remote row per email once.

        conn.execute("DROP TABLE IF EXISTS tmp_remote_latest")

        conn.execute(

            """

            CREATE TEMP TABLE tmp_remote_latest AS

            SELECT r.*

            FROM remote_accounts r

            INNER JOIN (

              SELECT lower(email) AS e, MAX(seen_at) AS max_seen

              FROM remote_accounts

              GROUP BY lower(email)

            ) t ON lower(r.email) = t.e AND r.seen_at = t.max_seen

            """

        )

        conn.execute("CREATE INDEX IF NOT EXISTS idx_tmp_remote_latest_email ON tmp_remote_latest(email)")

        relogin = int(

            conn.execute(

                """

                SELECT COUNT(*) AS n

                FROM accounts a

                JOIN tmp_remote_latest r ON lower(r.email) = lower(a.email)

                WHERE (

                    lower(IFNULL(r.action,'')) LIKE '%relogin%'

                    OR lower(IFNULL(r.classification,'')) IN ('reauth','relogin')

                    OR IFNULL(r.http_status,0) IN (401,403)

                  )

                  AND lower(IFNULL(r.reason,'')) NOT LIKE '%local_relogin_resolved%'

                  AND lower(IFNULL(a.status,'')) != 'relogged'

                """

            ).fetchone()["n"]

        )

        remote_failed = int(

            conn.execute(

                """

                SELECT COUNT(*) AS n

                FROM accounts a

                JOIN tmp_remote_latest r ON lower(r.email) = lower(a.email)

                WHERE (

                    lower(IFNULL(r.action,'')) LIKE '%fail%'

                    OR lower(IFNULL(r.action,'')) LIKE '%error%'

                    OR lower(IFNULL(r.classification,'')) LIKE '%error%'

                    OR (

                      IFNULL(r.http_status,0) >= 400

                      AND IFNULL(r.http_status,0) NOT IN (401,403,429)

                    )

                  )

                  AND lower(IFNULL(r.reason,'')) NOT LIKE '%local_relogin_resolved%'

                """

            ).fetchone()["n"]

        )

        remote_only_failures = int(

            conn.execute(

                """

                SELECT COUNT(*) AS n

                FROM tmp_remote_latest r

                LEFT JOIN accounts a ON lower(a.email) = lower(r.email)

                WHERE a.email IS NULL

                  AND (

                    lower(IFNULL(r.action,'')) != 'keep'

                    OR COALESCE(r.http_status, 200) != 200

                  )

                """

            ).fetchone()["n"]

        )

        matched_local = int(

            conn.execute(

                """

                SELECT COUNT(*) AS n

                FROM accounts a

                JOIN tmp_remote_latest r ON lower(r.email) = lower(a.email)

                """

            ).fetchone()["n"]

        )

        conn.execute("DROP TABLE IF EXISTS tmp_remote_latest")



    stats = {

        "ok": True,

        "local_total": local_total,

        "remote_total": remote_total,

        "remote_relogin": relogin,

        "remote_failed": remote_failed,

        "remote_only_failures": remote_only_failures,

        "matched_local": matched_local,

        "remote_synced_at": remote_synced_at or None,

        "remote_synced": bool(remote_synced_at or remote_total),

        "store_source": "sqlite",

        "cached": True,

        "updated_at": time.time(),

    }

    _set_json_setting("account_dashboard_stats", stats)

    return stats





def get_account_dashboard_stats(*, refresh: bool = False) -> dict[str, Any]:

    """Return dashboard stats.



    Default path is cache-only + cheap local COUNT(*). Heavy recompute only when

    refresh=True or cache is missing.

    """

    if refresh:

        return refresh_account_dashboard_stats()

    cached = _json_setting("account_dashboard_stats")

    if isinstance(cached, dict) and cached.get("ok") is True:

        out = dict(cached)

        # Local total is cheap and should stay live.

        try:

            out["local_total"] = account_count()

        except Exception:

            pass

        out["cached"] = True

        return out

    # First boot / empty cache: compute once.

    return refresh_account_dashboard_stats()





# Back-compat alias used by older call sites.

def account_dashboard_stats() -> dict[str, Any]:

    return get_account_dashboard_stats(refresh=False)





def status() -> dict[str, Any]:

    stats = get_account_dashboard_stats(refresh=False)

    return {

        "account_count": stats.get("local_total") or account_count(),

        "active_count": stats.get("local_total") or account_count(),

        "auth_file": str(AUTH_MAP_DIR),

        "store_source": "sqlite",

        **stats,

    }
