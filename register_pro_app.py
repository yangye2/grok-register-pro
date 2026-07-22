#!/usr/bin/env python3

"""grok-register-pro: registration-only local console.



Protocol registration + SQLite account pool + admin UI.

Does not depend on a full proxy PostgreSQL/Redis stack.

"""



from __future__ import annotations



import base64

import hashlib

import hmac

import json

import os

import signal

import re

import secrets

import time

import asyncio

import subprocess

import threading

import zipfile

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from io import BytesIO

from pathlib import Path

from typing import Any



os.environ.setdefault("GROK_REGISTER_PRO", "1")


os.environ.setdefault("GROK2API_STORE_BACKEND", "file")

os.environ.setdefault("GROK2API_REQUIRE_SHARED_STORES", "0")

os.environ.setdefault("GROK2API_REG_PROBE_DELAY_SEC", "0")



from fastapi import FastAPI, HTTPException, Request

from fastapi.responses import FileResponse, JSONResponse, Response

from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel



import grok_build_adapter as reg_adapter

import register_pro_store as pro_store





ROOT = Path(__file__).resolve().parent

STATIC_DIR = ROOT / "static"

APP_VERSION = "1.2.24"

LOCAL_SOLVER_PORT = 5072

LOCAL_SOLVER_URL = f"http://127.0.0.1:{LOCAL_SOLVER_PORT}"

SESSION_COOKIE = "register_pro_session"

SESSION_MAX_AGE = 7 * 24 * 3600

_local_solver_proc: subprocess.Popen | None = None

_probe_lock = threading.RLock()

_probe_task: dict[str, Any] | None = None

_relogin_lock = threading.RLock()

_relogin_task: dict[str, Any] | None = None



# Durable snapshots so refresh/re-login UI can reconnect to live progress.

_PROBE_TASK_SETTING = "runtime_probe_task"

_RELOGIN_TASK_SETTING = "runtime_relogin_task"

_REG_TASK_SETTING = "runtime_registration_task"

_schedule_stop = threading.Event()

_schedule_thread: threading.Thread | None = None

_schedule_lock = threading.RLock()

_SCHEDULE_TICK_SEC = max(10, int(os.getenv("GROK_REGISTER_SCHEDULE_TICK_SEC", "30") or 30))





def _jsonable_task_snapshot(task: dict[str, Any] | None, *, kind: str) -> dict[str, Any] | None:

    """Strip non-JSON fields (Event/threads) and keep UI-facing progress only."""

    if not isinstance(task, dict):

        return None

    out: dict[str, Any] = {"kind": kind}

    for key in (

        "id",

        "status",

        "done",

        "total",

        "success",

        "failed",

        "cancelled",

        "concurrency",

        "stagger_ms",

        "started_at",

        "finished_at",

        "email",

        "stage",

        "message",

        "error",

        "stopped",

        "sync",

        "result",

        "results",

        "batch_id",

        "session_id",

        "type",

    ):

        if key in task:

            out[key] = task.get(key)

    # Cap result lists so settings row stays small.

    if isinstance(out.get("results"), list):

        out["results"] = out["results"][-50:]

    if isinstance(out.get("result"), dict):

        result = dict(out["result"])

        if isinstance(result.get("results"), list):

            result["results"] = result["results"][-30:]

        out["result"] = result

    out["updated_at"] = time.time()

    return out





def _persist_probe_task(task: dict[str, Any] | None) -> None:

    try:

        snap = _jsonable_task_snapshot(task, kind="probe")

        if snap is None:

            return

        pro_store._set_json_setting(_PROBE_TASK_SETTING, snap)

    except Exception:

        pass





def _persist_relogin_task(task: dict[str, Any] | None) -> None:

    try:

        snap = _jsonable_task_snapshot(task, kind="relogin")

        if snap is None:

            return

        pro_store._set_json_setting(_RELOGIN_TASK_SETTING, snap)

    except Exception:

        pass





def _persist_registration_task(

    *,

    batch_id: str = "",

    session_id: str = "",

    status: str = "running",

) -> None:

    try:

        payload = {

            "kind": "registration",

            "type": "batch" if batch_id else ("session" if session_id else ""),

            "batch_id": str(batch_id or ""),

            "session_id": str(session_id or ""),

            "status": str(status or "running"),

            "updated_at": time.time(),

        }

        pro_store._set_json_setting(_REG_TASK_SETTING, payload)

    except Exception:

        pass





def _load_task_snapshot(key: str) -> dict[str, Any] | None:

    try:

        data = pro_store._json_setting(key)

    except Exception:

        return None

    return data if isinstance(data, dict) else None





def _hydrate_runtime_tasks_from_db() -> None:

    """On process boot, load last known task snapshots for UI reconnect.



    Running workers do not survive restart; mark stale ``running`` snapshots as

    interrupted so the UI does not spin forever.

    """

    global _probe_task, _relogin_task

    now = time.time()

    probe = _load_task_snapshot(_PROBE_TASK_SETTING)

    if probe and not _probe_task:

        if str(probe.get("status") or "") == "running":

            # Process restarted mid-probe — worker is gone.

            probe["status"] = "interrupted"

            probe["error"] = probe.get("error") or "进程重启，探测任务已中断（已完成的测活结果仍保留在账号列表）"

            probe["finished_at"] = probe.get("finished_at") or now

            probe["running"] = False

            try:

                pro_store._set_json_setting(_PROBE_TASK_SETTING, probe)

            except Exception:

                pass

        # Keep completed/interrupted snapshot for status API until next probe.

        _probe_task = {k: v for k, v in probe.items() if k != "kind"}



    relogin = _load_task_snapshot(_RELOGIN_TASK_SETTING)

    if relogin and not _relogin_task:

        if str(relogin.get("status") or "") == "running":

            relogin["status"] = "interrupted"

            relogin["error"] = relogin.get("error") or "进程重启，重登任务已中断（已成功重登的账号仍保留）"

            relogin["finished_at"] = relogin.get("finished_at") or now

            relogin["running"] = False

            try:

                pro_store._set_json_setting(_RELOGIN_TASK_SETTING, relogin)

            except Exception:

                pass

        _relogin_task = {k: v for k, v in relogin.items() if k != "kind"}



    reg = _load_task_snapshot(_REG_TASK_SETTING)

    if reg and str(reg.get("status") or "") == "running":

        # Registration threads also die on restart; mark pointer interrupted.

        reg["status"] = "interrupted"

        reg["updated_at"] = now

        try:

            pro_store._set_json_setting(_REG_TASK_SETTING, reg)

        except Exception:

            pass





def _env_flag(name: str, default: bool = False) -> bool:

    raw = os.getenv(name)

    if raw is None:

        return default

    return str(raw).strip().lower() in {"1", "true", "yes", "on"}





def _normalize_admin_base_path(raw: str | None) -> str:

    """Return admin URL prefix without trailing slash. Default: /admin.



    Examples:

      "" / "/" / "admin"  -> "/admin"

      "panel"             -> "/panel"

      "/my/console/"      -> "/my/console"

    """

    text = str(raw or "").strip()

    if not text or text == "/":

        return "/admin"

    if not text.startswith("/"):

        text = "/" + text

    text = re.sub(r"/+", "/", text).rstrip("/")

    # Keep path segment-ish; drop query/fragment characters.

    text = re.sub(r"[^A-Za-z0-9_./-]+", "", text)

    text = re.sub(r"/+", "/", text).rstrip("/")

    if not text or text == "/":

        return "/admin"

    # Never collide with static mount.

    if text == "/static" or text.startswith("/static/"):

        return "/admin"

    return text





# Configurable management path (hide default /admin on public servers).

ADMIN_BASE_PATH = _normalize_admin_base_path(

    os.getenv("GROK_REGISTER_ADMIN_BASE_PATH")

    or os.getenv("ADMIN_BASE_PATH")

    or "/admin"

)





def _admin_path(*parts: str) -> str:

    """Join ADMIN_BASE_PATH with sub-paths: _admin_path('api','session') -> /admin/api/session."""

    base = ADMIN_BASE_PATH.rstrip("/")

    segs = [str(p).strip("/") for p in parts if str(p).strip("/")]

    if not segs:

        return base or "/admin"

    return base + "/" + "/".join(segs)





def _cookie_secure() -> bool:

    """Prefer Secure cookies. Auto-on under HTTPS proxy; override with COOKIE_SECURE."""

    explicit = os.getenv("COOKIE_SECURE")

    if explicit is not None and str(explicit).strip() != "":

        return _env_flag("COOKIE_SECURE", True)

    # Common reverse-proxy / TLS termination signals.

    if _env_flag("HTTPS", False):

        return True

    if str(os.getenv("GROK_REGISTER_PRO_TLS", "")).strip().lower() in {"1", "true", "yes", "on"}:

        return True

    # Default False for local http://127.0.0.1 development so browsers still store cookie.

    return False





def _client_ip(request: Request) -> str:

    # Prefer direct peer; only trust X-Forwarded-For when explicitly enabled.

    if _env_flag("GROK_REGISTER_TRUST_X_FORWARDED_FOR", False):

        xff = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()

        if xff:

            return xff

    if request.client and request.client.host:

        return str(request.client.host)

    return ""





def _is_loopback_ip(ip: str) -> bool:

    host = (ip or "").strip().lower()

    if not host:

        return False

    if host in {"127.0.0.1", "::1", "localhost", "0:0:0:0:0:0:0:1"}:

        return True

    # IPv6-mapped IPv4 loopback

    if host.startswith("::ffff:127."):

        return True

    return host.startswith("127.")





def _setup_allowed(request: Request) -> bool:

    """First-time admin password setup: loopback only unless explicitly allowed."""

    if _env_flag("GROK_REGISTER_ALLOW_REMOTE_SETUP", False):

        return True

    return _is_loopback_ip(_client_ip(request))





def _set_session_cookie(res: Response, token: str) -> None:

    res.set_cookie(

        SESSION_COOKIE,

        token,

        max_age=SESSION_MAX_AGE,

        httponly=True,

        samesite="lax",

        secure=_cookie_secure(),

        path="/",

    )





app = FastAPI(title="grok-register-pro")

if STATIC_DIR.is_dir():

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")





# Public (no-auth) paths. API routes still under ADMIN_BASE_PATH.

PUBLIC_PATHS = {

    "/",

    ADMIN_BASE_PATH,

    ADMIN_BASE_PATH + "/",

    _admin_path("accounts"),

    _admin_path("accounts") + "/",

    _admin_path("api", "session"),

    _admin_path("api", "auth", "login"),

    # Retired endpoints remain public only so they correctly return 404.

    "/health",

    _admin_path("api", "status"),

}





class RegistrationBody(BaseModel):

    provider: str | None = None

    mail_provider: str | None = None

    protocol: str | None = "grpc"

    email: str | None = None

    mailbox_id: str | None = None

    prefix: str | None = None

    domain: str | None = None

    expiry_ms: int | None = None

    api_key: str | None = None

    moemail_api_key: str | None = None

    yyds_api_key: str | None = None

    gptmail_api_key: str | None = None

    cfmail_api_key: str | None = None

    duckmail_api_key: str | None = None

    outmail_api_key: str | None = None

    outmail_session_cookie: str | None = None

    outmail_api_base: str | None = None

    outmail_proxy: str | None = None

    outmail_plus_alias: bool | None = None

    outmail_plus_alias_count: int | None = None

    outmail_alias_suffix_len: int | None = None

    outmail_fetch_top: int | None = None

    outmail_poll_interval_sec: int | None = None

    outmail_poll_timeout_sec: int | None = None

    outmail_since_padding_sec: int | None = None

    outmail_from_filter: str | None = None

    outmail_subject_filter: str | None = None

    outmail_group_id: str | None = None

    outmail_anonymous_enabled: bool | None = None

    outmail_anonymous_provider: str | None = None

    outmail_anonymous_domain: str | None = None

    outmail_anonymous_username_prefix: str | None = None

    outmail_anonymous_password: str | None = None

    outmail_anonymous_delete_after: bool | None = None

    outmail_exclude_used: bool | None = None

    outmail_used_file: str | None = None

    moemail_domain: str | None = None

    yyds_domain: str | None = None

    gptmail_domain: str | None = None

    cfmail_domain: str | None = None

    duckmail_domain: str | None = None

    captcha_provider: str | None = None

    local_solver_url: str | None = None

    yescaptcha_key: str | None = None

    base_url: str | None = None

    moemail_base_url: str | None = None

    cfmail_base_url: str | None = None

    duckmail_base_url: str | None = None

    proxy: str | None = None

    proxy_username: str | None = None

    proxy_password: str | None = None

    proxy_strategy: str | None = None

    count: int | None = None

    concurrency: int | None = None

    stagger_ms: int | None = None

    probe_delay_sec: int | None = None

    # Skip post-register model probe; keep credentials as status=registered.

    skip_probe: bool | None = None

    # Stop after SSO cookie; skip device-flow conversion to Grok2API/CPA auth.

    sso_only: bool | None = None

    # Cross-batch global simultaneous registration cap (1..64).

    global_inflight: int | None = None

    # Local Camoufox captcha concurrency: 1=serial, 2~8 multi-open.

    captcha_concurrency: int | None = None

    power_mode: bool | None = None

    # When true, Turnstile browser uses the same proxy as the registration job.

    captcha_use_proxy: bool | None = None





class ExportSsoBody(BaseModel):

    batch_id: str | None = None

    status: list[str] | None = None

    emails: list[str] | None = None

    include_password: bool = False

    format: str = "sso"

    download: bool = True





class ExportAccountsBody(BaseModel):
    """Export selected accounts as txt: email----password----sso."""
    emails: list[str] | None = None
    # When true (default), emails must be non-empty. When false, export all.
    require_selected: bool = True



class ExportAuthZipBody(BaseModel):

    """Export Auth / CPA zip. When ``emails`` is non-empty, only those accounts."""

    emails: list[str] | None = None

    limit: int = 5000





class ConvertSsoBody(BaseModel):

    """Convert selected SSO-only accounts into Grok2API/CPA auth via device-flow."""

    emails: list[str]

    concurrency: int = 2

    force: bool = False





class ProbeBody(BaseModel):

    email: str | None = None

    account_id: str | None = None

    emails: list[str] | None = None

    model: str = "grok-4.5"

    limit: int = 20

    concurrency: int = 2

    cooldown_ms: int = 1000





class DeleteAccountsBody(BaseModel):

    emails: list[str]


class RestoreAccountsBackupBody(BaseModel):

    backup_path: str | None = None

    overwrite: bool = False


class RestoreRecycleBody(BaseModel):

    emails: list[str] | None = None

    restore_all: bool = False

    overwrite: bool = False


class PurgeRecycleBody(BaseModel):

    emails: list[str] | None = None

    purge_all: bool = False





class SelectedAccountsBody(BaseModel):

    emails: list[str]





class ReloginBody(BaseModel):

    emails: list[str]

    concurrency: int | None = None





class ReloginConfigBody(BaseModel):

    concurrency: int | None = None

    stagger_ms: int | None = None

    captcha_provider: str | None = None

    yescaptcha_key: str | None = None

    proxy: str | None = None

    proxy_username: str | None = None

    proxy_password: str | None = None

    proxy_strategy: str | None = None

    use_registration_proxy_fallback: bool | None = None

    use_registration_captcha_fallback: bool | None = None

    probe_model: str | None = None





class SchedulePolicyBody(BaseModel):

    enabled: bool | None = None

    interval_min: int | None = None

    batch_count: int | None = None

    window_start_hour: int | None = None

    window_end_hour: int | None = None

    skip_if_running: bool | None = None

    fallback_enabled: bool | None = None

    rotate_proxy_on_fail: bool | None = None

    rotate_domain_on_fail: bool | None = None

    rotate_mail_provider_on_fail: bool | None = None

    fail_threshold: int | None = None

    fail_window_sec: int | None = None

    min_concurrency: int | None = None

    min_global_inflight: int | None = None

    min_probe_delay_sec: int | None = None

    concurrency_step_down: int | None = None

    global_inflight_step_down: int | None = None

    probe_delay_step_up: int | None = None

    sys_guard_enabled: bool | None = None

    cpu_high_pct: int | None = None

    mem_high_pct: int | None = None

    cpu_critical_pct: int | None = None

    mem_critical_pct: int | None = None

    throttle_cooldown_sec: int | None = None

    recover_after_sec: int | None = None

    recover_step_up: int | None = None





class Grok2ApiConfigBody(BaseModel):

    base_url: str | None = None

    username: str | None = None

    password: str | None = None

    upload_mode: str | None = None

    limit: int | None = None

    upload_batch_size: int | None = None

    auto_upload_after_probe: bool | None = None

    auto_upload_after_relogin: bool | None = None







class Grok2ApiUploadBody(BaseModel):

    mode: str = "build_auth_files"

    limit: int = 1000

    emails: list[str] | None = None





class CpaConfigBody(BaseModel):

    base_url: str | None = None

    management_key: str | None = None

    limit: int | None = None

    auto_upload_after_probe: bool | None = None

    auto_upload_after_relogin: bool | None = None







class CpaUploadBody(BaseModel):

    limit: int = 1000

    emails: list[str] | None = None





class Sub2ApiConfigBody(BaseModel):

    api_base: str | None = None

    api_key: str | None = None

    upload_enabled: bool | None = None

    auto_upload_after_probe: bool | None = None

    auto_upload_after_relogin: bool | None = None

    timeout: int | None = None

    retries: int | None = None

    platform: str | None = None

    account_type: str | None = None

    account_concurrency: int | None = None

    account_priority: int | None = None

    account_load_factor: int | None = None

    account_rate_multiplier: float | None = None

    account_group_ids: str | None = None

    default_proxy: str | None = None

    local_export: bool | None = None

    local_export_dir: str | None = None

    limit: int | None = None





class Sub2ApiUploadBody(BaseModel):

    limit: int = 1000

    emails: list[str] | None = None

    skip_already_pushed: bool = True





class Grok2ApiRemoteStatusBody(BaseModel):

    providers: list[str] | str | None = None

    page_size: int = 200

    # problems = only reauth/waiting/disabled (default, fast)

    # full = mirror entire remote inventory (slow)

    mode: str = "problems"

    # Optional override; empty = use exclusive remote_backend switch.

    backend: str | None = None





class RemoteBackendBody(BaseModel):

    backend: str | None = None





class LocalSolverStartBody(BaseModel):

    thread: int = 1

    browser_type: str = "camoufox"





class LoginBody(BaseModel):

    password: str





class ChangePasswordBody(BaseModel):

    current_password: str

    new_password: str





def _b64_json(data: dict[str, Any]) -> str:

    raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")





def _unb64_json(data: str) -> dict[str, Any]:

    padded = data + "=" * (-len(data) % 4)

    raw = base64.urlsafe_b64decode(padded.encode("ascii"))

    parsed = json.loads(raw.decode("utf-8"))

    return parsed if isinstance(parsed, dict) else {}





def _session_signature(payload: str) -> str:

    secret = pro_store.admin_session_secret().encode("utf-8")

    return hmac.new(secret, payload.encode("ascii"), hashlib.sha256).hexdigest()





def _create_session_token() -> str:

    # Bind cookie to current password_version so password change / secret rotate

    # invalidates every outstanding session immediately.

    payload = _b64_json(

        {

            "iat": int(time.time()),

            "nonce": secrets.token_urlsafe(18),

            "pv": int(pro_store.admin_password_version()),

        }

    )

    return payload + "." + _session_signature(payload)





def _valid_session_token(token: str) -> bool:

    try:

        payload, sig = token.split(".", 1)

        if not hmac.compare_digest(_session_signature(payload), sig):

            return False

        data = _unb64_json(payload)

        iat = int(data.get("iat") or 0)

        pv = int(data.get("pv") or 0)

    except Exception:  # noqa: BLE001

        return False

    if not (0 < iat <= int(time.time()) and int(time.time()) - iat <= SESSION_MAX_AGE):

        return False

    # Reject cookies issued before the latest password change.

    if pv != int(pro_store.admin_password_version()):

        return False

    return True





def _is_authenticated(request: Request) -> bool:

    return _valid_session_token(request.cookies.get(SESSION_COOKIE, ""))





def _auth_required(path: str) -> bool:

    if path.startswith("/static/"):

        return False

    # Only enforce auth under the configured admin base.

    # Unknown paths fall through to FastAPI 404 instead of fake 401.

    p = path or ""

    base = (ADMIN_BASE_PATH or "/admin").rstrip("/") or "/admin"

    if p == base or p.startswith(base + "/"):

        return p not in PUBLIC_PATHS

    return False





@app.middleware("http")

async def require_admin_session(request: Request, call_next):

    if _auth_required(request.url.path) and not _is_authenticated(request):

        return Response(

            json.dumps({"ok": False, "authenticated": False, "detail": "请先登录"}, ensure_ascii=False),

            status_code=401,

            media_type="application/json; charset=utf-8",

        )

    return await call_next(request)





@app.on_event("startup")

async def _startup_security_bootstrap() -> None:

    """Optional env bootstrap + ensure DB ready before first request."""

    try:

        pro_store.init_db()

    except Exception as exc:  # noqa: BLE001

        print(f"[register-pro] init_db failed: {exc}")

    try:

        result = pro_store.maybe_bootstrap_admin_password()

        if result.get("reset"):

            print("[register-pro] admin password FORCE-RESET from env (all sessions rotated)")

        elif result.get("bootstrapped"):

            print("[register-pro] admin password bootstrapped from env (sessions rotated)")

        print(f"[register-pro] admin base path: {ADMIN_BASE_PATH}")

    except Exception as exc:  # noqa: BLE001

        print(f"[register-pro] admin bootstrap skipped/failed: {exc}")

    try:

        _hydrate_runtime_tasks_from_db()

        print("[register-pro] runtime task snapshots hydrated")

    except Exception as exc:  # noqa: BLE001

        print(f"[register-pro] runtime task hydrate skipped/failed: {exc}")

    try:

        # After container restart, mark stale in-memory-style running batches terminal

        # so the UI and schedule do not think a dead batch is still active.

        reclaimed = reg_adapter.reclaim_orphaned_registration_batches()

        if reclaimed:

            print(f"[register-pro] reclaimed orphaned registration state: {reclaimed}")

    except Exception as exc:  # noqa: BLE001

        print(f"[register-pro] orphan reclaim skipped/failed: {exc}")

    try:

        reg_cfg = pro_store.get_registration_config(include_secrets=False)

        applied = reg_adapter.set_global_reg_inflight_limit(reg_cfg.get("global_inflight"))

        cap = reg_adapter.set_local_captcha_concurrency(reg_cfg.get("captcha_concurrency"))

        os.environ["TURNSTILE_THREAD"] = str(cap)

        print(f"[register-pro] global_inflight limit={applied} captcha_concurrency={cap} TURNSTILE_THREAD={cap}")

    except Exception as exc:  # noqa: BLE001

        print(f"[register-pro] global_inflight apply skipped/failed: {exc}")

    try:

        _start_schedule_loop()

        print(f"[register-pro] schedule loop started (tick={_SCHEDULE_TICK_SEC}s)")

    except Exception as exc:  # noqa: BLE001

        print(f"[register-pro] schedule loop start failed: {exc}")

    # When this process is container PID 1 (no docker init/tini), orphaned

    # Camoufox children become our zombies. Reap them periodically.

    try:

        _start_zombie_reaper_loop()

        print("[register-pro] zombie reaper loop started")

    except Exception as exc:  # noqa: BLE001

        print(f"[register-pro] zombie reaper start failed: {exc}")





_zombie_reaper_started = False





def _reap_zombie_children(limit: int = 512) -> int:

    """Non-blocking waitpid loop. Only reaps direct children of this process."""

    reaped = 0

    for _ in range(max(1, int(limit))):

        try:

            pid, _status = os.waitpid(-1, os.WNOHANG)

        except ChildProcessError:

            break

        except Exception:

            break

        if pid <= 0:

            break

        reaped += 1

    return reaped





def _count_zombie_processes() -> int:

    """Count zombie processes visible under /proc (Linux/container)."""

    n = 0

    try:

        for name in os.listdir("/proc"):

            if not name.isdigit():

                continue

            try:

                with open(f"/proc/{name}/stat", "r", encoding="utf-8", errors="ignore") as fh:

                    stat = fh.read()

                rp = stat.rfind(")")

                if rp < 0:

                    continue

                parts = stat[rp + 2 :].split()

                if parts and parts[0] == "Z":

                    n += 1

            except Exception:

                continue

    except Exception:

        return 0

    return n





def _start_zombie_reaper_loop() -> None:

    """Background thread: reap orphaned Camoufox/Playwright zombies.



    Needed when this process inherits browser children after driver disconnect,

    or when running without an init process (non-Docker local start). Docker

    images bake tini as PID1; this loop is belt-and-suspenders for the app PID.

    """

    global _zombie_reaper_started

    if _zombie_reaper_started:

        return

    _zombie_reaper_started = True



    def _loop() -> None:

        last_log = 0.0

        while True:

            try:

                reaped = _reap_zombie_children()

                zombies = _count_zombie_processes()

                now = time.time()

                # Log only when something interesting happens, throttle to 60s.

                if (reaped or zombies) and (now - last_log) >= 60.0:

                    print(

                        f"[register-pro] zombie reaper: reaped={reaped} "

                        f"zombies_visible={zombies} pid={os.getpid()} "

                        f"is_pid1={os.getpid() == 1}"

                    )

                    last_log = now

            except Exception as exc:  # noqa: BLE001

                print(f"[register-pro] zombie reaper error: {exc}")

            time.sleep(5.0)



    t = threading.Thread(target=_loop, name="zombie-reaper", daemon=True)

    t.start()





def _start_scheduled_registration(**kwargs: Any) -> dict[str, Any]:

    """Adapter wrapper used by the schedule tick (sync, no preflight HTTP).



    Align with the admin UI start path: prepare admission + captcha pool size,

    ensure the inline Turnstile solver is up, then hand off to the adapter.

    """

    # Drop unknown keys defensively.

    allowed = {

        "proxy",

        "proxy_username",

        "proxy_password",

        "proxy_strategy",

        "moemail_api_key",

        "moemail_base_url",

        "prefix",

        "domain",

        "expiry_ms",

        "mail_provider",

        "captcha_provider",

        "local_solver_url",

        "yescaptcha_key",

        "count",

        "concurrency",

        "stagger_ms",

        "probe_delay_sec",

        "skip_probe",

        "sso_only",

        "captcha_use_proxy",

        "captcha_concurrency",

        "global_inflight",

    }

    clean = {k: v for k, v in kwargs.items() if k in allowed}

    clean.setdefault("captcha_provider", "local")

    clean.setdefault("local_solver_url", LOCAL_SOLVER_URL)

    clean.setdefault("yescaptcha_key", "")

    # Prepare runtime the same way as POST .../register-email (without live mailbox preflight).

    try:

        reg_cfg = pro_store.get_registration_config(include_secrets=False)

        inflight = clean.pop("global_inflight", None)

        if inflight is None:

            inflight = reg_cfg.get("global_inflight")

        cap = clean.pop("captcha_concurrency", None)

        if cap is None:

            cap = reg_cfg.get("captcha_concurrency")

        reg_adapter.set_global_reg_inflight_limit(inflight)

        reg_adapter.set_local_captcha_concurrency(cap)

        if hasattr(reg_adapter, "clear_reg_soft_pause"):

            reg_adapter.clear_reg_soft_pause()

        _ensure_solver_threads(cap, force_restart=False)

    except Exception as exc:  # noqa: BLE001

        print(f"[register-pro] schedule prepare admission/solver failed: {exc}")

    result = reg_adapter.start_registration(**clean)

    if result.get("ok"):

        try:

            _persist_registration_task(

                batch_id=str(result.get("batch_id") or result.get("id") or ""),

                session_id="" if result.get("batch_id") else str(result.get("id") or ""),

                status=str(result.get("status") or "running"),

            )

        except Exception:

            pass

    return result





def _schedule_loop() -> None:

    """Background ticker: system guard + optional auto registration."""

    # Small startup delay so DB/bootstrap settles first.

    if _schedule_stop.wait(5.0):

        return

    while not _schedule_stop.is_set():

        try:

            with _schedule_lock:

                out = pro_store.evaluate_schedule_tick(start_fn=_start_scheduled_registration, force=False)

            if out.get("started"):

                print(f"[register-pro] schedule started batch={out.get('batch_id')}")

            elif out.get("skipped") and out.get("skipped") not in {"disabled", "interval", "outside_window"}:

                # Log interesting skips only (critical / already_running / errors).

                print(f"[register-pro] schedule tick skip={out.get('skipped')} err={out.get('error') or ''}")

        except Exception as exc:  # noqa: BLE001

            print(f"[register-pro] schedule tick error: {exc}")

        if _schedule_stop.wait(_SCHEDULE_TICK_SEC):

            break





def _start_schedule_loop() -> None:

    global _schedule_thread

    if _schedule_thread and _schedule_thread.is_alive():

        return

    _schedule_stop.clear()

    _schedule_thread = threading.Thread(target=_schedule_loop, name="schedule-loop", daemon=True)

    _schedule_thread.start()





def _registration_cfg_from_body(body: RegistrationBody) -> dict[str, Any]:

    data = body.model_dump(exclude_none=False)

    if not data.get("mail_provider"):

        data["mail_provider"] = data.get("provider")

    return data





def _clean_emails(emails: list[str] | None) -> list[str]:

    return sorted({str(email or "").strip().lower() for email in (emails or []) if str(email or "").strip()})





def _probe_task_view(task: dict[str, Any] | None) -> dict[str, Any]:

    if not task:

        return {"ok": True, "running": False, "status": "idle"}

    result = task.get("result") if isinstance(task.get("result"), dict) else None

    return {

        "ok": True,

        "id": task.get("id"),

        "running": task.get("status") == "running",

        "status": task.get("status"),

        "done": int(task.get("done") or 0),

        "total": int(task.get("total") or 0),

        "success": int(task.get("success") or 0),

        "started_at": task.get("started_at"),

        "finished_at": task.get("finished_at"),

        "result": result,

        "error": task.get("error"),

    }





def _start_probe_task(body: ProbeBody) -> dict[str, Any]:

    global _probe_task

    with _probe_lock:

        if _probe_task and _probe_task.get("status") == "running":

            raise HTTPException(status_code=409, detail="已有探测任务正在运行")

        emails = _clean_emails(body.emails)

        if body.email or body.account_id:

            emails = _clean_emails([body.email or body.account_id or ""])

        total = len(emails) if emails else max(1, min(200, int(body.limit or 20)))

        task = {

            "id": "probe_" + secrets.token_hex(6),

            "status": "running",

            "stop": threading.Event(),

            "done": 0,

            "total": total,

            "success": 0,

            "started_at": time.time(),

        }

        _probe_task = task



    def progress(data: dict[str, Any]) -> None:

        with _probe_lock:

            task["done"] = int(data.get("done") or 0)

            task["total"] = int(data.get("total") or task["total"])

            task["success"] = int(data.get("ok") or 0)

            _persist_probe_task(task)



    def run() -> None:

        try:

            kwargs = {

                "model": body.model,

                "concurrency": body.concurrency,

                "cooldown_ms": body.cooldown_ms,

                "should_stop": task["stop"].is_set,

                "on_progress": progress,

            }

            result = (

                pro_store.probe_account_list(emails, **kwargs)

                if emails

                else pro_store.probe_accounts(limit=body.limit, **kwargs)

            )

            with _probe_lock:

                task["result"] = result

                task["done"] = int(result.get("count") or 0)

                task["total"] = int(result.get("requested") or task["total"])

                task["success"] = int(result.get("ok") or 0)

                task["status"] = "stopped" if result.get("stopped") else "completed"

                task["finished_at"] = time.time()

                _persist_probe_task(task)

        except Exception as exc:  # noqa: BLE001

            with _probe_lock:

                task["status"] = "failed"

                task["error"] = str(exc)

                task["finished_at"] = time.time()

                _persist_probe_task(task)



    threading.Thread(target=run, name=task["id"], daemon=True).start()

    _persist_probe_task(task)

    return _probe_task_view(task)





class _ReloginCancelled(Exception):

    """Raised when a relogin worker should abort because the batch was stopped."""





def _relogin_one_account(

    email: str,

    *,

    idx: int,

    record: dict[str, Any],

    cfg: dict[str, Any],

    default_proxy: str,

    emit,

    should_stop=None,

) -> dict[str, Any]:

    """Re-login one account: captcha → password login → write creds → probe → optional auto-upload."""



    def stop_requested() -> bool:

        return bool(callable(should_stop) and should_stop())



    def check_stop(stage: str = "") -> None:

        if stop_requested():

            raise _ReloginCancelled(stage or "已停止")



    if stop_requested():

        return {"email": email, "ok": False, "error": "已停止（未开始）", "cancelled": True}

    if not record or not record.get("password"):

        return {"email": email, "ok": False, "error": "本地没有账号密码"}



    password = str(record.get("password") or "")

    # Guard: imported mailbox JWT / email-token was historically written into

    # accounts.password. CreateSession then returns invalid-credentials and

    # looks like a "protocol bug". Fail fast with an actionable message.

    if not pro_store.is_plausible_account_password(password):

        if pro_store.looks_like_jwt(password):

            return {

                "email": email,

                "ok": False,

                "error": (

                    "本地 password 字段不是 xAI 密码，而是邮箱 JWT/地址 token"

                    "（导入格式错：把邮箱 token 写进了密码列）。"

                    "请用 email:真实密码 重新导入后再重登；协议 CreateSession 已通到鉴权层。"

                ),

            }

        return {

            "email": email,

            "ok": False,

            "error": f"本地密码形态异常（len={len(password)}），无法用于密码协议登录",

        }



    # Snapshot for rollback if probe fails after overwriting credentials.

    snapshot = dict(record)

    proxy = default_proxy

    strategy = str(cfg.get("proxy_strategy") or "round_robin")

    probe_model = str(cfg.get("probe_model") or "grok-4.5")

    wrote_credentials = False

    try:

        check_stop("派发前")

        # Rotate proxy per account when pool has multiple entries.

        try:

            from proxy_pool import parse_proxy_pool, pick_proxy



            pool = parse_proxy_pool(

                str(cfg.get("proxy") or ""),

                username=str(cfg.get("proxy_username") or "") or None,

                password=str(cfg.get("proxy_password") or "") or None,

                fallback_env=True,

            )

            proxy = pick_proxy(pool, strategy=strategy, index=idx) or proxy

        except Exception:

            pass



        def progress_with_stop(message: str, current: str = email) -> None:

            if stop_requested():

                raise _ReloginCancelled(str(message or "已停止"))

            emit("stage", email=current, message=message)



        check_stop("过盾前")

        fresh = reg_adapter.relogin_with_password(

            email=email,

            password=password,

            captcha_provider=str(cfg.get("captcha_provider") or "local"),

            yescaptcha_key=str(cfg.get("yescaptcha_key") or ""),

            local_solver_url=str(cfg.get("local_solver_url") or LOCAL_SOLVER_URL),

            proxy=proxy,

            on_progress=progress_with_stop,

        )

        check_stop("登录后")



        # Once we have new SSO/token material, always persist it.

        # Only stages before this (no fresh credentials) leave the DB untouched.

        access = str(fresh.get("access_token") or "").strip()

        sso = str(fresh.get("sso") or "").strip()

        if not access and not sso:

            return {

                "email": email,

                "ok": False,

                "error": "登录未返回新凭证（无 access_token / SSO），未改写数据库",

                "rolled_back": False,

            }



        emit("stage", email=email, message="已拿到新凭证，正在写入数据库")

        imported = pro_store.import_auth_payload(

            {

                "key": access or record.get("access_token") or "",

                "email": email,

                "registration_password": password,

                "sso": sso or record.get("sso") or "",

                "refresh_token": fresh.get("refresh_token") or "",

                "id_token": fresh.get("id_token") or "",

                "expires_at": fresh.get("expires_at") or "",

                "oidc_issuer": fresh.get("oidc_issuer") or "",

                "oidc_client_id": fresh.get("oidc_client_id") or "",

            },

            merge=True,

        )

        if not imported.get("ok"):

            raise RuntimeError(str(imported.get("error") or "凭证写入失败"))

        wrote_credentials = True



        # Probe is a separate stage: failure keeps the newly written credentials.

        check_stop("测活前")

        emit("stage", email=email, message="新凭证已写入，正在测活")

        if access:

            probe = pro_store.probe_access_token(

                access,

                email=email,

                model=probe_model,

                proxy=proxy or None,

                persist=True,

            )

        else:

            # SSO-only write without access token: probe via account row if possible.

            probe = pro_store.probe_account(email, model=probe_model)



        if not probe.get("ok"):

            err = str(probe.get("error") or "测活未通过")

            return {

                "email": email,

                "ok": False,

                "error": f"测活未通过，但新凭证已写入：{err[:200]}",

                "probe": probe,

                "wrote_credentials": True,

                "status": "probe_failed",

            }



        # Full success: status=relogged + clear stale remote 需重登 until next pull.

        try:

            pro_store.mark_local_relogin_resolved(email)

        except Exception:

            pass

        return {

            "email": email,

            "ok": True,

            "probe": probe,

            "wrote_credentials": True,

            "status": "relogged",

        }

    except _ReloginCancelled as exc:

        # Credentials already written: keep them. Cancel only aborts remaining stages.

        stage = str(exc) or "已停止"

        if wrote_credentials:

            return {

                "email": email,

                "ok": False,

                "error": f"已停止（{stage}），新凭证已写入",

                "cancelled": True,

                "wrote_credentials": True,

            }

        return {

            "email": email,

            "ok": False,

            "error": f"已停止（{stage}）",

            "cancelled": True,

        }

    except Exception as exc:  # noqa: BLE001

        # Never roll back after a successful new-credential write.

        # Pre-write failures leave the DB untouched automatically.

        msg = str(exc)

        if "已停止" in msg or isinstance(exc, _ReloginCancelled):

            return {

                "email": email,

                "ok": False,

                "error": (msg[:300] + ("，新凭证已写入" if wrote_credentials else "")),

                "cancelled": True,

                "wrote_credentials": wrote_credentials,

            }

        return {

            "email": email,

            "ok": False,

            "error": msg[:300] + ("（新凭证已写入）" if wrote_credentials else ""),

            "wrote_credentials": wrote_credentials,

        }





def _relogin_selected_accounts(

    emails: list[str],

    *,

    concurrency: int = 2,

    stagger_ms: int = 0,

    should_stop=None,

    on_progress=None,

) -> dict[str, Any]:

    clean = _clean_emails(emails)

    if not clean:

        raise ValueError("未选择账号")

    cfg = pro_store.resolve_relogin_runtime_config()

    credentials = {item["email"].lower(): item for item in pro_store.account_credentials(clean)}

    proxy = ""

    try:

        from proxy_pool import parse_proxy_pool, pick_proxy



        pool = parse_proxy_pool(

            str(cfg.get("proxy") or ""),

            username=str(cfg.get("proxy_username") or "") or None,

            password=str(cfg.get("proxy_password") or "") or None,

            fallback_env=True,

        )

        # Prefer configured strategy across the pool for multi-account relogin.

        proxy = pick_proxy(pool, strategy=str(cfg.get("proxy_strategy") or "round_robin"), index=0) or ""

    except Exception as exc:  # noqa: BLE001

        raise RuntimeError(f"代理池解析失败: {exc}") from exc



    workers = max(1, min(10, int(concurrency or cfg.get("concurrency") or 2), len(clean)))

    # Local captcha is serialized under a process lock. High worker counts only

    # queue on that lock and burn turnstile tokens; keep effective workers low.

    if str(cfg.get("captcha_provider") or "local").strip().lower() == "local":

        workers = min(workers, 2)

    stagger = max(0.0, min(60.0, float(stagger_ms if stagger_ms is not None else cfg.get("stagger_ms") or 0) / 1000.0))

    # Local mode benefits from a little stagger even if user left it at 0.

    if str(cfg.get("captcha_provider") or "local").strip().lower() == "local" and stagger < 0.2:

        stagger = 0.2

    results: list[dict[str, Any]] = []

    results_lock = threading.Lock()

    stopped = False

    cancelled = 0



    def stop_requested() -> bool:

        return bool(callable(should_stop) and should_stop())



    def emit(kind: str, **data: Any) -> None:

        if callable(on_progress):

            on_progress({"kind": kind, **data})



    def record_result(item: dict[str, Any]) -> None:

        nonlocal cancelled

        with results_lock:

            results.append(item)

            if item.get("cancelled"):

                cancelled += 1

            snapshot = list(results)

        emit("result", results=snapshot)



    def cancel_pending(futures: dict[Any, str]) -> None:

        """Cancel futures that have not started; mark the rest as cooperative-stop."""

        pending = list(futures.items())

        for fut, email in pending:

            if fut.cancel():

                futures.pop(fut, None)

                record_result({"email": email, "ok": False, "error": "已停止（未开始）", "cancelled": True})



    with ThreadPoolExecutor(max_workers=workers) as executor:

        futures: dict[Any, str] = {}

        next_index = 0

        last_started = 0.0

        while next_index < len(clean) or futures:

            if stop_requested():

                stopped = True

                # Do not submit anything else; drop queued work immediately.

                cancel_pending(futures)

                # Still drain already-running workers (they check should_stop).

                if not futures:

                    # Mark remaining unscheduled emails as cancelled so progress is honest.

                    while next_index < len(clean):

                        email = clean[next_index]

                        next_index += 1

                        record_result(

                            {"email": email, "ok": False, "error": "已停止（未开始）", "cancelled": True}

                        )

                    break



            while (not stopped) and next_index < len(clean) and len(futures) < workers:

                if stop_requested():

                    stopped = True

                    break

                if stagger > 0 and last_started:

                    remaining_wait = stagger - (time.monotonic() - last_started)

                    while remaining_wait > 0:

                        if stop_requested():

                            stopped = True

                            break

                        time.sleep(min(0.05, remaining_wait))

                        remaining_wait = stagger - (time.monotonic() - last_started)

                    if stopped:

                        break

                email = clean[next_index]

                idx = next_index

                next_index += 1

                record = credentials.get(email) or {}

                fut = executor.submit(

                    _relogin_one_account,

                    email,

                    idx=idx,

                    record=record,

                    cfg=cfg,

                    default_proxy=proxy,

                    emit=emit,

                    should_stop=should_stop,

                )

                futures[fut] = email

                last_started = time.monotonic()



            if stopped:

                cancel_pending(futures)

                # Mark remaining unscheduled emails as cancelled.

                while next_index < len(clean):

                    email = clean[next_index]

                    next_index += 1

                    record_result(

                        {"email": email, "ok": False, "error": "已停止（未开始）", "cancelled": True}

                    )



            if not futures:

                break



            # Wait for any in-flight work; stop cancels pending + cooperative abort.

            done_set, _ = wait(futures.keys(), return_when=FIRST_COMPLETED, timeout=0.5)

            for fut in list(done_set):

                email = futures.pop(fut, None) or "-"

                try:

                    item = fut.result()

                except Exception as exc:  # noqa: BLE001

                    item = {"email": email, "ok": False, "error": str(exc)[:300]}

                record_result(item)



            if stop_requested():

                stopped = True



    ok = sum(1 for item in results if item.get("ok"))

    failed = sum(1 for item in results if (not item.get("ok")) and (not item.get("cancelled")))



    # Batch-sync probe-passed accounts (never one-by-one HTTP upload).

    # Only emails that fully passed relogin+probe; failures/cancels are skipped.

    # Enabled per-remote via Grok2API/CPA "重登完自动导入" settings.

    #

    # IMPORTANT: when the operator clicked stop, skip remote sync so the UI can

    # finish immediately. Sync can hang for a long time on bad Grok2API/CPA and

    # was making the operation dialog look stuck / unstoppable.

    sync_result: dict[str, Any] | None = None

    gcfg = pro_store.get_grok2api_config(include_password=False)

    ccfg = pro_store.get_cpa_config(include_key=False)

    want_sync = bool(gcfg.get("auto_upload_after_relogin") or ccfg.get("auto_upload_after_relogin"))

    if stopped:

        sync_result = {

            "ok": True,

            "skipped": ["stopped_before_remote_sync"],

            "total": 0,

            "uploaded": 0,

        }

        emit("stage", email="", message="已停止，跳过远端同步")

    elif want_sync:

        passed = [str(item.get("email") or "") for item in results if item.get("ok") and item.get("email")]

        if passed:

            gcfg_full = pro_store.get_grok2api_config(include_password=True)

            emit("stage", email="", message=f"重登完成，开始批量同步远端（{len(passed)} 个）")

            try:

                sync_result = pro_store.sync_accounts_after_relogin(

                    passed,

                    batch_size=max(50, int(gcfg_full.get("upload_batch_size") or 50)),

                    on_progress=lambda event: emit(

                        "stage",

                        email="",

                        message=str((event or {}).get("message") or "正在同步远端"),

                    ),

                    should_stop=stop_requested,

                )

            except Exception as exc:  # noqa: BLE001

                sync_result = {"ok": False, "error": str(exc)[:300], "total": len(passed)}

            emit(

                "stage",

                email="",

                message=(

                    f"远端同步完成：上传 {int((sync_result or {}).get('uploaded') or 0)}"

                    f" / {int((sync_result or {}).get('total') or len(passed))}"

                    + (

                        f"，失败批次 {int((sync_result or {}).get('failed_batches') or 0)}"

                        if (sync_result or {}).get("failed_batches")

                        else ""

                    )

                ),

            )

        else:

            sync_result = {"ok": True, "total": 0, "uploaded": 0, "skipped": ["no probe-passed emails"]}



    return {

        "ok": (not stopped) and ok == len(results) and (sync_result is None or sync_result.get("ok", True)),

        "count": len(results),

        "success": ok,

        "failed": failed,

        "cancelled": cancelled,

        "results": results,

        "concurrency": workers,

        "stagger_ms": int(stagger * 1000),

        "stopped": stopped,

        "sync": sync_result,

    }





def _relogin_task_view(task: dict[str, Any] | None) -> dict[str, Any]:

    if not task:

        return {"ok": True, "running": False, "status": "idle"}

    status = str(task.get("status") or "idle")

    stop_evt = task.get("stop")

    stop_set = bool(stop_evt is not None and stop_evt.is_set())

    if status == "running" and stop_set:

        status = "stopping"

    results = list(task.get("results") or [])

    success = int(task.get("success") or 0)

    failed = int(task.get("failed") or 0)

    cancelled = int(task.get("cancelled") or 0)

    if results and (task.get("cancelled") is None or "cancelled" not in task):

        # Derive if worker hasn't written the aggregate yet.

        cancelled = sum(1 for item in results if item.get("cancelled"))

        success = sum(1 for item in results if item.get("ok"))

        failed = sum(1 for item in results if (not item.get("ok")) and (not item.get("cancelled")))

    return {

        "ok": True,

        "id": task.get("id"),

        "running": task.get("status") == "running",

        "status": status,

        "done": int(task.get("done") or len(results) or 0),

        "total": int(task.get("total") or 0),

        "success": success,

        "failed": failed,

        "cancelled": cancelled,

        "concurrency": int(task.get("concurrency") or 1),

        "stagger_ms": int(task.get("stagger_ms") or 0),

        "results": results,

        "email": task.get("email"),

        "stage": task.get("stage"),

        "message": task.get("message"),

        "error": task.get("error"),

        "stopped": bool(task.get("stopped")) or stop_set,

        "sync": task.get("sync"),

    }





def _start_relogin_task(emails: list[str], *, concurrency: int | None = None) -> dict[str, Any]:

    global _relogin_task

    clean = _clean_emails(emails)

    if not clean:

        raise ValueError("未选择账号")

    relogin_cfg = pro_store.get_relogin_config(include_secrets=True)

    workers = max(1, min(10, int(concurrency if concurrency is not None else relogin_cfg.get("concurrency") or 2)))

    stagger_ms = max(0, min(60000, int(relogin_cfg.get("stagger_ms") or 0)))

    with _relogin_lock:

        if _relogin_task and _relogin_task.get("status") == "running":

            raise HTTPException(status_code=409, detail="已有重登任务正在运行")

        task = {

            "id": "relogin_" + secrets.token_hex(6),

            "status": "running",

            "stop": threading.Event(),

            "total": len(clean),

            "done": 0,

            "success": 0,

            "failed": 0,

            "cancelled": 0,

            "concurrency": workers,

            "stagger_ms": stagger_ms,

            "results": [],

        }

        _relogin_task = task



    def progress(event: dict[str, Any]) -> None:

        with _relogin_lock:

            if event.get("kind") == "stage":

                task["email"] = event.get("email")

                msg = str(event.get("message") or "")

                # Distinguish remote sync from per-account login so the UI can

                # show "同步中" and allow close without looking stuck on login.

                if "同步" in msg:

                    task["stage"] = "同步中"

                else:

                    task["stage"] = "登录中"

                task["message"] = msg

                _persist_relogin_task(task)

                return

            results = list(event.get("results") or [])

            task["results"] = list(results)

            task["done"] = len(results)

            task["success"] = sum(1 for item in results if item.get("ok"))

            task["cancelled"] = sum(1 for item in results if item.get("cancelled"))

            task["failed"] = sum(

                1 for item in results if (not item.get("ok")) and (not item.get("cancelled"))

            )

            task["stage"] = ""

            task["message"] = ""

            _persist_relogin_task(task)



    def run() -> None:

        try:

            result = _relogin_selected_accounts(

                clean,

                concurrency=workers,

                stagger_ms=stagger_ms,

                should_stop=task["stop"].is_set,

                on_progress=progress,

            )

            with _relogin_lock:

                task.update(result)

                # If stop was requested mid-sync, still mark terminal so UI unlocks.

                if task["stop"].is_set() or result.get("stopped"):

                    task["status"] = "stopped"

                    task["stopped"] = True

                else:

                    task["status"] = "completed"

                task["finished_at"] = time.time()

                task["stage"] = ""

                _persist_relogin_task(task)

        except Exception as exc:  # noqa: BLE001

            with _relogin_lock:

                task["status"] = "failed"

                task["error"] = str(exc)

                task["finished_at"] = time.time()

                task["stage"] = ""

                _persist_relogin_task(task)



    threading.Thread(target=run, name=task["id"], daemon=True).start()

    _persist_relogin_task(task)

    return _relogin_task_view(task)





def _admin_page() -> Response:

    path = STATIC_DIR / "admin" / "accounts.html"

    if not path.is_file():

        raise HTTPException(status_code=404, detail="accounts.html not found")

    html = path.read_text(encoding="utf-8")

    # Inject configured admin base so frontend API calls follow ADMIN_BASE_PATH.

    boot = (

        "<script>window.__ADMIN_BASE__="

        + json.dumps(ADMIN_BASE_PATH)

        + ";</script>"

    )

    if "window.__ADMIN_BASE__" in html:

        html = html.replace(

            'window.__ADMIN_BASE__ = window.__ADMIN_BASE__ || "/admin";',

            "window.__ADMIN_BASE__ = " + json.dumps(ADMIN_BASE_PATH) + ";",

            1,

        )

    elif "<head>" in html:

        html = html.replace("<head>", "<head>\n  " + boot, 1)

    else:

        html = boot + html

    return Response(html, media_type="text/html; charset=utf-8")









def _check_registration_inputs(resolved: dict[str, Any]) -> dict[str, Any]:

    checks: list[dict[str, Any]] = []



    def add(

        name: str,

        ok: bool,

        message: str,

        detail: Any | None = None,

        *,

        blocking: bool = True,

    ) -> None:

        item = {"name": name, "ok": bool(ok), "message": message, "blocking": blocking}

        if detail is not None:

            item["detail"] = detail

        checks.append(item)



    provider = "local"

    solver = reg_adapter.probe_local_solver(LOCAL_SOLVER_URL, timeout=1.5)

    add(

        "本地过盾",

        bool(solver.get("ready")),

        "5072 可用" if solver.get("ready") else (solver.get("error") or "5072 未启动"),

        solver,

    )



    mail = str(resolved.get("mail_provider") or "moemail").strip().lower()

    base = str(resolved.get("base_url") or "").strip()

    api_key = str(resolved.get("api_key") or "").strip()

    domain = str(resolved.get("domain") or "").strip()

    try:

        from moemail import (

            cfmail_list_domains,

            create_mailbox,

            duckmail_list_domains,

            gptmail_pick_domain,

            normalize_mail_provider,

            yyds_list_domains,

        )



        mail = normalize_mail_provider(mail, base_url=base)

    except Exception:

        pass



    # ---- Live mailbox service probe (depends on selected provider) ----

    if mail == "moemail":

        if not base:

            add("邮箱服务", False, "MoeMail 缺少服务地址")

        elif not api_key:

            add("邮箱服务", False, "MoeMail 缺少 API Key / 管理员密码")

        else:

            try:

                from moemail import moemail_create_mailbox



                box = moemail_create_mailbox(

                    name=None,

                    domain=domain or None,

                    expiry_ms=int(resolved.get("expiry_ms") or 3_600_000),

                    api_key=api_key,

                    base_url=base,

                )

                addr = str(box.get("email") or "")

                add(

                    "邮箱服务",

                    bool(addr and "@" in addr),

                    f"MoeMail 可用，已试创建 {addr}" if addr else "MoeMail 返回异常",

                    {"provider": "moemail", "email": addr, "id": box.get("id")},

                )

            except Exception as e:  # noqa: BLE001

                add("邮箱服务", False, f"MoeMail 不可用：{e}")

    elif mail == "yyds":

        if not api_key:

            add("邮箱服务", False, "YYDS 缺少 API Key")

        else:

            try:

                domains = yyds_list_domains(api_key=api_key, base_url=base or None)

                if domain:

                    add(

                        "邮箱服务",

                        True,

                        f"YYDS 可用，已配置域名 {domain}；目录 {len(domains)} 个",

                        {"provider": "yyds", "domains": (domains or [])[:20]},

                    )

                elif domains:

                    add(

                        "邮箱服务",

                        True,

                        f"YYDS 可用，可自动随机 {len(domains)} 个域名",

                        {"provider": "yyds", "domains": domains[:20]},

                    )

                else:

                    # Fall back to a real create attempt.

                    box = create_mailbox(

                        provider="yyds",

                        api_key=api_key,

                        base_url=base or None,

                        domain=domain or None,

                    )

                    addr = str(box.get("email") or "")

                    add(

                        "邮箱服务",

                        bool(addr and "@" in addr),

                        f"YYDS 可用，已试创建 {addr}" if addr else "YYDS 返回异常",

                        {"provider": "yyds", "email": addr},

                    )

            except Exception as e:  # noqa: BLE001

                add("邮箱服务", False, f"YYDS 不可用：{e}")

    elif mail == "gptmail":

        if not api_key:

            add("邮箱服务", False, "GPTMail 缺少 API Key")

        else:

            try:

                picked = gptmail_pick_domain(api_key=api_key, base_url=base or None)

                if domain or picked:

                    # Also try a real mailbox create — domain list alone is public.

                    box = create_mailbox(

                        provider="gptmail",

                        api_key=api_key,

                        base_url=base or None,

                        domain=domain or picked,

                    )

                    addr = str(box.get("email") or "")

                    add(

                        "邮箱服务",

                        bool(addr and "@" in addr),

                        f"GPTMail 可用，已试创建 {addr}" if addr else "GPTMail 返回异常",

                        {

                            "provider": "gptmail",

                            "email": addr,

                            "domain": domain or picked,

                        },

                    )

                else:

                    add("邮箱服务", False, "GPTMail 未返回可用域名，请检查 API Key / 服务")

            except Exception as e:  # noqa: BLE001

                add("邮箱服务", False, f"GPTMail 不可用：{e}")

    elif mail == "cfmail":

        if not base:

            add("邮箱服务", False, "Cloudflare Temp Email 缺少 Worker / 服务地址")

        elif not api_key:

            add("邮箱服务", False, "Cloudflare Temp Email 缺少管理密码 / API Key")

        else:

            try:

                domains = cfmail_list_domains(api_key=api_key, base_url=base)

                usable = bool(domain or domains)

                if usable:

                    # Prefer domain listing; create may require captcha on some deploys.

                    add(

                        "邮箱服务",

                        True,

                        (

                            f"Cloudflare Temp Email 可用，已配置域名 {domain}"

                            if domain

                            else f"Cloudflare Temp Email 可用，可自动随机 {len(domains)} 个域名"

                        ),

                        {"provider": "cfmail", "domains": (domains or [])[:20]},

                    )

                else:

                    # Last resort: try create.

                    box = create_mailbox(

                        provider="cfmail",

                        api_key=api_key,

                        base_url=base,

                        domain=domain or None,

                        expiry_ms=int(resolved.get("expiry_ms") or 3_600_000),

                    )

                    addr = str(box.get("email") or "")

                    add(

                        "邮箱服务",

                        bool(addr and "@" in addr),

                        f"Cloudflare Temp Email 可用，已试创建 {addr}" if addr else "服务返回异常",

                        {"provider": "cfmail", "email": addr},

                    )

            except Exception as e:  # noqa: BLE001

                add("邮箱服务", False, f"Cloudflare Temp Email 不可用：{e}")

    elif mail == "duckmail":

        # Public domains work without API key; private domains need dk_ key.

        try:

            domains = duckmail_list_domains(api_key=api_key or None, base_url=base or None)

            if domain:

                add(

                    "邮箱服务",

                    True,

                    f"DuckMail 可用，已配置域名 {domain}；目录 {len(domains)} 个",

                    {"provider": "duckmail", "domains": (domains or [])[:20]},

                )

            elif domains:

                add(

                    "邮箱服务",

                    True,

                    f"DuckMail 可用，可自动随机 {len(domains)} 个公开域名",

                    {"provider": "duckmail", "domains": domains[:20]},

                )

            else:

                box = create_mailbox(

                    provider="duckmail",

                    api_key=api_key or None,

                    base_url=base or None,

                    domain=domain or None,

                    expiry_ms=int(resolved.get("expiry_ms") or 3_600_000),

                )

                addr = str(box.get("email") or "")

                add(

                    "邮箱服务",

                    bool(addr and "@" in addr),

                    f"DuckMail 可用，已试创建 {addr}" if addr else "DuckMail 返回异常",

                    {"provider": "duckmail", "email": addr},

                )

        except Exception as e:  # noqa: BLE001

            add("邮箱服务", False, f"DuckMail 不可用：{e}")

    elif mail == "outmail":

        base_om = str(resolved.get("outmail_api_base") or base or "").strip()

        key_om = str(resolved.get("outmail_api_key") or api_key or "").strip()

        cookie_om = str(resolved.get("outmail_session_cookie") or "").strip()

        if not base_om:

            add("邮箱服务", False, "Outmail 缺少服务地址 (outmail_api_base)")

        elif not key_om and not cookie_om:

            add("邮箱服务", False, "Outmail 缺少 API Key 或 Session Cookie")

        else:

            try:

                import outmail_client as om

                om_cfg = dict(resolved)

                om_cfg["outmail_api_base"] = base_om

                if key_om:

                    om_cfg["outmail_api_key"] = key_om

                if cookie_om:

                    om_cfg["outmail_session_cookie"] = cookie_om

                om.configure(om_cfg, merge=False)

                if bool(resolved.get("outmail_anonymous_enabled")):

                    domains = om.outmail_list_anonymous_domains()

                    add(

                        "邮箱服务",

                        True,

                        f"Outmail 匿名邮箱可用，域名 {len(domains or [])} 个",

                        {"provider": "outmail", "mode": "anon", "domains": (domains or [])[:20]},

                    )

                else:

                    accounts = om.outmail_list_accounts(limit=5, offset=0)

                    n = len(accounts or []) if isinstance(accounts, list) else 0

                    add(

                        "邮箱服务",

                        True,

                        f"Outmail 账号池可用（抽样 {n} 条）",

                        {"provider": "outmail", "mode": "pool", "sample": n},

                    )

            except Exception as e:  # noqa: BLE001

                add("邮箱服务", False, f"Outmail 不可用：{e}")

    else:

        add("邮箱服务", False, f"未知邮箱服务: {mail}")



    proxy = str(resolved.get("proxy") or "").strip()

    proxy_username = str(resolved.get("proxy_username") or "").strip()

    proxy_password = str(resolved.get("proxy_password") or "")

    strategy = str(resolved.get("proxy_strategy") or "round_robin").strip()

    probe_proxy = ""

    try:

        from proxy_pool import parse_proxy_pool, pick_proxy



        pool = parse_proxy_pool(

            proxy,

            username=proxy_username or None,

            password=proxy_password or None,

            fallback_env=True,

        )

        probe_proxy = pick_proxy(pool, strategy=strategy, index=0) or ""

        if proxy and not pool:

            add("代理配置", False, "已填写代理文本，但没有解析出可用代理 URL")

        elif pool:

            add(

                "代理配置",

                True,

                f"可用 {len(pool)} 条，策略 {strategy or 'round_robin'}"

                + (f"，探测用第 1 条" if probe_proxy else ""),

                {"pool_count": len(pool), "strategy": strategy},

                blocking=False,

            )

        else:

            add(

                "代理配置",

                True,

                "未配置代理（协议 + 本地过盾都走本机出口；与服务器对比时请两边都填同一代理）",

                {"pool_count": 0},

                blocking=False,

            )

    except Exception as e:  # noqa: BLE001

        add("代理配置", False, f"代理解析失败: {e}")



    # Protocol egress IP (curl_cffi). When local captcha is used with the same

    # proxy, Camoufox must mint Turnstile on this same IP — otherwise CF rejects.

    protocol_ip = ""

    try:

        from moemail import probe_egress_ip



        egress = probe_egress_ip(proxy=probe_proxy or None, timeout=12.0)

        protocol_ip = str(egress.get("ip") or "").strip()

        if protocol_ip:

            add(

                "协议出口 IP",

                True,

                f"{protocol_ip}"

                + ("（经代理）" if egress.get("proxy_enabled") else "（本机直连）"),

                egress,

                blocking=False,

            )

        else:

            add(

                "协议出口 IP",

                False,

                f"探测失败: {egress.get('error') or 'unknown'}",

                egress,

                blocking=False,

            )

    except Exception as e:  # noqa: BLE001

        add("协议出口 IP", False, f"探测异常: {e}", blocking=False)



    if provider == "local":

        # Local solver mints Turnstile via createTask.proxy (same egress as protocol).

        if probe_proxy:

            add(

                "过盾出口对齐",

                True,

                f"本地过盾与协议同代理"

                + (f"（出口 {protocol_ip}）" if protocol_ip else ""),

                {

                    "mode": "local+proxy",

                    "protocol_ip": protocol_ip,

                    "proxy_configured": True,

                },

                blocking=False,

            )

        else:

            add(

                "过盾出口对齐",

                True,

                "本地过盾与协议均本机直连",

                {"mode": "local+direct", "protocol_ip": protocol_ip},

                blocking=False,

            )



    try:

        reg_adapter.ensure_xconsole()

        from xconsole_client import XConsoleAuthClient



        client = XConsoleAuthClient(

            debug=False,

            proxy=probe_proxy,

            signup_url="https://accounts.x.ai/sign-up?redirect=grok-com",

            timeout=20.0,

        )

        status = client.visit_home()

        headers = client._base_headers()

        status2, _hdrs, _cookies, raw = client._request(

            "GET",

            client.signup_url,

            headers={

                **headers,

                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",

                "sec-fetch-site": "same-site",

                "sec-fetch-mode": "navigate",

                "sec-fetch-dest": "document",

                "referer": "https://console.x.ai/",

            },

        )

        html = raw.decode("utf-8", "replace")

        low = html.lower()

        has_next = "self.__next_f.push" in html and "/_next/static/chunks/" in html

        cf_block = (

            "attention required" in low

            or "cf-browser-verification" in low

            or "challenge-platform" in low

            or "just a moment" in low

        )

        transport = getattr(client, "transport_name", "") or ""

        if status2 < 400 and has_next:

            msg = f"可访问 HTTP {status2}（{transport}）"

            ok_flag = True

        elif cf_block:

            msg = (

                f"Cloudflare 拦截协议指纹 HTTP {status2}（{transport}）；"

                "浏览器可访问不代表 curl_cffi 指纹可用，请换代理出口或升级 impersonate"

            )

            ok_flag = False

        else:

            msg = (

                f"协议预检 HTTP {status2}（{transport}）；"

                "手动浏览器可访问时可继续启动，实际注册会再次验证"

            )

            ok_flag = False

        add(

            "x.ai 注册页",

            ok_flag,

            msg,

            {

                "home_status": status,

                "signup_status": status2,

                "proxy": "configured" if probe_proxy else "none",

                "egress_ip": protocol_ip,

                "has_next_payload": has_next,

                "cf_challenge": cf_block,

                "transport": transport,

                "body_preview": " ".join(html.split())[:200],

            },

            blocking=False,

        )

    except Exception as e:  # noqa: BLE001

        add(

            "x.ai 注册页",

            False,

            f"协议预检失败: {e}；实际注册会再次验证",

            {"proxy": "configured" if probe_proxy else "none", "egress_ip": protocol_ip},

            blocking=False,

        )



    ok = all(item["ok"] or not item["blocking"] for item in checks)

    return {"ok": ok, "checks": checks, "config": resolved}





def _local_solver_status() -> dict[str, Any]:

    status = reg_adapter.probe_local_solver(LOCAL_SOLVER_URL, timeout=1.5)

    proc = _local_solver_proc

    status["managed_pid"] = proc.pid if proc and proc.poll() is None else None

    return status







def _solver_reported_threads(status: dict[str, Any] | None = None) -> int:

    """Best-effort read of live solver browser pool size.



    Prefer structured /health fields (``thread`` / ``threads``). Do NOT fall back

    to ``owned`` (lazy mode often reports 0 while target is N) and do NOT fall

    back to TURNSTILE_THREAD env — that would make "already at N" always true

    after we write the env, and skip the actual resize.

    """

    st = status or {}

    for key in ("thread", "threads"):

        if st.get(key) in (None, ""):

            continue

        try:

            n = int(st.get(key))

            if n > 0:

                return n

        except (TypeError, ValueError):

            pass

    return 0





def _process_cmdline(pid: int) -> str:

    try:

        out = subprocess.check_output(

            ["ps", "-p", str(int(pid)), "-o", "command="],

            text=True,

            stderr=subprocess.DEVNULL,

        )

        return (out or "").strip()

    except Exception:

        return ""





def _list_child_pids(parent_pid: int) -> list[int]:

    try:

        out = subprocess.check_output(

            ["pgrep", "-P", str(int(parent_pid))],

            text=True,

            stderr=subprocess.DEVNULL,

        )

    except Exception:

        return []

    pids: list[int] = []

    for line in (out or "").splitlines():

        s = line.strip()

        if s.isdigit():

            pids.append(int(s))

    return pids





def _list_descendant_pids(root_pid: int, *, limit: int = 4000) -> list[int]:

    seen: set[int] = set()

    queue = [int(root_pid)]

    desc: list[int] = []

    while queue and len(desc) < limit:

        cur = queue.pop(0)

        for child in _list_child_pids(cur):

            if child in seen or child == root_pid:

                continue

            seen.add(child)

            desc.append(child)

            queue.append(child)

    return desc





def _is_browser_driver_cmd(cmd: str) -> bool:

    low = (cmd or "").lower()

    if not low:

        return False

    markers = (

        "cli.js run-driver",

        "playwright/driver",

        "ms-playwright",

        "camoufox",

        "firefox",

        "chromium",

        "chrome-headless",

        "headless_shell",

        "api_solver.py",

    )

    return any(m in low for m in markers)





def _count_browser_driver_processes() -> dict[str, int]:

    """Host-wide leftover counts for admin UI / cleanup button."""

    counts = {

        "cli_run_driver": 0,

        "camoufox_firefox": 0,

        "api_solver": 0,

        "total_driverish": 0,

    }

    try:

        out = subprocess.check_output(

            ["ps", "-axo", "pid=,command="],

            text=True,

            stderr=subprocess.DEVNULL,

        )

    except Exception:

        return counts

    for line in (out or "").splitlines():

        line = line.strip()

        if not line:

            continue

        # pid may be space-padded

        parts = line.split(None, 1)

        if len(parts) < 2:

            continue

        cmd = parts[1]

        low = cmd.lower()

        if "cli.js run-driver" in low or "playwright/driver" in low:

            counts["cli_run_driver"] += 1

            counts["total_driverish"] += 1

        if "camoufox" in low or ("firefox" in low and "playwright" in low):

            counts["camoufox_firefox"] += 1

            counts["total_driverish"] += 1

        if "api_solver.py" in low:

            counts["api_solver"] += 1

    return counts





def _kill_pids(pids: set[int], *, label: str) -> list[str]:

    stopped: list[str] = []

    me = os.getpid()

    for pid in sorted(p for p in pids if p not in (0, 1, me)):

        try:

            os.kill(pid, signal.SIGTERM)

            stopped.append(f"{label}:{pid}")

        except Exception:

            pass

    if pids:

        time.sleep(0.35)

        for pid in sorted(p for p in pids if p not in (0, 1, me)):

            try:

                os.kill(pid, 0)

                os.kill(pid, signal.SIGKILL)

                stopped.append(f"kill9:{pid}")

            except Exception:

                pass

    return stopped





def _collect_solver_related_pids() -> set[int]:

    """PIDs for api_solver on our port + its browser/driver descendants + strays."""

    pids: set[int] = set()

    # Listeners on 5072

    try:

        out = subprocess.check_output(

            ["sh", "-lc", f"ss -lntp 2>/dev/null | awk '/:{LOCAL_SOLVER_PORT} /{{print}}' || true"],

            text=True,

        )

        for m in re.finditer(r"pid=(\d+)", out or ""):

            pids.add(int(m.group(1)))

    except Exception:

        pass

    try:

        out = subprocess.check_output(

            ["sh", "-lc", f"lsof -nP -iTCP:{LOCAL_SOLVER_PORT} -sTCP:LISTEN -t 2>/dev/null || true"],

            text=True,

        )

        for line in (out or "").splitlines():

            if line.strip().isdigit():

                pids.add(int(line.strip()))

    except Exception:

        pass

    # api_solver processes for this port

    for pattern in (

        f"api_solver.py.*--port {LOCAL_SOLVER_PORT}",

        f"api_solver.py.*--port[ =]{LOCAL_SOLVER_PORT}",

        "api_solver.py",

    ):

        try:

            out = subprocess.check_output(["pgrep", "-f", pattern], text=True)

            for line in (out or "").splitlines():

                if line.strip().isdigit():

                    pids.add(int(line.strip()))

        except Exception:

            pass

    # Descendants of known solver roots

    roots = list(pids)

    for root in roots:

        for child in _list_descendant_pids(root):

            cmd = _process_cmdline(child)

            if _is_browser_driver_cmd(cmd) or "api_solver.py" in cmd:

                pids.add(child)

    # Host-wide stray playwright drivers / camoufox under our project path

    try:

        out = subprocess.check_output(["ps", "-axo", "pid=,command="], text=True, stderr=subprocess.DEVNULL)

        project_markers = (

            "turnstile-solver",

            "grok-register-pro",

            "cli.js run-driver",

            "playwright/driver",

            "camoufox",

        )

        for line in (out or "").splitlines():

            line = line.strip()

            parts = line.split(None, 1)

            if len(parts) < 2 or not parts[0].isdigit():

                continue

            pid = int(parts[0])

            cmd = parts[1]

            low = cmd.lower()

            if not any(m in low for m in project_markers):

                continue

            if _is_browser_driver_cmd(cmd) or "api_solver.py" in low:

                pids.add(pid)

    except Exception:

        pass

    me = os.getpid()

    pids.discard(me)

    pids.discard(0)

    pids.discard(1)

    return pids





def _http_solver_reclaim(*, timeout: float = 12.0) -> dict[str, Any]:

    """Ask live solver to reclaim pool + sweep drivers (preferred, in-process)."""

    try:

        import urllib.error

        import urllib.request



        req = urllib.request.Request(

            f"{LOCAL_SOLVER_URL.rstrip('/')}/reclaim",

            data=b"{}",

            headers={"Content-Type": "application/json", "Accept": "application/json"},

            method="POST",

        )

        with urllib.request.urlopen(req, timeout=timeout) as resp:

            raw = resp.read().decode("utf-8", "replace")

            try:

                data = json.loads(raw) if raw else {}

            except Exception:

                data = {"raw": raw[:200]}

            if isinstance(data, dict):

                data.setdefault("ok", True)

                data["http_status"] = int(resp.status)

                return data

            return {"ok": True, "http_status": int(resp.status), "raw": str(data)[:200]}

    except Exception as exc:  # noqa: BLE001

        return {"ok": False, "error": str(exc)[:240]}





def _cleanup_browser_leftovers(

    *,

    reason: str = "",

    hard: bool = False,

    restart: bool = False,

    thread: int | None = None,

    reclaim_pool: bool | None = None,

) -> dict[str, Any]:

    """Manual/fallback cleanup for Camoufox/Playwright leftovers.



    IMPORTANT: never call this on the hot path of registration start with

    reclaim/hard enabled. Reclaim closes the live browser pool and will make

    every in-flight captcha fail with health/createTask timeouts.



    Order when hard/reclaim requested:

      1) optional live solver ``POST /reclaim``

      2) stop solver process tree + kill strays

      3) optional restart with target thread count

    Soft mode (default for programmatic budget checks): count only, no kill.

    """

    before = _count_browser_driver_processes()

    actions: list[str] = []

    # Default: only hard/restart paths reclaim. Soft calls must be no-op kills.

    do_reclaim = bool(hard if reclaim_pool is None else reclaim_pool)

    reclaim: dict[str, Any] = {"ok": True, "skipped": True}

    stopped: list[str] = []

    if do_reclaim:

        reclaim = _http_solver_reclaim()

        if reclaim.get("ok"):

            actions.append("http_reclaim")

        else:

            actions.append(f"http_reclaim_skip:{reclaim.get('error') or 'unavailable'}")



    if hard or restart:

        stopped.extend(

            _stop_local_solver(reason=reason or "cleanup", sweep_drivers=True).get("stopped") or []

        )

        actions.append("stop_solver")

        stray_pids = _collect_solver_related_pids()

        if stray_pids:

            stopped.extend(_kill_pids(stray_pids, label="stray"))

            actions.append(f"stray_kill:{len(stray_pids)}")

    else:

        actions.append("soft_count_only")



    started: dict[str, Any] | None = None

    if restart:

        try:

            n = int(thread if thread is not None else (os.environ.get("TURNSTILE_THREAD") or 1))

        except (TypeError, ValueError):

            n = 1

        n = max(1, min(50, n))

        try:

            started = _start_local_solver(

                thread=n,

                browser_type=os.environ.get("TURNSTILE_BROWSER_TYPE") or "camoufox",

                force=True,

            )

            actions.append(f"restart_thread:{n}")

        except Exception as exc:  # noqa: BLE001

            started = {"ok": False, "error": str(exc)[:240]}

            actions.append(f"restart_fail:{exc}")



    if hard or restart or do_reclaim:

        time.sleep(0.4)

    after = _count_browser_driver_processes()

    status = _local_solver_status()

    result = {

        "ok": True,

        "reason": reason or "manual",

        "hard": bool(hard),

        "restart": bool(restart),

        "actions": actions,

        "reclaim": reclaim,

        "stopped": stopped,

        "started": started,

        "before": before,

        "after": after,

        "solver": status,

        "message": (

            f"清理完成：cli.js {before.get('cli_run_driver', 0)}→{after.get('cli_run_driver', 0)}，"

            f"api_solver {before.get('api_solver', 0)}→{after.get('api_solver', 0)}"

            if (hard or restart or do_reclaim)

            else (

                f"过盾残留检查：cli.js={before.get('cli_run_driver', 0)} "

                f"api_solver={before.get('api_solver', 0)}（未杀进程）"

            )

        ),

    }

    print(f"[register-pro] browser cleanup ({reason or 'manual'}): {result['message']} actions={actions}")

    return result





def _stop_local_solver(*, reason: str = "", sweep_drivers: bool = True) -> dict[str, Any]:

    """Stop solver we own and best-effort free :5072 listeners (Linux + macOS)."""

    global _local_solver_proc

    stopped: list[str] = []

    proc = _local_solver_proc

    managed_pid = proc.pid if proc is not None and proc.poll() is None else None

    if proc is not None and proc.poll() is None:

        # Capture descendants before killing parent so we can mop them after.

        pre_desc = set(_list_descendant_pids(proc.pid)) if sweep_drivers else set()

        try:

            os.killpg(proc.pid, signal.SIGTERM)

            stopped.append(f"pgid:{proc.pid}")

        except Exception:

            try:

                proc.terminate()

                stopped.append(f"pid:{proc.pid}")

            except Exception as exc:

                stopped.append(f"term_fail:{exc}")

        try:

            proc.wait(timeout=5)

        except Exception:

            try:

                os.killpg(proc.pid, signal.SIGKILL)

            except Exception:

                try:

                    proc.kill()

                except Exception:

                    pass

        if pre_desc:

            stopped.extend(_kill_pids(pre_desc, label="desc"))

    _local_solver_proc = None



    # Clear stray api_solver on our port (entrypoint child, old launches).

    try:

        pids = _collect_solver_related_pids()

        # Keep nothing: full stop.

        if managed_pid:

            pids.add(int(managed_pid))

        stopped.extend(_kill_pids(pids, label="portpid"))

    except Exception as exc:

        stopped.append(f"cleanup_err:{exc}")



    print(f"[register-pro] stop solver ({reason or 'manual'}): {stopped or 'none'}")

    return {"ok": True, "stopped": stopped}





def _wait_solver_ready(*, timeout_sec: float = 25.0, want_thread: int | None = None) -> dict[str, Any]:

    deadline = time.time() + max(1.0, float(timeout_sec))

    last: dict[str, Any] = {}

    while time.time() < deadline:

        last = _local_solver_status()

        if last.get("ready") or last.get("ok"):

            if want_thread is None:

                return last

            live = _solver_reported_threads(last)

            # live==0 means /health didn't report thread yet — keep polling.

            # live!=want means still on old size (or mid-restart) — keep polling.

            if live == int(want_thread):

                return last

        time.sleep(0.35)

    return last





def _ensure_solver_threads(captcha_concurrency: int | None, *, force_restart: bool = False) -> dict[str, Any]:

    """Hot-apply captcha browser pool size to N.



    Order of preference:

    1. In-process ``POST /resize`` (no kill of unrelated work when already at N)

    2. Process restart only when resize fails or force_restart=True



    NEVER reclaim/kill the live pool on registration start when already at target.

    That was killing in-flight Camoufox browsers and causing mass health timeouts.

    """

    try:

        n = max(1, min(50, int(captcha_concurrency or 1)))

    except (TypeError, ValueError):

        n = 1

    browser = os.environ.get("TURNSTILE_BROWSER_TYPE") or "camoufox"



    try:

        st = _local_solver_status()

    except Exception:

        st = {}

    live = _solver_reported_threads(st)

    ready = bool(st.get("ready") or st.get("ok"))

    os.environ["TURNSTILE_THREAD"] = str(n)



    if ready and live == n and not force_restart:

        print(f"[register-pro] solver already thread={live}, keep (no reclaim)")

        return {

            "ok": True,

            "restarted": False,

            "resized": False,

            "method": "noop",

            "thread": live,

            "solver": st,

        }



    # 1) Prefer in-process resize.

    if ready:

        try:

            resized = reg_adapter.resize_local_solver(n, LOCAL_SOLVER_URL, timeout=25.0)

        except Exception as exc:  # noqa: BLE001

            resized = {"ok": False, "error": str(exc)[:240]}

        if resized.get("ok"):

            ready_st = _wait_solver_ready(timeout_sec=8.0, want_thread=n)

            reported = _solver_reported_threads(ready_st) or int(resized.get("thread") or n)

            print(

                f"[register-pro] solver in-process resize {live or '?'} -> {n} "

                f"reported={reported} ready={bool(ready_st.get('ready') or ready_st.get('ok'))}"

            )

            return {

                "ok": True,

                "restarted": False,

                "resized": bool(resized.get("resized", True)),

                "method": "http_resize",

                "thread": n,

                "reported_thread": reported,

                "previous_thread": live or resized.get("previous_thread"),

                "resize": resized,

                "solver": ready_st or st,

            }

        print(

            f"[register-pro] in-process resize failed "

            f"({resized.get('error') or 'unknown'}); falling back to process restart"

        )

    elif not force_restart and not ready:

        pass



    # 2) Process-level restart fallback only.

    if ready or force_restart:

        print(f"[register-pro] solver hot-restart {live or '?'} -> {n}")

        _stop_local_solver(reason=f"restart {live}->{n}", sweep_drivers=True)

        time.sleep(0.5)



    try:

        started = _start_local_solver(thread=n, browser_type=browser, force=True)

    except Exception as exc:

        print(f"[register-pro] ensure solver threads={n} start failed: {exc}")

        return {

            "ok": False,

            "restarted": True,

            "resized": False,

            "method": "process_restart",

            "thread": n,

            "error": str(exc)[:240],

        }



    ready_st = _wait_solver_ready(timeout_sec=25.0, want_thread=n)

    reported = _solver_reported_threads(ready_st)

    print(

        f"[register-pro] solver hot-applied want={n} reported={reported} "

        f"ready={bool(ready_st.get('ready') or ready_st.get('ok'))}"

    )

    return {

        "ok": bool(ready_st.get("ready") or ready_st.get("ok") or started.get("ok")),

        "restarted": True,

        "resized": True,

        "method": "process_restart",

        "thread": n,

        "reported_thread": reported,

        "previous_thread": live or None,

        "started": started,

        "solver": ready_st,

    }



def _start_local_solver(thread: int = 1, browser_type: str = "camoufox", force: bool = False) -> dict[str, Any]:

    global _local_solver_proc

    current = _local_solver_status()

    if current.get("ready") and not force:

        return {"ok": True, "already_running": True, "solver": current}



    proc = _local_solver_proc

    if proc and proc.poll() is None and not force:

        return {"ok": True, "starting": True, "pid": proc.pid, "solver": current}



    solver_dir = ROOT / "turnstile-solver"

    script = solver_dir / "api_solver.py"

    if not script.is_file():

        raise RuntimeError("本地过盾代码缺失：turnstile-solver/api_solver.py 不存在")



    # Prefer dedicated venv when present (bare-metal). In Docker image packages

    # are installed into system python, so fall back to current interpreter.

    py_candidates = [

        solver_dir / ".venv" / "bin" / "python",

        Path(os.getenv("TURNSTILE_PYTHON") or "") if os.getenv("TURNSTILE_PYTHON") else None,

        Path("/usr/local/bin/python"),

        Path("/usr/bin/python3"),

    ]

    py = None

    for cand in py_candidates:

        if cand and cand.is_file() and os.access(cand, os.X_OK):

            py = cand

            break

    if py is None:

        # Last resort: whatever is running this app.

        import sys



        py = Path(sys.executable)



    log_dir = solver_dir / "logs"

    log_dir.mkdir(parents=True, exist_ok=True)

    log_file = log_dir / "turnstile_solver.log"

    browser = browser_type if browser_type in {"chromium", "chrome", "msedge", "camoufox"} else "camoufox"

    workers = max(1, min(50, int(thread or 1)))

    if force:

        # Make sure port is free before bind.

        try:

            _stop_local_solver(reason=f"force-start thread={workers}")

            time.sleep(0.3)

        except Exception:

            pass

    out = open(log_file, "ab", buffering=0)

    _local_solver_proc = subprocess.Popen(

        [

            str(py),

            str(script),

            "--browser_type",

            browser,

            "--thread",

            str(workers),

            "--debug",

            "--host",

            "127.0.0.1",

            "--port",

            str(LOCAL_SOLVER_PORT),

        ],

        cwd=str(solver_dir),

        stdout=out,

        stderr=subprocess.STDOUT,

        start_new_session=True,

        env={

            **os.environ,

            # Ensure browser cache resolves under persistent data dir in Docker.

            "XDG_CACHE_HOME": os.environ.get("XDG_CACHE_HOME")

            or str(Path(os.environ.get("GROK_REGISTER_PRO_DATA_DIR") or "/data") / "cache"),

            "PLAYWRIGHT_BROWSERS_PATH": os.environ.get("PLAYWRIGHT_BROWSERS_PATH")

            or str(

                Path(os.environ.get("XDG_CACHE_HOME") or (Path(os.environ.get("GROK_REGISTER_PRO_DATA_DIR") or "/data") / "cache"))

                / "ms-playwright"

            ),

            # Registration must not start a lazy/empty pool that idle-reclaims

            # after 30s — that freezes batches on "waiting for admission".

            "TURNSTILE_LAZY": os.environ.get("TURNSTILE_LAZY") or "0",

            "TURNSTILE_IDLE_SEC": os.environ.get("TURNSTILE_IDLE_SEC") or "0",

        },

    )

    return {

        "ok": True,

        "started": True,

        "pid": _local_solver_proc.pid,

        "url": LOCAL_SOLVER_URL,

        "log": str(log_file),

        "python": str(py),

    }






@app.get("/healthz")
async def healthz():
    """Public liveness probe (no admin auth)."""
    return {"ok": True, "service": "grok-register-pro"}


@app.get("/readyz")
async def readyz():
    """Public readiness: DB file path is writable/initable."""
    try:
        pro_store.init_db()
        return {"ok": True, "db": str(pro_store.DB_PATH)}
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=503, content={"ok": False, "error": str(exc)[:200]})


@app.get("/")

async def root():

    return _admin_page()





@app.get(ADMIN_BASE_PATH)

@app.get(ADMIN_BASE_PATH + "/")

@app.get(_admin_path("accounts"))

@app.get(_admin_path("accounts") + "/")

async def accounts_page():

    return _admin_page()





@app.get(_admin_path('api', 'session'))

async def session(request: Request):

    auth_state = pro_store.admin_auth_state()

    setup_required = bool(auth_state.get("setup_required"))

    return {

        "ok": True,

        "authenticated": _is_authenticated(request),

        "setup_required": setup_required,

        "setup_allowed": (not setup_required) or _setup_allowed(request),

        "min_password_len": int(auth_state.get("min_password_len") or pro_store.ADMIN_PASSWORD_MIN_LEN),

        "cookie_secure": _cookie_secure(),

        "admin_base_path": ADMIN_BASE_PATH,

    }





@app.post(_admin_path('api', 'auth', 'login'))

async def login(request: Request, body: LoginBody):

    auth_state = pro_store.admin_auth_state()

    if auth_state.get("setup_required"):

        # First-time setup: reject remote callers unless explicitly allowed.

        if not _setup_allowed(request):

            raise HTTPException(

                status_code=403,

                detail=(

                    "首次设置管理员密码仅允许本机访问。"

                    "请在服务器本机打开页面，或设置 GROK_REGISTER_ADMIN_BOOTSTRAP_PASSWORD，"

                    "或临时 GROK_REGISTER_ALLOW_REMOTE_SETUP=1。"

                ),

            )

        try:

            pro_store.set_admin_password(body.password, rotate_sessions=True)

        except ValueError as exc:

            raise HTTPException(status_code=400, detail=str(exc)) from exc

    elif not pro_store.verify_admin_password(body.password):

        raise HTTPException(status_code=401, detail="管理员密码不正确")

    res = Response(

        json.dumps({"ok": True, "authenticated": True, "setup_required": False}, ensure_ascii=False),

        media_type="application/json; charset=utf-8",

    )

    _set_session_cookie(res, _create_session_token())

    return res





@app.post(_admin_path('api', 'auth', 'logout'))

async def logout():

    res = Response(

        json.dumps({"ok": True, "authenticated": False}, ensure_ascii=False),

        media_type="application/json; charset=utf-8",

    )

    res.delete_cookie(SESSION_COOKIE, path="/")

    return res





@app.post(_admin_path('api', 'auth', 'change-password'))

async def change_password(body: ChangePasswordBody):

    current = str(body.current_password or "")

    new_password = str(body.new_password or "")

    if not pro_store.verify_admin_password(current):

        raise HTTPException(status_code=400, detail="当前密码不正确")

    min_len = int(pro_store.ADMIN_PASSWORD_MIN_LEN)

    if len(new_password) < min_len:

        raise HTTPException(status_code=400, detail=f"新密码至少 {min_len} 位")

    if new_password == current:

        raise HTTPException(status_code=400, detail="新密码不能与当前密码相同")

    try:

        # rotate_sessions=True invalidates every other cookie immediately.

        pro_store.set_admin_password(new_password, rotate_sessions=True)

    except ValueError as exc:

        raise HTTPException(status_code=400, detail=str(exc)) from exc

    res = Response(

        json.dumps({"ok": True, "message": "管理员密码已更新，其他会话已全部失效"}, ensure_ascii=False),

        media_type="application/json; charset=utf-8",

    )

    _set_session_cookie(res, _create_session_token())

    return res





@app.get(_admin_path('api', 'accounts'))

async def list_accounts(

    page: int = 1,

    page_size: int = 25,

    q: str = "",

    sort: str = "newest",

    status: str = "",

    probe: str = "",

    remote: str = "",

    summary: bool = False,

):

    if summary:

        return pro_store.status()

    return pro_store.list_accounts(

        page=page,

        page_size=page_size,

        q=q,

        sort=sort,

        status=status,

        probe=probe,

        remote=remote,

    )





@app.get(_admin_path('api', 'accounts', 'emails'))

async def list_account_emails(

    q: str = "",

    sort: str = "newest",

    status: str = "",

    probe: str = "",

    remote: str = "",

    limit: int = 20000,

):

    """Emails matching the same filters as /admin/api/accounts (no pagination)."""

    return pro_store.list_account_emails(

        q=q,

        sort=sort,

        status=status,

        probe=probe,

        remote=remote,

        limit=limit,

    )





@app.post(_admin_path('api', 'accounts', 'probe'))

async def probe_accounts(body: ProbeBody):

    return _start_probe_task(body)





@app.get(_admin_path('api', 'accounts', 'probe', 'status'))

async def probe_status():

    with _probe_lock:

        return _probe_task_view(_probe_task)





@app.get(_admin_path('api', 'runtime', 'active-tasks'))

async def runtime_active_tasks():

    """One-shot snapshot for UI reconnect after refresh / re-login.



    - registration: pointer + live batch/session if still in memory

    - probe / relogin: live task view (memory, hydrated from SQLite on boot)

    """

    with _probe_lock:

        probe = _probe_task_view(_probe_task)

    with _relogin_lock:

        relogin = _relogin_task_view(_relogin_task)

    reg_snap = _load_task_snapshot(_REG_TASK_SETTING) or {}

    reg_out: dict[str, Any] = {

        "ok": True,

        "running": False,

        "status": "idle",

        "type": "",

        "id": "",

        "batch_id": "",

        "session_id": "",

    }

    try:

        listed = reg_adapter.list_registration_sessions()

        batches = list(listed.get("batches") or [])

        sessions = list(listed.get("sessions") or [])

        live = None

        # Prefer currently running batch/session.

        for b in batches:

            st = str(b.get("status") or b.get("batch_status") or "").lower()

            if st in {"running", "starting", "stopping", "registering", "probing", "waiting_solver", "solving_turnstile"}:

                live = ("batch", b)

                break

        if live is None:

            for s in sessions:

                st = str(s.get("status") or "").lower()

                if st in {"running", "starting", "stopping", "registering", "probing", "waiting_solver", "solving_turnstile", "queued"}:

                    live = ("session", s)

                    break

        # Fall back to last remembered id if still present.

        if live is None and reg_snap:

            bid = str(reg_snap.get("batch_id") or "")

            sid = str(reg_snap.get("session_id") or "")

            if bid:

                b = reg_adapter.get_registration_batch(bid)

                if b:

                    live = ("batch", b)

            elif sid:

                s = reg_adapter.get_registration_session(sid) if hasattr(reg_adapter, "get_registration_session") else None

                if s:

                    live = ("session", s)

        if live is not None:

            kind, obj = live

            st = str(obj.get("status") or obj.get("batch_status") or "running")

            rid = str(obj.get("id") or obj.get("batch_id") or "")

            reg_out = {

                "ok": True,

                "running": st.lower() not in {"done", "completed", "failed", "error", "stopped", "cancelled", "partial", "success", "imported", "interrupted", "idle"},

                "status": st,

                "type": kind,

                "id": rid,

                "batch_id": rid if kind == "batch" else "",

                "session_id": rid if kind == "session" else "",

                "total": obj.get("total") or obj.get("count"),

                "done": obj.get("done") or obj.get("finished"),

                "success": obj.get("success") or obj.get("imported") or obj.get("ok"),

                "failed": obj.get("failed") or obj.get("error") or obj.get("fail"),

                "ok_count": obj.get("ok_count"),

                "fail_count": obj.get("fail_count"),

                "created_at": obj.get("created_at"),

                "updated_at": obj.get("updated_at"),

                "started_at": obj.get("started_at") or obj.get("created_at"),

                "message": obj.get("message") or "",

            }

            if reg_out["running"]:

                _persist_registration_task(

                    batch_id=reg_out.get("batch_id") or "",

                    session_id=reg_out.get("session_id") or "",

                    status=st,

                )

        elif reg_snap:

            reg_out.update(

                {

                    "status": str(reg_snap.get("status") or "idle"),

                    "type": str(reg_snap.get("type") or ""),

                    "id": str(reg_snap.get("batch_id") or reg_snap.get("session_id") or ""),

                    "batch_id": str(reg_snap.get("batch_id") or ""),

                    "session_id": str(reg_snap.get("session_id") or ""),

                    "running": False,

                }

            )

    except Exception as exc:  # noqa: BLE001

        reg_out = {"ok": False, "running": False, "status": "error", "error": str(exc)[:200]}

    return {"ok": True, "registration": reg_out, "probe": probe, "relogin": relogin}





@app.post(_admin_path('api', 'accounts', 'probe', 'stop'))

async def stop_probe():

    with _probe_lock:

        if not _probe_task or _probe_task.get("status") != "running":

            return {"ok": True, "running": False, "status": "idle", "message": "没有运行中的探测任务"}

        _probe_task["stop"].set()

        return {"ok": True, "running": True, "status": "stopping", "message": "已停止继续派发探测请求，正在等待在途请求结束"}





@app.delete(_admin_path('api', 'accounts'))

async def delete_accounts(body: DeleteAccountsBody):

    return await asyncio.to_thread(pro_store.delete_accounts, body.emails)


@app.get(_admin_path('api', 'accounts', 'backups'))

async def list_account_backups(limit: int = 20):

    return await asyncio.to_thread(pro_store.list_account_delete_backups, limit)


@app.post(_admin_path('api', 'accounts', 'restore-backup'))

async def restore_account_backup(body: RestoreAccountsBackupBody):

    try:

        return await asyncio.to_thread(

            pro_store.restore_accounts_from_backup,

            body.backup_path,

            overwrite=body.overwrite,

        )

    except Exception as exc:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(exc)) from exc






@app.get(_admin_path('api', 'accounts', 'recycle'))

async def list_account_recycle(limit: int = 100):

    return await asyncio.to_thread(pro_store.list_account_recycle_bin, limit)



@app.post(_admin_path('api', 'accounts', 'recycle', 'restore'))

async def restore_account_recycle(body: RestoreRecycleBody):

    try:

        return await asyncio.to_thread(

            pro_store.restore_accounts_from_recycle,

            body.emails,

            restore_all=body.restore_all,

            overwrite=body.overwrite,

        )

    except Exception as exc:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(exc)) from exc



@app.post(_admin_path('api', 'accounts', 'recycle', 'purge'))

async def purge_account_recycle(body: PurgeRecycleBody):

    try:

        return await asyncio.to_thread(

            pro_store.purge_accounts_from_recycle,

            body.emails,

            purge_all=body.purge_all,

        )

    except Exception as exc:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(exc)) from exc



@app.post(_admin_path('api', 'accounts', 'relogin'))

async def relogin_accounts(body: ReloginBody):

    try:

        return _start_relogin_task(body.emails, concurrency=body.concurrency)

    except Exception as exc:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(exc)) from exc





@app.get(_admin_path('api', 'accounts', 'relogin', 'status'))

async def relogin_status():

    with _relogin_lock:

        return _relogin_task_view(_relogin_task)





@app.post(_admin_path('api', 'accounts', 'relogin', 'stop'))

async def stop_relogin():

    with _relogin_lock:

        if not _relogin_task or _relogin_task.get("status") != "running":

            return {"ok": True, "running": False, "status": "idle", "message": "没有运行中的重登任务"}

        stop_evt = _relogin_task.get("stop")

        if stop_evt is not None:

            stop_evt.set()

        return {

            "ok": True,

            "running": True,

            "status": "stopping",

            "message": "已停止派发并取消未开始任务；排队过盾会退出，在途请求尽快结束",

        }





@app.get(_admin_path('api', 'accounts', 'relogin', 'config'))

async def get_relogin_config():

    return {"ok": True, "config": pro_store.get_relogin_config(include_secrets=True), "source": "sqlite"}





@app.put(_admin_path('api', 'accounts', 'relogin', 'config'))

async def put_relogin_config(body: ReloginConfigBody):

    try:

        cfg = pro_store.set_relogin_config(body.model_dump(exclude_none=True))

        return {"ok": True, "config": cfg, "source": "sqlite"}

    except Exception as exc:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(exc)) from exc





@app.get(_admin_path('api', 'local-solver', 'status'))

async def local_solver_status():

    st = _local_solver_status()

    st["leftovers"] = _count_browser_driver_processes()

    return st





@app.post(_admin_path('api', 'local-solver', 'start'))

async def start_local_solver(body: LocalSolverStartBody):

    try:

        return _start_local_solver(thread=body.thread, browser_type=body.browser_type)

    except Exception as e:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(e)) from e





class LocalSolverCleanupBody(BaseModel):

    hard: bool = False

    restart: bool = False

    thread: int | None = None





@app.post(_admin_path('api', 'local-solver', 'cleanup'))

async def cleanup_local_solver(body: LocalSolverCleanupBody = LocalSolverCleanupBody()):

    """Manual fallback: reclaim/kill Camoufox + Playwright leftovers.



    Prefer automatic cleanup on resize/downsize. This button is belt-and-suspenders

    when something still leaks.

    """

    try:

        # Default manual click = hard clean + restart with current captcha concurrency.

        hard = bool(body.hard) if body is not None else False

        restart = bool(body.restart) if body is not None else False

        # UI "清理残留" should be effective: hard+restart unless caller opts out.

        if body is None or (body.hard is False and body.restart is False and body.thread is None):

            hard = True

            restart = True

        thread = body.thread if body is not None else None

        if thread is None:

            try:

                cfg = pro_store.get_registration_config(include_secrets=False)

                thread = int(cfg.get("captcha_concurrency") or 1)

            except Exception:

                thread = int(os.environ.get("TURNSTILE_THREAD") or 1)

        return await asyncio.to_thread(

            _cleanup_browser_leftovers,

            reason="admin-button",

            hard=hard,

            restart=restart,

            thread=thread,

        )

    except Exception as e:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(e)) from e





@app.post(_admin_path('api', 'accounts', 'register-email', 'preflight'))

async def registration_preflight(body: RegistrationBody):

    resolved = pro_store.resolve_registration_inputs(_registration_cfg_from_body(body))

    return await asyncio.to_thread(_check_registration_inputs, resolved)





@app.get(_admin_path('api', 'grok2api', 'config'))

async def get_grok2api_config():

    return {"ok": True, "config": pro_store.get_grok2api_config(include_password=True), "source": "sqlite"}





@app.put(_admin_path('api', 'grok2api', 'config'))

async def put_grok2api_config(body: Grok2ApiConfigBody):

    try:

        cfg = pro_store.set_grok2api_config(body.model_dump(exclude_none=False), replace=False)

    except ValueError as e:

        raise HTTPException(status_code=400, detail=str(e)) from e

    backend = pro_store.get_remote_backend(resolve=True)

    return {

        "ok": True,

        "config": cfg,

        "backend": backend,

        "message": "Grok2API 配置已保存"

        + ("（已锁定远端对接=Grok2API，CPA 自动导入已关闭）" if backend == "grok2api" else ""),

    }





@app.post(_admin_path('api', 'grok2api', 'test-login'))

async def test_grok2api_login(body: Grok2ApiConfigBody):

    cfg = pro_store.normalize_grok2api_config(body.model_dump(exclude_none=False))

    try:

        result = await asyncio.to_thread(pro_store.test_grok2api_login, cfg)

    except Exception as e:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(e)) from e

    return result





@app.post(_admin_path('api', 'grok2api', 'upload'))

async def upload_grok2api(body: Grok2ApiUploadBody):

    """Manual import from the accounts page.



    Probe is NOT required here — operator selected accounts explicitly.

    Registration / relogin auto-upload still enforces probe via store helpers.

    """

    mode = (body.mode or "build_auth_files").strip()

    limit = max(1, min(5000, int(body.limit or 1000)))

    emails = _clean_emails(body.emails)

    try:

        if mode == "web_sso":

            return await asyncio.to_thread(

                pro_store.upload_grok2api_sso,

                None,

                limit=limit,

                emails=emails,

                require_probe=False,

            )

        if mode == "build_auth_files":

            return await asyncio.to_thread(

                pro_store.upload_grok2api_auth_files,

                None,

                limit=limit,

                emails=emails,

                require_probe=False,

            )

    except Exception as e:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(e)) from e

    raise HTTPException(status_code=400, detail="未知上传类型")





@app.post(_admin_path('api', 'grok2api', 'remote-status'))

async def sync_grok2api_remote_status(body: Grok2ApiRemoteStatusBody):

    """Pull remote status from the exclusive backend (Grok2API or CPA).



    Kept under the historical grok2api path so existing UI buttons keep working.

    When remote_backend=cpa, routes to grok-inspection plugin status.

    """

    try:

        return await asyncio.to_thread(

            pro_store.sync_remote_status,

            mode=body.mode or "problems",

            providers=body.providers,

            page_size=body.page_size,

            backend=body.backend,

        )

    except Exception as e:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(e)) from e





@app.get(_admin_path('api', 'remote-backend'))

async def get_remote_backend():

    backend = pro_store.get_remote_backend(resolve=True)

    stored = pro_store.get_remote_backend(resolve=False)

    return {

        "ok": True,

        "backend": backend,

        "stored": stored,

        "options": list(pro_store.REMOTE_BACKENDS),

        "exclusive": True,

        "note": "Grok2API 与 CPA 互斥：选一个自动导入/拉取，另一个不会跑",

    }





@app.put(_admin_path('api', 'remote-backend'))

async def put_remote_backend(body: RemoteBackendBody):

    try:

        backend = pro_store.set_remote_backend(body.backend)

    except ValueError as e:

        raise HTTPException(status_code=400, detail=str(e)) from e

    return {

        "ok": True,

        "backend": backend,

        "message": (

            f"远端对接已锁定为 {backend}"

            if backend

            else "已清除远端对接锁定（将按自动导入勾选推断）"

        ),

        "grok2api": pro_store.get_grok2api_config(include_password=False),

        "cpa": pro_store.get_cpa_config(include_key=False),

    }





@app.post(_admin_path('api', 'cpa', 'remote-status'))

async def sync_cpa_remote_status(body: Grok2ApiRemoteStatusBody):

    """Explicit CPA grok-inspection pull (same payload as unified remote-status)."""

    try:

        return await asyncio.to_thread(

            pro_store.sync_cpa_remote_status,

            mode=body.mode or "problems",

        )

    except Exception as e:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(e)) from e





@app.get(_admin_path('api', 'cpa', 'config'))

async def get_cpa_config():

    return {"ok": True, "config": pro_store.get_cpa_config(include_key=True), "source": "sqlite"}





@app.put(_admin_path('api', 'cpa', 'config'))

async def put_cpa_config(body: CpaConfigBody):

    try:

        cfg = pro_store.set_cpa_config(body.model_dump(exclude_none=False), replace=False)

    except ValueError as e:

        raise HTTPException(status_code=400, detail=str(e)) from e

    backend = pro_store.get_remote_backend(resolve=True)

    return {

        "ok": True,

        "config": cfg,

        "backend": backend,

        "message": "CPA 配置已保存"

        + ("（已锁定远端对接=CPA，Grok2API 自动导入已关闭）" if backend == "cpa" else ""),

    }





@app.post(_admin_path('api', 'cpa', 'test'))

async def test_cpa(body: CpaConfigBody):

    cfg = pro_store.normalize_cpa_config(body.model_dump(exclude_none=False))

    try:

        return await asyncio.to_thread(pro_store.test_cpa_remote, cfg)

    except Exception as e:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(e)) from e





@app.post(_admin_path('api', 'cpa', 'upload'))

async def upload_cpa(body: CpaUploadBody):

    """Manual CPA import — probe not required (operator selected accounts)."""

    try:

        return await asyncio.to_thread(

            pro_store.upload_cpa_auth_files,

            None,

            limit=max(1, min(5000, int(body.limit or 1000))),

            emails=_clean_emails(body.emails),

            require_probe=False,

        )

    except Exception as e:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(e)) from e





@app.get(_admin_path('api', 'sub2api', 'config'))

async def get_sub2api_config():

    return {"ok": True, "config": pro_store.get_sub2api_config(include_key=True), "source": "sqlite"}





@app.put(_admin_path('api', 'sub2api', 'config'))

async def put_sub2api_config(body: Sub2ApiConfigBody):

    cfg = pro_store.set_sub2api_config(body.model_dump(exclude_none=False), replace=False)

    return {"ok": True, "config": cfg, "message": "Sub2API 配置已保存"}





@app.post(_admin_path('api', 'sub2api', 'test'))

async def test_sub2api(body: Sub2ApiConfigBody):

    cfg = pro_store.normalize_sub2api_config(body.model_dump(exclude_none=False))

    try:

        return await asyncio.to_thread(pro_store.test_sub2api_remote, cfg)

    except Exception as e:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(e)) from e





@app.post(_admin_path('api', 'sub2api', 'upload'))

async def upload_sub2api(body: Sub2ApiUploadBody):

    """Manual Sub2API push from local CPA auth; marks sub2_pushed on success."""

    try:

        return await asyncio.to_thread(

            pro_store.upload_sub2api_auth_files,

            None,

            limit=max(1, min(5000, int(body.limit or 1000))),

            emails=_clean_emails(body.emails),

            require_probe=False,

            skip_already_pushed=bool(body.skip_already_pushed),

        )

    except Exception as e:  # noqa: BLE001

        raise HTTPException(status_code=400, detail=str(e)) from e





@app.get(_admin_path('api', 'accounts', 'register-email', 'config'))

async def get_registration_config():

    return {"ok": True, "config": pro_store.get_registration_config(include_secrets=True), "source": "sqlite"}





@app.put(_admin_path('api', 'accounts', 'register-email', 'config'))

async def put_registration_config(body: RegistrationBody):

    # exclude_none=True so omitted fields do not wipe saved secrets; store also

    # ignores blank strings for protected keys (api_key/domain/proxy/…).

    cfg = pro_store.set_registration_config(body.model_dump(exclude_none=True), replace=False)

    # Manual save re-anchors schedule recover baseline to the values the user just chose.

    try:

        pro_store.refresh_schedule_baseline_from_config(cfg)

    except Exception:

        pass

    # Hot-apply captcha browser pool size immediately (no full container restart).

    # Never force process restart here: that was reclaiming a warm Camoufox pool

    # and leaving registration stuck with pool_ready=false.

    solver_apply: dict[str, Any] = {}

    try:

        solver_apply = await asyncio.to_thread(

            _ensure_solver_threads,

            cfg.get("captcha_concurrency"),

            force_restart=False,

        )

    except Exception as exc:  # noqa: BLE001

        solver_apply = {"ok": False, "error": str(exc)[:200]}

        print(f"[register-pro] solver hot-apply failed: {exc}")

    msg = "注册配置已保存"

    if solver_apply.get("resized") or solver_apply.get("restarted"):

        applied_n = solver_apply.get("thread") or cfg.get("captcha_concurrency")

        method = solver_apply.get("method") or ""

        if solver_apply.get("ok"):

            if method == "http_resize":

                msg += f"；过盾已热加载为 {applied_n} 浏览器（进程内扩缩）"

            else:

                msg += f"；过盾已热加载为 {applied_n} 浏览器"

        else:

            err = str(solver_apply.get("error") or "unknown")

            msg += f"；过盾热加载失败：{err}"

    elif solver_apply.get("ok") and solver_apply.get("method") == "noop":

        n = solver_apply.get("thread") or cfg.get("captcha_concurrency")

        msg += f"；过盾已是 {n} 浏览器，无需重启"

    return {

        "ok": True,

        "config": cfg,

        "solver": solver_apply,

        "message": msg,

    }





@app.get(_admin_path('api', 'schedule', 'policy'))

async def get_schedule_policy():

    return {"ok": True, "policy": pro_store.get_schedule_policy(), "source": "sqlite"}





@app.put(_admin_path('api', 'schedule', 'policy'))

async def put_schedule_policy(body: SchedulePolicyBody):

    # exclude_none so unchecked-absent fields don't wipe existing values when client

    # only patches a subset; UI payload should still send the full form.

    cfg = pro_store.set_schedule_policy(body.model_dump(exclude_none=True), replace=False)

    return {"ok": True, "policy": cfg, "message": "定时策略已保存"}





@app.get(_admin_path('api', 'schedule', 'status'))

async def get_schedule_status():

    return pro_store.get_schedule_status()





@app.post(_admin_path('api', 'schedule', 'run-now'))

async def schedule_run_now():

    with _schedule_lock:

        out = await asyncio.to_thread(

            pro_store.evaluate_schedule_tick,

            start_fn=_start_scheduled_registration,

            force=True,

        )

    return out





@app.post(_admin_path('api', 'schedule', 'reset-throttle'))

async def schedule_reset_throttle():

    with _schedule_lock:

        out = await asyncio.to_thread(pro_store.reset_schedule_throttle)

    return out





@app.post(_admin_path('api', 'accounts', 'register-email'))

async def start_registration(body: RegistrationBody):

    resolved = pro_store.resolve_registration_inputs(_registration_cfg_from_body(body))

    preflight = await asyncio.to_thread(_check_registration_inputs, resolved)

    if not preflight.get("ok"):

        raise HTTPException(status_code=400, detail={"message": "注册链路自检未通过", "preflight": preflight})

    pro_store.set_registration_config(resolved, replace=False)

    # Ensure runtime admission cap matches saved/UI value before workers start.

    try:

        reg_adapter.set_global_reg_inflight_limit(resolved.get("global_inflight"))

        reg_adapter.set_local_captcha_concurrency(resolved.get("captcha_concurrency"))

        # New batch must not inherit soft-pause / leaked admission from a prior stop.

        if hasattr(reg_adapter, "clear_reg_soft_pause"):

            reg_adapter.clear_reg_soft_pause()

        try:

            active = int(reg_adapter.get_global_reg_inflight_active() or 0)

        except Exception:

            active = 0

        # No live workers should hold slots when starting a fresh batch from UI.

        if active > 0 and hasattr(reg_adapter, "reset_reg_admission_counters"):

            print(f"[register-pro] clearing leaked admission active={active} before start")

            reg_adapter.reset_reg_admission_counters()

        _ensure_solver_threads(resolved.get("captcha_concurrency"), force_restart=False)

    except Exception as exc:

        print(f"[register-pro] admission/solver prepare failed: {exc}")

    result = await asyncio.to_thread(

        reg_adapter.start_registration,

        proxy=resolved.get("proxy") or None,

        proxy_username=resolved.get("proxy_username") or None,

        proxy_password=resolved.get("proxy_password") or None,

        proxy_strategy=resolved.get("proxy_strategy") or None,

        moemail_api_key=resolved.get("api_key") or None,

        moemail_base_url=resolved.get("base_url") or None,

        prefix=resolved.get("prefix") or None,

        domain=resolved.get("domain") or None,

        expiry_ms=resolved.get("expiry_ms"),

        mail_provider=resolved.get("mail_provider") or None,

        captcha_provider="local",

        local_solver_url=resolved.get("local_solver_url") or LOCAL_SOLVER_URL,

        yescaptcha_key="",

        count=resolved.get("count"),

        concurrency=resolved.get("concurrency"),

        stagger_ms=resolved.get("stagger_ms"),

        probe_delay_sec=resolved.get("probe_delay_sec"),

        skip_probe=resolved.get("skip_probe"),

        sso_only=resolved.get("sso_only"),

        captcha_use_proxy=resolved.get("captcha_use_proxy"),

    )

    if not result.get("ok"):

        raise HTTPException(status_code=400, detail=result.get("error") or "start failed")

    # Remember the live batch/session so refresh / re-login can reconnect the UI.

    try:

        _persist_registration_task(

            batch_id=str(result.get("batch_id") or result.get("id") or ""),

            session_id="" if result.get("batch_id") else str(result.get("id") or ""),

            status=str(result.get("status") or "running"),

        )

    except Exception:

        pass

    return result





@app.post(_admin_path('api', 'accounts', 'register-email', 'test-proxy'))

async def test_proxy(body: RegistrationBody):

    from moemail import test_xai_proxy

    from proxy_pool import parse_proxy_pool, pool_summary



    resolved = pro_store.resolve_registration_inputs(_registration_cfg_from_body(body))

    proxy_text = resolved.get("proxy") or ""

    user = resolved.get("proxy_username") or None

    password = resolved.get("proxy_password") or None

    strategy = resolved.get("proxy_strategy") or "round_robin"

    pool = parse_proxy_pool(proxy_text, username=user, password=password, fallback_env=True)

    summary = pool_summary(proxy_text, username=user, password=password, strategy=strategy, fallback_env=True)

    if not pool:

        return {

            "ok": False,

            "error": "未配置可测试的代理",

            "proxy_pool": summary,

            "proxy_results": [],

            "tested": 0,

            "available": 0,

            "unavailable": 0,

        }



    # Keep each probe short so reverse proxies (openresty ~60s) do not 504.

    # 8s connect+read is enough to prove an open proxy can reach accounts.x.ai;

    # dead proxies fail fast instead of burning 15s egress + 45s xAI.

    per_proxy_timeout = 8.0



    def probe(proxy: str) -> dict[str, Any]:

        started = time.monotonic()

        result = test_xai_proxy(

            proxy=proxy,

            timeout=per_proxy_timeout,

            # Skip ipify on pool scan: halves wall-clock and still validates xAI path.

            probe_egress=False,

        )

        return {

            "proxy": proxy,

            "ok": bool(result.get("ok")),

            "status_code": int(result.get("status_code") or 0),

            "transport": str(result.get("transport") or ""),

            "egress_ip": str(result.get("egress_ip") or ""),

            "error": str(result.get("body_preview") or result.get("error") or "")[:240]

            if not result.get("ok")

            else "",

            "elapsed_ms": round((time.monotonic() - started) * 1000),

        }



    def run_probes() -> list[dict[str, Any]]:

        # Higher fan-out: 10 proxies × 8s worst case ≈ ~8–16s with 10 workers,

        # instead of 10 × (15+45)s with only 5 workers.

        workers = min(10, max(1, len(pool)))

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="proxy-probe") as executor:

            return list(executor.map(probe, pool))



    results = await asyncio.to_thread(run_probes)

    available = sum(1 for item in results if item["ok"])

    return {

        "ok": available == len(results),

        "proxy_pool": summary,

        "proxy_results": results,

        "tested": len(results),

        "available": available,

        "unavailable": len(results) - available,

        "message": (

            f"已完成 {len(results)} 个代理测试：可用 {available}，"

            f"不可用 {len(results) - available}（单代理超时 {int(per_proxy_timeout)}s）"

        ),

    }





@app.get(_admin_path('api', 'accounts', 'register-email', 'sessions'))

async def list_sessions():

    return reg_adapter.list_registration_sessions()





@app.get(_admin_path('api', 'accounts', 'register-email', 'batches', '{batch_id}'))

async def get_batch(batch_id: str):

    result = reg_adapter.get_registration_batch(batch_id)

    if not result:

        raise HTTPException(status_code=404, detail="registration batch not found")

    return result





@app.get(_admin_path('api', 'accounts', 'register-email', 'sessions', '{session_id}'))

async def get_session(session_id: str, include_auth_json: int = 0):

    result = reg_adapter.get_registration_session(session_id, include_auth_json=bool(include_auth_json))

    if not result:

        raise HTTPException(status_code=404, detail="registration session not found")

    return result





@app.post(_admin_path('api', 'accounts', 'register-email', 'sessions', '{session_id}', 'stop'))

async def stop_session(session_id: str):

    result = reg_adapter.stop_registration_session(session_id)

    if not result.get("ok"):

        raise HTTPException(status_code=404, detail=result.get("error") or "stop failed")

    return result





@app.post(_admin_path('api', 'accounts', 'register-email', 'batches', '{batch_id}', 'stop'))

async def stop_batch(batch_id: str):

    result = reg_adapter.stop_registration_batch(batch_id)

    if not result.get("ok"):

        raise HTTPException(status_code=404, detail=result.get("error") or "stop failed")

    return result





@app.post(_admin_path('api', 'accounts', 'register-email', 'stop'))

async def stop_all():

    return reg_adapter.stop_all_active_registrations()





@app.get(_admin_path('api', 'accounts', 'register-email', 'export-sso'))

async def export_sso_get(batch_id: str | None = None, status: str | None = None, include_password: int = 0, format: str = "sso", download: int = 1):

    body = ExportSsoBody(

        batch_id=batch_id,

        status=[x.strip() for x in (status or "").split(",") if x.strip()],

        include_password=bool(include_password),

        format=format,

        download=bool(download),

    )

    return await export_sso(body)





@app.post(_admin_path('api', 'accounts', 'register-email', 'export-sso'))

async def export_sso(body: ExportSsoBody):

    rows = pro_store.export_sso_rows(

        batch_id=(body.batch_id or "").strip(),

        status=[str(x).strip() for x in (body.status or []) if str(x).strip()],

        emails=body.emails,

    )

    if not rows:

        raise HTTPException(status_code=404, detail="没有匹配的 SSO 记录")

    fmt = (body.format or "sso").strip().lower()

    ts = time.strftime("%Y%m%d-%H%M%S", time.localtime())

    if fmt == "json":

        payload = {"ok": True, "count": len(rows), "format": fmt, "exported_at": ts, "items": rows}

        if not body.download:

            return payload

        return Response(

            json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),

            media_type="application/json; charset=utf-8",

            headers={"Content-Disposition": f'attachment; filename="register-pro-sso-{ts}.json"'},

        )



    lines: list[str] = []

    for row in rows:

        email = str(row.get("email") or "")

        password = str(row.get("password") or "")

        sso = str(row.get("sso") or "")

        if fmt == "cookie":

            lines.append(f"sso={sso}")

        elif fmt == "email_sso":

            lines.append(f"{email}\t{sso}" if email else sso)

        elif fmt == "email_password_sso":

            lines.append(f"{email}:{password}:{sso}" if body.include_password else f"{email}::{sso}")

        else:

            lines.append(sso)

    text = "\n".join(lines) + "\n"

    if not body.download:

        return {"ok": True, "count": len(rows), "format": fmt, "text": text}

    return Response(

        text.encode("utf-8"),

        media_type="text/plain; charset=utf-8",

        headers={"Content-Disposition": f'attachment; filename="register-pro-sso-{ts}.txt"'},

    )






@app.post(_admin_path('api', 'accounts', 'export'))
async def export_accounts_txt(body: ExportAccountsBody):
    """Export accounts as plain text: email----password----sso (one per line).

    Mirrors grok-register /api/accounts/export behaviour for selected accounts.
    """
    emails = _clean_emails(body.emails)
    if body.require_selected and not emails:
        raise HTTPException(status_code=400, detail="请先选择账号")
    lines = await asyncio.to_thread(
        pro_store.export_account_txt_lines,
        emails,
        require_selected=bool(body.require_selected),
    )
    if not lines:
        raise HTTPException(status_code=404, detail="没有可导出的账号")
    ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    content = "\n".join(lines) + "\n"
    return Response(
        content.encode("utf-8"),
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="accounts_{ts}.txt"',
            "X-Export-Count": str(len(lines)),
        },
    )


@app.post(_admin_path('api', 'accounts', 'convert-sso'))

async def convert_sso_selected(body: ConvertSsoBody):

    """Convert selected accounts that have SSO into Grok2API/CPA auth."""

    emails = [str(e or "").strip() for e in (body.emails or []) if str(e or "").strip()]

    if not emails:

        raise HTTPException(status_code=400, detail="请先选择账号")

    try:

        workers = max(1, min(8, int(body.concurrency or 2)))

    except (TypeError, ValueError):

        workers = 2

    result = await asyncio.to_thread(

        pro_store.convert_sso_accounts_to_auth,

        emails,

        concurrency=workers,

        force=bool(body.force),

    )

    return result





def _zip_auth_parts(parts: list[tuple[str, bytes]], *, filename_prefix: str) -> Response:

    if not parts:

        raise HTTPException(status_code=404, detail="没有可导出的 Auth 数据")

    ts = time.strftime("%Y%m%d-%H%M%S", time.localtime())

    buffer = BytesIO()

    seen: set[str] = set()

    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:

        for name, payload in parts:

            if name in seen:

                stem, suffix = os.path.splitext(name)

                name = f"{stem}-{len(seen) + 1}{suffix or '.json'}"

            seen.add(name)

            zf.writestr(name, payload)

    return Response(

        buffer.getvalue(),

        media_type="application/zip",

        headers={

            "Content-Disposition": f'attachment; filename="{filename_prefix}-{ts}.zip"',

            "X-Export-Count": str(len(parts)),

        },

    )





def _export_auth_zip_parts(

    *,

    kind: str,

    emails: list[str] | None,

    limit: int = 5000,

) -> Response:

    clean = _clean_emails(emails)

    lim = max(1, min(5000, int(limit or 5000)))

    if clean:

        lim = max(1, min(5000, max(lim, len(clean))))

    if kind == "cpa":

        parts = pro_store.list_cpa_auth_parts(limit=lim, emails=clean or None)

        if not parts:

            detail = (

                f"选中的 {len(clean)} 个账号没有可导出的 CPA Auth"

                if clean

                else "没有可导出的 CPA Auth 数据"

            )

            raise HTTPException(status_code=404, detail=detail)

        return _zip_auth_parts(parts, filename_prefix="register-pro-cpa")

    parts = pro_store.list_grok2api_auth_parts(limit=lim, emails=clean or None)

    if not parts:

        detail = (

            f"选中的 {len(clean)} 个账号没有可导出的 Auth"

            if clean

            else "没有可导出的 Auth 数据"

        )

        raise HTTPException(status_code=404, detail=detail)

    return _zip_auth_parts(parts, filename_prefix="register-pro-auth")





@app.get(_admin_path('api', 'accounts', 'register-email', 'export-auth-zip'))

async def export_auth_zip_get(limit: int = 5000, emails: str | None = None):

    # Optional comma-separated emails for small selections; prefer POST for large sets.

    email_list = [x.strip() for x in (emails or "").split(",") if x.strip()] or None

    return await asyncio.to_thread(

        _export_auth_zip_parts, kind="grok2api", emails=email_list, limit=limit

    )





@app.post(_admin_path('api', 'accounts', 'register-email', 'export-auth-zip'))

async def export_auth_zip_post(body: ExportAuthZipBody):

    return await asyncio.to_thread(

        _export_auth_zip_parts,

        kind="grok2api",

        emails=body.emails,

        limit=body.limit,

    )





@app.get(_admin_path('api', 'accounts', 'register-email', 'export-cpa-zip'))

async def export_cpa_zip_get(limit: int = 5000, emails: str | None = None):

    email_list = [x.strip() for x in (emails or "").split(",") if x.strip()] or None

    return await asyncio.to_thread(

        _export_auth_zip_parts, kind="cpa", emails=email_list, limit=limit

    )





@app.post(_admin_path('api', 'accounts', 'register-email', 'export-cpa-zip'))

async def export_cpa_zip_post(body: ExportAuthZipBody):

    return await asyncio.to_thread(

        _export_auth_zip_parts,

        kind="cpa",

        emails=body.emails,

        limit=body.limit,

    )





def _acquire_singleton_lock() -> Any:

    """Prevent two register_pro_app processes from sharing one data dir.



    Uses an exclusive flock on a lock file under the data directory. Returns the

    open file handle that must stay open for the process lifetime.

    """

    import fcntl



    data_dir = Path(

        os.getenv("GROK_REGISTER_PRO_DATA_DIR")

        or (ROOT / "data" / "register_pro")

    ).expanduser().resolve()

    data_dir.mkdir(parents=True, exist_ok=True)

    lock_path = Path(

        os.getenv("GROK_REGISTER_PRO_LOCK_FILE")

        or (data_dir / "register_pro.instance.lock")

    )

    pid_path = Path(

        os.getenv("GROK_REGISTER_PRO_PID_FILE")

        or (data_dir / "register_pro.pid")

    )

    fh = open(lock_path, "a+", encoding="utf-8")

    try:

        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    except BlockingIOError:

        fh.seek(0)

        holder = (fh.read() or "").strip() or "unknown"

        fh.close()

        raise SystemExit(

            f"ERROR: another register_pro_app is already using data dir {data_dir} "

            f"(lock={lock_path}, holder={holder}). Stop the old process first, or run ./start.sh "

            f"(FORCE_RESTART is on by default)."

        ) from None

    fh.seek(0)

    fh.truncate()

    fh.write(f"pid={os.getpid()} started={time.time():.0f}\n")

    fh.flush()

    try:

        pid_path.write_text(str(os.getpid()), encoding="utf-8")

    except OSError as exc:

        print(f"[register-pro] warn: could not write pid file {pid_path}: {exc}")

    return fh





if __name__ == "__main__":

    import atexit

    import uvicorn



    # Docker / remote access needs 0.0.0.0; local default stays loopback unless overridden.

    host = (os.getenv("GROK_REGISTER_PRO_HOST") or os.getenv("HOST") or "127.0.0.1").strip() or "127.0.0.1"

    try:

        port = int(os.getenv("GROK_REGISTER_PRO_PORT") or os.getenv("PORT") or "8788")

    except (TypeError, ValueError):

        port = 8788



    _instance_lock_fh = _acquire_singleton_lock()



    def _release_singleton() -> None:

        try:

            import fcntl



            fcntl.flock(_instance_lock_fh.fileno(), fcntl.LOCK_UN)

        except Exception:

            pass

        try:

            _instance_lock_fh.close()

        except Exception:

            pass

        pid_path = Path(

            os.getenv("GROK_REGISTER_PRO_PID_FILE")

            or (Path(os.getenv("GROK_REGISTER_PRO_DATA_DIR") or (ROOT / "data" / "register_pro")) / "register_pro.pid")

        )

        try:

            if pid_path.is_file() and pid_path.read_text(encoding="utf-8").strip() == str(os.getpid()):

                pid_path.unlink(missing_ok=True)

        except Exception:

            pass



    atexit.register(_release_singleton)

    print(f"[register-pro] singleton lock ok pid={os.getpid()} data={os.getenv('GROK_REGISTER_PRO_DATA_DIR') or ''}")

    uvicorn.run("register_pro_app:app", host=host, port=port, reload=False)
