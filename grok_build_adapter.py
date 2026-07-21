"""Adapter: grok-build-auth -> grok-register-pro account pool.



Drives the vendored ``grok-build-auth/xconsole_client`` protocol client to:



1. register an x.ai account with MoeMail + YesCaptcha

2. extract SSO/session cookies

3. convert SSO via sso_to_auth_json into a local auth.json entry

4. import that entry into the multi-account pool



Import of ``xconsole_client`` is deferred so the main API can start even when

optional deps are missing. Registration endpoints then return a clear error

instead of crashing process startup.



``grok-build-auth`` is vendored in-tree (not a git submodule).

Legacy browser (DrissionPage) and grpc-session registration engines were removed.

"""

from __future__ import annotations



import json

import os

import re

import secrets

import sys

import threading

import time

import uuid

from pathlib import Path

from typing import Any



ROOT = Path(__file__).resolve().parent

GBA = ROOT / "grok-build-auth"

ADAPTER_BUILD = "2026-07-20-socks5-auth-bridge"

# Newly registered accounts often need a short settle window before probe.

REGISTER_PROBE_DELAY_SEC = float(

    os.environ.get("GROK2API_REG_PROBE_DELAY_SEC", "30") or 30

)

# When true, keep credentials after register without model probe (bulk mode).

REGISTER_SKIP_PROBE = str(

    os.environ.get("GROK2API_REG_SKIP_PROBE", "0") or "0"

).strip().lower() in {"1", "true", "yes", "on"}



YESCAPTCHA_KEY = (

    os.environ.get("GROK2API_YESCAPTCHA_KEY")

    or os.environ.get("YESCAPTCHA_API_KEY")

    or ""

).strip()



CAPTCHA_PROVIDER = (

    os.environ.get("GROK2API_CAPTCHA_PROVIDER")

    or os.environ.get("CAPTCHA_PROVIDER")

    or "local"

).strip().lower()

if CAPTCHA_PROVIDER not in {"local", "yescaptcha"}:

    CAPTCHA_PROVIDER = "local"



LOCAL_SOLVER_URL = (

    os.environ.get("GROK2API_LOCAL_SOLVER_URL")

    or os.environ.get("LOCAL_SOLVER_URL")

    or os.environ.get("GROK2API_YESCAPTCHA_ENDPOINT")

    or os.environ.get("YESCAPTCHA_ENDPOINT")

    or "http://127.0.0.1:5072"

).strip().rstrip("/")



# Hard cap for multi-thread registration concurrency only (captcha + xAI rate limits).

# Batch count is intentionally uncapped — only concurrency bounds parallelism.

MAX_CONCURRENCY = int(os.environ.get("GROK2API_REG_MAX_CONCURRENCY", "50") or 50)

DEFAULT_CONCURRENCY = int(os.environ.get("GROK2API_REG_CONCURRENCY", "1") or 1)

# Local multi-browser captcha pool size (turnstile-solver --thread).

DEFAULT_CAPTCHA_CONCURRENCY = int(os.environ.get("GROK2API_CAPTCHA_CONCURRENCY", "1") or 1)

MAX_CAPTCHA_CONCURRENCY = int(os.environ.get("GROK2API_CAPTCHA_MAX_CONCURRENCY", "50") or 50)



# When captcha_provider=local, registration must wait for the inline Turnstile

# Solver HTTP to answer before spawning workers. Prevents "already running but

# captcha always fails because solver is still booting / restarting".

LOCAL_SOLVER_WAIT_SEC = float(

    os.environ.get("GROK2API_LOCAL_SOLVER_WAIT_SEC", "120") or 120

)

LOCAL_SOLVER_POLL_SEC = float(

    os.environ.get("GROK2API_LOCAL_SOLVER_POLL_SEC", "1.0") or 1.0

)



# --------------------------------------------------------------------------- #

# session state

# --------------------------------------------------------------------------- #

_sessions: dict[str, dict[str, Any]] = {}

_batches: dict[str, dict[str, Any]] = {}

_lock = threading.RLock()

# batch_id -> True while a local ThreadPool spawner is alive in THIS process.

_active_batch_runners: dict[str, bool] = {}

# Local captcha: multi-browser pool (like grok_reg TabPool — one browser lane

# per captcha worker). Controlled by registration_config.captcha_concurrency and

# TURNSTILE_THREAD. Use a semaphore so N solves can run in parallel.

_local_captcha_limit = max(1, min(MAX_CAPTCHA_CONCURRENCY, DEFAULT_CAPTCHA_CONCURRENCY))

_local_captcha_sem = threading.Semaphore(_local_captcha_limit)

_local_captcha_active = 0

_local_captcha_active_lock = threading.Lock()





def get_local_captcha_concurrency() -> int:

    return int(_local_captcha_limit)





def get_local_captcha_active() -> int:

    with _local_captcha_active_lock:

        return int(_local_captcha_active)





def set_local_captcha_concurrency(value: int | str | None) -> int:

    """Set how many local Camoufox captcha solves may run at once (1..50)."""

    global _local_captcha_limit, _local_captcha_sem

    try:

        n = int(value if value is not None else DEFAULT_CAPTCHA_CONCURRENCY)

    except (TypeError, ValueError):

        n = DEFAULT_CAPTCHA_CONCURRENCY

    n = max(1, min(MAX_CAPTCHA_CONCURRENCY, n))

    _local_captcha_limit = n

    # Replace semaphore; in-flight tasks keep old slots until release.

    _local_captcha_sem = threading.Semaphore(n)

    return n





class _CaptchaSlot:

    """Context manager: acquire one captcha lane from the pool."""



    def __enter__(self):

        global _local_captcha_active

        _local_captcha_sem.acquire()

        with _local_captcha_active_lock:

            _local_captcha_active += 1

        return self



    def __exit__(self, exc_type, exc, tb):

        global _local_captcha_active

        with _local_captcha_active_lock:

            _local_captcha_active = max(0, int(_local_captcha_active) - 1)

        _local_captcha_sem.release()

        return False



# Cross-batch in-flight registration jobs. Configurable from UI

# (registration_config.global_inflight); env is only the boot default.

try:

    _GLOBAL_REG_INFLIGHT_MAX = max(

        1,

        min(

            64,

            int(os.environ.get("GROK2API_REG_GLOBAL_INFLIGHT", "1") or 1),

        ),

    )

except (TypeError, ValueError):

    _GLOBAL_REG_INFLIGHT_MAX = 1

# Dynamic admission (limit can change without restart).

_global_reg_inflight_limit = int(_GLOBAL_REG_INFLIGHT_MAX)

_global_reg_inflight_active = 0

_global_reg_inflight_cond = threading.Condition()

# Soft rate-limit signal: after device-flow / captcha storms, temporarily reduce

# new job admission without killing already-running workers.

_reg_soft_pause_until = 0.0

_reg_soft_pause_lock = threading.Lock()

_xconsole_ready = False

_xconsole_error: str | None = None





def get_global_reg_inflight_limit() -> int:

    with _global_reg_inflight_cond:

        return int(_global_reg_inflight_limit)





def get_global_reg_inflight_active() -> int:

    with _global_reg_inflight_cond:

        return int(_global_reg_inflight_active)





def set_global_reg_inflight_limit(value: int | str | None) -> int:

    """Update cross-batch admission cap at runtime (1..64)."""

    global _global_reg_inflight_limit

    try:

        n = int(value if value is not None else _GLOBAL_REG_INFLIGHT_MAX)

    except (TypeError, ValueError):

        n = int(_GLOBAL_REG_INFLIGHT_MAX)

    n = max(1, min(64, n))

    with _global_reg_inflight_cond:

        _global_reg_inflight_limit = n

        _global_reg_inflight_cond.notify_all()

    return n





# Background remote-upload queue: registration workers only enqueue emails so

# they never block on Grok2API/CPA HTTP. A single daemon flushes in groups.

_upload_queue_lock = threading.RLock()

_upload_queue_cond = threading.Condition(_upload_queue_lock)

_upload_queue: list[dict[str, Any]] = []  # {email, require_probe, session_id, batch_id, enqueued_at}

_upload_queue_pending: set[str] = set()

_upload_worker_started = False

_upload_worker_stop = False

# Flush when this many unique emails are queued, or after this idle wait.

_UPLOAD_GROUP_SIZE = max(

    1, min(200, int(os.environ.get("GROK2API_AUTO_UPLOAD_GROUP_SIZE", "20") or 20))

)

_UPLOAD_FLUSH_IDLE_SEC = max(

    0.5,

    min(30.0, float(os.environ.get("GROK2API_AUTO_UPLOAD_FLUSH_IDLE_SEC", "3") or 3)),

)





def _upload_group_size() -> int:

    try:

        return max(

            1,

            min(

                200,

                int(os.environ.get("GROK2API_AUTO_UPLOAD_GROUP_SIZE", str(_UPLOAD_GROUP_SIZE)) or 20),

            ),

        )

    except (TypeError, ValueError):

        return 20





def _upload_flush_idle_sec() -> float:

    try:

        return max(

            0.5,

            min(

                30.0,

                float(

                    os.environ.get(

                        "GROK2API_AUTO_UPLOAD_FLUSH_IDLE_SEC", str(_UPLOAD_FLUSH_IDLE_SEC)

                    )

                    or 3

                ),

            ),

        )

    except (TypeError, ValueError):

        return 3.0





def _sync_upload_emails(

    emails: list[str],

    *,

    require_probe: bool = True,

    batch_size: int | None = None,

) -> dict[str, Any]:

    """Blocking remote sync (used by the background uploader only)."""

    clean: list[str] = []

    seen: set[str] = set()

    for email in emails or []:

        key = str(email or "").strip().lower()

        if not key or key in seen:

            continue

        seen.add(key)

        clean.append(key)

    if not clean:

        return {"ok": True, "uploaded": 0, "total": 0, "emails": [], "skipped": ["no emails"]}

    size = batch_size if batch_size is not None else max(1, len(clean))

    try:

        import register_pro_store as _store



        return _store.sync_accounts_after_probe(

            clean,

            batch_size=size,

            require_probe=require_probe,

        )

    except TypeError:

        try:

            import register_pro_store as _store



            return _store.sync_accounts_after_probe(clean, batch_size=size)

        except Exception as exc:  # noqa: BLE001

            return {

                "ok": False,

                "error": str(exc)[:240],

                "total": len(clean),

                "emails": clean,

            }

    except Exception as exc:  # noqa: BLE001

        return {"ok": False, "error": str(exc)[:240], "total": len(clean), "emails": clean}





def _apply_auto_upload_result(

    emails: list[str],

    result: dict[str, Any],

    *,

    session_ids: list[str] | None = None,

    batch_ids: list[str] | None = None,

) -> None:

    """Attach upload result to related sessions / batches (best-effort)."""

    clean = {

        str(e or "").strip().lower()

        for e in (emails or [])

        if str(e or "").strip()

    }

    sid_set = {str(s) for s in (session_ids or []) if s}

    bid_set = {str(b) for b in (batch_ids or []) if b}

    uploaded = int(result.get("uploaded") or 0) if isinstance(result, dict) else 0

    total = int(result.get("total") or len(clean) or 0) if isinstance(result, dict) else len(clean)

    ok = bool(result.get("ok")) if isinstance(result, dict) else False

    err = str(result.get("error") or "")[:200] if isinstance(result, dict) else ""

    with _lock:

        for sid, sess in list(_sessions.items()):

            if not isinstance(sess, dict):

                continue

            em = str(sess.get("email") or "").strip().lower()

            if sid_set and sid not in sid_set and em not in clean:

                continue

            if not sid_set and em not in clean:

                continue

            prev = sess.get("auto_upload") if isinstance(sess.get("auto_upload"), dict) else {}

            sess["auto_upload"] = {

                **(prev or {}),

                **(result if isinstance(result, dict) else {}),

                "queued": False,

                "async": True,

                "finished_at": _now(),

            }

            # Don't rewrite terminal success message unless still showing queued.

            msg = str(sess.get("message") or "")

            if "排队" in msg or "远端同步" not in msg:

                if ok:

                    sess["message"] = (msg.rstrip("。") + f"。 远端同步 {uploaded}/{total}").strip()

                elif err:

                    sess["message"] = (msg.rstrip("。") + f"。 远端同步失败：{err[:120]}").strip()

            sess["updated_at"] = _now()

            _mirror_reg_sess(sid, sess)

        for bid, batch in list(_batches.items()):

            if not isinstance(batch, dict):

                continue

            owns = False

            if bid_set and bid in bid_set:

                owns = True

            elif sid_set and any(str(s) in sid_set for s in (batch.get("session_ids") or [])):

                owns = True

            elif clean:

                # Match by session emails belonging to this batch.

                for sid0 in list(batch.get("session_ids") or []):

                    sess0 = _sessions.get(str(sid0)) or {}

                    em0 = str(sess0.get("email") or "").strip().lower()

                    if em0 in clean:

                        owns = True

                        break

            if not owns:

                continue

            prev = batch.get("auto_upload") if isinstance(batch.get("auto_upload"), dict) else {}

            prev_up = int(prev.get("uploaded") or 0) if isinstance(prev, dict) else 0

            prev_tot = int(prev.get("total") or 0) if isinstance(prev, dict) else 0

            batch["auto_upload"] = {

                "ok": ok if not prev else (bool(prev.get("ok")) and ok),

                "uploaded": prev_up + uploaded,

                "total": prev_tot + total,

                "async": True,

                "last_error": err or prev.get("last_error"),

                "mode": "grouped_async",

                "finished_at": _now(),

            }

            batch["updated_at"] = _now()

            _mirror_reg_batch(bid, dict(batch))





def _flush_upload_queue_once(force_all: bool = False) -> dict[str, Any] | None:

    """Pop one group (or all if force_all) and upload it. Returns last result."""

    group_size = _upload_group_size()

    with _upload_queue_cond:

        if not _upload_queue:

            return None

        if not force_all and len(_upload_queue) < group_size:

            # Caller decides whether idle timeout warrants a partial flush.

            pass

        take_n = len(_upload_queue) if force_all else min(len(_upload_queue), group_size)

        if take_n <= 0:

            return None

        items = _upload_queue[:take_n]

        del _upload_queue[:take_n]

        for it in items:

            _upload_queue_pending.discard(str(it.get("email") or ""))

    # Prefer require_probe=False if any item was skip-probe; else True.

    require_probe = True

    emails: list[str] = []

    session_ids: list[str] = []

    batch_ids: list[str] = []

    for it in items:

        em = str(it.get("email") or "").strip().lower()

        if not em:

            continue

        emails.append(em)

        if not it.get("require_probe", True):

            require_probe = False

        if it.get("session_id"):

            session_ids.append(str(it["session_id"]))

        if it.get("batch_id"):

            batch_ids.append(str(it["batch_id"]))

    if not emails:

        return None

    print(

        f"[auto-upload] flushing group n={len(emails)} require_probe={require_probe} "

        f"queue_left={len(_upload_queue)}"

    )

    result = _sync_upload_emails(

        emails,

        require_probe=require_probe,

        batch_size=max(1, len(emails)),

    )

    try:

        _apply_auto_upload_result(

            emails, result, session_ids=session_ids, batch_ids=batch_ids

        )

    except Exception as exc:  # noqa: BLE001

        print(f"[auto-upload] apply result error: {exc}")

    ok = bool(result.get("ok")) if isinstance(result, dict) else False

    print(

        f"[auto-upload] group done ok={ok} uploaded={result.get('uploaded')} "

        f"total={result.get('total')} err={str(result.get('error') or '')[:120]}"

    )

    return result





def _upload_worker_loop() -> None:

    idle = _upload_flush_idle_sec()

    while True:

        with _upload_queue_cond:

            if _upload_worker_stop and not _upload_queue:

                return

            if not _upload_queue:

                _upload_queue_cond.wait(timeout=1.0)

                continue

            # Wait until group full or idle timeout since first item.

            first_at = float(_upload_queue[0].get("enqueued_at") or _now())

            group_size = _upload_group_size()

            while (

                not _upload_worker_stop

                and len(_upload_queue) < group_size

                and (_now() - first_at) < idle

            ):

                remaining = idle - (_now() - first_at)

                if remaining <= 0:

                    break

                _upload_queue_cond.wait(timeout=min(0.5, remaining))

                if _upload_queue:

                    first_at = float(_upload_queue[0].get("enqueued_at") or first_at)

            force_all = bool(_upload_worker_stop)

        try:

            _flush_upload_queue_once(force_all=force_all)

        except Exception as exc:  # noqa: BLE001

            print(f"[auto-upload] worker flush error: {exc}")

            time.sleep(0.5)





def _ensure_upload_worker() -> None:

    global _upload_worker_started

    with _upload_queue_lock:

        if _upload_worker_started:

            return

        _upload_worker_started = True

        threading.Thread(

            target=_upload_worker_loop,

            daemon=True,

            name="gba-auto-upload",

        ).start()





def _enqueue_auto_upload_emails(

    emails: list[str],

    *,

    require_probe: bool = True,

    session_id: str | None = None,

    batch_id: str | None = None,

) -> dict[str, Any] | None:

    """Queue emails for grouped async remote upload; never blocks on HTTP.



    Returns a queued marker so callers can show progress without waiting.

    """

    clean: list[str] = []

    seen: set[str] = set()

    for email in emails or []:

        key = str(email or "").strip().lower()

        if not key or key in seen:

            continue

        seen.add(key)

        clean.append(key)

    if not clean:

        return None

    _ensure_upload_worker()

    now = _now()

    queued = 0

    with _upload_queue_cond:

        for em in clean:

            if em in _upload_queue_pending:

                continue

            _upload_queue.append(

                {

                    "email": em,

                    "require_probe": bool(require_probe),

                    "session_id": session_id or "",

                    "batch_id": batch_id or "",

                    "enqueued_at": now,

                }

            )

            _upload_queue_pending.add(em)

            queued += 1

        _upload_queue_cond.notify()

    return {

        "ok": True,

        "queued": True,

        "async": True,

        "mode": "grouped_async",

        "enqueued": queued,

        "total": len(clean),

        "emails": clean,

        "require_probe": bool(require_probe),

        "queue_depth": len(_upload_queue),

        "group_size": _upload_group_size(),

    }





def _immediate_auto_upload_emails(

    emails: list[str],

    *,

    require_probe: bool = True,

    session_id: str | None = None,

    batch_id: str | None = None,

) -> dict[str, Any] | None:

    """Compatibility wrapper: enqueue for grouped async upload (non-blocking)."""

    return _enqueue_auto_upload_emails(

        emails,

        require_probe=require_probe,

        session_id=session_id,

        batch_id=batch_id,

    )





def _note_reg_pressure(reason: str = "", *, pause_sec: float | None = None) -> None:

    """Backoff new admissions briefly when upstream rate-limits hit."""

    global _reg_soft_pause_until

    try:

        sec = float(

            pause_sec

            if pause_sec is not None

            else (os.environ.get("GROK2API_REG_SOFT_PAUSE_SEC", "8") or 8)

        )

    except (TypeError, ValueError):

        sec = 8.0

    sec = max(1.0, min(60.0, sec))

    with _reg_soft_pause_lock:

        _reg_soft_pause_until = max(_reg_soft_pause_until, time.time() + sec)

    if reason:

        print(f"[registration] soft-pause {sec:.0f}s ({reason})")





def clear_reg_soft_pause() -> None:

    """Clear soft admission pause (call on stop / new batch start)."""

    global _reg_soft_pause_until

    with _reg_soft_pause_lock:

        _reg_soft_pause_until = 0.0





def reset_reg_admission_counters() -> None:

    """Emergency reset of leaked admission counters (stop-all / process recover)."""

    global _global_reg_inflight_active

    with _global_reg_inflight_cond:

        if _global_reg_inflight_active:

            print(

                f"[registration] reset admission active "

                f"{_global_reg_inflight_active} -> 0 (limit={_global_reg_inflight_limit})"

            )

        _global_reg_inflight_active = 0

        _global_reg_inflight_cond.notify_all()

    clear_reg_soft_pause()





def _wait_reg_admission(*, check_cancel=None) -> None:

    """Block until global inflight slot is free and soft-pause window ends."""

    global _global_reg_inflight_active

    last_log = 0.0

    while True:

        if check_cancel is not None:

            try:

                check_cancel()

            except Exception:

                raise

        with _reg_soft_pause_lock:

            wait = _reg_soft_pause_until - time.time()

        if wait > 0:

            now = time.time()

            if now - last_log > 5.0:

                print(

                    f"[registration] admission soft-pause "

                    f"{wait:.1f}s left (active={get_global_reg_inflight_active()}/"

                    f"{get_global_reg_inflight_limit()})"

                )

                last_log = now

            time.sleep(min(1.0, wait))

            continue

        with _global_reg_inflight_cond:

            if _global_reg_inflight_active < _global_reg_inflight_limit:

                _global_reg_inflight_active += 1

                return

            now = time.time()

            if now - last_log > 5.0:

                print(

                    f"[registration] admission full "

                    f"{_global_reg_inflight_active}/{_global_reg_inflight_limit}"

                )

                last_log = now

            _global_reg_inflight_cond.wait(timeout=0.15)





def _release_reg_admission() -> None:

    global _global_reg_inflight_active

    with _global_reg_inflight_cond:

        _global_reg_inflight_active = max(0, int(_global_reg_inflight_active) - 1)

        _global_reg_inflight_cond.notify_all()



# How many jobs may be pre-created (mailbox + session) beyond the live concurrency

# cap. Keep small so stop/cancel doesn't waste dozens of mailboxes.

REG_PREFETCH_SLOTS = int(os.environ.get("GROK2API_REG_PREFETCH_SLOTS", "1") or 1)



# Default gap between successive job *submits* when caller/config omits stagger_ms.

# Actual value always comes from the user setting when provided — no provider floor.

try:

    REG_DEFAULT_STAGGER_MS = max(

        0,

        min(10_000, int(os.environ.get("GROK2API_REG_STAGGER_MS", "800") or 800)),

    )

except (TypeError, ValueError):

    REG_DEFAULT_STAGGER_MS = 800





def _effective_reg_stagger_ms(

    stagger_ms: int | float | None,

    *,

    captcha_provider: str | None = None,

) -> int:

    """Clamp stagger to 0..10000. Respects the configured value as-is (no forced floor)."""

    del captcha_provider  # kept for call-site compatibility only

    try:

        stagger = int(stagger_ms if stagger_ms is not None else REG_DEFAULT_STAGGER_MS)

    except (TypeError, ValueError):

        stagger = REG_DEFAULT_STAGGER_MS

    return max(0, min(stagger, 10_000))





def _now() -> float:

    return time.time()





def _reg_redis() -> bool:

    """The registration-only server has no Redis dependency."""

    return False





# Kept for the local batch heartbeat loop (full multi-worker stack used Redis TTL).

# Lite mode only sleeps on this interval; ownership is process-local.

try:

    REG_BATCH_RUNNER_LOCK_TTL = max(

        15,

        min(600, int(os.environ.get("GROK2API_REG_RUNNER_LOCK_TTL", "90") or 90)),

    )

except (TypeError, ValueError):

    REG_BATCH_RUNNER_LOCK_TTL = 90





def _renew_batch_runner(_batch_id: str, _token: str | None) -> None:

    """Local batch ownership lives for the lifetime of this process."""





def _try_acquire_batch_runner(batch_id: str) -> tuple[bool, str | None]:

    """Claim exclusive spawner ownership for one local process."""

    bid = str(batch_id or "").strip()

    if not bid:

        return False, None

    with _lock:

        if _active_batch_runners.get(bid):

            return False, None

        _active_batch_runners[bid] = True

    return True, f"{uuid.uuid4().hex}|{os.getpid()}|{_now():.0f}"





def _release_batch_runner(batch_id: str, _token: str | None) -> None:

    bid = str(batch_id or "").strip()

    with _lock:

        _active_batch_runners.pop(bid, None)





def _snapshot_reg_config(

    *,

    captcha_provider: str,

    yescaptcha_key: str,

    proxy: str,

    moemail_api_key: str | None,

    moemail_base_url: str | None,

    prefix: str | None,

    domain: str | None,

    expiry_ms: int | None,

    concurrency: int,

    stagger_ms: int,

    mail_provider: str | None = None,

    captcha_use_proxy: bool | None = None,

) -> dict[str, Any]:

    """Config snapshot kept with the in-memory/Redis batch while it is running."""

    use_proxy = True if captcha_use_proxy is None else bool(captcha_use_proxy)

    return {

        "captcha_provider": captcha_provider,

        "yescaptcha_key": yescaptcha_key if captcha_provider == "yescaptcha" else "",

        "proxy": proxy or "",

        "moemail_api_key": moemail_api_key or "",

        "moemail_base_url": moemail_base_url or "",

        "prefix": prefix or "",

        "domain": domain or "",

        "expiry_ms": expiry_ms,

        "concurrency": concurrency,

        "stagger_ms": stagger_ms,

        "local_solver_url": "http://127.0.0.1:5072",

        "mail_provider": (mail_provider or "moemail").strip().lower() or "moemail",

        "captcha_use_proxy": use_proxy,

    }





class _RegCancelled(Exception):

    """Cooperative cancel for in-flight registration workers."""





_TERMINAL_STATUSES = frozenset(

    {

        "imported",

        "success",

        "completed",

        "error",

        "failed",

        "probe_failed",

        "expired",

        "protocol_error",

        "protocol_blocked",

        "cancelled",

        "stopped",

    }

)





def _is_cancel_status(status: str | None) -> bool:

    return str(status or "").lower() in ("cancelled", "stopped", "stopping")





def _session_cancel_requested(sess: dict[str, Any] | None) -> bool:

    if not isinstance(sess, dict):

        return False

    if sess.get("cancel_requested"):

        return True

    return _is_cancel_status(sess.get("status"))





def _mirror_reg_sess(_sid: str, _sess: dict[str, Any] | None) -> None:

    """Compatibility hook retained for local in-memory sessions only."""





def _mirror_reg_batch(_batch_id: str, _batch: dict[str, Any] | None) -> None:

    """Compatibility hook retained for local in-memory batches only."""





def _record_register_task(

    *,

    task_id: str | None,

    summary: str,

    status: str,

    ok: bool | None = None,

    progress_done: int = 0,

    progress_total: int = 0,

    finished: bool = True,

    detail: dict[str, Any] | None = None,

) -> None:

    # The pro UI reads live registration session and batch state directly.

    return None





def _session_task_log_payload(sess: dict[str, Any] | None) -> dict[str, Any]:

    s = sess if isinstance(sess, dict) else {}

    st = str(s.get("status") or "done").lower() or "done"

    ok: bool | None

    if st in ("imported", "success", "completed", "done"):

        ok = True

    elif st in ("error", "failed", "probe_failed", "expired", "protocol_error", "protocol_blocked"):

        ok = False

    elif st in ("cancelled", "stopped"):

        ok = False

    else:

        ok = None

    email = str(s.get("email") or "").strip()

    summary = str(s.get("message") or "").strip()

    if not summary:

        summary = f"协议注册 {email or s.get('id') or ''}".strip()

    return {

        "task_id": str(s.get("id") or ""),

        "summary": summary,

        "status": st,

        "ok": ok,

        "progress_done": 1 if st in _TERMINAL_STATUSES else 0,

        "progress_total": 1,

        "finished": st in _TERMINAL_STATUSES,

        "detail": {

            "session_id": s.get("id"),

            "batch_id": s.get("batch_id"),

            "email": email or None,

            "status": st,

            "error": s.get("error"),

            "imported_account_ids": list(s.get("imported_account_ids") or [])[:20],

            "adapter_build": s.get("adapter_build") or ADAPTER_BUILD,

        },

    }





def _load_reg_sess(sid: str) -> dict[str, Any] | None:

    with _lock:

        return _sessions.get(sid)





def _load_reg_batch(batch_id: str) -> dict[str, Any] | None:

    with _lock:

        return _batches.get(batch_id)





def _clean_old_sessions() -> None:

    cutoff = _now() - 6 * 3600

    for sid in list(_sessions.keys()):

        sess = _sessions.get(sid) or {}

        if float(sess.get("updated_at") or 0) < cutoff:

            _sessions.pop(sid, None)

            _mirror_reg_sess(sid, None)





def _compact_session(sess: dict[str, Any]) -> dict[str, Any]:

    out = dict(sess)

    out.pop("_client", None)

    out.pop("_oauth_client", None)

    out.pop("password", None)

    out.pop("yescaptcha_key", None)

    # Prefer explicit imported ids; fall back to auth_json summary for UI/logs.

    imported_ids = list(out.get("imported_account_ids") or [])

    imported_accounts = list(out.get("imported_accounts") or [])

    aj = out.get("auth_json")

    if isinstance(aj, dict):

        rows = [x for x in (aj.get("imported") or []) if isinstance(x, dict)]

        out["auth_json_count"] = len(rows)

        if not imported_ids:

            imported_ids = [str(x.get("id")) for x in rows if x.get("id")]

        if not imported_accounts:

            imported_accounts = [

                {"id": x.get("id"), "email": x.get("email")}

                for x in rows

                if x.get("id") or x.get("email")

            ]

    elif aj is not None:

        try:

            out["auth_json_count"] = len(aj)  # type: ignore[arg-type]

        except Exception:

            out["auth_json_count"] = 0

    if imported_ids:

        out["imported_account_ids"] = imported_ids

    if imported_accounts:

        out["imported_accounts"] = imported_accounts

    # Drop full auth payload from list/poll responses (secrets).

    out.pop("auth_json", None)

    return out





def ensure_xconsole() -> None:

    """Ensure vendored grok-build-auth/xconsole_client is importable.



    Raises RuntimeError with actionable message when unavailable.

    Safe to call multiple times.

    """

    global _xconsole_ready, _xconsole_error

    if _xconsole_ready:

        return

    if _xconsole_error:

        raise RuntimeError(_xconsole_error)



    if not GBA.is_dir():

        _xconsole_error = (

            "grok-build-auth 目录不存在。请确认仓库完整检出，"

            "或重新 clone 本项目。"

        )

        raise RuntimeError(_xconsole_error)



    xc = GBA / "xconsole_client"

    if not xc.is_dir():

        _xconsole_error = (

            "grok-build-auth/xconsole_client 不存在。"

            "请确认仓库完整检出（该目录已内置，不再使用 git submodule）。"

        )

        raise RuntimeError(_xconsole_error)



    # Put vendored package root on sys.path so `import xconsole_client` works.

    gba_str = str(GBA.resolve())

    if gba_str not in sys.path:

        sys.path.insert(0, gba_str)



    try:

        # Import side-effect: validate package is loadable.

        import xconsole_client  # noqa: F401

        from xconsole_client import (  # noqa: F401

            XConsoleAuthClient,

            YesCaptchaSolver,

            create_solver,

            xai_oauth_login_protocol,

        )

        from xconsole_client.oauth_protocol import (  # noqa: F401

            extract_cookies_from_auth_client,

        )

        from xconsole_client.xai_oauth import (  # noqa: F401

            CLIPROXYAPI_GROK_HEADERS,

            build_cliproxyapi_auth_record,

        )

    except ModuleNotFoundError as e:

        missing = getattr(e, "name", None) or str(e)

        if missing in ("curl_cffi", "requests") or "curl_cffi" in str(e) or "requests" in str(e):

            _xconsole_error = (

                f"注册机依赖缺失: {missing}。请执行: pip install -r requirements.txt"

            )

        else:

            _xconsole_error = (

                f"无法导入 xconsole_client ({e})。请执行: pip install -r requirements.txt"

            )

        raise RuntimeError(_xconsole_error) from e

    except Exception as e:  # noqa: BLE001

        _xconsole_error = f"加载 grok-build-auth 失败: {e}"

        raise RuntimeError(_xconsole_error) from e



    _xconsole_ready = True

    _xconsole_error = None





def _local_solver_base_url(url: str | None = None) -> str:

    """Always pin local captcha to the in-container inline solver."""

    raw = (

        (url or "").strip()

        or (LOCAL_SOLVER_URL or "").strip()

        or os.environ.get("GROK2API_LOCAL_SOLVER_URL")

        or os.environ.get("LOCAL_SOLVER_URL")

        or "http://127.0.0.1:5072"

    ).strip().rstrip("/")

    # Registration must never hit an external "local" URL; force loopback.

    if (

        not raw

        or "127.0.0.1" not in raw

        and "localhost" not in raw

    ):

        return "http://127.0.0.1:5072"

    return raw





def probe_local_solver(

    url: str | None = None,

    *,

    timeout: float = 2.0,

) -> dict[str, Any]:

    """Probe inline Turnstile Solver readiness.



    HTTP up is enough to accept createTask (lazy browser mode warms on first

    solve). We prefer ``/health`` but also accept ``/`` returning any HTTP body.

    """

    base = _local_solver_base_url(url)

    out: dict[str, Any] = {

        "ok": False,

        "ready": False,

        "url": base,

        "http_up": False,

        "lazy": None,

        "pool_ready": None,

        # Live pool size fields from /health (critical for power-mode hot-apply).

        "thread": None,

        "threads": None,

        "owned": None,

        "queue": None,

        "in_flight": None,

        "browser_type": None,

        "error": None,

        "status_code": None,

    }

    try:

        import urllib.error

        import urllib.request

    except Exception as e:  # noqa: BLE001

        out["error"] = f"urllib unavailable: {e}"

        return out



    def _absorb_health(data: dict[str, Any]) -> None:

        """Copy structured /health fields so callers can compare pool size."""

        out["lazy"] = data.get("lazy")

        out["pool_ready"] = data.get("pool_ready")

        out["browser_type"] = data.get("browser_type")

        for key in ("thread", "threads", "owned", "queue", "in_flight"):

            if key not in data:

                continue

            try:

                out[key] = int(data.get(key))

            except (TypeError, ValueError):

                out[key] = data.get(key)



    # 1) /health — structured

    try:

        req = urllib.request.Request(

            f"{base}/health",

            headers={"Accept": "application/json"},

            method="GET",

        )

        with urllib.request.urlopen(req, timeout=max(0.5, float(timeout))) as resp:

            out["status_code"] = int(getattr(resp, "status", 200) or 200)

            body = resp.read().decode("utf-8", errors="replace")

        out["http_up"] = True

        try:

            data = json.loads(body) if body else {}

        except Exception:

            data = {}

        if isinstance(data, dict):

            _absorb_health(data)

            # Solver process is ready when /health answers ok=true.

            # pool_ready may still be false under TURNSTILE_LAZY=1 — that is OK;

            # browsers warm on the first captcha task.

            if data.get("ok") is False:

                out["error"] = f"solver health ok=false body={body[:200]}"

            else:

                out["ok"] = True

                out["ready"] = True

                return out

        else:

            out["ok"] = True

            out["ready"] = True

            return out

    except Exception as e:  # noqa: BLE001

        out["error"] = f"health: {e}"



    # 2) fallback: any response from /

    try:

        req = urllib.request.Request(f"{base}/", method="GET")

        with urllib.request.urlopen(req, timeout=max(0.5, float(timeout))) as resp:

            out["status_code"] = int(getattr(resp, "status", 200) or 200)

            _ = resp.read(256)

        out["http_up"] = True

        out["ok"] = True

        out["ready"] = True

        out["error"] = None

        return out

    except Exception as e:  # noqa: BLE001

        if not out.get("error"):

            out["error"] = f"root: {e}"

        else:

            out["error"] = f"{out['error']}; root: {e}"

        return out





def resize_local_solver(

    thread: int | str | None,

    url: str | None = None,

    *,

    timeout: float = 20.0,

) -> dict[str, Any]:

    """Ask a live Turnstile Solver to resize its browser pool in-process.



    Prefers ``POST /resize`` (no process kill). Returns ok=False when the

    endpoint is missing/unreachable so callers can fall back to process restart.

    """

    base = _local_solver_base_url(url)

    try:

        n = max(1, min(MAX_CAPTCHA_CONCURRENCY, int(thread if thread is not None else 1)))

    except (TypeError, ValueError):

        n = 1

    out: dict[str, Any] = {

        "ok": False,

        "url": base,

        "thread": n,

        "method": "http_resize",

        "error": None,

    }

    try:

        import urllib.error

        import urllib.request

    except Exception as e:  # noqa: BLE001

        out["error"] = f"urllib unavailable: {e}"

        return out



    body = json.dumps({"thread": n}).encode("utf-8")

    last_err = ""

    for path in ("/resize", "/resize/"):

        try:

            req = urllib.request.Request(

                f"{base}{path}",

                data=body,

                headers={

                    "Accept": "application/json",

                    "Content-Type": "application/json",

                },

                method="POST",

            )

            with urllib.request.urlopen(req, timeout=max(1.0, float(timeout))) as resp:

                status = int(getattr(resp, "status", 200) or 200)

                raw = resp.read().decode("utf-8", errors="replace")

            try:

                data = json.loads(raw) if raw else {}

            except Exception:

                data = {}

            if not isinstance(data, dict):

                data = {"raw": raw[:200]}

            out["status_code"] = status

            out["response"] = data

            if data.get("ok") is False:

                out["error"] = str(data.get("error") or data.get("errorDescription") or raw[:200])

                return out

            # Prefer reported thread from solver.

            try:

                reported = int(data.get("thread") or data.get("threads") or n)

            except (TypeError, ValueError):

                reported = n

            out["ok"] = True

            out["thread"] = reported

            out["previous_thread"] = data.get("previous_thread")

            out["resized"] = bool(data.get("resized", True))

            out["pool_ready"] = data.get("pool_ready")

            return out

        except Exception as e:  # noqa: BLE001

            last_err = str(e)

            # 404/405 → try next path or give up for process-restart fallback.

            continue

    out["error"] = last_err or "resize endpoint unavailable"

    return out





def wait_for_local_solver(

    url: str | None = None,

    *,

    timeout_sec: float | None = None,

    poll_sec: float | None = None,

    progress: Any | None = None,

) -> dict[str, Any]:

    """Block until local Turnstile Solver is HTTP-ready, or fail.



    Used by registration start so workers never race a still-booting solver.

    """

    base = _local_solver_base_url(url)

    try:

        wait_s = float(

            timeout_sec

            if timeout_sec is not None

            else LOCAL_SOLVER_WAIT_SEC

        )

    except (TypeError, ValueError):

        wait_s = 120.0

    wait_s = max(1.0, min(wait_s, 600.0))

    try:

        every = float(

            poll_sec if poll_sec is not None else LOCAL_SOLVER_POLL_SEC

        )

    except (TypeError, ValueError):

        every = 1.0

    every = max(0.2, min(every, 5.0))



    deadline = time.time() + wait_s

    last: dict[str, Any] = {

        "ok": False,

        "ready": False,

        "url": base,

        "waited_sec": 0.0,

        "error": "not started",

    }

    started = time.time()

    attempt = 0

    while True:

        attempt += 1

        last = probe_local_solver(base, timeout=min(2.0, every + 0.5))

        last["waited_sec"] = round(time.time() - started, 2)

        last["attempts"] = attempt

        last["url"] = base

        if last.get("ready"):

            last["ok"] = True

            if progress:

                try:

                    progress(

                        f"本地过盾已就绪 url={base} waited={last['waited_sec']}s"

                    )

                except Exception:

                    pass

            return last

        remaining = deadline - time.time()

        if remaining <= 0:

            break

        msg = (

            f"等待本地过盾就绪… url={base} "

            f"attempt={attempt} left={remaining:.0f}s "

            f"err={last.get('error') or 'down'}"

        )

        if progress:

            try:

                progress(msg)

            except Exception:

                pass

        if attempt == 1 or attempt % 5 == 0:

            print(f"[grok-build-auth] {msg}")

        time.sleep(min(every, max(0.2, remaining)))



    last["ok"] = False

    last["ready"] = False

    last["error"] = (

        f"本地过盾服务未在 {wait_s:.0f}s 内就绪 "

        f"(url={base}; last={last.get('error') or 'unreachable'}). "

        f"请确认 inline Turnstile Solver 已启动（entrypoint / TURNSTILE_PORT），"

        f"或稍后重试注册。"

    )

    return last





def registration_available() -> dict[str, Any]:

    """Non-raising health probe for admin UI / startup logs."""

    moemail_configured = bool(

        os.environ.get("GROK2API_MOEMAIL_API_KEY")

        or os.environ.get("MOEMAIL_API_KEY")

    )

    try:

        from register_pro_config import MOEMAIL_API_KEY as _cfg_moemail



        moemail_configured = moemail_configured or bool(_cfg_moemail)

    except Exception:

        pass

    provider = (

        CAPTCHA_PROVIDER

        or os.environ.get("GROK2API_CAPTCHA_PROVIDER")

        or os.environ.get("CAPTCHA_PROVIDER")

        or "local"

    ).strip().lower()

    if provider not in {"local", "yescaptcha"}:

        provider = "local"

    local_url = _local_solver_base_url(

        LOCAL_SOLVER_URL

        or os.environ.get("GROK2API_LOCAL_SOLVER_URL")

        or os.environ.get("LOCAL_SOLVER_URL")

        or ""

    )

    captcha_ready = bool(local_url) if provider == "local" else bool(YESCAPTCHA_KEY)

    local_solver_live: dict[str, Any] | None = None

    if provider == "local":

        local_solver_live = probe_local_solver(local_url, timeout=1.2)

        captcha_ready = bool(local_solver_live.get("ready"))

    try:

        ensure_xconsole()

        out = {

            "ok": True,

            "available": True,

            "engine": "dongguatanglinux/grok-build-auth",

            "path": str(GBA),

            "vendored": True,

            "adapter_build": ADAPTER_BUILD,

            "captcha_provider": provider,

            "local_solver_url": local_url,

            "local_solver_configured": bool(local_url),

            "local_solver_ready": (

                bool(local_solver_live.get("ready")) if local_solver_live else None

            ),

            "local_solver_probe": local_solver_live,

            "yescaptcha_configured": (

                captcha_ready if provider == "local" else bool(YESCAPTCHA_KEY)

            ),

            "moemail_configured": moemail_configured,

        }

        return out

    except Exception as e:  # noqa: BLE001

        return {

            "ok": False,

            "available": False,

            "engine": "dongguatanglinux/grok-build-auth",

            "path": str(GBA),

            "vendored": True,

            "adapter_build": ADAPTER_BUILD,

            "error": str(e),

            "captcha_provider": provider,

            "local_solver_url": local_url,

            "local_solver_configured": bool(local_url),

            "local_solver_ready": (

                bool(local_solver_live.get("ready")) if local_solver_live else None

            ),

            "local_solver_probe": local_solver_live,

            "yescaptcha_configured": (

                captcha_ready if provider == "local" else bool(YESCAPTCHA_KEY)

            ),

            "moemail_configured": moemail_configured,

        }





def relogin_with_password(

    *,

    email: str,

    password: str,

    captcha_provider: str,

    yescaptcha_key: str = "",

    local_solver_url: str = "",

    proxy: str = "",

    on_progress=None,

) -> dict[str, Any]:

    """Protocol password relogin: captcha → CreateSession → new SSO → OAuth.



    Must mint a **new** SSO via password CreateSession (not reuse stored SSO).

    Browser/Camoufox only solves Turnstile; login is pure gRPC-web protocol.

    One Turnstile token is single-use — each outer pass re-solves captcha.

    """

    def progress(message: str) -> None:

        if callable(on_progress):

            on_progress(str(message))



    ensure_xconsole()

    email = str(email or "").strip().lower()

    password = str(password or "")

    if not email or not password:

        raise ValueError("账号或密码为空")



    from xconsole_client import XConsoleAuthClient, YesCaptchaSolver

    from xconsole_client import config as C



    progress("访问 xAI 登录页")

    # debug=True so CreateSession rejection reason lands in app log.

    client = XConsoleAuthClient(debug=True, proxy=proxy or "")

    client.visit_home()

    # Warm accounts host + scrape sitekey (same scraper registration uses).

    client.load_signup_page()

    sitekey = str(getattr(client, "turnstile_sitekey", None) or C.TURNSTILE_SITEKEY or "").strip()

    if not sitekey:

        raise RuntimeError("无法获取 x.ai Turnstile sitekey")

    signin_url = "https://accounts.x.ai/sign-in?redirect=grok-com"

    provider = str(captcha_provider or "local").strip().lower()

    if provider == "local":

        progress("等待本地过盾服务")

        endpoint = _local_solver_base_url(local_solver_url)

        ready = wait_for_local_solver(endpoint, timeout_sec=min(60.0, LOCAL_SOLVER_WAIT_SEC))

        if not ready.get("ready"):

            raise RuntimeError(ready.get("error") or "本地过盾未就绪")

        solver = YesCaptchaSolver(

            "local",

            endpoint=endpoint,

            timeout=120,

            poll_interval=1.0,

            on_progress=lambda _message: progress("正在过盾"),

        )

    elif provider == "yescaptcha":

        key = str(yescaptcha_key or YESCAPTCHA_KEY).strip()

        if not key:

            raise ValueError("YesCaptcha 模式缺少 Key")

        solver = YesCaptchaSolver(

            key,

            timeout=120,

            poll_interval=2.0,

            on_progress=lambda _message: progress("正在过盾"),

        )

    else:

        raise ValueError(f"未知过盾方式: {provider}")



    def _solve_turnstile(*, premium: bool = False) -> str:

        # captcha_use_proxy: align Turnstile browser egress with job proxy.

        use_premium = bool(premium) and provider != "local"

        captcha_proxy = None

        try:

            import register_pro_store as _store



            if bool(_store.get_registration_config(include_secrets=False).get("captcha_use_proxy", True)):

                captcha_proxy = (proxy or "").strip() or None

        except Exception:

            captcha_proxy = (proxy or "").strip() or None

        return solver.solve_turnstile(

            signin_url,

            sitekey,

            premium=use_premium,

            fallback_non_premium=True,

            proxy=captcha_proxy if provider == "local" else None,

        )



    def _attempt_login(*, pass_label: str, premium: bool) -> str | None:

        # Fresh captcha every pass. CreateSession retries=1: rejected token is dead.

        progress(f"正在过盾（{pass_label}）")

        turnstile = _solve_turnstile(premium=premium)

        if not turnstile:

            raise RuntimeError("过盾返回空 token")

        progress(f"过盾通过，协议密码登录 CreateSession（{pass_label}）")

        return client.obtain_session_via_password(

            email=email,

            password=password,

            turnstile_token=turnstile,

            referer=signin_url,

            retries=1,

        )



    # Up to 3 independent password-login passes, each with a fresh token.

    # Local Camoufox: hold captcha lock across solve + CreateSession so the

    # token is consumed immediately (no queue aging).

    max_passes = 3

    sso: str | None = None

    last_diag = ""



    def _run_passes() -> str | None:

        nonlocal last_diag

        out: str | None = None

        for i in range(1, max_passes + 1):

            premium = provider != "local" and i == 1

            out = _attempt_login(pass_label=f"第{i}轮", premium=premium)

            last_diag = str(getattr(client, "last_session_diagnostic", "") or "")

            if out:

                return out

            if i < max_passes:

                progress(f"第{i}轮 CreateSession 未拿到新 SSO，重新过盾再登录")

                time.sleep(0.8 * i)

        return out



    if provider == "local":

        # Original serial strategy: one local captcha/login flight at a time.

        with _CaptchaSlot():

            sso = _run_passes()

    else:

        sso = _run_passes()



    if not sso:

        raise RuntimeError(last_diag or client.last_session_diagnostic or "账号密码登录未取得 SSO")



    import sso_to_auth_json as sso_import



    progress("已取得新 SSO，正在换取 OAuth 凭证")

    token = sso_import.sso_to_token(sso)

    if not token or not token.get("access_token"):

        raise RuntimeError("已取得新 SSO，但 OAuth 凭证转换失败")

    _key, entry = sso_import.token_to_auth_entry(token, email=email)

    return {

        "email": email,

        "sso": sso,

        "access_token": token.get("access_token") or "",

        "refresh_token": token.get("refresh_token") or "",

        "id_token": token.get("id_token") or "",

        "expires_at": entry.get("expires_at") or "",

        "oidc_issuer": entry.get("oidc_issuer") or "https://auth.x.ai",

        "oidc_client_id": entry.get("oidc_client_id") or "",

    }







def _build_register_password(min_len: int = 14, max_len: int = 22) -> str:

    """Strong variable-length password (aligned with grok-register)."""

    import string



    length = secrets.randbelow(max(1, max_len - min_len + 1)) + min_len

    upper = string.ascii_uppercase

    lower = string.ascii_lowercase

    digits = string.digits

    specials = "!@#$%^&*_-+=?"

    pool = upper + lower + digits + specials

    required = [

        secrets.choice(upper),

        secrets.choice(lower),

        secrets.choice(digits),

        secrets.choice(specials),

    ]

    rest = [secrets.choice(pool) for _ in range(length - len(required))]

    chars = required + rest

    for i in range(len(chars) - 1, 0, -1):

        j = secrets.randbelow(i + 1)

        chars[i], chars[j] = chars[j], chars[i]

    password = "".join(chars)

    if not re.search(r"[A-Z]", password):

        password = password[:-1] + secrets.choice(upper)

    if not re.search(r"[a-z]", password):

        password = password[:-2] + secrets.choice(lower) + password[-1:]

    if not re.search(r"[0-9]", password):

        password = password[:-3] + secrets.choice(digits) + password[-2:]

    if not re.search(r"[!@#$%^&*_\-+=?]", password):

        password = password[:-4] + secrets.choice(specials) + password[-3:]

    return password





def build_register_profile() -> tuple[str, str, str]:

    """Diverse given/family names + strong password (mirror grok-register)."""

    given_name_pool = [

        "Neo", "Ethan", "Liam", "Noah", "Lucas", "Mason", "Ryan", "Leo",

        "Owen", "Aiden", "Elio", "Aron", "Ivan", "Nolan", "Evan", "Kai",

        "Caleb", "Adam", "Ezra", "Miles", "Logan", "Carter", "Hunter", "Jason",

        "Brian", "Dylan", "Alex", "Colin", "Blake", "Gavin", "Henry", "Julian",

        "Kevin", "Louis", "Marcus", "Nathan", "Oscar", "Peter", "Quinn", "Robin",

        "Simon", "Tristan", "Victor", "Wesley", "Xavier", "Yuri", "Zane", "Felix",

        "Aaron", "Damian", "Sofia", "Emma", "Olivia", "Ava", "Mia", "Luna",

        "Chloe", "Nora", "Ivy", "Zoe", "Ella", "Aria", "Maya", "Ruby",

        "Grace", "Hazel", "Iris", "Jade", "Leah", "Nina", "Tara", "Vera",

        "Daniel", "Michael", "James", "Robert", "David", "Thomas", "Andrew",

        "Matthew", "Joseph", "Samuel", "Benjamin", "Christopher", "Anthony",

        "William", "Alexander", "Sebastian", "Theodore", "Gabriel", "Mateo",

    ]

    family_name_pool = [

        "Lin", "Wang", "Zhao", "Liu", "Chen", "Zhang", "Xu", "Sun",

        "Guo", "He", "Yang", "Wu", "Zhou", "Tang", "Qin", "Shi",

        "Fang", "Peng", "Cao", "Deng", "Fan", "Fu", "Gao", "Han",

        "Hu", "Jiang", "Kong", "Lu", "Ma", "Nie", "Pan", "Qiao",

        "Ren", "Shao", "Tian", "Xie", "Yan", "Yao", "Yu", "Zeng",

        "Bai", "Duan", "Hou", "Jin", "Kang", "Luo", "Mao", "Song",

        "Wei", "Xiong",

        "Smith", "Johnson", "Brown", "Jones", "Miller", "Davis", "Wilson",

        "Moore", "Taylor", "Anderson", "Thomas", "Jackson", "White", "Harris",

        "Martin", "Thompson", "Garcia", "Martinez", "Robinson", "Clark",

        "Rodriguez", "Lewis", "Lee", "Walker", "Hall", "Allen", "Young",

        "King", "Wright", "Scott", "Green", "Baker", "Adams", "Nelson",

        "Hill", "Ramirez", "Campbell", "Mitchell", "Roberts", "Carter",

        "Phillips", "Evans", "Turner", "Torres", "Parker", "Collins",

        "Edwards", "Stewart", "Morris", "Murphy", "Cook", "Rogers", "Morgan",

        "Peterson", "Cooper", "Reed", "Bailey", "Bell", "Gomez", "Kelly",

        "Howard", "Ward", "Cox", "Diaz", "Richardson", "Wood", "Watson",

        "Brooks", "Bennett", "Gray", "James", "Reyes", "Cruz", "Hughes",

        "Price", "Myers", "Long", "Foster", "Sanders", "Ross", "Morales",

        "Powell", "Sullivan", "Russell", "Ortiz", "Jenkins", "Gutierrez",

        "Perry", "Butler", "Barnes", "Fisher", "Henderson", "Coleman",

        "Simmons", "Patterson", "Jordan", "Reynolds", "Hamilton", "Graham",

        "Kim", "Park", "Choi", "Nguyen", "Tran", "Patel", "Singh", "Khan",

        "Ali", "Hassan", "Ahmed", "Silva", "Santos", "Costa", "Oliveira",

    ]

    given_name = secrets.choice(given_name_pool)

    family_name = secrets.choice(family_name_pool)

    password = _build_register_password(14, 22)

    return given_name, family_name, password





# --------------------------------------------------------------------------- #

# mail provider: moemail / yyds / gptmail / cfmail / duckmail

# --------------------------------------------------------------------------- #

def _make_email_receiver(

    *,

    api_key: str | None = None,

    base_url: str | None = None,

    prefix: str | None = None,

    domain: str | None = None,

    expiry_ms: int | None = None,

    mail_provider: str | None = None,

):

    from moemail import create_mailbox, fetch_messages, normalize_mail_provider

    from register_pro_config import MOEMAIL_API_KEY, MOEMAIL_BASE_URL, MOEMAIL_DOMAIN, MOEMAIL_EXPIRY_MS



    key = (api_key or MOEMAIL_API_KEY or "").strip()

    base = (base_url or MOEMAIL_BASE_URL).rstrip("/")

    prov = normalize_mail_provider(mail_provider, base_url=base)



    # ---- Outmail (Outlook pool / anonymous temp) ----

    if prov == "outmail":

        import outmail_client as om

        try:

            import register_pro_store as _store

            reg_cfg = _store.get_registration_config(include_secrets=True)

        except Exception:

            reg_cfg = {}

        om_cfg = dict(reg_cfg or {})

        if base:

            om_cfg["outmail_api_base"] = base

        if key:

            om_cfg["outmail_api_key"] = key

        om.configure(om_cfg, merge=False)

        email_addr, dev_token = om.outmail_get_email_and_token()

        poll_timeout = int(om_cfg.get("outmail_poll_timeout_sec") or 180)

        poll_interval = float(om_cfg.get("outmail_poll_interval_sec") or 5)



        class _OutmailReceiver:

            def __init__(self, email: str, token: str):

                self.email = email

                self.email_id = email

                self.api_key = key

                self.base_url = base

                self.provider = "outmail"

                self.token = token



            def wait_for_code(

                self,

                timeout: float = 120,

                *,

                should_cancel=None,

                poll_interval: float | None = None,

            ) -> str:

                def _cancel() -> bool:

                    return bool(callable(should_cancel) and should_cancel())



                code = om.outmail_get_oai_code(

                    self.token,

                    timeout=int(timeout or poll_timeout or 180),

                    poll_interval=float(poll_interval if poll_interval is not None else 5),

                    cancel_callback=_cancel,

                )

                if not code:

                    raise TimeoutError(f"outmail code timeout for {self.email}")

                return str(code)



            def cleanup_success(self) -> None:

                try:

                    mailbox, _s, _r, mode = om.outmail_decode_token(

                        self.token, fallback_email=self.email

                    )

                    om.outmail_mark_mailbox_used(

                        mailbox or self.email, register_email=self.email, reason="success"

                    )

                    om.outmail_cleanup_mailbox(mailbox or self.email, mode=mode)

                except Exception as exc:  # noqa: BLE001

                    print(f"[outmail] cleanup skipped: {exc}", flush=True)



        return email_addr, _OutmailReceiver(email_addr, dev_token)



    # DuckMail public domains work without API key; others still require one.

    if prov != "duckmail" and not key:

        raise ValueError(

            "Mail API key missing. Set GROK2API_MOEMAIL_API_KEY or pass api_key."

        )

    # YYDS/GPTMail/CFMail/DuckMail: empty domain means provider-side auto/random pick.

    # Never bleed MoeMail's MOEMAIL_DOMAIN (default example.com) into them.

    if prov in {"yyds", "gptmail", "cfmail", "duckmail"}:

        dom = _pick_domain_from_pool(domain)

    else:

        dom = _pick_domain_from_pool(domain) or (MOEMAIL_DOMAIN or "").strip().lstrip("@").strip(".")

    # Random local-part only (no "grok-" brand prefix). Admin UI no longer exposes

    # a custom prefix field; ignore leftover config values for new mailboxes.

    pre = secrets.token_hex(5).lower()



    mailbox = create_mailbox(

        provider=prov,

        name=pre,

        domain=dom or None,

        expiry_ms=expiry_ms if expiry_ms is not None else MOEMAIL_EXPIRY_MS,

        api_key=key or None,

        base_url=base or None,

    )

    email_id = mailbox["id"]

    address = mailbox["email"]

    token = str(mailbox.get("token") or "")



    class _MailReceiver:

        def __init__(

            self,

            email: str,

            email_id: str,

            api_key: str | None,

            base_url: str | None,

            *,

            provider: str,

            token: str = "",

        ):

            self.email = email

            self.email_id = email_id

            self.api_key = api_key

            if provider == "yyds":

                default_base = "https://maliapi.215.im"

            elif provider == "gptmail":

                default_base = "https://mail.chatgpt.org.uk"

            elif provider == "cfmail":

                default_base = "https://temp-email-api.awsl.uk"

            elif provider == "duckmail":

                default_base = "https://api.duckmail.sbs"

            else:

                default_base = "https://moemail.521884.xyz"

            self.base_url = base_url or default_base

            self.provider = provider

            self.token = token



        def wait_for_code(

            self,

            timeout: float = 120,

            *,

            should_cancel=None,

            poll_interval: float | None = None,

        ) -> str:

            import re as _re



            deadline = time.time() + float(timeout or 120)

            # Keep polls short so cooperative cancel can land quickly.

            poll = float(poll_interval if poll_interval is not None else 1.0)

            poll = max(0.4, min(poll, 2.0))

            while time.time() < deadline:

                if callable(should_cancel) and should_cancel():

                    raise _RegCancelled("cancelled while waiting for email code")

                try:

                    messages = fetch_messages(

                        self.email_id,

                        provider=self.provider,

                        api_key=self.api_key,

                        base_url=self.base_url,

                        include_details=True,

                        address=self.email,

                        token=self.token or None,

                    )

                    for item in messages:

                        # Prefer xAI AAA-BBB codes first.

                        text = "\n".join(

                            str(item.get(k) or "")

                            for k in (

                                "subject",

                                "content",

                                "text",

                                "textBody",

                                "html",

                                "htmlBody",

                                "body",

                                "from_address",

                                "from",

                                "verificationCode",

                            )

                        )

                        match = _re.search(

                            r"\b([A-Z0-9]{3})-([A-Z0-9]{3})\b", text, flags=_re.I

                        )

                        if match:

                            return "".join(match.groups()).upper()

                        # Also accept plain 6-char alnum codes from xAI mails.

                        match2 = _re.search(

                            r"\b([A-Z0-9]{6})\b", text, flags=_re.I

                        )

                        if match2 and "x.ai" in text.lower():

                            return match2.group(1).upper()

                        extracted = item.get("extracted") or {}

                        codes = extracted.get("codes") or []

                        for code in codes:

                            clean = str(code).replace("-", "").strip().upper()

                            if len(clean) == 6 and _re.fullmatch(r"[A-Z0-9]{6}", clean):

                                return clean

                except Exception:

                    pass

                # Sleep in small slices so stop can interrupt mid-wait.

                slept = 0.0

                while slept < poll:

                    if callable(should_cancel) and should_cancel():

                        raise _RegCancelled("cancelled while waiting for email code")

                    step = min(0.25, poll - slept)

                    time.sleep(step)

                    slept += step

                poll = min(2.0, poll + 0.15)

            raise RuntimeError("timeout waiting for xAI email verification code")



    return address, _MailReceiver(

        address,

        email_id,

        api_key=key,

        base_url=base,

        provider=prov,

        token=token,

    )





def _proxy_url() -> str:

    """Pick one proxy from the configured pool (env / registration config)."""

    try:

        from proxy_pool import resolve_proxy_for_request



        return resolve_proxy_for_request(fallback_env=True) or ""

    except Exception:

        try:

            from moemail import normalize_proxy_config

            from register_pro_config import XAI_PROXY



            cfg = normalize_proxy_config(XAI_PROXY or None)

            return cfg["proxy"] if cfg else ""

        except Exception:

            return ""





def _proxy_pool(

    proxy_text: str | None = None,

    *,

    username: str | None = None,

    password: str | None = None,

) -> list[str]:

    """Parse multi-line proxy text into full proxy URLs."""

    try:

        from proxy_pool import parse_proxy_pool



        pool = parse_proxy_pool(

            proxy_text,

            username=username,

            password=password,

            fallback_env=True,

        )

        if pool:

            return pool

    except Exception:

        pass

    # Fallback: treat as single proxy via classic normalizer.

    one = (proxy_text or "").strip() or _proxy_url()

    return [one] if one else []





def _pick_proxy_from_pool(

    pool: list[str],

    *,

    strategy: str | None = None,

    index: int | None = None,

) -> str:

    try:

        from proxy_pool import pick_proxy, normalize_proxy_strategy



        strat = strategy

        if not strat:

            try:

                from register_pro_config import XAI_PROXY_STRATEGY as _strat

            except Exception:

                _strat = "round_robin"

            strat = _strat

        return pick_proxy(pool, strategy=normalize_proxy_strategy(strat), index=index) or ""

    except Exception:

        return pool[0] if pool else ""





def _domain_pool(domain: str | None) -> list[str]:

    """Parse multi-domain text (comma / CJK comma / whitespace / ; |).



    Keep separators aligned with register_pro_store._DOMAIN_SPLIT_RE so

    schedule rotation and per-account pick see the same pool.

    """

    raw = str(domain or "")

    if not raw.strip():

        return []

    out: list[str] = []

    seen: set[str] = set()

    for item in re.split(r"[\s,;|，、；]+", raw):

        dom = item.strip().lstrip("@").strip(".").lower()

        if not dom or dom in seen:

            continue

        seen.add(dom)

        out.append(dom)

    return out





def _pick_domain_from_pool(domain: str | None) -> str:

    pool = _domain_pool(domain)

    if not pool:

        return ""

    if len(pool) == 1:

        return pool[0]

    return secrets.choice(pool)





# --------------------------------------------------------------------------- #

# registration flow

# --------------------------------------------------------------------------- #

def _prepare_registration_session(

    *,

    yescaptcha_key: str,

    proxy: str,

    moemail_api_key: str | None = None,

    moemail_base_url: str | None = None,

    prefix: str | None = None,

    domain: str | None = None,

    expiry_ms: int | None = None,

    mail_provider: str | None = None,

    batch_id: str | None = None,

    batch_index: int | None = None,

    batch_total: int | None = None,

    start_delay: float = 0.0,

) -> dict[str, Any]:

    """Create mailbox + session record. Does NOT start the registration worker."""

    if start_delay > 0:

        time.sleep(start_delay)



    try:

        email, receiver = _make_email_receiver(

            api_key=moemail_api_key,

            base_url=moemail_base_url,

            prefix=prefix,

            domain=domain,

            expiry_ms=expiry_ms,

            mail_provider=mail_provider,

        )

    except Exception as e:  # noqa: BLE001

        return {"ok": False, "error": str(e)}



    # Diverse name + strong variable password (same strategy as grok-register).

    given_name, family_name, password = build_register_profile()

    sid = f"gba_{uuid.uuid4().hex[:16]}"



    sess = {

        "id": sid,

        "status": "queued",

        "created_at": _now(),

        "updated_at": _now(),

        "email": email,

        "password": password,

        "given_name": given_name,

        "family_name": family_name,

        "message": f"queued; email={email}",

        "sso": None,

        "oauth": None,

        "auth_json": None,

        "error": None,

        "yescaptcha_key": yescaptcha_key,

        "proxy": proxy or None,

        "adapter_build": ADAPTER_BUILD,

        "batch_id": batch_id,

        "batch_index": batch_index,

        "batch_total": batch_total,

        # Keep receiver process-local only (not mirrored to Redis).

        "_receiver": receiver,

    }

    with _lock:

        _sessions[sid] = sess

        if batch_id and batch_id in _batches:

            _batches[batch_id]["session_ids"].append(sid)

            _batches[batch_id]["updated_at"] = _now()

            _mirror_reg_batch(batch_id, dict(_batches[batch_id]))

    _mirror_reg_sess(sid, sess)

    return {"ok": True, **_compact_session(sess)}





def _start_one_registration(

    *,

    yescaptcha_key: str,

    proxy: str,

    moemail_api_key: str | None = None,

    moemail_base_url: str | None = None,

    prefix: str | None = None,

    domain: str | None = None,

    expiry_ms: int | None = None,

    mail_provider: str | None = None,

    batch_id: str | None = None,

    batch_index: int | None = None,

    batch_total: int | None = None,

    start_delay: float = 0.0,

) -> dict[str, Any]:

    """Create one session and spawn its worker thread (single-job path)."""

    prepared = _prepare_registration_session(

        yescaptcha_key=yescaptcha_key,

        proxy=proxy,

        moemail_api_key=moemail_api_key,

        moemail_base_url=moemail_base_url,

        prefix=prefix,

        domain=domain,

        expiry_ms=expiry_ms,

        mail_provider=mail_provider,

        batch_id=batch_id,

        batch_index=batch_index,

        batch_total=batch_total,

        start_delay=start_delay,

    )

    if not prepared.get("ok"):

        return prepared

    sid = str(prepared.get("id") or "")

    with _lock:

        sess = _sessions.get(sid) or {}

        receiver = sess.get("_receiver")

    if not sid or receiver is None:

        return {"ok": False, "error": "registration session prepare failed"}

    with _lock:

        if sid in _sessions:

            _sessions[sid]["status"] = "started"

            _sessions[sid]["message"] = f"started; email={_sessions[sid].get('email') or ''}"

            _sessions[sid]["updated_at"] = _now()

            _mirror_reg_sess(sid, _sessions[sid])

    # Single-job starts are not covered by the batch finalizer — log "running"

    # immediately so 任务日志 shows the registration task right away.

    if not batch_id:

        with _lock:

            started_sess = dict(_sessions.get(sid) or {})

        if started_sess:

            payload = _session_task_log_payload(started_sess)

            _record_register_task(

                task_id=payload["task_id"],

                summary=payload["summary"] or f"协议注册启动 {started_sess.get('email') or sid}",

                status="running",

                ok=None,

                progress_done=0,

                progress_total=1,

                finished=False,

                detail={**payload["detail"], "phase": "started"},

            )

    threading.Thread(

        target=_run_registration,

        args=(sid, yescaptcha_key, proxy or "", receiver),

        daemon=True,

        name=f"gba-reg-{sid[-8:]}",

    ).start()

    with _lock:

        sess = _sessions.get(sid)

        if sess is None:

            return prepared

        return {"ok": True, **_compact_session(sess)}





def start_registration(

    *,

    captcha_provider: str | None = None,

    local_solver_url: str | None = None,

    yescaptcha_key: str | None = None,

    proxy: str | None = None,

    proxy_username: str | None = None,

    proxy_password: str | None = None,

    proxy_strategy: str | None = None,

    moemail_api_key: str | None = None,

    moemail_base_url: str | None = None,

    prefix: str | None = None,

    domain: str | None = None,

    expiry_ms: int | None = None,

    mail_provider: str | None = None,

    count: int | None = None,

    concurrency: int | None = None,

    stagger_ms: int | None = None,

    probe_delay_sec: float | int | None = None,

    skip_probe: bool | None = None,

    sso_only: bool | None = None,

    captcha_use_proxy: bool | None = None,

) -> dict[str, Any]:

    """Start one or many registration sessions (multi-thread).



    ``count`` > 1 enables batch mode. ``concurrency`` is the real in-flight

    limit: e.g. concurrency=3 means only 3 accounts register at the same time;

    when one finishes, the next queued account starts.



    ``proxy`` may be a single URL or a multi-line proxy pool. Each registration

    job picks one entry via ``proxy_strategy`` (round_robin / random / sticky).

    """

    try:

        ensure_xconsole()

    except Exception as e:  # noqa: BLE001

        return {"ok": False, "error": str(e)}



    _clean_old_sessions()



    # Allow admin form / env to override settle window for post-import probe.

    if probe_delay_sec is not None:

        try:

            globals()["REGISTER_PROBE_DELAY_SEC"] = max(

                0.0, min(600.0, float(probe_delay_sec))

            )

            os.environ["GROK2API_REG_PROBE_DELAY_SEC"] = str(

                int(globals()["REGISTER_PROBE_DELAY_SEC"])

            )

        except (TypeError, ValueError):

            pass



    if skip_probe is not None:

        try:

            if isinstance(skip_probe, str):

                flag = skip_probe.strip().lower() in {"1", "true", "yes", "on"}

            else:

                flag = bool(skip_probe)

            globals()["REGISTER_SKIP_PROBE"] = flag

            os.environ["GROK2API_REG_SKIP_PROBE"] = "1" if flag else "0"

        except Exception:

            pass



    if sso_only is not None:

        try:

            if isinstance(sso_only, str):

                sso_flag = sso_only.strip().lower() in {"1", "true", "yes", "on"}

            else:

                sso_flag = bool(sso_only)

            globals()["REGISTER_SSO_ONLY"] = sso_flag

            os.environ["GROK2API_REG_SSO_ONLY"] = "1" if sso_flag else "0"

            # SSO-only implies skip probe (no OAuth tokens to probe).

            if sso_flag:

                globals()["REGISTER_SKIP_PROBE"] = True

                os.environ["GROK2API_REG_SKIP_PROBE"] = "1"

        except Exception:

            pass



    # Resolve captcha_use_proxy once for this batch (default True = same egress as job proxy).

    captcha_proxy_flag = True

    if captcha_use_proxy is not None:

        if isinstance(captcha_use_proxy, str):

            captcha_proxy_flag = captcha_use_proxy.strip().lower() in {"1", "true", "yes", "on"}

        else:

            captcha_proxy_flag = bool(captcha_use_proxy)

    else:

        try:

            import register_pro_store as _store



            captcha_proxy_flag = bool(

                _store.get_registration_config(include_secrets=False).get("captcha_use_proxy", True)

            )

        except Exception:

            captcha_proxy_flag = True

    globals()["REGISTER_CAPTCHA_USE_PROXY"] = captcha_proxy_flag



    provider = (

        captcha_provider

        or CAPTCHA_PROVIDER

        or os.environ.get("GROK2API_CAPTCHA_PROVIDER")

        or os.environ.get("CAPTCHA_PROVIDER")

        or "local"

    ).strip().lower()

    if provider not in {"local", "yescaptcha"}:

        provider = "local"

    try:

        globals()["CAPTCHA_PROVIDER"] = provider

    except Exception:

        pass



    if provider == "local":

        # Always inline in main container; ignore any external/custom URL.

        solver_url = _local_solver_base_url(local_solver_url)

        try:

            globals()["LOCAL_SOLVER_URL"] = solver_url

        except Exception:

            pass

        os.environ["GROK2API_LOCAL_SOLVER_URL"] = solver_url

        os.environ["LOCAL_SOLVER_URL"] = solver_url

        os.environ["GROK2API_YESCAPTCHA_ENDPOINT"] = solver_url

        os.environ["YESCAPTCHA_ENDPOINT"] = solver_url

        key = "local"

        # Gate: never spawn registration workers before the inline solver answers.

        # Lazy browser mode is fine (pool_ready may be false); HTTP /health is enough.

        solver_wait = wait_for_local_solver(solver_url)

        if not solver_wait.get("ready"):

            return {

                "ok": False,

                "error": solver_wait.get("error")

                or f"本地过盾未就绪: {solver_url}",

                "local_solver": solver_wait,

            }

    else:

        # Cloud YesCaptcha must not inherit local solver endpoint/key.

        try:

            globals()["LOCAL_SOLVER_URL"] = ""

        except Exception:

            pass

        for k in (

            "GROK2API_LOCAL_SOLVER_URL",

            "LOCAL_SOLVER_URL",

            "GROK2API_YESCAPTCHA_ENDPOINT",

            "YESCAPTCHA_ENDPOINT",

            "YESCAPTCHA_API_BASE",

        ):

            os.environ.pop(k, None)

        key = (

            yescaptcha_key

            or YESCAPTCHA_KEY

            or os.environ.get("GROK2API_YESCAPTCHA_KEY")

            or os.environ.get("YESCAPTCHA_API_KEY")

            or ""

        ).strip()

        if key == "local":

            key = ""

        if not key:

            return {

                "ok": False,

                "error": "YESCAPTCHA_KEY is required (set GROK2API_YESCAPTCHA_KEY, save in 协议注册配置, or pass yescaptcha_key)",

            }



    if key and key != YESCAPTCHA_KEY:

        # keep module attr in sync for subsequent workers

        try:

            globals()["YESCAPTCHA_KEY"] = key

        except Exception:

            pass



    try:

        n = int(count if count is not None else 1)

    except (TypeError, ValueError):

        n = 1

    n = max(1, n)



    try:

        workers = int(

            concurrency

            if concurrency is not None

            else DEFAULT_CONCURRENCY

        )

    except (TypeError, ValueError):

        workers = DEFAULT_CONCURRENCY

    workers = max(1, min(workers, MAX_CONCURRENCY, n))



    stagger = _effective_reg_stagger_ms(stagger_ms, captcha_provider=provider)



    # Build proxy pool once; each job picks one URL (rotation / random / sticky).

    proxy_pool = _proxy_pool(

        proxy,

        username=proxy_username,

        password=proxy_password,

    )

    try:

        from register_pro_config import XAI_PROXY_STRATEGY as _default_strat

    except Exception:

        _default_strat = "round_robin"

    proxy_strat = (proxy_strategy or _default_strat or "round_robin").strip().lower()

    proxy_val = _pick_proxy_from_pool(proxy_pool, strategy=proxy_strat, index=0)

    try:

        from moemail import normalize_mail_provider as _norm_mail



        mail_prov = _norm_mail(mail_provider, base_url=moemail_base_url)

    except Exception:

        mail_prov = (mail_provider or "moemail").strip().lower() or "moemail"



    # Single job — keep original response shape for UI compatibility.

    if n == 1:

        return _start_one_registration(

            yescaptcha_key=key,

            proxy=proxy_val,

            moemail_api_key=moemail_api_key,

            moemail_base_url=moemail_base_url,

            prefix=prefix,

            domain=domain,

            expiry_ms=expiry_ms,

            mail_provider=mail_prov,

        )



    batch_id = f"batch_{uuid.uuid4().hex[:12]}"

    # Snapshot keeps the full multi-line text so resume / UI can re-parse the pool.

    proxy_snapshot = (proxy or "\n".join(proxy_pool) or proxy_val or "").strip()

    reg_cfg = _snapshot_reg_config(

        captcha_provider=provider,

        yescaptcha_key=key,

        proxy=proxy_snapshot,

        moemail_api_key=moemail_api_key,

        moemail_base_url=moemail_base_url,

        prefix=prefix,

        domain=domain,

        expiry_ms=expiry_ms,

        concurrency=workers,

        stagger_ms=stagger,

        mail_provider=mail_prov,

        captcha_use_proxy=captcha_proxy_flag,

    )

    reg_cfg["proxy_strategy"] = proxy_strat

    reg_cfg["proxy_pool_count"] = len(proxy_pool)

    batch = {

        "id": batch_id,

        "status": "running",

        "created_at": _now(),

        "updated_at": _now(),

        "count": n,

        "concurrency": workers,

        "stagger_ms": stagger,

        "session_ids": [],

        "adapter_build": ADAPTER_BUILD,

        "message": f"batch started count={n} concurrency={workers}",

        "error": None,

        "finished": 0,

        "ok_count": 0,

        "fail_count": 0,

        "spawned": 0,

        "reg_config": reg_cfg,

        "owner_pid": os.getpid(),

        "runner_alive": True,

        "cancel_requested": False,

    }

    with _lock:

        _batches[batch_id] = batch

    _mirror_reg_batch(batch_id, batch)

    # Log batch start so 任务日志 has a running row even before the first

    # session finishes (previously only the terminal row was written).

    _record_register_task(

        task_id=batch_id,

        summary=f"协议注册批次启动 count={n} concurrency={workers}",

        status="running",

        ok=None,

        progress_done=0,

        progress_total=n,

        finished=False,

        detail={

            "batch_id": batch_id,

            "count": n,

            "concurrency": workers,

            "stagger_ms": stagger,

            "phase": "started",

            "adapter_build": ADAPTER_BUILD,

        },

    )



    started = _spawn_batch_runner(

        batch_id,

        remaining=n,

        concurrency=workers,

        stagger_ms=stagger,

        captcha_provider=provider,

        yescaptcha_key=key,

        proxy=proxy_snapshot,

        proxy_strategy=proxy_strat,

        moemail_api_key=moemail_api_key,

        moemail_base_url=moemail_base_url,

        prefix=prefix,

        domain=domain,

        expiry_ms=expiry_ms,

        mail_provider=mail_prov,

    )

    if not started.get("ok"):

        return started



    # Brief wait so the first wave (up to `workers`) is usually visible to UI.

    time.sleep(min(0.45, 0.08 * workers + 0.08))

    with _lock:

        b = dict(_batches.get(batch_id) or batch)

        sids = list(b.get("session_ids") or [])

        sessions = [_compact_session(_sessions[s]) for s in sids if s in _sessions]



    return {

        "ok": True,

        "batch": True,

        "batch_id": batch_id,

        "count": n,

        "concurrency": workers,

        "stagger_ms": stagger,

        "proxy_pool_count": len(proxy_pool),

        "session_ids": sids,

        "sessions": sessions,

        "adapter_build": ADAPTER_BUILD,

        "message": (

            f"batch started: count={n}, threads={workers} "

            f"(in-flight cap), proxy_pool={len(proxy_pool)}, queued/started={len(sids)}"

        ),

        # Back-compat: first session fields for old UI single-session path.

        **(sessions[0] if sessions else {"id": None, "status": "starting"}),

    }





def _spawn_batch_runner(

    batch_id: str,

    *,

    remaining: int,

    concurrency: int,

    stagger_ms: int,

    captcha_provider: str,

    yescaptcha_key: str,

    proxy: str,

    proxy_strategy: str | None = None,

    moemail_api_key: str | None,

    moemail_base_url: str | None,

    prefix: str | None,

    domain: str | None,

    expiry_ms: int | None,

    mail_provider: str | None = None,

) -> dict[str, Any]:

    """Start the ThreadPool spawner for a batch (also used by resume/reclaim)."""

    bid = str(batch_id or "").strip()

    if not bid:

        return {"ok": False, "error": "missing batch id"}

    batch = _load_reg_batch(bid)

    if not batch:

        return {"ok": False, "error": "registration batch not found"}



    if remaining <= 0:

        with _lock:

            b = _batches.get(bid) or dict(batch)

            b["runner_alive"] = False

            b["status"] = "done"

            b["updated_at"] = _now()

            b["message"] = "nothing to spawn"

            _batches[bid] = b

            _mirror_reg_batch(bid, dict(b))

        return {

            "ok": True,

            "batch_id": bid,

            "already_complete": True,

            "remaining": 0,

            "batch": get_registration_batch(bid),

        }



    acquired, lock_token = _try_acquire_batch_runner(bid)

    if not acquired:

        return {

            "ok": False,

            "error": "batch runner already active on another worker",

            "batch_id": bid,

            "already_running": True,

        }



    provider = (captcha_provider or "local").strip().lower()

    if provider not in {"local", "yescaptcha"}:

        provider = "local"

    key = (yescaptcha_key or "").strip()

    if provider == "local":

        key = "local"

        solver_url = _local_solver_base_url(None)

        try:

            globals()["CAPTCHA_PROVIDER"] = "local"

            globals()["LOCAL_SOLVER_URL"] = solver_url

        except Exception:

            pass

        os.environ["GROK2API_CAPTCHA_PROVIDER"] = "local"

        os.environ["CAPTCHA_PROVIDER"] = "local"

        os.environ["GROK2API_LOCAL_SOLVER_URL"] = solver_url

        os.environ["LOCAL_SOLVER_URL"] = solver_url

        os.environ["GROK2API_YESCAPTCHA_ENDPOINT"] = solver_url

        os.environ["YESCAPTCHA_ENDPOINT"] = solver_url

        solver_wait = wait_for_local_solver(solver_url)

        if not solver_wait.get("ready"):

            _release_batch_runner(bid, lock_token)

            return {

                "ok": False,

                "error": solver_wait.get("error")

                or f"本地过盾未就绪: {solver_url}",

                "batch_id": bid,

                "local_solver": solver_wait,

            }

    else:

        if not key:

            _release_batch_runner(bid, lock_token)

            return {

                "ok": False,

                "error": "YESCAPTCHA_KEY missing",

                "batch_id": bid,

            }

        try:

            globals()["CAPTCHA_PROVIDER"] = "yescaptcha"

            globals()["YESCAPTCHA_KEY"] = key

            globals()["LOCAL_SOLVER_URL"] = ""

        except Exception:

            pass

        for k in (

            "GROK2API_LOCAL_SOLVER_URL",

            "LOCAL_SOLVER_URL",

            "GROK2API_YESCAPTCHA_ENDPOINT",

            "YESCAPTCHA_ENDPOINT",

            "YESCAPTCHA_API_BASE",

        ):

            os.environ.pop(k, None)



    # `proxy` may be multi-line pool text; expand once for this runner.

    proxy_pool = _proxy_pool(proxy)

    try:

        from register_pro_config import XAI_PROXY_STRATEGY as _default_strat

    except Exception:

        _default_strat = "round_robin"

    proxy_strat = (proxy_strategy or _default_strat or "round_robin").strip().lower()

    proxy_snapshot = (proxy or "\n".join(proxy_pool) or "").strip()

    workers = max(1, min(int(concurrency or DEFAULT_CONCURRENCY), MAX_CONCURRENCY, remaining))

    stagger = _effective_reg_stagger_ms(stagger_ms, captcha_provider=provider)



    with _lock:

        b = _batches.get(bid) or dict(batch)

        b["status"] = "running"

        b["cancel_requested"] = False

        b["concurrency"] = workers

        b["stagger_ms"] = stagger

        b["runner_alive"] = True

        b["owner_pid"] = os.getpid()

        b["adapter_build"] = ADAPTER_BUILD

        b["reg_config"] = _snapshot_reg_config(

            captcha_provider=provider,

            yescaptcha_key=key,

            proxy=proxy_snapshot,

            moemail_api_key=moemail_api_key,

            moemail_base_url=moemail_base_url,

            prefix=prefix,

            domain=domain,

            expiry_ms=expiry_ms,

            concurrency=workers,

            stagger_ms=stagger,

            mail_provider=mail_provider,

            captcha_use_proxy=bool(globals().get("REGISTER_CAPTCHA_USE_PROXY", True)),

        )

        b["reg_config"]["proxy_strategy"] = proxy_strat

        b["reg_config"]["proxy_pool_count"] = len(proxy_pool)

        b["updated_at"] = _now()

        # Preserve historical counters when reclaiming after process restart;

        # only reset if this is a brand-new spawn with no prior progress.

        prior_finished = int(b.get("finished") or 0)

        prior_ok = int(b.get("ok_count") or 0)

        prior_fail = int(b.get("fail_count") or 0)

        b["message"] = (

            f"starting remaining={remaining} threads={workers}"

            + (f" already_done={prior_finished}" if prior_finished else "")

            + (f" proxies={len(proxy_pool)}" if proxy_pool else "")

        )

        if prior_finished <= 0 and not (b.get("session_ids") or []):

            b["finished"] = 0

            b["ok_count"] = 0

            b["fail_count"] = 0

        else:

            b["finished"] = prior_finished

            b["ok_count"] = prior_ok

            b["fail_count"] = prior_fail

        _batches[bid] = b

        _mirror_reg_batch(bid, dict(b))



    def _run_batch() -> None:

        from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait



        errors: list[str] = []

        with _lock:

            _seed = dict(_batches.get(bid) or batch or {})

        finished = int(_seed.get("finished") or 0)

        ok_n = int(_seed.get("ok_count") or 0)

        fail_n = int(_seed.get("fail_count") or 0)

        stop_renew = False

        # Feed the pool gradually: only keep ~workers(+prefetch) jobs prepared

        # at once. Submitting all remaining jobs up-front used to create hundreds

        # of mailboxes immediately and made stop/cancel racey under multi-thread.

        next_i = 1

        in_flight: dict[Any, int] = {}

        prefetch = max(0, min(int(REG_PREFETCH_SLOTS), max(0, workers)))

        max_inflight = max(1, workers + prefetch)



        def _batch_cancel_requested() -> bool:

            with _lock:

                local = _batches.get(bid) or {}

            if local.get("cancel_requested") or str(local.get("status") or "").lower() in (

                "stopping",

                "cancelled",

                "stopped",

            ):

                return True

            if not _reg_redis():

                return False

            try:

                from store import sessions_redis



                remote = sessions_redis.reg_batch_get(bid)

                if not isinstance(remote, dict):

                    return False

                if remote.get("cancel_requested") or str(remote.get("status") or "").lower() in (

                    "stopping",

                    "cancelled",

                    "stopped",

                ):

                    with _lock:

                        cur = _batches.get(bid) or dict(remote)

                        cur["cancel_requested"] = True

                        if str(cur.get("status") or "").lower() not in (

                            "cancelled",

                            "stopped",

                            "done",

                            "partial",

                            "error",

                        ):

                            cur["status"] = remote.get("status") or "stopping"

                            if remote.get("message"):

                                cur["message"] = remote.get("message")

                        cur["updated_at"] = _now()

                        _batches[bid] = cur

                    return True

            except Exception:

                pass

            return False



        def _renew_loop() -> None:

            while not stop_renew:

                time.sleep(max(5.0, REG_BATCH_RUNNER_LOCK_TTL / 3))

                if stop_renew:

                    break

                if _batch_cancel_requested():

                    # Keep heartbeat while draining, but mark status as stopping.

                    with _lock:

                        bb = _batches.get(bid)

                        if bb is not None:

                            bb["cancel_requested"] = True

                            if str(bb.get("status") or "").lower() not in (

                                "cancelled",

                                "stopped",

                                "done",

                                "partial",

                                "error",

                            ):

                                bb["status"] = "stopping"

                            bb["updated_at"] = _now()

                            bb["runner_alive"] = True

                            _mirror_reg_batch(bid, dict(bb))

                _renew_batch_runner(bid, lock_token)

                with _lock:

                    bb = _batches.get(bid)

                    if bb is not None:

                        bb["updated_at"] = _now()

                        bb["runner_alive"] = True

                        bb["owner_pid"] = os.getpid()

                        _mirror_reg_batch(bid, dict(bb))



        renew_t = threading.Thread(

            target=_renew_loop,

            daemon=True,

            name=f"gba-batch-lock-{bid[-8:]}",

        )

        renew_t.start()



        def _job(i: int) -> dict[str, Any]:

            # Honour batch-level stop before creating more mailboxes.

            if _batch_cancel_requested():

                return {

                    "ok": False,

                    "id": None,

                    "status": "cancelled",

                    "error": "cancelled before start",

                }

            # One proxy per registration job (pool rotation / random / sticky).

            job_proxy = _pick_proxy_from_pool(

                proxy_pool, strategy=proxy_strat, index=max(0, int(i) - 1)

            )

            # In-job stagger only for the first concurrency wave. Later refills are

            # already naturally desynced by finish times; sleeping again only cuts

            # steady-state throughput without helping the startup stampede.

            if int(i) <= max(1, workers):

                delay = (stagger / 1000.0) * ((i - 1) % max(1, workers))

            else:

                delay = 0.0

            prepared = _prepare_registration_session(

                yescaptcha_key=key,

                proxy=job_proxy,

                moemail_api_key=moemail_api_key,

                moemail_base_url=moemail_base_url,

                prefix=prefix,

                domain=domain,

                expiry_ms=expiry_ms,

                mail_provider=mail_provider,

                batch_id=bid,

                batch_index=i,

                batch_total=int((_load_reg_batch(bid) or {}).get("count") or remaining),

                start_delay=delay,

            )

            if not prepared.get("ok"):

                return prepared

            sid = str(prepared.get("id") or "")

            with _lock:

                # Re-check cancel after prepare (user may stop mid-queue).

                b1 = _batches.get(bid) or {}

                sess = _sessions.get(sid) or {}

                if (

                    b1.get("cancel_requested")

                    or str(b1.get("status") or "").lower() in ("stopping", "cancelled", "stopped")

                    or sess.get("cancel_requested")

                ):

                    if sid in _sessions:

                        _sessions[sid]["status"] = "cancelled"

                        _sessions[sid]["message"] = "cancelled before worker start"

                        _sessions[sid]["error"] = "cancelled"

                        _sessions[sid]["cancel_requested"] = True

                        _sessions[sid]["updated_at"] = _now()

                        _sessions[sid].pop("_receiver", None)

                        _mirror_reg_sess(sid, _sessions[sid])

                    return {

                        "ok": False,

                        "id": sid,

                        "status": "cancelled",

                        "error": "cancelled",

                        "email": sess.get("email"),

                    }

                receiver = sess.get("_receiver")

                email_hint = str((sess or {}).get("email") or "")

                if sid in _sessions:

                    # Do NOT mark "started" before admission — UI would show

                    # fake progress while jobs sit in the global inflight queue.

                    _sessions[sid]["status"] = "waiting"

                    _sessions[sid]["message"] = (

                        f"waiting for admission; email={email_hint}"

                    )

                    _sessions[sid]["updated_at"] = _now()

                    _mirror_reg_sess(sid, _sessions[sid])

            if not sid or receiver is None:

                return {"ok": False, "error": "registration session prepare failed", "id": sid}

            # Cross-batch admission control: many resumed batches otherwise all

            # run concurrency=8 and overwhelm local captcha + device-flow.

            admitted = False

            try:

                def _job_cancel() -> None:

                    with _lock:

                        sess2 = _sessions.get(sid) or {}

                        b2 = _batches.get(bid) or {}

                        if (

                            sess2.get("cancel_requested")

                            or b2.get("cancel_requested")

                        ):

                            raise _RegCancelled("cancelled while waiting for admission")



                _wait_reg_admission(check_cancel=_job_cancel)

                admitted = True

                with _lock:

                    if sid in _sessions:

                        _sessions[sid]["status"] = "started"

                        _sessions[sid]["message"] = (

                            f"started; email={_sessions[sid].get('email') or email_hint}"

                        )

                        _sessions[sid]["updated_at"] = _now()

                        _mirror_reg_sess(sid, _sessions[sid])

                _run_registration(sid, key, job_proxy or "", receiver)

            except _RegCancelled as e:

                with _lock:

                    if sid in _sessions:

                        _sessions[sid]["status"] = "cancelled"

                        _sessions[sid]["error"] = str(e)

                        _sessions[sid]["message"] = str(e)

                        _sessions[sid]["updated_at"] = _now()

                        _mirror_reg_sess(sid, _sessions[sid])

                return {

                    "ok": False,

                    "id": sid,

                    "status": "cancelled",

                    "error": str(e),

                }

            finally:

                if admitted:

                    _release_reg_admission()

                with _lock:

                    if sid in _sessions:

                        _sessions[sid].pop("_receiver", None)

            with _lock:

                final = _sessions.get(sid) or {}

            st = str(final.get("status") or "")

            # Only probe-passed terminal statuses count as batch success.

            # probe_failed / failed / error never increment ok_count.

            ok = st in ("imported", "success", "completed")

            return {

                "ok": ok,

                "id": sid,

                "status": st,

                "error": final.get("error"),

                "email": final.get("email"),

            }



        def _note_result(idx: int, r: dict[str, Any] | None = None, exc: Exception | None = None) -> None:

            nonlocal finished, ok_n, fail_n

            finished += 1

            if exc is not None:

                fail_n += 1

                errors.append(f"#{idx}: {exc}")

            elif not isinstance(r, dict):

                fail_n += 1

                errors.append(f"#{idx}: empty result")

            elif r.get("ok"):

                ok_n += 1

            else:

                fail_n += 1

                errors.append(

                    f"#{idx}: {r.get('error') or r.get('status') or 'failed'}"

                )

            with _lock:

                b = _batches.get(bid)

                if b is not None:

                    b["updated_at"] = _now()

                    # Don't clobber explicit stop marker.

                    if not b.get("cancel_requested"):

                        b["status"] = "running"

                    b["finished"] = finished

                    b["ok_count"] = ok_n

                    b["fail_count"] = fail_n

                    b["spawned"] = len(b.get("session_ids") or [])

                    b["spawn_errors"] = errors[-20:]

                    b["runner_alive"] = True

                    b["inflight"] = len(in_flight)

                    b["message"] = (

                        f"running {finished}/{target_total} done "

                        f"(ok={ok_n} fail={fail_n}, threads={workers}, "

                        f"inflight={len(in_flight)})"

                    )

                    _mirror_reg_batch(bid, dict(b))



        try:

            target_total = int((_load_reg_batch(bid) or {}).get("count") or remaining)

            # Only stagger the *startup wave* (first `workers` submits). Applying

            # the same gap to every later refill cut steady-state throughput roughly

            # in half without improving success rate. After the pool is warm, free

            # slots refill immediately — finish times already desync workers.

            stagger_sec = max(0.0, float(stagger) / 1000.0)

            startup_wave = max(1, workers)

            last_submit_mono = 0.0

            with ThreadPoolExecutor(

                max_workers=workers, thread_name_prefix=f"gba-batch-{bid[-6:]}"

            ) as pool:

                while True:

                    # Fill up to concurrency(+prefetch) only while not cancelled.

                    # Submit gap applies only while next_i is still in the startup wave.

                    while (

                        next_i <= remaining

                        and len(in_flight) < max_inflight

                        and not _batch_cancel_requested()

                    ):

                        if (

                            stagger_sec > 0

                            and last_submit_mono > 0

                            and next_i <= startup_wave

                        ):

                            remaining_wait = stagger_sec - (

                                time.monotonic() - last_submit_mono

                            )

                            waited_out = False

                            while remaining_wait > 0:

                                if _batch_cancel_requested():

                                    waited_out = True

                                    break

                                # Wake often so cancel stays responsive.

                                time.sleep(min(0.05, remaining_wait))

                                remaining_wait = stagger_sec - (

                                    time.monotonic() - last_submit_mono

                                )

                            if waited_out:

                                break

                        fut = pool.submit(_job, next_i)

                        in_flight[fut] = next_i

                        next_i += 1

                        last_submit_mono = time.monotonic()

                        with _lock:

                            bb = _batches.get(bid)

                            if bb is not None:

                                bb["inflight"] = len(in_flight)

                                bb["updated_at"] = _now()

                                if not bb.get("cancel_requested"):

                                    bb["status"] = "running"

                                bb["message"] = (

                                    f"running {finished}/{target_total} done "

                                    f"(ok={ok_n} fail={fail_n}, threads={workers}, "

                                    f"inflight={len(in_flight)}, stagger={stagger}ms)"

                                )

                                _mirror_reg_batch(bid, dict(bb))



                    if not in_flight:

                        break



                    done, _pending = wait(

                        set(in_flight.keys()),

                        return_when=FIRST_COMPLETED,

                        timeout=0.5,

                    )

                    if not done:

                        # Timeout tick: re-check cancel and refresh progress.

                        if _batch_cancel_requested():

                            # Stop feeding new jobs; still drain in-flight workers.

                            pass

                        continue

                    for fut in done:

                        idx = in_flight.pop(fut, 0)

                        try:

                            r = fut.result()

                            _note_result(idx, r=r)

                        except Exception as e:  # noqa: BLE001

                            _note_result(idx, exc=e)



                    # If cancelled and no more work in flight, exit promptly.

                    if _batch_cancel_requested() and not in_flight:

                        break

                    # If cancelled, do not submit more jobs even if capacity frees.

                    if _batch_cancel_requested():

                        continue

        finally:

            stop_renew = True

            # Best-effort cancel of any leftover futures (usually empty now).

            for fut in list(in_flight.keys()):

                try:

                    fut.cancel()

                except Exception:

                    pass

            with _lock:

                b = _batches.get(bid)

                if b is not None:

                    b["updated_at"] = _now()

                    b["finished"] = finished

                    b["ok_count"] = ok_n

                    b["fail_count"] = fail_n

                    b["spawned"] = len(b.get("session_ids") or [])

                    b["spawn_errors"] = errors[-20:]

                    b["runner_alive"] = False

                    b["inflight"] = 0

                    target_total = int(b.get("count") or finished or 0)

                    cancelled = bool(b.get("cancel_requested")) or str(b.get("status") or "").lower() in (

                        "stopping",

                        "cancelled",

                        "stopped",

                    )

                    if cancelled and finished < target_total:

                        b["status"] = "cancelled"

                        b["message"] = (

                            f"stopped {finished}/{target_total} "

                            f"(ok={ok_n} fail={fail_n}, threads={workers})"

                        )

                    elif fail_n and not ok_n:

                        b["status"] = "error"

                        b["error"] = "; ".join(errors[:5]) or "all failed"

                        b["message"] = (

                            f"finished {finished}/{target_total} "

                            f"(ok={ok_n} fail={fail_n}, threads={workers})"

                            + (f"; errors={len(errors)}" if errors else "")

                        )

                    elif fail_n:

                        b["status"] = "partial"

                        b["message"] = (

                            f"finished {finished}/{target_total} "

                            f"(ok={ok_n} fail={fail_n}, threads={workers})"

                            + (f"; errors={len(errors)}" if errors else "")

                        )

                    else:

                        b["status"] = "done"

                        b["message"] = (

                            f"finished {finished}/{target_total} "

                            f"(ok={ok_n} fail={fail_n}, threads={workers})"

                        )

                    _mirror_reg_batch(bid, dict(b))

                    st = str(b.get("status") or "done")



                    # Registration workers only enqueue; kick a flush of any

                    # partial group left in the async upload queue.

                    batch_sync = b.get("auto_upload") if isinstance(b.get("auto_upload"), dict) else None

                    try:

                        qdepth = 0

                        with _upload_queue_cond:

                            qdepth = len(_upload_queue)

                            if qdepth:

                                _upload_queue_cond.notify()

                        if qdepth:

                            b["message"] = (

                                str(b.get("message") or "")

                                + f"；远端同步队列剩余 {qdepth}（后台分组上传中）"

                            )

                            _mirror_reg_batch(bid, dict(b))

                        # Summarize finished session uploads if any already applied.

                        uploaded = 0

                        total = 0

                        for sid0 in list(b.get("session_ids") or []):

                            sess0 = _sessions.get(sid0) or _load_reg_sess(str(sid0)) or {}

                            au = sess0.get("auto_upload") if isinstance(sess0.get("auto_upload"), dict) else None

                            if not au:

                                continue

                            if au.get("queued") and not au.get("finished_at"):

                                continue

                            if au.get("ok"):

                                uploaded += int(au.get("uploaded") or au.get("total") or 1)

                                total += int(au.get("total") or au.get("uploaded") or 1)

                        if uploaded:

                            batch_sync = {

                                "ok": True,

                                "uploaded": uploaded,

                                "total": total or uploaded,

                                "mode": "grouped_async",

                            }

                            b["auto_upload"] = batch_sync

                            b["message"] = str(b.get("message") or "") + f"；远端已同步 {uploaded}/{total or uploaded}"

                            _mirror_reg_batch(bid, dict(b))

                    except Exception as se:  # noqa: BLE001

                        batch_sync = {"ok": False, "error": str(se)[:240]}



                    _record_register_task(

                        task_id=str(bid),

                        summary=str(b.get("message") or f"协议注册批次 {bid}"),

                        status=st,

                        ok=st in {"done", "partial"} and ok_n > 0,

                        progress_done=int(finished or 0),

                        progress_total=int(target_total or finished or 0),

                        finished=True,

                        detail={

                            "batch_id": bid,

                            "ok_count": ok_n,

                            "fail_count": fail_n,

                            "threads": workers,

                            "status": st,

                            "errors": (errors or [])[:10],

                            "phase": "finished",

                            "adapter_build": ADAPTER_BUILD,

                            "auto_upload": batch_sync,

                        },

                    )

            _release_batch_runner(bid, lock_token)



    threading.Thread(

        target=_run_batch,

        daemon=True,

        name=f"gba-batch-{bid[-8:]}",

    ).start()



    return {

        "ok": True,

        "batch_id": bid,

        "remaining": remaining,

        "concurrency": workers,

        "message": f"started batch {bid}: remaining={remaining} threads={workers}",

    }





def _run_registration(

    sid: str,

    yescaptcha_key: str,

    proxy: str,

    receiver: Any,

) -> None:

    with _lock:

        sess = _sessions.get(sid)

    if not sess:

        # Another worker may hold the durable copy; still try to load.

        sess = _load_reg_sess(sid)

    if not sess:

        return

    # Re-bind process-local map so later progress stays readable on this worker.

    with _lock:

        _sessions[sid] = sess



    def _refresh_cancel_from_redis() -> None:

        """Pull cancel_requested from Redis so multi-worker stop works.



        Also honour batch-level stop so stopping a batch reaches in-flight

        sessions even if the session mirror lags.

        """

        if not _reg_redis():

            return

        try:

            from store import sessions_redis



            remote = sessions_redis.reg_sess_get(sid)

            batch_cancel = False

            remote_batch = None

            bid = ""

            with _lock:

                local_sess = _sessions.get(sid) or sess or {}

                bid = str(local_sess.get("batch_id") or "")

            if not bid and isinstance(remote, dict):

                bid = str(remote.get("batch_id") or "")

            if bid:

                try:

                    remote_batch = sessions_redis.reg_batch_get(bid)

                except Exception:

                    remote_batch = None

                if isinstance(remote_batch, dict) and (

                    remote_batch.get("cancel_requested")

                    or _is_cancel_status(remote_batch.get("status"))

                ):

                    batch_cancel = True

                    with _lock:

                        bb = _batches.get(bid) or dict(remote_batch)

                        bb["cancel_requested"] = True

                        if str(bb.get("status") or "").lower() not in (

                            "cancelled",

                            "stopped",

                            "done",

                            "partial",

                            "error",

                        ):

                            bb["status"] = remote_batch.get("status") or "stopping"

                        bb["updated_at"] = _now()

                        _batches[bid] = bb



            sess_cancel = isinstance(remote, dict) and (

                remote.get("cancel_requested")

                or _is_cancel_status(remote.get("status"))

            )

            if not sess_cancel and not batch_cancel:

                return

            with _lock:

                cur = _sessions.get(sid) or sess

                cur["cancel_requested"] = True

                if str(cur.get("status") or "").lower() not in _TERMINAL_STATUSES:

                    if sess_cancel and str(remote.get("status") or "").lower() in (

                        "stopping",

                        "cancelled",

                        "stopped",

                    ):

                        cur["status"] = remote.get("status") or "stopping"

                        if remote.get("message"):

                            cur["message"] = remote.get("message")

                    elif batch_cancel:

                        cur["status"] = "stopping"

                        cur["message"] = "stop requested via batch"

                _sessions[sid] = cur

        except Exception:

            pass



    def update(status: str, message: str, **kwargs: Any) -> None:

        _refresh_cancel_from_redis()

        with _lock:

            cur = _sessions.get(sid) or sess

            # Batch-level cancel also aborts this worker.

            bid = str(cur.get("batch_id") or "")

            batch_hit = False

            if bid:

                bb = _batches.get(bid) or {}

                if bb.get("cancel_requested") or _is_cancel_status(bb.get("status")):

                    batch_hit = True

                    cur["cancel_requested"] = True

            # Do not overwrite a terminal cancel with intermediate progress.

            if (_session_cancel_requested(cur) or batch_hit) and status not in (

                "cancelled",

                "stopped",

                "error",

                "imported",

            ):

                raise _RegCancelled(cur.get("message") or "cancelled by user")

            cur["status"] = status

            cur["message"] = message

            cur["updated_at"] = _now()

            cur.update(kwargs)

            _sessions[sid] = cur

            _mirror_reg_sess(sid, cur)



    def _check_cancel() -> None:

        _refresh_cancel_from_redis()

        with _lock:

            cur = _sessions.get(sid) or sess

            bid = str(cur.get("batch_id") or "")

            if bid:

                bb = _batches.get(bid) or {}

                if bb.get("cancel_requested") or _is_cancel_status(bb.get("status")):

                    cur["cancel_requested"] = True

                    _sessions[sid] = cur

        if _session_cancel_requested(cur):

            raise _RegCancelled(cur.get("message") or "cancelled by user")



    email = str(sess.get("email") or "").strip().lower()

    password = sess.get("password") or ""

    if not password:

        update("error", "missing password for registration session", error="missing password")

        return

    sess["email"] = email

    client = None



    try:

        _check_cancel()

        ensure_xconsole()

        from xconsole_client import (

            XConsoleAuthClient,

            YesCaptchaSolver,

            xai_oauth_login_protocol,

        )

        from xconsole_client import config as C

        from xconsole_client.oauth_protocol import extract_cookies_from_auth_client

        from xconsole_client.xai_oauth import (

            CLIPROXYAPI_GROK_HEADERS,

            build_cliproxyapi_auth_record,

        )

        import register_pro_store as accounts



        update("registering", "visiting signup page")

        _check_cancel()

        client = XConsoleAuthClient(

            debug=True,

            proxy=proxy or "",

            signup_url="https://accounts.x.ai/sign-up?redirect=grok-com",

        )

        client.visit_home()

        _check_cancel()

        client.load_signup_page()



        sitekey = (

            getattr(client, "turnstile_sitekey", None)

            or getattr(C, "TURNSTILE_SITEKEY", None)

            or ""

        ).strip()

        website_url = (getattr(client, "signup_url", None) or C.SIGNUP_URL or "").strip()

        if not sitekey:

            raise RuntimeError(

                "Turnstile sitekey missing. Signup page scrape failed and "

                "config TURNSTILE_SITEKEY is empty."

            )



        provider = (

            CAPTCHA_PROVIDER

            or os.environ.get("GROK2API_CAPTCHA_PROVIDER")

            or os.environ.get("CAPTCHA_PROVIDER")

            or "local"

        ).strip().lower()

        if provider not in {"local", "yescaptcha"}:

            provider = "local"



        if provider == "local":

            # Always use in-container inline solver; ignore external/custom URL.

            endpoint = _local_solver_base_url(None)

            solver_key = "local"

            auto_fallback = False

            # Re-check right before first solve so a mid-batch solver restart

            # doesn't burn mailboxes while HTTP is still down.

            wait = wait_for_local_solver(

                endpoint,

                timeout_sec=min(60.0, max(5.0, LOCAL_SOLVER_WAIT_SEC)),

                progress=lambda m: update("waiting_solver", m),

            )

            if not wait.get("ready"):

                raise RuntimeError(

                    wait.get("error")

                    or f"本地过盾未就绪，无法开始打码: {endpoint}"

                )

        else:

            # Cloud YesCaptcha only; never inherit local solver endpoint.

            endpoint = (

                os.environ.get("GROK2API_YESCAPTCHA_ENDPOINT")

                or os.environ.get("YESCAPTCHA_ENDPOINT")

                or os.environ.get("YESCAPTCHA_API_BASE")

                or ""

            ).strip() or None

            # Guard against accidental local leftover endpoint.

            if endpoint and (

                "127.0.0.1" in endpoint

                or "localhost" in endpoint

                or endpoint.rstrip("/").endswith(":5072")

            ):

                endpoint = None

            solver_key = (

                yescaptcha_key

                or YESCAPTCHA_KEY

                or os.environ.get("GROK2API_YESCAPTCHA_KEY")

                or os.environ.get("YESCAPTCHA_API_KEY")

                or ""

            ).strip()

            if not solver_key or solver_key == "local":

                raise RuntimeError("YesCaptcha 模式需要有效的 YESCAPTCHA_KEY")

            auto_fallback = True



        def _turnstile_progress(msg: str) -> None:

            # Raise cancel out of solver polling so stop doesn't wait full captcha timeout.

            _check_cancel()

            update("solving_turnstile", f"Turnstile: {msg}")



        solver = YesCaptchaSolver(

            solver_key,

            endpoint=endpoint,

            # Keep captcha wait bounded; cancel still interrupts via on_progress.

            timeout=float(os.environ.get("GROK2API_YESCAPTCHA_TIMEOUT", "120") or 120),

            poll_interval=float(os.environ.get("GROK2API_YESCAPTCHA_POLL", "2") or 2),

            debug=True,

            on_progress=_turnstile_progress,

            # Local: no cloud fallback. YesCaptcha: allow cn/global peer fallback.

            auto_fallback_endpoint=auto_fallback,

        )

        print(

            f"[grok-build-auth] turnstile provider={provider} website_url={website_url} "

            f"sitekey={sitekey} endpoint={getattr(solver, '_endpoint', '?')}"

        )



        # Critical ordering:

        # 1) solve Turnstile first (slow, ~20-40s)

        # 2) send email code

        # 3) wait for mailbox code

        # 4) immediately verify + create_account

        # Old order verified the code then waited for captcha; create_account then

        # failed with WKE=email:invalid-validation-code because the code expired /

        # was single-use after the slow captcha step.

        solver_label = "本地过盾" if provider == "local" else "YesCaptcha"

        update("solving_turnstile", f"solving Turnstile via {solver_label} (before email code)")

        _check_cancel()



        def _solve_turnstile(url: str, *, premium: bool = True) -> Any:

            # Local inline solver is single-process and browser-backed; concurrent

            # createTask storms from many registration workers cause timeouts /

            # mixed results. Serialize local solves while keeping YesCaptcha parallel.

            # captcha_use_proxy: when True, Camoufox uses the same job proxy as protocol.

            use_premium = bool(premium) and provider != "local"

            captcha_proxy = None

            if provider == "local":

                use_px = True

                try:

                    bid = str(sess.get("batch_id") or "")

                    if bid:

                        with _lock:

                            bb = _batches.get(bid) or {}

                        rc = bb.get("reg_config") if isinstance(bb.get("reg_config"), dict) else {}

                        if "captcha_use_proxy" in rc:

                            use_px = bool(rc.get("captcha_use_proxy"))

                        else:

                            use_px = bool(globals().get("REGISTER_CAPTCHA_USE_PROXY", True))

                    else:

                        use_px = bool(globals().get("REGISTER_CAPTCHA_USE_PROXY", True))

                except Exception:

                    use_px = bool(globals().get("REGISTER_CAPTCHA_USE_PROXY", True))

                if use_px:

                    captcha_proxy = (proxy or "").strip() or None

            kwargs = {

                "website_url": url,

                "website_key": sitekey,

                "premium": use_premium,

                "fallback_non_premium": True,

                "proxy": captcha_proxy,

            }

            if provider == "local":

                # Original serial strategy from git history.

                with _CaptchaSlot():

                    _check_cancel()

                    try:

                        return solver.solve_turnstile(**kwargs)

                    except Exception as e:

                        # Camoufox queue meltdown / timeout → brief global pause

                        msg = str(e).lower()

                        if any(

                            k in msg

                            for k in (

                                "timeout",

                                "timed out",

                                "queue",

                                "busy",

                                "no browser",

                                "target closed",

                                "crashed",

                            )

                        ):

                            _note_reg_pressure(f"local captcha: {e}")

                        raise

            return solver.solve_turnstile(**kwargs)



        try:

            # Local: Proxyless only. Remote YesCaptcha: premium M1 first.

            turnstile = _solve_turnstile(website_url, premium=(provider != "local"))

        except _RegCancelled:

            raise

        except Exception as captcha_err:

            _check_cancel()

            alt_url = "https://accounts.x.ai/sign-up?redirect=cloud-console"

            if website_url.rstrip("/") == alt_url.rstrip("/"):

                alt_url = "https://accounts.x.ai/sign-up?redirect=grok-com"

            update(

                "solving_turnstile",

                f"primary Turnstile failed ({captcha_err}); retry {alt_url}",

            )

            try:

                turnstile = _solve_turnstile(alt_url, premium=False)

            except Exception as retry_err:

                if provider == "local":

                    raise RuntimeError(

                        "本地过盾失败：Camoufox 没有拿到 Turnstile token；"

                        f"首轮错误：{captcha_err}; 重试错误：{retry_err}"

                    ) from retry_err

                raise

        if not turnstile:

            raise RuntimeError("YesCaptcha returned empty Turnstile token")

        _check_cancel()



        # Password can be validated any time before create; do it while warm.

        client.validate_password(email, password)



        update("registering", "sending email validation code")

        _check_cancel()

        send_res = client.create_email_validation_code(email)

        if hasattr(send_res, "ok") and send_res.ok is False:

            print(

                f"[grok-build-auth] CreateEmailValidationCode ok=False "

                f"http={getattr(send_res, 'http_status', None)} "

                f"grpc={getattr(send_res, 'grpc_status', None)}"

            )



        update("waiting_email", "waiting for xAI verification code")

        # Poll mailbox with cancel-aware receiver so stop lands in ~0.25–1s.

        _check_cancel()



        def _mail_should_cancel() -> bool:

            # _check_cancel raises _RegCancelled when stop is requested.

            _check_cancel()

            return False



        try:

            code = receiver.wait_for_code(

                timeout=120.0,

                should_cancel=_mail_should_cancel,

                poll_interval=1.0,

            )

        except TypeError:

            # Older receiver signature fallback.

            code = None

            mail_deadline = time.time() + 120.0

            while time.time() < mail_deadline:

                _check_cancel()

                try:

                    code = receiver.wait_for_code(

                        timeout=min(4.0, max(1.0, mail_deadline - time.time()))

                    )

                except Exception:

                    code = None

                if code:

                    break

        if not code:

            raise RuntimeError("email verification code timeout")

        code = str(code or "").strip().upper().replace(" ", "").replace("-", "")

        if len(code) != 6:

            raise RuntimeError(

                f"invalid email verification code shape: {code!r} "

                f"(expect 6 alnum chars)"

            )

        update("registering", f"code received: {code}; verifying + creating immediately")



        # Prefer empty castle token (YesCaptcha cannot mint Castle fingerprints).

        # Retry create_account once with a fresh Turnstile + fresh email code when

        # the first flight is a structured hard error (expired code / turnstile).

        create_attempts = 2

        res = None

        sc: list[str] = []

        rsc_body = ""

        rsc_preview = ""

        http_status = 0

        signup_err: str | None = None

        for ca in range(1, create_attempts + 1):

            if ca > 1:

                # Full refresh path for invalid code / captcha failures.

                update(

                    "solving_turnstile",

                    f"create_account hard error ({signup_err}); refreshing Turnstile+email code",

                )

                try:

                    turnstile = _solve_turnstile(

                        website_url, premium=(provider != "local")

                    )

                except Exception as captcha_err:  # noqa: BLE001

                    print(f"[grok-build-auth] turnstile refresh failed: {captcha_err}")

                    break

                # New email code required after invalid-validation-code.

                try:

                    client.create_email_validation_code(email)

                    update("waiting_email", "waiting for fresh xAI verification code")

                    code = receiver.wait_for_code(timeout=120)

                    code = (

                        str(code or "")

                        .strip()

                        .upper()

                        .replace(" ", "")

                        .replace("-", "")

                    )

                    if len(code) != 6:

                        raise RuntimeError(f"fresh email code invalid: {code!r}")

                    update("registering", f"fresh code received: {code}")

                except Exception as mail_err:  # noqa: BLE001

                    print(f"[grok-build-auth] email code refresh failed: {mail_err}")

                    break



            # verify immediately before create_account (same second when possible)

            try:

                vres = client.verify_email_validation_code(email, code)

                print(

                    f"[grok-build-auth] VerifyEmailValidationCode "

                    f"ok={getattr(vres, 'ok', None)} "

                    f"http={getattr(vres, 'http_status', None)} "

                    f"grpc={getattr(vres, 'grpc_status', None)}"

                )

            except Exception as v_err:  # noqa: BLE001

                print(f"[grok-build-auth] verify_email error: {v_err}")



            update(

                "creating_account",

                f"creating xAI account (attempt {ca}/{create_attempts})",

            )

            res = client.create_account(

                email=email,

                given_name=str(sess.get("given_name") or "User"),

                family_name=str(sess.get("family_name") or "Grok"),

                password=password,

                email_validation_code=code,

                turnstile_token=turnstile,

                castle_request_token="",

                conversion_id=str(uuid.uuid4()),

            )

            sc = list(getattr(res, "set_cookies", None) or [])

            rsc_body = getattr(res, "rsc_body", "") or ""

            rsc_preview = rsc_body[:800]

            http_status = int(getattr(res, "http_status", 0) or 0)

            try:

                signup_err = client.extract_signup_error(rsc_body)

            except Exception:

                signup_err = None

            print(f"[grok-build-auth] create_account HTTP={http_status}")

            print(f"[grok-build-auth] create_account set-cookies count={len(sc)}")

            print(f"[grok-build-auth] create_account ok={bool(getattr(res, 'ok', False))}")

            print(f"[grok-build-auth] create_account error={signup_err!r}")

            print(f"[grok-build-auth] create_account rsc_body preview: {rsc_preview}")

            print(f"[grok-build-auth] adapter_build={ADAPTER_BUILD}")

            sess["create_account_http"] = http_status

            sess["create_account_ok_flag"] = bool(getattr(res, "ok", False))

            sess["create_account_set_cookies"] = len(sc)

            sess["create_account_error"] = signup_err



            # Optional offline diagnosis dump (off by default; ~70KB each).

            # Enable with GROK2API_DUMP_CREATE_ACCOUNT_RSC=1 when debugging signup.

            if os.environ.get("GROK2API_DUMP_CREATE_ACCOUNT_RSC", "").strip().lower() in {

                "1", "true", "yes", "on"

            }:

                try:

                    debug_path = (

                        # Prefer the pro data dir (Docker volume /data) when present.

                        Path(os.getenv("GROK_REGISTER_PRO_DATA_DIR") or (ROOT / "generated" / "register_pro"))

                        / "register_sso"

                        / f"{sid}.create_account.rsc.txt"

                    )

                    debug_path.parent.mkdir(parents=True, exist_ok=True)

                    debug_path.write_text(rsc_body[:200_000], encoding="utf-8")

                except Exception:

                    pass



            if http_status != 200:

                # Non-200 is terminal for this attempt; try once more only on 5xx.

                if http_status >= 500 and ca < create_attempts:

                    continue

                raise RuntimeError(

                    "create_account transport failed. "

                    f"adapter_build={ADAPTER_BUILD}; HTTP {http_status}; "

                    f"error={signup_err!r}; set_cookies={len(sc)}; "

                    f"body_preview={rsc_preview!r}"

                )



            # Structured hard error: retry with fresh captcha when recoverable.

            if signup_err:

                recoverable = any(

                    x in str(signup_err).lower()

                    for x in (

                        "turnstile",

                        "rate_limited",

                        "rate limit",

                        "captcha",

                        "account_signup_error",

                    )

                )

                if recoverable and ca < create_attempts:

                    continue

                raise RuntimeError(

                    "create_account rejected by xAI. "

                    f"adapter_build={ADAPTER_BUILD}; HTTP {http_status}; "

                    f"error={signup_err!r}; set_cookies={len(sc)}; "

                    f"body_preview={rsc_preview!r}"

                )



            # HTTP 200 without structured error — proceed even if res.ok is False

            # due to historical false negatives on RSC-only flights.

            break



        update(

            "fetching_sso",

            f"create_account HTTP {http_status} accepted; extracting SSO [{ADAPTER_BUILD}]",

        )



        sso = None

        try:

            sso = client.fetch_sso_token(

                email=email, password=password, save=True, retries=4

            )

        except Exception as sso_fetch_err:  # noqa: BLE001

            print(f"[grok-build-auth] fetch_sso_token error: {sso_fetch_err}")



        if not sso:

            try:

                from xconsole_client.sso import (

                    SSOExtractor,

                    parse_all_set_cookie_urls,

                    parse_sso_from_set_cookies,

                    parse_sso_jwt_url,

                    parse_sso_token_from_text,

                )



                sso = parse_sso_from_set_cookies(sc) or parse_sso_token_from_text(

                    rsc_body

                )

                if not sso and rsc_body:

                    print(

                        f"[grok-build-auth] set-cookie candidates="

                        f"{parse_all_set_cookie_urls(rsc_body)[:3]}"

                    )

                    print(

                        f"[grok-build-auth] primary set-cookie url="

                        f"{parse_sso_jwt_url(rsc_body)}"

                    )

                    extractor = SSOExtractor(

                        transport_request=client._request,

                        base_headers=client._base_headers,

                        cookie_jar=client._t.cookies,

                        debug=True,

                    )

                    sso = extractor.extract(

                        rsc_body, email=email, password=password, save=False

                    )

            except Exception as recover_err:  # noqa: BLE001

                print(f"[grok-build-auth] SSO recover failed: {recover_err}")



        # Current xAI create_account often returns only RSC chunks + CF cookies,

        # with no set-cookie JWT chain. Fall back to password CreateSession and

        # treat the returned session JWT as the sso cookie for sso_to_auth_json.

        if not sso:

            update(

                "fetching_sso",

                f"RSC has no sso chain; CreateSession password fallback [{ADAPTER_BUILD}]",

            )

            try:

                # Fresh turnstile for sign-in page improves CreateSession success.

                # Allow account propagation delay before first login attempt.

                time.sleep(2.0)

                signin_url = "https://accounts.x.ai/sign-in?redirect=grok-com"

                try:

                    signin_turnstile = _solve_turnstile(

                        signin_url, premium=(provider != "local")

                    )

                except Exception:

                    signin_turnstile = turnstile

                sso = client.obtain_session_via_password(

                    email=email,

                    password=password,

                    turnstile_token=signin_turnstile,

                    referer=signin_url,

                    retries=4,

                )

                # One more captcha + login if first CreateSession returned empty.

                if not sso:

                    try:

                        signin_turnstile = _solve_turnstile(signin_url, premium=False)

                        time.sleep(1.5)

                        sso = client.obtain_session_via_password(

                            email=email,

                            password=password,

                            turnstile_token=signin_turnstile,

                            referer=signin_url,

                            retries=2,

                        )

                    except Exception as cs2_err:  # noqa: BLE001

                        print(

                            f"[grok-build-auth] CreateSession second pass failed: {cs2_err}"

                        )

                print(

                    f"[grok-build-auth] CreateSession fallback sso="

                    f"{(sso[:60] if sso else None)}"

                )

            except Exception as cs_err:  # noqa: BLE001

                print(f"[grok-build-auth] CreateSession fallback failed: {cs_err}")



        print(f"[grok-build-auth] fetch_sso_token result: {sso[:60] if sso else None}")

        sess["sso"] = sso

        session_cookies = extract_cookies_from_auth_client(client)

        print(

            f"[grok-build-auth] session cookies after signup: "

            f"{sorted((session_cookies or {}).keys())}"

        )

        if sso:

            session_cookies = dict(session_cookies or {})

            session_cookies["sso"] = sso

            session_cookies["sso-rw"] = sso



        if not sso:

            raise RuntimeError(

                "SSO_COOKIE_MISSING after create_account. "

                f"adapter_build={ADAPTER_BUILD}; HTTP {http_status}; "

                f"create_ok={bool(getattr(res, 'ok', False))}; "

                f"signup_error={signup_err!r}; set_cookies={len(sc)}; "

                f"cookie_keys={sorted((session_cookies or {}).keys())}; "

                f"body_preview={rsc_preview!r}. "

                "Account may have been created, but neither RSC set-cookie chain "

                "nor CreateSession password fallback produced an sso cookie. "

                "Common causes: turnstile_failed, rate_limited, or account not yet "

                "visible to CreateSession."

            )



        # Required path: SSO/session JWT -> sso_to_auth_json device flow -> auth.json

        # Optional: sso_only keeps the SSO cookie and skips device-flow conversion.

        sso_only = bool(globals().get("REGISTER_SSO_ONLY")) or (

            str(os.environ.get("GROK2API_REG_SSO_ONLY", "") or "").strip().lower()

            in {"1", "true", "yes", "on"}

        )

        if sso_only:

            update(

                "importing",

                f"SSO obtained; sso_only=1 跳过 OAuth/CPA 转换 [{ADAPTER_BUILD}]",

            )

            try:

                import register_pro_store as pro_store



                saved = pro_store.import_sso_only_account(

                    email=email,

                    password=password,

                    sso=sso,

                    batch_id=str(sess.get("batch_id") or ""),

                    session_id=sid,

                )

                try:

                    recv = sess.get("_receiver")

                    if recv is not None and callable(getattr(recv, "cleanup_success", None)):

                        recv.cleanup_success()

                except Exception as _om_exc:  # noqa: BLE001

                    print(f"[outmail] post-success cleanup skipped: {_om_exc}", flush=True)

            except Exception as se:  # noqa: BLE001

                raise RuntimeError(

                    f"SSO-only 入库失败: {se}; adapter_build={ADAPTER_BUILD}"

                ) from se

            if not saved.get("ok"):

                raise RuntimeError(

                    f"SSO-only 入库失败: {saved.get('error')}; "

                    f"adapter_build={ADAPTER_BUILD}"

                )

            imported_rows = [

                x for x in (saved.get("imported") or []) if isinstance(x, dict)

            ]

            imported_ids = [str(x.get("id")) for x in imported_rows if x.get("id")]

            imported_accounts = [

                {"id": x.get("id"), "email": x.get("email") or email}

                for x in imported_rows

                if x.get("id") or x.get("email")

            ]

            sess["auth_json"] = saved

            sess["imported_account_ids"] = imported_ids

            sess["imported_accounts"] = imported_accounts

            sess["oauth"] = {

                "path": "sso_only",

                "sso_only": True,

                "email": email,

            }

            sess["probe"] = {

                "count": 0,

                "ok": 1,

                "fail": 0,

                "skipped": True,

                "sso_only": True,

                "results": [],

            }

            message = f"已保存 SSO（未转 Auth/CPA）email={email} [{ADAPTER_BUILD}]"

            # Still auto-import to remote when enabled. Grok2API web_sso can take

            # SSO cookies directly; CPA needs Auth and will skip until convert.

            auto_upload = None

            try:

                auto_upload = _enqueue_auto_upload_emails(

                    [str(email).strip().lower()] if email else [],

                    require_probe=False,

                    session_id=str(sess.get("id") or ""),

                    batch_id=str(sess.get("batch_id") or ""),

                )

            except Exception as ae:  # noqa: BLE001

                auto_upload = {"ok": False, "error": str(ae)[:240]}

            if isinstance(auto_upload, dict):

                sess["auto_upload"] = auto_upload

                if auto_upload.get("queued"):

                    message += (

                        f"；远端同步已排队（组大小 {_upload_group_size()}，"

                        f"队列 {int(auto_upload.get('queue_depth') or 0)}）"

                    )

                elif auto_upload.get("error"):

                    message += "；自动导入排队失败：" + str(auto_upload.get("error"))[:120]

            update(

                "imported",

                message,

                error=None,

                imported_account_ids=imported_ids,

                imported_accounts=imported_accounts,

                probe=sess.get("probe"),

                auto_upload=sess.get("auto_upload"),

                sso_only=True,

                sso=True,

            )

            return



        update(

            "importing",

            f"SSO obtained; converting via sso_to_auth_json [{ADAPTER_BUILD}]",

        )

        import sso_to_auth_json as sso_import



        token = sso_import.sso_to_token(sso)

        if not token or not token.get("access_token"):

            _note_reg_pressure("device-flow conversion failed", pause_sec=10)

            raise RuntimeError(

                "SSO obtained but sso_to_auth_json conversion failed "

                "(device verify/approve/token poll; often xAI device-flow "

                "rate_limited/slow_down under concurrent registration). "

                f"adapter_build={ADAPTER_BUILD}; sso_prefix={sso[:24]!r}"

            )

        _key, entry = sso_import.token_to_auth_entry(token, email=email)

        import_result = accounts.import_auth_payload(

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

                "batch_id": sess.get("batch_id") or "",

                "session_id": sid,

                "given_name": sess.get("given_name") or "",

                "family_name": sess.get("family_name") or "",

            },

            merge=True,

        )

        # Outmail: mark mailbox used + optional anon cleanup after success.

        try:

            recv = sess.get("_receiver")

            if recv is not None and callable(getattr(recv, "cleanup_success", None)):

                recv.cleanup_success()

        except Exception as _om_exc:  # noqa: BLE001

            print(f"[outmail] post-success cleanup skipped: {_om_exc}", flush=True)

        if not import_result.get("ok"):

            raise RuntimeError(

                f"SSO account import failed: {import_result.get('error')}; "

                f"adapter_build={ADAPTER_BUILD}"

            )

        # Registration import is persisted in the local SQLite account store.

        imported_rows = [

            x for x in (import_result.get("imported") or []) if isinstance(x, dict)

        ]

        imported_ids = [str(x.get("id")) for x in imported_rows if x.get("id")]

        imported_accounts = [

            {"id": x.get("id"), "email": x.get("email") or email}

            for x in imported_rows

            if x.get("id") or x.get("email")

        ]

        sess["auth_json"] = import_result

        sess["imported_account_ids"] = imported_ids

        sess["imported_accounts"] = imported_accounts

        sess["oauth"] = {

            "path": "sso_to_auth_json",

            "access_token": (token.get("access_token") or "")[:20] + "...",

            "refresh_token": bool(token.get("refresh_token")),

            "email": email,

        }

        # Auto probe newly imported accounts so they are validated in the pool.

        # skip_probe: keep credentials without model probe (bulk / speed mode).

        skip_probe = bool(globals().get("REGISTER_SKIP_PROBE")) or (

            str(os.environ.get("GROK2API_REG_SKIP_PROBE", "") or "").strip().lower()

            in {"1", "true", "yes", "on"}

        )

        probe_summaries: list[dict[str, Any]] = []

        pro_mode = os.environ.get("GROK_REGISTER_PRO", "").strip().lower() in {

            "1",

            "true",

            "yes",

            "on",

        }

        if imported_ids and skip_probe:

            update(

                "imported",

                f"已导入 {len(imported_ids)} 个账号；已跳过测活，凭证已保留 "

                f"[{ADAPTER_BUILD}]",

                imported_account_ids=imported_ids,

                imported_accounts=imported_accounts,

                skip_probe=True,

            )

            keep_emails = []

            for acc in imported_accounts or []:

                em = str(acc.get("email") or "").strip().lower()

                if em:

                    keep_emails.append(em)

            if not keep_emails and email:

                keep_emails = [str(email).strip().lower()]

            ok_n = max(1, len(keep_emails) or len(imported_ids))

            fail_n = 0

            probe_error = ""

            sess["probe"] = {

                "count": 0,

                "ok": ok_n,

                "fail": 0,

                "skipped": True,

                "results": [],

            }

            status = "imported"

            message = f"已跳过测活，凭证已写入数据库（{ok_n}）。"

            # Non-blocking: enqueue for grouped async remote upload.

            auto_upload = None

            try:

                auto_upload = _enqueue_auto_upload_emails(

                    keep_emails,

                    require_probe=False,

                    session_id=str(sess.get("id") or ""),

                    batch_id=str(sess.get("batch_id") or ""),

                )

            except Exception as ae:  # noqa: BLE001

                auto_upload = {"ok": False, "error": str(ae)[:240]}

            if isinstance(auto_upload, dict):

                sess["auto_upload"] = auto_upload

                if auto_upload.get("queued"):

                    message += (

                        f" 远端同步已排队（组大小 {_upload_group_size()}，"

                        f"队列 {int(auto_upload.get('queue_depth') or 0)}）"

                    )

                elif auto_upload.get("error"):

                    message += " 自动导入排队失败：" + str(auto_upload.get("error"))[:120]

            sess["imported_account_ids"] = imported_ids

            sess["imported_accounts"] = imported_accounts

            update(

                status,

                message,

                error=None,

                imported_account_ids=imported_ids,

                imported_accounts=imported_accounts,

                probe=sess.get("probe"),

                auto_upload=sess.get("auto_upload"),

                skip_probe=True,

            )

            return

        if imported_ids and not pro_mode:

            delay = max(0.0, float(REGISTER_PROBE_DELAY_SEC or 0.0))

            if delay > 0:

                update(

                    "probing",

                    f"imported {len(imported_ids)} account(s); wait {int(delay)}s "

                    f"before probe [{ADAPTER_BUILD}]",

                    imported_account_ids=imported_ids,

                    imported_accounts=imported_accounts,

                    probe_delay_sec=delay,

                )

                time.sleep(delay)

            update(

                "probing",

                f"imported {len(imported_ids)} account(s); probing pool health "

                f"(delay={int(delay)}s) [{ADAPTER_BUILD}]",

                imported_account_ids=imported_ids,

                imported_accounts=imported_accounts,

                probe_delay_sec=delay,

            )

            try:

                import model_health



                for aid in imported_ids:

                    try:

                        pr = model_health.probe_single_account(

                            aid, None, auto_disable=True, source="register"

                        )

                        detail = pr.get("result") if isinstance(pr, dict) else None

                        if not isinstance(detail, dict):

                            detail = pr if isinstance(pr, dict) else {}

                        err_text = (

                            detail.get("error")

                            or detail.get("message")

                            or (pr.get("error") if isinstance(pr, dict) else None)

                            or ""

                        )

                        latency = (

                            detail.get("latency_ms")

                            or detail.get("elapsed_ms")

                            or detail.get("duration_ms")

                        )

                        probe_summaries.append(

                            {

                                "account_id": aid,

                                "ok": bool(pr.get("ok") if isinstance(pr, dict) else False),

                                "model": detail.get("model")

                                or (pr.get("model") if isinstance(pr, dict) else None),

                                "error": (str(err_text)[:180] if err_text else None),

                                "latency_ms": latency,

                            }

                        )

                    except Exception as pe:  # noqa: BLE001

                        probe_summaries.append(

                            {

                                "account_id": aid,

                                "ok": False,

                                "error": str(pe)[:180],

                            }

                        )

            except Exception as pe:  # noqa: BLE001

                probe_summaries.append(

                    {

                        "account_id": None,

                        "ok": False,

                        "error": f"probe module error: {pe}"[:180],

                    }

                )

        elif imported_ids:

            delay = max(0.0, float(REGISTER_PROBE_DELAY_SEC or 0.0))

            if delay > 0:

                update(

                    "probing",

                    f"已导入 {len(imported_ids)} 个账号；等待 {int(delay)} 秒后测活 "

                    f"[{ADAPTER_BUILD}]",

                    imported_account_ids=imported_ids,

                    imported_accounts=imported_accounts,

                    probe_delay_sec=delay,

                )

                time.sleep(delay)

            update(

                "probing",

                f"已导入 {len(imported_ids)} 个账号；正在测活 [{ADAPTER_BUILD}]",

                imported_account_ids=imported_ids,

                imported_accounts=imported_accounts,

                probe_delay_sec=delay,

            )

            for account in imported_accounts or [{"id": imported_ids[0], "email": email}]:

                ident = str(account.get("email") or account.get("id") or "").strip()

                if not ident:

                    continue

                try:

                    pr = accounts.probe_account(ident, model="grok-4.5")

                    probe_summaries.append(

                        {

                            "account_id": account.get("id") or ident,

                            "email": account.get("email") or ident,

                            "ok": bool(pr.get("ok")),

                            "model": pr.get("model") or "grok-4.5",

                            "error": (str(pr.get("error"))[:180] if pr.get("error") else None),

                            "latency_ms": pr.get("latency_ms"),

                        }

                    )

                except Exception as pe:  # noqa: BLE001

                    probe_summaries.append(

                        {

                            "account_id": account.get("id") or ident,

                            "email": account.get("email") or ident,

                            "ok": False,

                            "error": str(pe)[:180],

                        }

                    )

        sess["probe"] = {

            "count": len(probe_summaries),

            "ok": sum(1 for p in probe_summaries if p.get("ok")),

            "fail": sum(1 for p in probe_summaries if not p.get("ok")),

            "results": probe_summaries,

        }

        ok_n = int(sess["probe"]["ok"])

        fail_n = int(sess["probe"]["fail"])

        probe_error = next(

            (str(item.get("error") or "") for item in probe_summaries if not item.get("ok")),

            "",

        )

        # Gate: only probe-passed accounts stay in SQLite and count as success.

        # Registration may write credentials first so probe can run; failures are discarded.

        if not probe_summaries:

            # No probe ran → do not keep half-baked credentials.

            fail_n = max(fail_n, 1)

            ok_n = 0

            probe_error = probe_error or "未测活，凭证未保留"

        keep_emails: list[str] = []

        drop_emails: list[str] = []

        for item in probe_summaries:

            em = str(item.get("email") or "").strip().lower()

            if not em and email:

                em = str(email).strip().lower()

            if not em:

                continue

            if item.get("ok"):

                keep_emails.append(em)

            else:

                drop_emails.append(em)

        if not probe_summaries and email:

            drop_emails.append(str(email).strip().lower())

        # Also drop anything we imported that is not in keep list.

        for acc in imported_accounts or []:

            em = str(acc.get("email") or "").strip().lower()

            if em and em not in keep_emails and em not in drop_emails:

                drop_emails.append(em)

        if drop_emails:

            try:

                discard_fn = getattr(accounts, "discard_accounts", None) or accounts.delete_accounts

                discarded = discard_fn(drop_emails)

                print(

                    f"[grok-build-auth] probe-fail discard emails={drop_emails} "

                    f"result={discarded}"

                )

            except Exception as de:  # noqa: BLE001

                print(f"[grok-build-auth] probe-fail discard error: {de}")

        if keep_emails and fail_n == 0:

            status = "imported"

            message = f"测活通过，已写入数据库（{ok_n}）。"

            imported_accounts = [

                a

                for a in (imported_accounts or [])

                if str(a.get("email") or "").strip().lower() in set(keep_emails)

            ] or [{"id": imported_ids[0] if imported_ids else "", "email": keep_emails[0]}]

            imported_ids = [

                str(a.get("id") or "")

                for a in imported_accounts

                if a.get("id")

            ] or list(imported_ids)



            # Non-blocking: enqueue for grouped async remote upload.

            auto_upload = None

            try:

                auto_upload = _enqueue_auto_upload_emails(

                    keep_emails,

                    require_probe=True,

                    session_id=str(sess.get("id") or ""),

                    batch_id=str(sess.get("batch_id") or ""),

                )

            except Exception as ae:  # noqa: BLE001

                auto_upload = {"ok": False, "error": str(ae)[:240]}

            if isinstance(auto_upload, dict):

                sess["auto_upload"] = auto_upload

                if auto_upload.get("queued"):

                    message += (

                        f" 远端同步已排队（组大小 {_upload_group_size()}，"

                        f"队列 {int(auto_upload.get('queue_depth') or 0)}）"

                    )

                elif auto_upload.get("error"):

                    message += " 自动导入排队失败：" + str(auto_upload.get("error"))[:120]

        else:

            # Count as hard failure so batch ok/fail reflects probe gate only.

            status = "failed"

            message = (

                f"测活未通过，已丢弃本地凭证（失败 {max(fail_n, 1)}）。"

            )

            if probe_error:

                message += f" 原因：{str(probe_error)[:160]}"

            imported_ids = []

            imported_accounts = []

            ok_n = 0

            fail_n = max(fail_n, 1)

            sess["probe"]["ok"] = 0

            sess["probe"]["fail"] = fail_n

        sess["imported_account_ids"] = imported_ids

        sess["imported_accounts"] = imported_accounts

        update(

            status,

            message,

            error=probe_error or None if status != "imported" else None,

            imported_account_ids=imported_ids,

            imported_accounts=imported_accounts,

            probe=sess.get("probe"),

            auto_upload=sess.get("auto_upload"),

        )

        return

    except _RegCancelled as exc:

        with _lock:

            cur = _sessions.get(sid) or sess

            cur["status"] = "cancelled"

            cur["message"] = str(exc) or "cancelled by user"

            cur["error"] = "cancelled"

            cur["cancel_requested"] = True

            cur["updated_at"] = _now()

            _sessions[sid] = cur

            _mirror_reg_sess(sid, cur)

        return

    except Exception as exc:  # noqa: BLE001

        try:

            update("error", f"failed: {exc}", error=str(exc))

        except _RegCancelled:

            with _lock:

                cur = _sessions.get(sid) or sess

                cur["status"] = "cancelled"

                cur["message"] = "cancelled by user"

                cur["error"] = "cancelled"

                cur["cancel_requested"] = True

                cur["updated_at"] = _now()

                _sessions[sid] = cur

                _mirror_reg_sess(sid, cur)

    finally:

        if client is not None:

            try:

                client.close()

            except Exception:

                pass

        with _lock:

            final_sess = dict(_sessions.get(sid) or sess or {})

            if sid in _sessions:

                _sessions[sid].pop("_receiver", None)

                _sessions[sid].pop("_client", None)

        # Single sessions write their own terminal task log. Batch sessions are

        # summarized once by the batch finalizer (avoids N noise rows).

        if final_sess and not final_sess.get("batch_id"):

            payload = _session_task_log_payload(final_sess)

            if payload.get("finished"):

                _record_register_task(

                    task_id=payload["task_id"] or sid,

                    summary=payload["summary"],

                    status=payload["status"],

                    ok=payload["ok"],

                    progress_done=payload["progress_done"],

                    progress_total=payload["progress_total"],

                    finished=True,

                    detail={**payload["detail"], "phase": "finished"},

                )







def _nonterminal_session_statuses() -> frozenset[str]:

    return frozenset(

        {

            "pending",

            "queued",

            "starting",

            "started",

            "running",

            "probing",

            "solving_turnstile",

            "waiting_email",

            "fetching_sso",

            "converting",

            "importing",

            "stopping",

        }

    )





def reclaim_orphaned_registration_sessions(

    *,

    stale_sec: float | None = None,

    batch_id: str | None = None,

) -> dict[str, Any]:

    """Mark abandoned non-terminal sessions as error so a batch can resume.



    After process restart / image upgrade, in-flight workers die but Redis still

    shows ``solving_turnstile`` etc. Those sessions never finish, and the

    batch runner is gone — registration appears "hung mid-way".

    """

    try:

        ttl = float(

            stale_sec

            if stale_sec is not None

            else (os.environ.get("GROK2API_REG_STALE_SEC", "180") or 180)

        )

    except (TypeError, ValueError):

        ttl = 180.0

    ttl = max(30.0, min(ttl, 3600.0))

    now = _now()

    nonterm = _nonterminal_session_statuses()

    want_batch = (batch_id or "").strip() or None



    reclaimed: list[dict[str, Any]] = []

    # Prefer durable Redis list when available.

    sessions: list[dict[str, Any]] = []

    if _reg_redis():

        try:

            from store import sessions_redis



            listed = sessions_redis.reg_sess_list() or []

            if isinstance(listed, list):

                sessions = [s for s in listed if isinstance(s, dict)]

        except Exception:

            sessions = []

    if not sessions:

        with _lock:

            sessions = [dict(v) for v in _sessions.values() if isinstance(v, dict)]



    for sess in sessions:

        sid = str(sess.get("id") or "").strip()

        if not sid:

            continue

        bid = str(sess.get("batch_id") or "").strip()

        if want_batch and bid != want_batch:

            continue

        st = str(sess.get("status") or "").strip().lower()

        if st in _TERMINAL_STATUSES or st not in nonterm:

            continue

        # Always reclaim if no local/remote runner can own it; use stale age as

        # a safety so we don't kill a still-running worker in the same process.

        age = now - float(sess.get("updated_at") or sess.get("created_at") or 0)

        # If this process holds an active runner for the batch, only reclaim

        # sessions older than ttl (true stalls). If no runner, reclaim all

        # non-terminal after a short grace (30s) so resume can proceed.

        has_runner = False

        if bid:

            with _lock:

                has_runner = bool(_active_batch_runners.get(bid))

            if not has_runner and _reg_redis():

                try:

                    from store.redis_client import get_str as redis_get



                    has_runner = bool(redis_get(_batch_runner_lock_key(bid)))

                except Exception:

                    has_runner = False

        min_age = ttl if has_runner else min(30.0, ttl)

        if age < min_age:

            continue

        msg = (

            f"reclaimed orphan session after {age:.0f}s "

            f"(status was {st}; runner_alive={has_runner})"

        )

        with _lock:

            cur = _sessions.get(sid) or dict(sess)

            prev = str(cur.get("status") or "").strip().lower()

            already_terminal = prev in _TERMINAL_STATUSES

            cur["status"] = "error"

            cur["error"] = msg

            cur["message"] = msg

            cur["cancel_requested"] = False

            cur["updated_at"] = now

            _sessions[sid] = cur

            _mirror_reg_sess(sid, dict(cur))

            # Count orphan as failed completion so batch remaining does not overshoot.

            if bid and not already_terminal:

                b = _batches.get(bid) or _load_reg_batch(bid) or {"id": bid}

                b = dict(b)

                b["fail_count"] = int(b.get("fail_count") or 0) + 1

                b["finished"] = int(b.get("finished") or 0) + 1

                b["updated_at"] = now

                if not b.get("message"):

                    b["message"] = "reclaimed orphan sessions"

                _batches[bid] = b

                _mirror_reg_batch(bid, dict(b))

        reclaimed.append(

            {

                "id": sid,

                "batch_id": bid,

                "prev_status": st,

                "age_sec": int(age),

                "email": sess.get("email"),

            }

        )

    return {

        "ok": True,

        "reclaimed": len(reclaimed),

        "stale_sec": ttl,

        "items": reclaimed[:100],

    }





def resume_registration_batch(

    batch_id: str,

    *,

    force: bool = False,

    reclaim_stale_sec: float | None = None,

) -> dict[str, Any]:

    """Reclaim orphan sessions and re-spawn the batch runner for remaining count.



    Used after process restart when Redis still shows status=running but no

    worker is actually spawning jobs.

    """

    bid = str(batch_id or "").strip()

    if not bid:

        return {"ok": False, "error": "missing batch id"}

    batch = _load_reg_batch(bid)

    if not batch:

        return {"ok": False, "error": "registration batch not found"}



    st = str(batch.get("status") or "").strip().lower()

    if st in {"done", "cancelled", "stopped"} and not force:

        return {

            "ok": False,

            "error": f"batch already terminal ({st}); pass force=true to resume",

            "batch_id": bid,

            "status": st,

        }

    if batch.get("cancel_requested") and not force:

        return {

            "ok": False,

            "error": "batch cancel_requested; clear stop or pass force=true",

            "batch_id": bid,

        }



    # Drop dead runner lock if our process does not own it (TTL may still hold).

    if force and _reg_redis():

        try:

            from store.redis_client import get_str as redis_get



            lock_k = _batch_runner_lock_key(bid)

            token = redis_get(lock_k)

            with _lock:

                local_alive = bool(_active_batch_runners.get(bid))

            if token and not local_alive:

                try:

                    from store.redis_client import compare_and_delete



                    compare_and_delete(lock_k, str(token))

                except Exception:

                    try:

                        # last resort: overwrite with short TTL empty marker then let expire

                        from store.redis_client import set_ex



                        set_ex(lock_k, "reclaimed", 1)

                    except Exception:

                        pass

        except Exception:

            pass



    reclaimed = reclaim_orphaned_registration_sessions(

        stale_sec=reclaim_stale_sec, batch_id=bid

    )



    count = int(batch.get("count") or 0)

    finished = int(batch.get("finished") or 0)

    # Prefer durable session list to compute remaining if counters lag.

    sids = list(batch.get("session_ids") or [])

    terminal = 0

    if sids and _reg_redis():

        try:

            from store import sessions_redis



            for sid in sids:

                sess = sessions_redis.reg_sess_get(str(sid)) or {}

                st_s = str(sess.get("status") or "").lower()

                if st_s in _TERMINAL_STATUSES:

                    terminal += 1

        except Exception:

            terminal = finished

    else:

        terminal = finished

    remaining = max(0, count - max(finished, terminal))

    if remaining <= 0:

        with _lock:

            b = _batches.get(bid) or dict(batch)

            b["status"] = "done" if int(b.get("fail_count") or 0) == 0 else "partial"

            b["runner_alive"] = False

            b["updated_at"] = _now()

            b["message"] = (

                f"resume: nothing remaining "

                f"(count={count} finished={finished} terminal={terminal})"

            )

            _batches[bid] = b

            _mirror_reg_batch(bid, dict(b))

        return {

            "ok": True,

            "batch_id": bid,

            "remaining": 0,

            "reclaimed": reclaimed.get("reclaimed") or 0,

            "message": "batch already complete",

            "status": (_load_reg_batch(bid) or {}).get("status"),

        }



    cfg = batch.get("reg_config") if isinstance(batch.get("reg_config"), dict) else {}

    provider = str(cfg.get("captcha_provider") or CAPTCHA_PROVIDER or "local").strip().lower()

    key = str(cfg.get("yescaptcha_key") or "").strip()

    proxy = str(cfg.get("proxy") or "").strip()

    workers = int(cfg.get("concurrency") or batch.get("concurrency") or DEFAULT_CONCURRENCY)

    # Local captcha is the bottleneck; when resuming after restart, prefer a

    # safer concurrency so multiple auto-resumed batches don't thrash Camoufox.

    if provider == "local":

        try:

            local_cap = int(os.environ.get("GROK2API_REG_LOCAL_CONCURRENCY", "3") or 3)

        except (TypeError, ValueError):

            local_cap = 3

        workers = max(1, min(workers, max(1, local_cap)))

    stagger = _effective_reg_stagger_ms(

        cfg.get("stagger_ms") if cfg.get("stagger_ms") is not None else batch.get("stagger_ms"),

        captcha_provider=provider,

    )

    mail_provider = str(cfg.get("mail_provider") or "moemail").strip().lower()

    proxy_strategy = str(cfg.get("proxy_strategy") or "round_robin").strip().lower()



    # Clear cancel so spawn is allowed.

    with _lock:

        b = _batches.get(bid) or dict(batch)

        b["cancel_requested"] = False

        if str(b.get("status") or "").lower() in {"stopping", "cancelled", "stopped", "error"}:

            b["status"] = "running"

        b["updated_at"] = _now()

        b["message"] = (

            f"resume requested remaining={remaining} "

            f"(reclaimed={reclaimed.get('reclaimed') or 0})"

        )

        _batches[bid] = b

        _mirror_reg_batch(bid, dict(b))



    spawned = _spawn_batch_runner(

        bid,

        remaining=remaining,

        concurrency=workers,

        stagger_ms=stagger,

        captcha_provider=provider,

        yescaptcha_key=key,

        proxy=proxy,

        proxy_strategy=proxy_strategy,

        moemail_api_key=cfg.get("moemail_api_key"),

        moemail_base_url=cfg.get("moemail_base_url"),

        prefix=cfg.get("prefix"),

        domain=cfg.get("domain"),

        expiry_ms=cfg.get("expiry_ms"),

        mail_provider=mail_provider,

    )

    out = {

        "ok": bool(spawned.get("ok")),

        "batch_id": bid,

        "remaining": remaining,

        "reclaimed": reclaimed.get("reclaimed") or 0,

        "reclaim": reclaimed,

        "spawn": spawned,

        "message": spawned.get("message") or spawned.get("error"),

    }

    if not out["ok"]:

        out["error"] = spawned.get("error") or "spawn failed"

    return out





def reclaim_orphaned_registration_batches(

    *,

    stale_sec: float | None = None,

    auto_resume: bool = True,

    max_batches: int | None = None,

) -> dict[str, Any]:

    """On startup: reclaim orphan sessions and optionally resume open batches."""

    try:

        ttl = float(

            stale_sec

            if stale_sec is not None

            else (os.environ.get("GROK2API_REG_STALE_SEC", "120") or 120)

        )

    except (TypeError, ValueError):

        ttl = 120.0

    if max_batches is None:

        try:

            max_batches = int(os.environ.get("GROK2API_REG_AUTO_RESUME_MAX", "1") or 1)

        except (TypeError, ValueError):

            max_batches = 1

    max_batches = max(0, min(10, int(max_batches)))



    # First pass: mark dead in-flight sessions.

    sess_result = reclaim_orphaned_registration_sessions(stale_sec=ttl)



    batches: list[dict[str, Any]] = []

    if _reg_redis():

        try:

            from store import sessions_redis



            listed = sessions_redis.reg_batch_list() or []

            if isinstance(listed, list):

                batches = [b for b in listed if isinstance(b, dict)]

        except Exception:

            batches = []

    if not batches:

        with _lock:

            batches = [dict(v) for v in _batches.values() if isinstance(v, dict)]



    resumed: list[dict[str, Any]] = []

    skipped: list[dict[str, Any]] = []

    # Newest first.

    batches = sorted(

        batches, key=lambda b: float(b.get("updated_at") or b.get("created_at") or 0), reverse=True

    )

    for b in batches:

        if len(resumed) >= max(0, int(max_batches)):

            break

        bid = str(b.get("id") or "").strip()

        if not bid:

            continue

        st = str(b.get("status") or "").strip().lower()

        if st not in {"running", "starting", "stopping", "partial"} and not (

            st == "error" and int(b.get("finished") or 0) < int(b.get("count") or 0)

        ):

            continue

        if b.get("cancel_requested") and st in {"stopping", "cancelled", "stopped"}:

            skipped.append({"batch_id": bid, "reason": "cancel_requested", "status": st})

            continue

        # Skip only if THIS process has a live runner. Redis locks from a dead

        # process (image restart) must not block auto-resume forever — force

        # clear them when no local runner owns the batch.

        has_local = False

        with _lock:

            has_local = bool(_active_batch_runners.get(bid))

        if has_local:

            skipped.append({"batch_id": bid, "reason": "local_runner_alive", "status": st})

            continue

        if _reg_redis():

            try:

                from store.redis_client import get_str as redis_get



                token = redis_get(_batch_runner_lock_key(bid))

                if token:

                    # Stale lock from previous process — clear so resume can claim.

                    try:

                        from store.redis_client import compare_and_delete



                        compare_and_delete(_batch_runner_lock_key(bid), str(token))

                    except Exception:

                        try:

                            from store.redis_client import set_ex



                            set_ex(_batch_runner_lock_key(bid), "reclaimed", 1)

                        except Exception:

                            pass

            except Exception:

                pass

        count = int(b.get("count") or 0)

        finished = int(b.get("finished") or 0)

        if count > 0 and finished >= count:

            skipped.append({"batch_id": bid, "reason": "already_finished", "status": st})

            continue

        if not auto_resume:

            skipped.append({"batch_id": bid, "reason": "auto_resume_disabled", "status": st})

            continue

        r = resume_registration_batch(bid, force=True, reclaim_stale_sec=ttl)

        resumed.append(r)



    return {

        "ok": True,

        "sessions_reclaimed": sess_result.get("reclaimed") or 0,

        "session_reclaim": sess_result,

        "batches_resumed": sum(1 for r in resumed if r.get("ok")),

        "resumed": resumed,

        "skipped": skipped[:20],

    }





def stop_registration_session(session_id: str) -> dict[str, Any]:

    """Request cooperative cancel for one registration session."""

    sid = str(session_id or "").strip()

    if not sid:

        return {"ok": False, "error": "missing session id"}

    sess = _load_reg_sess(sid)

    if not sess:

        return {"ok": False, "error": "registration session not found"}

    st = str(sess.get("status") or "").lower()

    if st in _TERMINAL_STATUSES:

        return {

            "ok": True,

            "id": sid,

            "status": st,

            "already_terminal": True,

            "message": sess.get("message") or st,

        }

    with _lock:

        cur = _sessions.get(sid) or dict(sess)

        cur["cancel_requested"] = True

        cur["status"] = "stopping"

        cur["message"] = "stop requested; waiting for worker to exit"

        cur["updated_at"] = _now()

        _sessions[sid] = cur

        _mirror_reg_sess(sid, cur)

        out = _compact_session(cur)

    return {"ok": True, "id": sid, **out}





def stop_registration_batch(batch_id: str) -> dict[str, Any]:

    """Request cooperative cancel for every non-terminal session in a batch."""

    bid = str(batch_id or "").strip()

    if not bid:

        return {"ok": False, "error": "missing batch id"}

    batch = _load_reg_batch(bid)

    if not batch:

        return {"ok": False, "error": "registration batch not found"}



    # Unblock waiters immediately so stop does not wait out soft-pause.

    clear_reg_soft_pause()



    # Mark batch cancelled FIRST so spawner/workers observe stop even before

    # individual session mirrors catch up (multi-worker / Redis path).

    with _lock:

        b = _batches.get(bid) or dict(batch)

        b["cancel_requested"] = True

        if str(b.get("status") or "").lower() not in (

            "done",

            "partial",

            "error",

            "cancelled",

            "stopped",

        ):

            b["status"] = "stopping"

        b["message"] = "stop requested; signalling sessions"

        b["updated_at"] = _now()

        _batches[bid] = b

        _mirror_reg_batch(bid, dict(b))

        sids = list(b.get("session_ids") or [])



    stopped: list[str] = []

    already: list[str] = []

    missing: list[str] = []

    for sid in sids:

        r = stop_registration_session(str(sid))

        if not r.get("ok"):

            missing.append(str(sid))

            continue

        if r.get("already_terminal"):

            already.append(str(sid))

        else:

            stopped.append(str(sid))



    with _lock:

        b = _batches.get(bid) or dict(batch)

        b["cancel_requested"] = True

        if str(b.get("status") or "").lower() not in (

            "done",

            "partial",

            "error",

            "cancelled",

            "stopped",

        ):

            b["status"] = "stopping"

        b["message"] = (

            f"stop requested: stopping={len(stopped)} "

            f"already_done={len(already)} missing={len(missing)}"

        )

        b["updated_at"] = _now()

        _batches[bid] = b

        _mirror_reg_batch(bid, dict(b))

        out = dict(b)

    return {

        "ok": True,

        "batch_id": bid,

        "stopped": stopped,

        "already_terminal": already,

        "missing": missing,

        "message": out.get("message") or "stop requested",

        "batch": out,

    }





def stop_all_active_registrations() -> dict[str, Any]:

    """Stop every non-terminal registration session currently visible."""

    clear_reg_soft_pause()

    listed = list_registration_sessions()

    sessions = list(listed.get("sessions") or [])

    stopped = []

    already = []

    for s in sessions:

        sid = str(s.get("id") or "")

        if not sid:

            continue

        r = stop_registration_session(sid)

        if r.get("already_terminal"):

            already.append(sid)

        elif r.get("ok"):

            stopped.append(sid)

    # Free any leaked admission slots so the next batch is not deadlocked.

    reset_reg_admission_counters()

    # Also mark running batches as stopping.

    for b in list(listed.get("batches") or []):

        bid = str(b.get("id") or b.get("batch_id") or "")

        if not bid:

            continue

        st = str(b.get("status") or b.get("batch_status") or "").lower()

        if st in ("done", "partial", "error", "cancelled", "stopped"):

            continue

        try:

            stop_registration_batch(bid)

        except Exception:

            pass

    return {

        "ok": True,

        "stopped": stopped,

        "already_terminal": already,

        "stopped_count": len(stopped),

        "already_count": len(already),

    }





def list_registration_sessions() -> dict[str, Any]:

    _clean_old_sessions()

    # Merge Redis-visible sessions/batches so other workers can observe progress.

    if _reg_redis():

        try:

            from store import sessions_redis



            for remote in sessions_redis.reg_sess_list():

                sid = str(remote.get("id") or "")

                if not sid:

                    continue

                with _lock:

                    if sid not in _sessions:

                        _sessions[sid] = remote

                    else:

                        # Prefer newer updated_at, but keep local process-only fields.

                        local = _sessions[sid]

                        if float(remote.get("updated_at") or 0) >= float(

                            local.get("updated_at") or 0

                        ):

                            merged = {**local, **remote}

                            for k, v in local.items():

                                if isinstance(k, str) and k.startswith("_") and k not in remote:

                                    merged[k] = v

                            _sessions[sid] = merged

            for remote_b in sessions_redis.reg_batch_list():

                bid = str(remote_b.get("id") or remote_b.get("batch_id") or "")

                if not bid:

                    continue

                with _lock:

                    if bid not in _batches:

                        _batches[bid] = remote_b

                    else:

                        local_b = _batches[bid]

                        if float(remote_b.get("updated_at") or 0) >= float(

                            local_b.get("updated_at") or 0

                        ):

                            # Union session_ids so late workers don't drop early ones.

                            ids = list(local_b.get("session_ids") or [])

                            for x in remote_b.get("session_ids") or []:

                                if x not in ids:

                                    ids.append(x)

                            merged_b = {**local_b, **remote_b, "session_ids": ids}

                            _batches[bid] = merged_b

        except Exception:

            pass

    with _lock:

        sessions = [_compact_session(s) for s in _sessions.values()]

        sessions.sort(

            key=lambda s: float(s.get("updated_at") or s.get("created_at") or 0),

            reverse=True,

        )

        batches = []

        for b in _batches.values():

            sids = list(b.get("session_ids") or [])

            stats = _batch_stats(sids, batch=b)

            # If all observed sessions cancelled, surface batch as cancelled.

            if sids and stats.get("running") == 0 and stats.get("cancelled", 0) > 0:

                if (

                    stats.get("imported", 0) == 0

                    and stats.get("error", 0) == 0

                    and stats.get("missing", 0) == 0

                ):

                    stats["batch_status"] = "cancelled"

            item = {**b, **stats}

            # Align top-level status with computed batch_status for UI restore filters.

            bst = str(stats.get("batch_status") or "").lower()

            cur = str(b.get("status") or "").lower()

            if bst and (

                cur in ("", "running", "starting")

                or (bst in ("done", "partial", "error", "cancelled", "stopped") and stats.get("running", 0) == 0)

            ):

                if cur != "stopping" or stats.get("running", 0) == 0:

                    item["status"] = bst if bst != "running" or cur != "stopping" else cur

            batches.append(item)

        batches.sort(

            key=lambda b: float(b.get("updated_at") or b.get("created_at") or 0),

            reverse=True,

        )

    return {

        "sessions": sessions,

        "batches": batches,

        "active": sum(

            1

            for s in sessions

            if str(s.get("status") or "").lower() not in _TERMINAL_STATUSES

        ),

    }





def get_registration_session(

    sid: str, *, include_auth_json: bool = False

) -> dict[str, Any] | None:

    sess = _load_reg_sess(sid)

    if not sess:

        return None

    out = dict(sess)

    out.pop("_client", None)

    out.pop("_oauth_client", None)

    out.pop("password", None)

    out.pop("yescaptcha_key", None)

    if not include_auth_json:

        out.pop("auth_json", None)

    return out





def _batch_stats(

    session_ids: list[str],

    *,

    batch: dict[str, Any] | None = None,

) -> dict[str, Any]:

    """Compute batch counters from live sessions.



    Missing sessions (TTL expired / not mirrored) are *not* treated as running —

    that previously made finished historical batches look active after Redis

    session keys aged out. When no live sessions remain, fall back to the

    persisted batch status/message counters.

    """

    imported = error = running = cancelled = missing = 0

    for sid in session_ids:

        sess = _load_reg_sess(sid)

        if not sess:

            missing += 1

            continue

        st = str(sess.get("status") or "").lower()

        if st in ("imported", "success", "completed"):

            imported += 1

        elif st in ("cancelled", "stopped"):

            cancelled += 1

        elif st in ("error", "failed", "probe_failed", "expired", "protocol_error", "protocol_blocked"):

            error += 1

        else:

            running += 1



    total = len(session_ids)

    observed = imported + error + cancelled + running

    done = imported + error + cancelled

    target = 0

    if isinstance(batch, dict):

        try:

            target = int(batch.get("count") or 0)

        except Exception:

            target = 0

    if target <= 0:

        target = total



    status = "running"

    if observed == 0:

        # No live sessions left — trust last mirrored batch status if terminal.

        stored = ""

        if isinstance(batch, dict):

            stored = str(batch.get("batch_status") or batch.get("status") or "").lower()

        if stored in ("done", "partial", "error", "cancelled", "stopped"):

            status = stored

            # Prefer stored counters when present so UI keeps final totals.

            try:

                imported = int(batch.get("imported") or imported)

            except Exception:

                pass

            try:

                error = int(batch.get("error") or error)

            except Exception:

                pass

            try:

                cancelled = int(batch.get("cancelled") or cancelled)

            except Exception:

                pass

            try:

                done = int(batch.get("done") or (imported + error + cancelled))

            except Exception:

                done = imported + error + cancelled

            running = 0

        elif total and missing >= total:

            # All session keys gone and no terminal marker.

            # Prefer counters / message fragments; never keep a fully-missing

            # batch as "running" forever (ghost cards after Redis TTL).

            msg = str((batch or {}).get("message") or "")

            if isinstance(batch, dict):

                try:

                    imported = int(batch.get("imported") or imported or 0)

                except Exception:

                    pass

                try:

                    error = int(batch.get("error") or error or 0)

                except Exception:

                    pass

                try:

                    cancelled = int(batch.get("cancelled") or cancelled or 0)

                except Exception:

                    pass

            # Parse "ok=N fail=M" style messages written by the spawner.

            if imported == 0 and error == 0 and cancelled == 0 and msg:

                import re as _re



                m_ok = _re.search(r"ok\s*=\s*(\d+)", msg)

                m_fail = _re.search(r"fail\s*=\s*(\d+)", msg)

                if m_ok:

                    try:

                        imported = int(m_ok.group(1))

                    except Exception:

                        pass

                if m_fail:

                    try:

                        error = int(m_fail.group(1))

                    except Exception:

                        pass

            done = imported + error + cancelled

            if cancelled and not imported and not error:

                status = "cancelled"

            elif imported and not error and not cancelled:

                status = "done"

            elif imported:

                status = "partial"

            elif error:

                status = "error"

            elif stored in ("stopping",):

                status = "stopped"

            else:

                status = "done"

            running = 0

        else:

            status = "running"

    elif done >= max(target, total) and running == 0:

        if cancelled and not imported and not error:

            status = "cancelled"

        elif error == 0 and cancelled == 0:

            status = "done"

        elif imported:

            status = "partial"

        else:

            status = "error"

    elif running == 0 and missing > 0 and done > 0 and observed < total:

        # Partial visibility (some sessions expired) but nothing live.

        if imported and (error or cancelled or missing):

            status = "partial"

        elif imported and not error and not cancelled:

            status = "done"

        elif cancelled and not imported and not error:

            status = "cancelled"

        elif error and not imported:

            status = "error"

        else:

            status = "partial"

    elif total and (imported or error or cancelled) and running:

        status = "running"

    elif running:

        status = "running"



    # Honour explicit cooperative stop marker on the batch itself.

    if isinstance(batch, dict):

        bst = str(batch.get("status") or "").lower()

        if bst in ("stopping", "cancelled", "stopped") and running == 0:

            if status == "running":

                status = "cancelled" if cancelled or bst != "stopping" else "stopped"

        if bst == "stopping" and running:

            status = "running"



        # Runner already finalized the batch (done/partial/error) but some session

        # rows may still look non-terminal (stale status, missing keys, skip-probe

        # race). Prefer the stored terminal status so UI does not stick on 运行中.

        runner_alive = bool(batch.get("runner_alive"))

        try:

            batch_finished = int(batch.get("finished") or 0)

        except Exception:

            batch_finished = 0

        try:

            batch_ok = int(batch.get("ok_count") or 0)

        except Exception:

            batch_ok = 0

        try:

            batch_fail = int(batch.get("fail_count") or 0)

        except Exception:

            batch_fail = 0

        msg = str(batch.get("message") or "")

        msg_finished = msg.lower().startswith("finished ") or "finished " in msg.lower()[:24]

        stored_terminal = bst in ("done", "partial", "error", "cancelled", "stopped")

        count_done = target > 0 and batch_finished >= target

        if (not runner_alive) and (stored_terminal or count_done or msg_finished):

            if stored_terminal:

                status = bst

            elif batch_fail and not batch_ok:

                status = "error"

            elif batch_fail:

                status = "partial"

            elif batch_ok or count_done or msg_finished:

                status = "done"

            # Align counters with runner totals so progress is not 197/200 forever.

            if batch_finished > 0:

                done = max(done, batch_finished)

            if batch_ok > 0:

                imported = max(imported, batch_ok)

            if batch_fail > 0:

                error = max(error, batch_fail)

            if done >= max(target, total) or stored_terminal or msg_finished:

                running = 0

            done = max(done, imported + error + cancelled)



    return {

        "total": max(total, target),

        "imported": imported,

        "error": error,

        "cancelled": cancelled,

        "running": running,

        "missing": missing,

        "done": done,

        "batch_status": status,

    }





def get_registration_batch(batch_id: str) -> dict[str, Any] | None:

    b = _load_reg_batch(batch_id)

    if not b:

        return None

    sids = list(b.get("session_ids") or [])

    stats = _batch_stats(sids, batch=b)

    # Keep response bounded for large batches: newest sessions first for UI.

    MAX_BATCH_SESSIONS = 120

    sessions = []

    for s in sids[-MAX_BATCH_SESSIONS:]:

        sess = _load_reg_sess(s)

        if sess:

            sessions.append(_compact_session(sess))

    # Prefer recency if timestamps available.

    try:

        sessions.sort(

            key=lambda s: float(s.get("updated_at") or s.get("created_at") or 0),

            reverse=True,

        )

    except Exception:

        pass

    out = {**b, **stats, "sessions": sessions}

    # Surface effective status for older UIs that only read `status`.

    if stats.get("batch_status"):

        bst = str(stats.get("batch_status") or "").lower()

        cur = str(b.get("status") or "").lower()

        # Don't clobber an explicit cooperative "stopping" marker while workers live.

        if cur != "stopping" or stats.get("running", 0) == 0:

            if (

                stats.get("running", 0) == 0

                or cur in ("", "running", "starting")

                # Runner finished: always expose terminal status even if a few

                # session rows still look non-terminal in memory.

                or (

                    not bool(b.get("runner_alive"))

                    and bst in ("done", "partial", "error", "cancelled", "stopped")

                )

            ):

                out["status"] = stats["batch_status"]

    # Explicit fields for UI polling (avoid mistaking async-upload text for still-running).

    out["runner_alive"] = bool(b.get("runner_alive"))

    if not out.get("runner_alive") and str(out.get("status") or "").lower() in (

        "done",

        "partial",

        "error",

        "cancelled",

        "stopped",

    ):

        out["running"] = 0

    return out





# --------------------------------------------------------------------------- #

# CLI

# --------------------------------------------------------------------------- #

def main() -> int:

    print("grok-build-auth adapter for grok-register-pro")

    result = start_registration()

    print(json.dumps(result, ensure_ascii=False, indent=2))

    if not result.get("ok"):

        return 1



    sid = result["id"]

    deadline = time.time() + 600

    while time.time() < deadline:

        sess = get_registration_session(sid, include_auth_json=True)

        if not sess:

            print("session disappeared", file=sys.stderr)

            return 1

        status = sess.get("status")

        print(f"[{time.strftime('%H:%M:%S')}] {status}: {sess.get('message')}")

        if status in ("imported", "error"):

            print(json.dumps(sess, ensure_ascii=False, indent=2))

            return 0 if status == "imported" else 1

        time.sleep(5)



    print("timeout", file=sys.stderr)

    return 1





if __name__ == "__main__":

    raise SystemExit(main())

