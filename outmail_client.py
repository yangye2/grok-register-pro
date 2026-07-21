"""Outmail (Outlook pool + anonymous temp mailbox) client for grok-register.

Ported from grok-register-roxy/grok_register_ttk.py outmail_* helpers.

Modes:
  - pool: pick Outlook mailbox from Outmail account pool (/api/accounts)
  - anon: generate anonymous temp email via /api/temp-emails/generate
          (providers: cloudflare | duckmail | gptmail)

Config keys (config.json):
  email_provider: outmail | outlook | outlookemail  (or temp_mail_provider)
  outmail_api_base, outmail_api_key, outmail_session_cookie, outmail_proxy
  outmail_plus_alias, outmail_plus_alias_count, outmail_alias_suffix_len,
  outmail_fetch_top, outmail_poll_* , outmail_from/subject_filter
  outmail_group_id, outmail_exclude_used, outmail_used_file
  outmail_anonymous_enabled, outmail_anonymous_provider, outmail_anonymous_domain
  outmail_anonymous_username_prefix, outmail_anonymous_password, outmail_anonymous_delete_after
"""

from __future__ import annotations

import json
import os
import random
import re
import secrets
import string
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import quote, urlparse

try:
    from curl_cffi import requests as curl_requests
except ImportError:  # pragma: no cover
    curl_requests = None

import requests as std_requests

LogFn = Callable[[str], None]
CancelFn = Callable[[], bool]

_config: dict[str, Any] = {}
_config_lock = threading.RLock()
_outmail_lock = threading.Lock()
_outmail_in_use: set[str] = set()
_outmail_anon_domain_index = 0
_outmail_anon_domain_lock = threading.Lock()
_outmail_selector_cache: list[Any] = []
_outmail_selector_cursor = 0
_outmail_csrf_token = ""
_outmail_csrf_lock = threading.Lock()
_outmail_used_cache: dict[str, int] | None = None  # mailbox -> success usage count
_outmail_used_lock = threading.Lock()



_ORIG_PRINT = print


def _stamp_message(message: object) -> str:
    """Prefix a single log line with local time; skip if already stamped."""
    text = str(message)
    if not text.strip():
        return text
    head = text.lstrip()
    if re.match(r"^\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", head):
        return text
    if re.match(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", head):
        return text
    # use module-specific now() filled per file
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # preserve original leading whitespace/newlines outside the stamped body
    lead_len = len(text) - len(text.lstrip(" \t"))
    lead = text[:lead_len]
    core = text[lead_len:]
    return f"{lead}[{ts}] {core}"


def print(*args, **kwargs):  # type: ignore[no-redef]
    """Timestamp each non-empty line; never attach time to a bare newline-only prefix."""
    if not args:
        return _ORIG_PRINT(*args, **kwargs)
    sep = kwargs.get("sep", " ")
    try:
        body = sep.join(str(a) for a in args)
    except Exception:
        body = " ".join(map(str, args))
    if "\n" in body or "\r" in body:
        parts = re.split(r"(\r?\n)", body)
        out = []
        for part in parts:
            if part in ("\n", "\r\n", "\r") or part == "":
                out.append(part)
            else:
                out.append(_stamp_message(part))
        stamped = "".join(out)
    else:
        stamped = _stamp_message(body)
    kw = {k: v for k, v in kwargs.items() if k != "sep"}
    return _ORIG_PRINT(stamped, **kw)



def _file_lock_exclusive(lock_path: str, timeout_sec: float = 30.0):
    """Cross-process exclusive lock (Windows msvcrt / Unix fcntl)."""
    class _Lock:
        def __init__(self, path: str, timeout: float):
            self.path = path
            self.timeout = max(1.0, float(timeout or 30.0))
            self._fh = None

        def __enter__(self):
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            self._fh = open(self.path, "a+", encoding="utf-8")
            deadline = time.time() + self.timeout
            last_err = None
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt

                        self._fh.seek(0)
                        # Ensure at least 1 byte exists for locking
                        if self._fh.read(1) == "":
                            self._fh.write("0")
                            self._fh.flush()
                        self._fh.seek(0)
                        msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return self
                except OSError as exc:
                    last_err = exc
                    if time.time() >= deadline:
                        raise TimeoutError(
                            f"Outmail used-file lock timeout: {self.path} ({last_err})"
                        ) from exc
                    time.sleep(0.05)

        def __exit__(self, exc_type, exc, tb):
            if self._fh is not None:
                try:
                    if os.name == "nt":
                        import msvcrt

                        self._fh.seek(0)
                        msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
                try:
                    self._fh.close()
                except Exception:
                    pass
                self._fh = None
            return False

    return _Lock(lock_path, timeout_sec)


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
)


class OutmailCancelled(Exception):
    """Raised when cancel_callback requests stop."""


def _cfg() -> dict[str, Any]:
    with _config_lock:
        return dict(_config)


def configure(config: dict[str, Any] | None = None, *, merge: bool = True) -> dict[str, Any]:
    """Set module config from a dict (typically task config.json)."""
    global _config
    with _config_lock:
        if config is None:
            return dict(_config)
        if merge:
            merged = dict(_config)
            merged.update(config)
            _config = merged
        else:
            _config = dict(config)
        return dict(_config)


def load_config_file(path: str | Path | None = None) -> dict[str, Any]:
    """Load config.json next to caller or given path into module config."""
    if path is None:
        # prefer cwd config, then package parent configs
        candidates = [
            Path.cwd() / "config.json",
            Path(__file__).resolve().parent / "config.json",
            Path(__file__).resolve().parents[1] / "config.json",
            Path(__file__).resolve().parents[2] / "config.json",
        ]
    else:
        candidates = [Path(path)]
    data: dict[str, Any] = {}
    for p in candidates:
        try:
            if p.is_file():
                data = json.loads(p.read_text(encoding="utf-8"))
                break
        except Exception:
            continue
    return configure(data, merge=True)


def get_email_provider() -> str:
    cfg = _cfg()
    return str(
        cfg.get("email_provider")
        or cfg.get("temp_mail_provider")
        or cfg.get("mail_provider")
        or ""
    ).strip().lower()


def normalize_proxy_url(raw: Any) -> str:
    """Normalize proxy URL (socks5/http; host:port:user:pass => socks5)."""
    p = str(raw or "").strip()
    if not p or p.startswith("#"):
        return ""
    if "://" in p:
        return p
    parts = p.split(":")
    if len(parts) == 4 and "@" not in p:
        host, port, user, password = parts
        return f"socks5://{user}:{password}@{host}:{port}"
    if "@" in p:
        return f"socks5://{p}"
    return f"socks5://{p}"


def get_user_agent() -> str:
    return str(_cfg().get("user_agent") or DEFAULT_USER_AGENT)


def raise_if_cancelled(cancel_callback: CancelFn | None = None) -> None:
    if cancel_callback and cancel_callback():
        raise OutmailCancelled("cancelled")


def sleep_with_cancel(seconds: float, cancel_callback: CancelFn | None = None) -> None:
    deadline = time.time() + max(float(seconds or 0), 0.0)
    while True:
        raise_if_cancelled(cancel_callback)
        remaining = deadline - time.time()
        if remaining <= 0:
            return
        time.sleep(min(0.2, remaining))


def extract_verification_code(text: str, subject: str = "") -> str | None:
    if subject:
        match = re.search(r"^([A-Z0-9]{3}-[A-Z0-9]{3})\s+xAI", subject, re.IGNORECASE)
        if match:
            return match.group(1)
    match = re.search(r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b", text or "", re.IGNORECASE)
    if match:
        return match.group(1)
    patterns = [
        r"verification\s+code[:\s]+(\d{4,8})",
        r"your\s+code[:\s]+(\d{4,8})",
        r"confirm(?:ation)?\s+code[:\s]+(\d{4,8})",
        r"\b(\d{6})\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text or "", re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def _http():
    """Prefer curl_cffi chrome impersonation for Cloudflare-fronted Outmail."""
    if curl_requests is not None:
        return curl_requests, True
    return std_requests, False


# ---------------------------------------------------------------------------
# Outmail API helpers (from grok-register-roxy)
# ---------------------------------------------------------------------------


# requests: curl_cffi when available (Cloudflare-friendly)
requests, _USE_CURL_CFFI = _http()

def _outmail_is_provider(provider=None):
    p = str(provider or get_email_provider() or "").strip().lower()
    return p in ("outmail", "outlook", "outlookemail")


def get_outmail_api_base():
    return str(_cfg().get("outmail_api_base", "") or "").rstrip("/")


def get_outmail_api_key():
    return str(_cfg().get("outmail_api_key", "") or "").strip()


def get_outmail_session_cookie():
    raw = str(_cfg().get("outmail_session_cookie", "") or "").strip()
    if not raw:
        return ""
    # 兼容仅填写 session 值
    if "=" not in raw and ";" not in raw:
        return f"session={raw}"
    return raw


def _outmail_request_proxies():
    """访问 outmail 面板：默认直连；可单独配置 outmail_proxy。"""
    p = normalize_proxy_url(_cfg().get("outmail_proxy", "") or "")
    if p:
        return {"http": p, "https": p}
    return {}


def _outmail_headers(extra=None):
    headers = {"Accept": "application/json"}
    key = get_outmail_api_key()
    if key:
        headers["X-API-Key"] = key
    cookie = get_outmail_session_cookie()
    if cookie:
        headers["Cookie"] = cookie
    if extra:
        headers.update(extra)
    return headers


def outmail_http_get(url, params=None, timeout=30):
    """请求 Outmail API。

    目标站常挂 Cloudflare，必须用 curl_cffi 浏览器指纹（impersonate），
    否则会 403 HTML 挑战页。
    """
    headers = _outmail_headers(
        {
            "User-Agent": get_user_agent(),
            "Accept": "application/json, text/plain, */*",
        }
    )
    proxies = _outmail_request_proxies()
    kwargs = {
        "params": params or None,
        "headers": headers,
        "timeout": timeout,
        "impersonate": "chrome",
    }
    if proxies:
        kwargs["proxies"] = proxies
    else:
        kwargs["proxies"] = {}

    try:
        resp = requests.get(url, **kwargs)
    except Exception as exc:
        err = str(exc)
        # 代理挂了时回退直连
        if proxies and (
            "Could not connect to server" in err
            or "Failed to connect" in err
            or "TLS connect error" in err
            or "proxy" in err.lower()
            or "SOCKS" in err
        ):
            kwargs["proxies"] = {}
            resp = requests.get(url, **kwargs)
        else:
            raise

    # Cloudflare 403 时再试一次直连（有些代理出口被 CF 拦截）
    text_head = (getattr(resp, "text", None) or "")[:200].lower()
    if resp.status_code in (403, 503) and (
        "cloudflare" in text_head
        or "attention required" in text_head
        or "just a moment" in text_head
        or "<!doctype html" in text_head
    ):
        if proxies:
            kwargs["proxies"] = {}
            try:
                resp2 = requests.get(url, **kwargs)
                if resp2.status_code == 200:
                    return resp2
            except Exception:
                pass
    return resp


def outmail_http_request(method, url, params=None, json_body=None, timeout=30, extra_headers=None):
    """统一 Outmail HTTP（GET/POST/DELETE），curl_cffi impersonate + 代理回退。"""
    method = str(method or "GET").strip().upper()
    headers = _outmail_headers(
        {
            "User-Agent": get_user_agent(),
            "Accept": "application/json, text/plain, */*",
        }
    )
    if extra_headers:
        headers.update(extra_headers)
    if json_body is not None and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    proxies = _outmail_request_proxies()
    kwargs = {
        "params": params or None,
        "headers": headers,
        "timeout": timeout,
        "impersonate": "chrome",
        "proxies": proxies if proxies else {},
    }
    if json_body is not None:
        kwargs["json"] = json_body

    def _do(req_kwargs):
        if method == "GET":
            return requests.get(url, **req_kwargs)
        if method == "POST":
            return requests.post(url, **req_kwargs)
        if method == "DELETE":
            return requests.delete(url, **req_kwargs)
        raise Exception(f"Outmail 不支持的 HTTP 方法: {method}")

    try:
        resp = _do(kwargs)
    except Exception as exc:
        err = str(exc)
        if proxies and (
            "Could not connect to server" in err
            or "Failed to connect" in err
            or "TLS connect error" in err
            or "proxy" in err.lower()
            or "SOCKS" in err
        ):
            kwargs["proxies"] = {}
            resp = _do(kwargs)
        else:
            raise

    text_head = (getattr(resp, "text", None) or "")[:200].lower()
    if resp.status_code in (403, 503) and (
        "cloudflare" in text_head
        or "attention required" in text_head
        or "just a moment" in text_head
        or "<!doctype html" in text_head
    ):
        if proxies:
            kwargs["proxies"] = {}
            try:
                resp2 = _do(kwargs)
                if resp2.status_code == 200:
                    return resp2
            except Exception:
                pass
    return resp


def outmail_http_post(url, params=None, json_body=None, timeout=30, extra_headers=None):
    return outmail_http_request(
        "POST",
        url,
        params=params,
        json_body=json_body,
        timeout=timeout,
        extra_headers=extra_headers,
    )


def outmail_http_delete(url, params=None, timeout=30, extra_headers=None):
    return outmail_http_request(
        "DELETE",
        url,
        params=params,
        timeout=timeout,
        extra_headers=extra_headers,
    )


def _outmail_is_missing_csrf_error(resp, data):
    if getattr(resp, "status_code", 0) != 400:
        return False
    parts = []
    if isinstance(data, dict):
        parts.append(str(data.get("error") or ""))
        parts.append(str(data.get("message") or ""))
        parts.append(str(data.get("detail") or ""))
    parts.append(str(getattr(resp, "text", None) or ""))
    text_l = " ".join(parts).lower()
    return "csrf" in text_l and ("missing" in text_l or "required" in text_l)


def outmail_load_csrf_token(force=False):
    """从 /api/csrf-token 拉取 CSRF，匿名邮箱 generate/refresh/delete 需要。"""
    global _outmail_csrf_token
    with _outmail_csrf_lock:
        if _outmail_csrf_token and not force:
            return _outmail_csrf_token
        base = get_outmail_api_base()
        if not base:
            return ""
        if not get_outmail_session_cookie():
            return ""
        try:
            resp = outmail_http_get(f"{base}/api/csrf-token", timeout=15)
            data = None
            try:
                data = resp.json()
            except Exception:
                data = None
            token = ""
            if isinstance(data, dict):
                token = str(
                    data.get("csrf_token")
                    or data.get("csrfToken")
                    or data.get("token")
                    or ""
                ).strip()
            if not token:
                headers = getattr(resp, "headers", None) or {}
                token = str(
                    headers.get("X-CSRF-Token")
                    or headers.get("X-CSRFToken")
                    or headers.get("x-csrf-token")
                    or headers.get("x-csrftoken")
                    or ""
                ).strip()
            if not token:
                cookies = getattr(resp, "cookies", None)
                if cookies is not None:
                    try:
                        token = str(
                            cookies.get("csrf_token")
                            or cookies.get("csrftoken")
                            or cookies.get("XSRF-TOKEN")
                            or ""
                        ).strip()
                    except Exception:
                        token = ""
            if token:
                _outmail_csrf_token = token
            return _outmail_csrf_token
        except Exception:
            return _outmail_csrf_token or ""


def outmail_csrf_headers(force=False):
    token = outmail_load_csrf_token(force=force)
    if not token:
        return {}
    return {"X-CSRF-Token": token, "X-CSRFToken": token}


def outmail_extract_email_address(data):
    candidates = []
    if isinstance(data, dict):
        candidates.extend(
            [
                data.get("email"),
                data.get("address"),
                data.get("temp_email"),
                data.get("mailbox"),
                data.get("data"),
                data.get("account"),
                data.get("item"),
                data.get("result"),
            ]
        )
    else:
        candidates.append(data)
    for candidate in candidates:
        if isinstance(candidate, str):
            text_v = candidate.strip()
            if "@" in text_v:
                return text_v
        if isinstance(candidate, dict):
            for key in ("email", "address", "temp_email", "mailbox"):
                text_v = str(candidate.get(key) or "").strip()
                if "@" in text_v:
                    return text_v
    return ""



def outmail_list_anonymous_domains():
    """解析匿名邮箱域名列表（支持逗号/分号/空白分隔）。

    优先级：
      1) outmail_anonymous_domain（可多域名）
      2) provider 为 cloudflare/gptmail 时回退 defaultDomains
    """
    raw = str(_cfg().get("outmail_anonymous_domain", "") or "").strip()
    if not raw:
        provider = str(
            _cfg().get("outmail_anonymous_provider", "cloudflare") or "cloudflare"
        ).strip().lower()
        if provider in ("cloudflare", "gptmail"):
            raw = str(_cfg().get("defaultDomains", "") or "").strip()
    if not raw:
        return []

    parts = []
    for chunk in re.split(r"[,;\s]+", raw):
        domain = str(chunk or "").strip().lstrip("@").lower()
        if domain:
            parts.append(domain)

    seen = set()
    ordered = []
    for domain in parts:
        if domain in seen:
            continue
        seen.add(domain)
        ordered.append(domain)
    return ordered


def outmail_next_anonymous_domain(domains=None):
    """线程安全轮询下一个匿名邮箱域名。domains 为空时自动读配置。"""
    global _outmail_anon_domain_index
    items = list(domains) if domains is not None else outmail_list_anonymous_domains()
    if not items:
        return ""
    with _outmail_anon_domain_lock:
        domain = items[_outmail_anon_domain_index % len(items)]
        _outmail_anon_domain_index += 1
    return domain


def outmail_generate_temp_email(
    provider="cloudflare",
    domain="",
    username_prefix="",
    password="",
):
    """POST /api/temp-emails/generate — 通过 Outmail 创建匿名临时期箱。"""
    base = get_outmail_api_base()
    if not base:
        raise Exception("outmail_api_base 未配置")
    if not get_outmail_session_cookie():
        raise Exception(
            "匿名邮箱需要 outmail_session_cookie（用于 CSRF），请在 config.json 配置"
        )

    provider_lc = str(provider or "cloudflare").strip().lower() or "cloudflare"
    if provider_lc not in ("cloudflare", "duckmail", "gptmail"):
        raise Exception(
            f"outmail_anonymous_provider 无效: {provider_lc}，支持 cloudflare/duckmail/gptmail"
        )
    domain_val = str(domain or "").strip()
    prefix_val = str(username_prefix or "").strip()
    if prefix_val:
        generated_name = prefix_val
    else:
        # avoid always tmp+hex
        _anon_styles = [
            lambda: "u" + secrets.token_hex(random.randint(3, 5)),
            lambda: "m" + secrets.token_hex(4),
            lambda: "".join(secrets.choice(string.ascii_lowercase) for _ in range(random.randint(6, 10))),
            lambda: random.choice(["neo", "sam", "kai", "lee", "rio", "sky"]) + secrets.token_hex(3),
        ]
        generated_name = random.choice(_anon_styles)()

    candidate_payloads = []
    dedup_keys = set()

    def add_candidate(extra_fields):
        payload = {"provider": provider_lc}
        if domain_val:
            payload["domain"] = domain_val
        for key, value in (extra_fields or {}).items():
            if value is None:
                continue
            text_v = str(value).strip()
            if not text_v:
                continue
            payload[key] = text_v
        dedup_key = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        if dedup_key in dedup_keys:
            return
        dedup_keys.add(dedup_key)
        candidate_payloads.append(payload)

    if provider_lc == "duckmail":
        if not domain_val:
            raise Exception(
                "provider=duckmail 时必须配置 outmail_anonymous_domain"
            )
        username_val = generated_name
        if len(username_val) < 3:
            username_val = f"{username_val}123"
        password_val = str(password or secrets.token_urlsafe(12))
        if len(password_val) < 6:
            password_val = secrets.token_urlsafe(12)
        add_candidate({"username": username_val, "password": password_val})
    elif provider_lc == "gptmail":
        if prefix_val:
            add_candidate({"prefix": prefix_val})
        else:
            add_candidate({})
            add_candidate({"prefix": generated_name})
    else:
        # cloudflare: domain/username 可选
        if prefix_val:
            add_candidate({"username": prefix_val})
        else:
            add_candidate({})
            add_candidate({"username": generated_name})

    if not candidate_payloads:
        add_candidate({})

    url = f"{base}/api/temp-emails/generate"
    outmail_load_csrf_token(force=True)
    errors = []
    for payload in candidate_payloads:
        headers = outmail_csrf_headers() or None
        try:
            resp = outmail_http_post(
                url, json_body=payload, timeout=30, extra_headers=headers
            )
        except Exception as exc:
            errors.append({"payload": payload, "error": f"request_error:{exc}"})
            continue

        data = None
        try:
            data = resp.json()
        except Exception:
            data = None

        if _outmail_is_missing_csrf_error(resp, data):
            outmail_load_csrf_token(force=True)
            retry_headers = outmail_csrf_headers() or None
            try:
                resp = outmail_http_post(
                    url,
                    json_body=payload,
                    timeout=30,
                    extra_headers=retry_headers,
                )
                try:
                    data = resp.json()
                except Exception:
                    data = None
            except Exception as exc:
                errors.append(
                    {"payload": payload, "error": f"csrf_retry_request_error:{exc}"}
                )
                continue

        if resp.status_code >= 400:
            detail = data if data is not None else (resp.text or "")
            errors.append(
                {
                    "payload": payload,
                    "http_status": resp.status_code,
                    "detail": detail,
                }
            )
            continue
        if data is None:
            errors.append(
                {
                    "payload": payload,
                    "error": "invalid_json",
                    "detail": resp.text or "",
                }
            )
            continue
        if isinstance(data, dict) and data.get("success") is False:
            errors.append(
                {"payload": payload, "error": "api_success_false", "detail": data}
            )
            continue

        email_addr = outmail_extract_email_address(data)
        if email_addr:
            return email_addr, data if isinstance(data, dict) else {"raw": data}

        errors.append(
            {
                "payload": payload,
                "error": "email_not_found_in_response",
                "detail": data,
            }
        )

    raise Exception(
        f"Outmail 匿名邮箱生成失败 provider={provider_lc} attempts={errors}"
    )


def outmail_get_temp_email_messages(email, since_ts, limit=20):
    """GET /api/temp-emails/{email}/messages"""
    base = get_outmail_api_base()
    if not base:
        raise Exception("outmail_api_base 未配置")
    encoded_email = quote(str(email or "").strip(), safe="")
    url = f"{base}/api/temp-emails/{encoded_email}/messages"
    params = {"limit": max(1, min(int(limit or 20), 50))}
    resp = outmail_http_get(url, params=params, timeout=30)
    if resp.status_code >= 400:
        raise Exception(
            f"获取临时邮箱邮件列表失败 HTTP {resp.status_code}: {(resp.text or '')[:200]}"
        )
    try:
        data = resp.json()
    except Exception as exc:
        raise Exception(f"获取临时邮箱邮件列表 JSON 解析失败: {exc}") from exc
    if isinstance(data, dict) and data.get("success") is False:
        raise Exception(f"获取临时邮箱邮件列表失败: {data}")
    raw_emails = data.get("emails", []) if isinstance(data, dict) else []
    if not isinstance(raw_emails, list):
        raw_emails = []
    emails = outmail_filter_emails_since(raw_emails, since_ts)
    emails.sort(key=lambda x: outmail_parse_email_timestamp(x) or 0, reverse=True)
    meta = data if isinstance(data, dict) else {"raw": data}
    meta["emails_before_since_filter"] = len(raw_emails)
    meta["emails_after_since_filter"] = len(emails)
    return emails, meta


def outmail_refresh_temp_email_messages(email, since_ts, limit=20):
    """POST /api/temp-emails/{email}/refresh"""
    base = get_outmail_api_base()
    if not base:
        raise Exception("outmail_api_base 未配置")
    encoded_email = quote(str(email or "").strip(), safe="")
    url = f"{base}/api/temp-emails/{encoded_email}/refresh"
    params = {"limit": max(1, min(int(limit or 20), 50))}
    headers = outmail_csrf_headers() or None
    resp = outmail_http_post(url, params=params, timeout=30, extra_headers=headers)
    data = None
    try:
        data = resp.json()
    except Exception:
        data = None
    if _outmail_is_missing_csrf_error(resp, data):
        outmail_load_csrf_token(force=True)
        retry_headers = outmail_csrf_headers() or None
        resp = outmail_http_post(
            url, params=params, timeout=30, extra_headers=retry_headers
        )
        try:
            data = resp.json()
        except Exception:
            data = None
    if resp.status_code >= 400:
        detail = data if data is not None else (resp.text or "")
        raise Exception(f"刷新临时邮箱邮件失败 HTTP {resp.status_code}: {detail}")
    if data is None:
        try:
            data = resp.json()
        except Exception as exc:
            raise Exception(f"刷新临时邮箱邮件 JSON 解析失败: {exc}") from exc
    if isinstance(data, dict) and data.get("success") is False:
        raise Exception(f"刷新临时邮箱邮件失败: {data}")
    raw_emails = data.get("emails", []) if isinstance(data, dict) else []
    if not isinstance(raw_emails, list):
        raw_emails = []
    emails = outmail_filter_emails_since(raw_emails, since_ts)
    emails.sort(key=lambda x: outmail_parse_email_timestamp(x) or 0, reverse=True)
    meta = data if isinstance(data, dict) else {"raw": data}
    meta["emails_before_since_filter"] = len(raw_emails)
    meta["emails_after_since_filter"] = len(emails)
    return emails, meta


def outmail_get_temp_email_detail(email, message_id):
    """GET /api/temp-emails/{email}/messages/{message_id}"""
    base = get_outmail_api_base()
    if not base:
        return None, {"ok": False, "error": "outmail_api_base empty"}
    encoded_email = quote(str(email or "").strip(), safe="")
    encoded_message_id = quote(str(message_id or "").strip(), safe="")
    url = f"{base}/api/temp-emails/{encoded_email}/messages/{encoded_message_id}"
    try:
        resp = outmail_http_get(url, timeout=30)
        if resp.status_code == 404:
            return None, {"ok": False, "error": f"not_found:{url}"}
        if resp.status_code >= 400:
            return None, {
                "ok": False,
                "error": f"http_{resp.status_code}:{(resp.text or '')[:120]}",
            }
        data = resp.json()
        if isinstance(data, dict) and data.get("success") is False:
            return None, {"ok": False, "error": f"api_fail:{url}:{data}"}
        detail_candidates = []
        if isinstance(data, dict):
            detail_candidates.extend(
                [
                    data.get("email"),
                    data.get("message"),
                    data.get("data"),
                    data.get("item"),
                ]
            )
            detail_candidates.append(data)
        for candidate in detail_candidates:
            if not isinstance(candidate, dict):
                continue
            if any(
                k in candidate
                for k in ("body", "html", "text", "body_preview", "content")
            ):
                return candidate, {"url": url, "ok": True}
        return None, {"ok": False, "error": f"no_body_fields:{url}"}
    except Exception as exc:
        return None, {"ok": False, "error": f"request_error:{url}:{exc}"}


def outmail_delete_temp_email(email):
    """DELETE /api/temp-emails/{email}"""
    base = get_outmail_api_base()
    if not base:
        raise Exception("outmail_api_base 未配置")
    encoded_email = quote(str(email or "").strip(), safe="")
    url = f"{base}/api/temp-emails/{encoded_email}"
    outmail_load_csrf_token(force=True)
    headers = outmail_csrf_headers() or None
    resp = outmail_http_delete(url, timeout=30, extra_headers=headers)
    data = None
    try:
        data = resp.json()
    except Exception:
        data = None
    if _outmail_is_missing_csrf_error(resp, data):
        outmail_load_csrf_token(force=True)
        retry_headers = outmail_csrf_headers() or None
        resp = outmail_http_delete(url, timeout=30, extra_headers=retry_headers)
        try:
            data = resp.json()
        except Exception:
            data = None
    if resp.status_code >= 400:
        detail = data if data is not None else (resp.text or "")
        raise Exception(f"删除临时邮箱失败 HTTP {resp.status_code}: {detail}")
    if data is None:
        data = {"success": True, "raw": resp.text or ""}
    if isinstance(data, dict) and data.get("success") is False:
        raise Exception(f"删除临时邮箱失败: {data}")
    if isinstance(data, dict):
        return data
    return {"success": True, "raw": data}


def outmail_cleanup_mailbox(mailbox, mode="pool", log_callback=None):
    """释放账号池占用；匿名模式下可选删除临时期箱。"""
    mode_s = str(mode or "pool").strip().lower()
    if mode_s in ("anon", "anonymous", "temp"):
        mode_s = "anon"
    else:
        mode_s = "pool"
        outmail_release_mailbox(mailbox)
    if mode_s == "anon" and bool(_cfg().get("outmail_anonymous_delete_after", False)):
        try:
            outmail_delete_temp_email(mailbox)
            if log_callback:
                log_callback(f"[Debug] Outmail 已删除匿名邮箱: {mailbox}")
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] Outmail 删除匿名邮箱失败: {exc}")


def outmail_list_accounts(limit=100, offset=0, group_id=None):
    base = get_outmail_api_base()
    if not base:
        raise Exception("outmail_api_base 未配置")
    params = {
        "limit": max(1, int(limit)),
        "offset": max(0, int(offset)),
        "sort_by": "created_at",
        "sort_order": "desc",
    }
    if group_id is not None and str(group_id).strip() != "":
        try:
            params["group_id"] = int(group_id)
        except (TypeError, ValueError):
            params["group_id"] = group_id
    resp = outmail_http_get(f"{base}/api/external/accounts", params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict) and data.get("success") is False:
        raise Exception(f"Outmail 获取账号列表失败: {data}")
    if isinstance(data, dict):
        accounts = data.get("accounts") or data.get("data") or []
    elif isinstance(data, list):
        accounts = data
    else:
        accounts = []
    if not isinstance(accounts, list):
        accounts = []
    return accounts


def outmail_get_recent_emails(
    email,
    since_ts=0,
    subject_filter="",
    from_filter="",
    folder="all",
    limit=10,
    skip=0,
):
    base = get_outmail_api_base()
    if not base:
        raise Exception("outmail_api_base 未配置")
    top = max(1, min(int(limit or 10), 50))
    params = {
        "email": email,
        "folder": folder or "all",
        "skip": max(0, int(skip or 0)),
        "top": top,
    }
    subject_filter = str(subject_filter or "").strip()
    from_filter = str(from_filter or "").strip()
    if subject_filter:
        params["subject_contains"] = subject_filter
        params["keyword"] = subject_filter
    if from_filter:
        params["from_contains"] = from_filter
    resp = outmail_http_get(f"{base}/api/external/emails", params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict) and data.get("success") is False:
        raise Exception(f"Outmail 获取邮件失败: {data}")
    raw_emails = []
    if isinstance(data, dict):
        raw_emails = data.get("emails") or data.get("messages") or data.get("data") or []
    elif isinstance(data, list):
        raw_emails = data
    if not isinstance(raw_emails, list):
        raw_emails = []
    emails = outmail_filter_emails_since(raw_emails, since_ts)
    emails.sort(key=lambda x: outmail_parse_email_timestamp(x) or 0, reverse=True)
    meta = data if isinstance(data, dict) else {"raw": data}
    meta["emails_before_since_filter"] = len(raw_emails)
    meta["emails_after_since_filter"] = len(emails)
    return emails, meta


def outmail_get_email_detail(email, message_id, folder=""):
    base = get_outmail_api_base()
    if not base:
        return None, {"ok": False, "error": "outmail_api_base empty"}
    encoded_email = quote(str(email or ""), safe="")
    encoded_message_id = quote(str(message_id or ""), safe="")
    endpoints = [
        f"{base}/api/external/email/{encoded_email}/{encoded_message_id}",
        f"{base}/api/email/{encoded_email}/{encoded_message_id}",
        f"{base}/api/external/emails/{encoded_email}/{encoded_message_id}",
    ]
    last_error = ""
    for url in endpoints:
        params = {}
        if folder:
            params["folder"] = folder
        try:
            resp = outmail_http_get(url, params=params or None, timeout=30)
            if resp.status_code == 404:
                last_error = f"not_found:{url}"
                continue
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and data.get("success") is False:
                last_error = (
                    f"api_fail:{url}:{data.get('error') or data.get('message') or 'unknown'}"
                )
                continue
            detail_candidates = []
            if isinstance(data, dict):
                detail_candidates.extend(
                    [
                        data.get("email"),
                        data.get("message"),
                        data.get("data"),
                        data.get("item"),
                    ]
                )
                detail_candidates.append(data)
            for candidate in detail_candidates:
                if not isinstance(candidate, dict):
                    continue
                if any(
                    k in candidate
                    for k in ("body", "html", "text", "body_preview", "content", "snippet")
                ):
                    return candidate, {"url": url, "ok": True}
            last_error = f"no_body_fields:{url}"
        except Exception as exc:
            last_error = f"request_error:{url}:{exc}"
            continue
    return None, {"ok": False, "error": last_error}


def outmail_parse_email_timestamp(mail):
    if not isinstance(mail, dict):
        return None
    candidates = (
        "date",
        "received_at",
        "receivedAt",
        "created_at",
        "createdAt",
        "timestamp",
        "sent_at",
        "sentDateTime",
        "receivedDateTime",
    )
    for key in candidates:
        value = mail.get(key)
        if value is None:
            continue
        if isinstance(value, (int, float)):
            ts = int(value)
            if ts > 10_000_000_000:
                ts //= 1000
            return ts
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text:
            continue
        if text.isdigit():
            ts = int(text)
            if ts > 10_000_000_000:
                ts //= 1000
            return ts
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            try:
                dt = parsedate_to_datetime(text)
            except Exception:
                continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    return None


def outmail_filter_emails_since(emails, since_ts):
    if not since_ts or int(since_ts) <= 0:
        return list(emails or [])
    since_ts = int(since_ts)
    filtered = []
    for mail in emails or []:
        mail_ts = outmail_parse_email_timestamp(mail)
        if mail_ts is None or mail_ts >= since_ts:
            filtered.append(mail)
    return filtered


def outmail_mail_from_text(mail):
    sender = (mail or {}).get("from", "")
    if isinstance(sender, dict):
        name = str(sender.get("name", "") or "")
        addr = str(sender.get("address", "") or sender.get("email", "") or "")
        return f"{name} {addr}".strip().lower()
    return str(sender or "").lower()


def outmail_filter_verification_emails(emails, sender_filter="", subject_filter=""):
    sender_kw = str(sender_filter or "").strip().lower()
    subject_kw = str(subject_filter or "").strip().lower()
    filtered = []
    for mail in emails or []:
        subject = str((mail or {}).get("subject", "") or "").lower()
        sender = outmail_mail_from_text(mail)
        if sender_kw and sender_kw not in sender:
            continue
        if subject_kw and subject_kw not in subject:
            continue
        filtered.append(mail)
    return filtered


def outmail_message_id(mail):
    return str(
        (mail or {}).get("id")
        or (mail or {}).get("message_id")
        or (mail or {}).get("messageId")
        or ""
    ).strip()


def outmail_flatten_mail_text(mail):
    """把列表项/详情里的正文字段拼成纯文本，供验证码提取。"""
    if not isinstance(mail, dict):
        return "", ""
    subject = str(mail.get("subject", "") or "")
    parts = [
        subject,
        str(mail.get("body_preview", "") or ""),
        str(mail.get("bodyPreview", "") or ""),
        str(mail.get("snippet", "") or ""),
        str(mail.get("intro", "") or ""),
        str(mail.get("text", "") or ""),
        str(mail.get("content", "") or ""),
        str(mail.get("body", "") or ""),
    ]
    html_val = mail.get("html")
    if isinstance(html_val, list):
        for h in html_val:
            parts.append(re.sub(r"<[^>]+>", " ", str(h or "")))
    elif isinstance(html_val, str) and html_val.strip():
        parts.append(re.sub(r"<[^>]+>", " ", html_val))
    body_obj = mail.get("body")
    if isinstance(body_obj, dict):
        parts.append(str(body_obj.get("content", "") or ""))
    combined = "\n".join(p for p in parts if p)
    combined = re.sub(r"<[^>]+>", " ", combined)
    return subject, combined


def outmail_alias_suffix_len() -> int:
    """Random plus-alias suffix length (local+XXXX@domain). Default 6, clamp 2..32."""
    try:
        n = int(_cfg().get("outmail_alias_suffix_len", 6) or 6)
    except (TypeError, ValueError):
        n = 6
    return max(2, min(32, n))


def outmail_plus_alias_count() -> int:
    """Max successful registrations per main mailbox when plus-alias is on.

    Each success consumes one quota; mailbox is skipped after reaching this count.
    When plus-alias is off, effective limit is always 1.
    """
    if not bool(_cfg().get("outmail_plus_alias", True)):
        return 1
    try:
        n = int(_cfg().get("outmail_plus_alias_count", 1) or 1)
    except (TypeError, ValueError):
        n = 1
    return max(1, min(1000, n))


def outmail_build_alias_email(base_email, suffix_len: int | None = None):
    """Build plus-alias. Suffix length jitters around config so not every alias is same width."""
    local, domain = base_email.split("@", 1)
    base_n = int(suffix_len) if suffix_len is not None else outmail_alias_suffix_len()
    base_n = max(2, min(32, base_n))
    # jitter ?2 within clamp (keeps config intent, breaks fixed-width fingerprint)
    n = max(2, min(32, base_n + random.randint(-2, 2)))
    alphabet = string.ascii_lowercase + string.digits
    # prefer letter-start suffix occasionally mixed; pure digit-looking less often
    if random.random() < 0.75:
        suffix = "".join(random.choice(alphabet) for _ in range(n))
    else:
        suffix = random.choice(string.ascii_lowercase) + "".join(
            random.choice(alphabet) for _ in range(max(0, n - 1))
        )
    return f"{local}+{suffix}@{domain}"


def outmail_encode_token(mailbox, since_ts, register_email="", mode="pool"):
    """dev_token 编码：outmail|mailbox|since_ts|register_email|mode

    mode: pool=账号池；anon=匿名临时期箱
    """
    mb = str(mailbox or "").strip()
    reg = str(register_email or mb).strip()
    mode_s = str(mode or "pool").strip().lower()
    if mode_s in ("anon", "anonymous", "temp"):
        mode_s = "anon"
    else:
        mode_s = "pool"
    return f"outmail|{mb}|{int(since_ts or 0)}|{reg}|{mode_s}"


def outmail_decode_token(dev_token, fallback_email=""):
    """返回 (mailbox, since_ts, register_email, mode)。mode=pool|anon。"""
    text = str(dev_token or "").strip()
    if text.startswith("outmail|"):
        parts = text.split("|")
        mailbox = parts[1] if len(parts) > 1 else ""
        try:
            since_ts = int(parts[2]) if len(parts) > 2 else 0
        except ValueError:
            since_ts = 0
        register_email = parts[3] if len(parts) > 3 else fallback_email
        mode = parts[4] if len(parts) > 4 else "pool"
        mode = str(mode or "pool").strip().lower()
        if mode in ("anon", "anonymous", "temp"):
            mode = "anon"
        else:
            mode = "pool"
        return (
            mailbox or fallback_email,
            since_ts,
            register_email or fallback_email,
            mode,
        )
    mailbox = text if "@" in text else (fallback_email or "")
    return mailbox, 0, fallback_email or mailbox, "pool"


def outmail_filter_account_candidates(accounts, excluded=None):
    excluded = {str(x).strip().lower() for x in (excluded or set()) if str(x).strip()}
    candidates = []
    for acc in accounts or []:
        if not isinstance(acc, dict):
            continue
        email = str(
            acc.get("email") or acc.get("address") or acc.get("mailbox") or ""
        ).strip()
        if not email or "@" not in email:
            continue
        status = str(acc.get("status") or "").strip().lower()
        if status in {"disabled", "error", "fail", "failed", "banned", "invalid", "expired"}:
            continue
        if email.lower() in excluded:
            continue
        candidates.append(email)
    return candidates


def outmail_used_file_path():
    """Resolve shared used-mailbox ledger path.

    Absolute path is preferred (console writes one under apps/console/runtime).
    Relative names resolve in order:
      1) GROK_REGISTER_OUTMAIL_USED_DIR / GROK_REGISTER_CONSOLE_RUNTIME
      2) sibling apps/console/runtime when running from source tree
      3) script directory (legacy task-local fallback)
    """
    raw = str(_cfg().get("outmail_used_file") or "outmail_used_mailboxes.txt").strip()
    if not raw:
        raw = "outmail_used_mailboxes.txt"
    if os.path.isabs(raw):
        return os.path.normpath(raw)

    base = (
        str(os.getenv("GROK_REGISTER_OUTMAIL_USED_DIR") or "").strip()
        or str(os.getenv("GROK_REGISTER_CONSOLE_RUNTIME") or "").strip()
    )
    if not base:
        # apps/register-runner -> apps/console/runtime (source layout)
        here = os.path.dirname(os.path.abspath(__file__))
        candidate = os.path.normpath(
            os.path.join(here, "..", "console", "runtime")
        )
        if os.path.isdir(candidate):
            base = candidate
        else:
            # task_dir copy: prefer env; else keep local (legacy)
            base = here
    return os.path.normpath(os.path.join(base, raw))


def outmail_used_lock_path() -> str:
    return outmail_used_file_path() + ".lock"


def outmail_load_usage_counts(force=False) -> dict[str, int]:
    """Load per-mailbox success usage counts (lowercase email -> count).

    Shared across tasks via absolute used-file path + cross-process lock.
    File format (append-only, backward compatible):
      email
      email<TAB>ts<TAB>reason...
    Each non-comment line counts as +1 use for that mailbox.
    """
    global _outmail_used_cache
    with _outmail_used_lock:
        if _outmail_used_cache is not None and not force:
            return dict(_outmail_used_cache)
        counts: dict[str, int] = {}
        path = outmail_used_file_path()
        lock_path = outmail_used_lock_path()

        def _parse_file() -> dict[str, int]:
            out: dict[str, int] = {}
            if not os.path.exists(path):
                return out
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = str(line or "").strip()
                    if not line or line.startswith("#"):
                        continue
                    email = line.split("\t", 1)[0].split(",", 1)[0].strip().lower()
                    if "@" in email:
                        out[email] = int(out.get(email, 0)) + 1
            return out

        try:
            with _file_lock_exclusive(lock_path):
                counts = _parse_file()
        except Exception:
            try:
                counts = _parse_file()
            except Exception:
                counts = {}
        _outmail_used_cache = counts
        return dict(counts)



def outmail_load_used_mailboxes(force=False):
    """Mailboxes that reached the alias/use quota (set of lowercase emails)."""
    limit = outmail_plus_alias_count()
    counts = outmail_load_usage_counts(force=force)
    return {mb for mb, n in counts.items() if int(n or 0) >= limit}


def outmail_mailbox_usage(mailbox) -> int:
    mb = str(mailbox or "").strip().lower()
    if not mb:
        return 0
    return int(outmail_load_usage_counts().get(mb, 0) or 0)


def outmail_is_mailbox_used(mailbox):
    """True when mailbox has consumed its full alias/use quota."""
    mb = str(mailbox or "").strip().lower()
    if not mb or "@" not in mb:
        return False
    return outmail_mailbox_usage(mb) >= outmail_plus_alias_count()


def outmail_mark_mailbox_used(mailbox, register_email="", reason="success", log_callback=None):
    """Record one successful use of a main mailbox (shared ledger, cross-process).

    With outmail_plus_alias_count>1, the same mailbox stays selectable until
    usage reaches the quota; only then is it treated as fully used.
    """
    global _outmail_used_cache
    mb = str(mailbox or "").strip().lower()
    if not mb or "@" not in mb:
        return False
    reg = str(register_email or "").strip()
    path = outmail_used_file_path()
    lock_path = outmail_used_lock_path()
    limit = outmail_plus_alias_count()
    new_n = 0

    def _parse_file() -> dict[str, int]:
        out: dict[str, int] = {}
        if not os.path.exists(path):
            return out
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = str(line or "").strip()
                if not line or line.startswith("#"):
                    continue
                email = line.split("\t", 1)[0].split(",", 1)[0].strip().lower()
                if "@" in email:
                    out[email] = int(out.get(email, 0)) + 1
        return out

    with _outmail_used_lock:
        try:
            with _file_lock_exclusive(lock_path):
                counts = _parse_file()
                prev = int(counts.get(mb, 0) or 0)
                new_n = prev + 1
                parent = os.path.dirname(path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with open(path, "a", encoding="utf-8") as f:
                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    extra = ("\t" + reg) if reg else ""
                    f.write(f"{mb}\t{ts}\t{reason}\tuse={new_n}/{limit}{extra}\n")
                counts[mb] = new_n
                _outmail_used_cache = counts
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] ????????: {exc}")
            try:
                _outmail_used_cache = _parse_file()
            except Exception:
                pass
            return False
    if log_callback:
        if new_n >= limit:
            log_callback(
                f"[Debug] Outmail ????????? {new_n}/{limit}?????: {mb}"
            )
        else:
            msg = f"[Debug] Outmail ??????? {new_n}/{limit}: {mb}"
            if reg:
                msg += f" (alias={reg})"
            log_callback(msg)
    return True



def outmail_select_mailbox(excluded=None):
    """从 Outmail 账号池选取可用主邮箱（并发占用 + 已用排除 + 轮询缓存）。"""
    global _outmail_selector_cache, _outmail_selector_cursor
    excluded = {str(x).strip().lower() for x in (excluded or set()) if str(x).strip()}
    group_id = _cfg().get("outmail_group_id", None)
    batch = 50

    # Global shared used ledger: skip mailboxes that reached alias quota
    if bool(_cfg().get("outmail_exclude_used", True)):
        global _outmail_used_cache
        with _outmail_used_lock:
            _outmail_used_cache = None
        excluded |= outmail_load_used_mailboxes(force=True)

    with _outmail_lock:
        excluded = set(excluded) | set(_outmail_in_use)

        def _next_from_cache():
            global _outmail_selector_cursor
            if not _outmail_selector_cache:
                return ""
            n = len(_outmail_selector_cache)
            for _ in range(n):
                email = _outmail_selector_cache[_outmail_selector_cursor % n]
                _outmail_selector_cursor = (_outmail_selector_cursor + 1) % n
                if email.lower() not in excluded:
                    return email
            return ""

        picked = _next_from_cache()
        if not picked:
            offset = 0
            found = []
            for _ in range(20):
                accounts = outmail_list_accounts(
                    limit=batch, offset=offset, group_id=group_id
                )
                if not accounts:
                    break
                found.extend(
                    outmail_filter_account_candidates(accounts, excluded=excluded)
                )
                if len(accounts) < batch:
                    break
                offset += batch
                if found:
                    break
            _outmail_selector_cache = found
            _outmail_selector_cursor = 0
            picked = _next_from_cache()

        if not picked:
            used_n = len(outmail_load_used_mailboxes(force=True)) if bool(
                _cfg().get("outmail_exclude_used", True)
            ) else 0
            raise Exception(
                "Outmail 邮箱池为空，或可用账号均已被占用/排除"
                f"（进行中={len(_outmail_in_use)}, 已用跳过={used_n}），"
                "请补充账号或清理 outmail_used_mailboxes.txt"
            )

        _outmail_in_use.add(picked.lower())
        return picked


def outmail_release_mailbox(mailbox):
    if not mailbox:
        return
    with _outmail_lock:
        _outmail_in_use.discard(str(mailbox).strip().lower())


def outmail_get_email_and_token():
    """
    获取注册邮箱。
    - outmail_anonymous_enabled=True: 走 Outmail 匿名临时期箱 API
    - 否则: 从 Outlook 账号池取主邮箱（可 plus 别名）
    返回 (register_email, dev_token)
    - dev_token: outmail|mailbox|since_ts|register_email|mode
    """
    base = get_outmail_api_base()
    if not base:
        raise Exception("email_provider=outmail 时必须配置 outmail_api_base")

    anonymous = bool(_cfg().get("outmail_anonymous_enabled", False))
    if anonymous:
        if not get_outmail_session_cookie():
            raise Exception(
                "outmail_anonymous_enabled=true 时必须配置 outmail_session_cookie"
            )
        provider = str(
            _cfg().get("outmail_anonymous_provider", "cloudflare") or "cloudflare"
        ).strip().lower()
        prefix = str(
            _cfg().get("outmail_anonymous_username_prefix", "") or ""
        ).strip()
        password = str(_cfg().get("outmail_anonymous_password", "") or "").strip()
        # 多域名轮询：outmail_anonymous_domain 支持逗号分隔；空则回退 defaultDomains
        domain_list = outmail_list_anonymous_domains()
        mailbox = None
        last_err = None
        if domain_list:
            # 从轮询起点开始，失败则依次尝试其余域名，避免单域名不可用卡死
            start = outmail_next_anonymous_domain(domain_list)
            try:
                start_idx = domain_list.index(start)
            except ValueError:
                start_idx = 0
            ordered_domains = domain_list[start_idx:] + domain_list[:start_idx]
            for domain in ordered_domains:
                try:
                    mailbox, _meta = outmail_generate_temp_email(
                        provider=provider,
                        domain=domain,
                        username_prefix=prefix,
                        password=password,
                    )
                    print(
                        f"[Outmail] 匿名邮箱域名={domain} -> {mailbox}",
                        flush=True,
                    )
                    break
                except Exception as exc:
                    last_err = exc
                    print(
                        f"[Outmail] 域名 {domain} 生成失败，尝试下一个: {exc}",
                        flush=True,
                    )
            if not mailbox:
                raise Exception(
                    f"Outmail 匿名邮箱多域名均失败 domains={domain_list}: {last_err}"
                )
        else:
            # 未配置域名：交给 Outmail 侧默认选择
            if provider == "duckmail":
                raise Exception(
                    "provider=duckmail 时必须配置 outmail_anonymous_domain（可逗号分隔多域名）"
                )
            mailbox, _meta = outmail_generate_temp_email(
                provider=provider,
                domain="",
                username_prefix=prefix,
                password=password,
            )
            print(f"[Outmail] 匿名邮箱(默认域名) -> {mailbox}", flush=True)
        register_email = mailbox
        mode = "anon"
    else:
        if not get_outmail_api_key() and not get_outmail_session_cookie():
            raise Exception(
                "email_provider=outmail 时必须配置 outmail_api_key 或 outmail_session_cookie"
            )
        mailbox = outmail_select_mailbox()
        use_alias = bool(_cfg().get("outmail_plus_alias", True))
        if use_alias:
            register_email = outmail_build_alias_email(
                mailbox, suffix_len=outmail_alias_suffix_len()
            )
        else:
            register_email = mailbox
        mode = "pool"

    padding = int(_cfg().get("outmail_since_padding_sec", 30) or 30)
    since_ts = int(time.time()) - max(0, padding)
    token = outmail_encode_token(mailbox, since_ts, register_email, mode=mode)
    return register_email, token


def outmail_extract_code_from_mails(mails):
    """优先详情正文，再回退列表字段；复用项目现有 xAI 验证码规则。"""
    for mail in mails or []:
        subject, text = outmail_flatten_mail_text(mail)
        code = extract_verification_code(text, subject)
        if code:
            return code
    return None


def outmail_get_oai_code(
    dev_token,
    email,
    timeout=None,
    poll_interval=None,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    """
    收信提码：
    - mode=pool: 参考 poll_email_code（账号池 + 多文件夹）
    - mode=anon: 参考 poll_temp_email_code（匿名临时期箱 refresh/list）
    """
    mailbox, since_ts, register_email, mode = outmail_decode_token(
        dev_token, fallback_email=email
    )
    if not mailbox:
        mailbox = email
    if not since_ts:
        padding = int(_cfg().get("outmail_since_padding_sec", 30) or 30)
        since_ts = int(time.time()) - max(0, padding)

    if timeout is None:
        timeout = int(_cfg().get("outmail_poll_timeout_sec", 180) or 180)
    if poll_interval is None:
        poll_interval = int(_cfg().get("outmail_poll_interval_sec", 5) or 5)
    fetch_top = int(_cfg().get("outmail_fetch_top", 10) or 10)
    fetch_top = max(1, min(fetch_top, 50))
    from_filter_cfg = str(_cfg().get("outmail_from_filter", "x.ai") or "").strip()
    subject_filter_cfg = str(_cfg().get("outmail_subject_filter", "xAI") or "").strip()

    deadline = time.time() + max(30, int(timeout))
    poll_rounds = 0
    resend_at = time.time() + max(45, int(timeout) // 2)
    last_err = ""

    try:
        if mode == "anon":
            if log_callback:
                log_callback(
                    f"[Debug] Outmail 匿名邮箱开始收信: mailbox={mailbox}, "
                    f"since_ts={since_ts}, timeout={timeout}s"
                )
            while time.time() < deadline:
                raise_if_cancelled(cancel_callback)
                poll_rounds += 1

                if resend_callback and time.time() >= resend_at:
                    try:
                        resend_callback()
                        if log_callback:
                            log_callback("[Debug] Outmail 已触发重新发送验证码")
                    except Exception as exc:
                        if log_callback:
                            log_callback(f"[Debug] Outmail 触发重发失败: {exc}")
                    resend_at = time.time() + 60

                for query_type in ("refresh", "list"):
                    raise_if_cancelled(cancel_callback)
                    try:
                        if query_type == "refresh":
                            emails, _meta = outmail_refresh_temp_email_messages(
                                email=mailbox,
                                since_ts=since_ts,
                                limit=fetch_top,
                            )
                        else:
                            emails, _meta = outmail_get_temp_email_messages(
                                email=mailbox,
                                since_ts=since_ts,
                                limit=fetch_top,
                            )
                    except Exception as exc:
                        last_err = str(exc)
                        if log_callback and poll_rounds <= 2:
                            log_callback(
                                f"[Debug] Outmail 匿名拉信失败 query={query_type}: {exc}"
                            )
                        continue

                    matched = outmail_filter_verification_emails(
                        emails,
                        sender_filter=from_filter_cfg,
                        subject_filter=subject_filter_cfg,
                    )
                    if not matched:
                        matched = list(emails or [])
                    if not matched:
                        continue

                    if log_callback:
                        log_callback(
                            f"[Debug] Outmail 匿名本轮命中 {len(matched)} 封 "
                            f"query={query_type}"
                        )

                    matched = sorted(
                        matched,
                        key=lambda x: outmail_parse_email_timestamp(x) or 0,
                        reverse=True,
                    )

                    detail_mails = []
                    for mail in matched[:3]:
                        msg_id = outmail_message_id(mail)
                        if not msg_id:
                            detail_mails.append(mail)
                            continue
                        detail, detail_meta = outmail_get_temp_email_detail(
                            email=mailbox, message_id=msg_id
                        )
                        if detail:
                            merged = dict(mail)
                            merged.update(detail)
                            detail_mails.append(merged)
                        else:
                            detail_mails.append(mail)
                            if log_callback and poll_rounds <= 2:
                                log_callback(
                                    f"[Debug] Outmail 匿名详情失败 id={msg_id}: "
                                    f"{detail_meta.get('error')}"
                                )

                    code = outmail_extract_code_from_mails(detail_mails)
                    if not code:
                        code = outmail_extract_code_from_mails(matched)
                    if code:
                        if log_callback:
                            subj = ""
                            if detail_mails:
                                subj = str(
                                    detail_mails[0].get("subject", "") or ""
                                )
                            log_callback(
                                f"[Debug] Outmail 匿名提取到验证码: {code} "
                                f"(query={query_type}, subject={subj})"
                            )
                        return code

                sleep_with_cancel(max(1, int(poll_interval)), cancel_callback)

            err_tail = f", last_error={last_err}" if last_err else ""
            raise Exception(
                f"Outmail 匿名邮箱在 {timeout}s 内未收到验证码邮件"
                f"(poll_rounds={poll_rounds}, mailbox={mailbox}{err_tail})"
            )

        # ---- 账号池模式 ----
        checked_set = []
        for item in (register_email or email, mailbox, email):
            t = str(item or "").strip()
            if t and t.lower() not in {x.lower() for x in checked_set}:
                checked_set.append(t)

        query_plans = [
            {
                "folder": "all",
                "subject_filter": subject_filter_cfg,
                "from_filter": from_filter_cfg,
            },
            {
                "folder": "junkemail",
                "subject_filter": subject_filter_cfg,
                "from_filter": from_filter_cfg,
            },
            {
                "folder": "inbox",
                "subject_filter": subject_filter_cfg,
                "from_filter": from_filter_cfg,
            },
            {"folder": "all", "subject_filter": "", "from_filter": from_filter_cfg},
            {
                "folder": "junkemail",
                "subject_filter": "",
                "from_filter": from_filter_cfg,
            },
            {"folder": "inbox", "subject_filter": "", "from_filter": from_filter_cfg},
            {"folder": "all", "subject_filter": "", "from_filter": ""},
            {"folder": "junkemail", "subject_filter": "", "from_filter": ""},
        ]

        if log_callback:
            log_callback(
                f"[Debug] Outmail 开始收信: mailbox={mailbox}, "
                f"register={register_email or email}, "
                f"since_ts={since_ts}, timeout={timeout}s"
            )

        while time.time() < deadline:
            raise_if_cancelled(cancel_callback)
            poll_rounds += 1

            if resend_callback and time.time() >= resend_at:
                try:
                    resend_callback()
                    if log_callback:
                        log_callback("[Debug] Outmail 已触发重新发送验证码")
                except Exception as exc:
                    if log_callback:
                        log_callback(f"[Debug] Outmail 触发重发失败: {exc}")
                resend_at = time.time() + 60

            for target in checked_set:
                for plan in query_plans:
                    raise_if_cancelled(cancel_callback)
                    folder = plan["folder"]
                    subject_filter = plan["subject_filter"]
                    from_filter = plan["from_filter"]
                    try:
                        emails, _meta = outmail_get_recent_emails(
                            email=target,
                            since_ts=since_ts,
                            subject_filter=subject_filter,
                            from_filter=from_filter,
                            folder=folder,
                            limit=fetch_top,
                        )
                    except Exception as exc:
                        last_err = str(exc)
                        if log_callback and poll_rounds <= 2:
                            log_callback(
                                f"[Debug] Outmail 拉信失败 target={target} "
                                f"folder={folder}: {exc}"
                            )
                        continue

                    matched = outmail_filter_verification_emails(
                        emails,
                        sender_filter=from_filter_cfg,
                        subject_filter=subject_filter_cfg if subject_filter else "",
                    )
                    if not matched:
                        matched = list(emails or [])
                    if not matched:
                        continue

                    if log_callback:
                        log_callback(
                            f"[Debug] Outmail 本轮命中 {len(matched)} 封 "
                            f"target={target} folder={folder} "
                            f"subject={subject_filter or '-'} "
                            f"from={from_filter or '-'}"
                        )

                    matched = sorted(
                        matched,
                        key=lambda x: outmail_parse_email_timestamp(x) or 0,
                        reverse=True,
                    )

                    detail_mails = []
                    for mail in matched[:3]:
                        msg_id = outmail_message_id(mail)
                        if not msg_id:
                            detail_mails.append(mail)
                            continue
                        detail, detail_meta = outmail_get_email_detail(
                            email=target,
                            message_id=msg_id,
                            folder=str(mail.get("folder") or folder),
                        )
                        if detail:
                            merged = dict(mail)
                            merged.update(detail)
                            detail_mails.append(merged)
                        else:
                            detail_mails.append(mail)
                            if log_callback and poll_rounds <= 2:
                                log_callback(
                                    f"[Debug] Outmail 详情失败 id={msg_id}: "
                                    f"{detail_meta.get('error')}"
                                )

                    code = outmail_extract_code_from_mails(detail_mails)
                    if not code:
                        code = outmail_extract_code_from_mails(matched)
                    if code:
                        if log_callback:
                            subj = ""
                            if detail_mails:
                                subj = str(
                                    detail_mails[0].get("subject", "") or ""
                                )
                            log_callback(
                                f"[Debug] Outmail 提取到验证码: {code} "
                                f"(folder={folder}, target={target}, subject={subj})"
                            )
                        return code

            sleep_with_cancel(max(1, int(poll_interval)), cancel_callback)

        err_tail = f", last_error={last_err}" if last_err else ""
        raise Exception(
            f"Outmail 在 {timeout}s 内未收到验证码邮件"
            f"(poll_rounds={poll_rounds}, mailbox={mailbox}{err_tail})"
        )
    finally:
        # 账号池释放占用；匿名模式按配置删除临时期箱
        outmail_cleanup_mailbox(mailbox, mode=mode, log_callback=log_callback)


