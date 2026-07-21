# -*- coding: utf-8 -*-
"""Convert CPA xAI auth JSON and push/export to Sub2API.

Push API (open-cpa style):
  1) POST /api/v1/admin/accounts  (create oauth/apikey)
  2) fallback POST /api/v1/admin/accounts/data  (import bundle)
Auth header: x-api-key

Account payload aligned with sub2api GrokOAuthService.BuildAccountCredentials
and CreateAccountRequest (also compatible with roxy cpa_to_sub2.py):
  - platform=grok (xAI OAuth)
  - credentials: access_token / token_type / base_url / expires_at(RFC3339) /
    refresh_token / id_token / client_id / scope / email
  - top-level expires_at as unix seconds
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import requests

LogFn = Callable[[str], None]


def _noop_log(message: str) -> None:
    print(message, flush=True)


def _as_int(value: Any, default: int, minimum: int = 0, maximum: int | None = None) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    if n < minimum:
        n = minimum
    if maximum is not None and n > maximum:
        n = maximum
    return n


def _as_float(value: Any, default: float, minimum: float = 0.0) -> float:
    try:
        n = float(value)
    except (TypeError, ValueError):
        n = default
    if n < minimum:
        n = minimum
    return n


def _parse_group_ids(raw: Any) -> list[int]:
    if isinstance(raw, list):
        out: list[int] = []
        for item in raw:
            try:
                out.append(int(item))
            except (TypeError, ValueError):
                text = str(item or "").strip()
                if text.isdigit():
                    out.append(int(text))
        return out
    text = str(raw or "").replace(";", ",").replace(" ", ",")
    return [int(part) for part in text.split(",") if part.strip().isdigit()]


def _normalize_api_base(value: str) -> str:
    base = (value or "").strip().rstrip("/")
    if not base:
        return ""
    if not re.match(r"^https?://", base, re.IGNORECASE):
        base = f"http://{base}"
    # Accept full admin path pasted by mistake
    base = re.sub(r"/api/v1/admin/?$", "", base, flags=re.IGNORECASE).rstrip("/")
    return base


def _api_key(config: dict[str, Any]) -> str:
    return (
        str(os.environ.get("SUB2API_API_KEY") or os.environ.get("SUB2API_KEY") or "").strip()
        or str(config.get("sub2api_api_key") or config.get("sub2api_key") or "").strip()
    )


def _api_base(config: dict[str, Any]) -> str:
    return _normalize_api_base(
        str(
            config.get("sub2api_api_base")
            or config.get("sub2api_url")
            or os.environ.get("SUB2API_API_BASE")
            or os.environ.get("SUB2API_URL")
            or ""
        )
    )


def get_sub2api_push_settings(config: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = config or {}
    return {
        "concurrency": _as_int(cfg.get("sub2api_account_concurrency", 1), 1, 1, 200),
        "load_factor": _as_int(cfg.get("sub2api_account_load_factor", 10), 10, 1, 10000),
        "priority": _as_int(cfg.get("sub2api_account_priority", 1), 1, 0, 1000),
        "rate_multiplier": _as_float(cfg.get("sub2api_account_rate_multiplier", 1.0), 1.0, 0.0),
        "group_ids": _parse_group_ids(cfg.get("sub2api_account_group_ids")),
        "platform": str(cfg.get("sub2api_platform") or "grok").strip() or "grok",
        "account_type": str(cfg.get("sub2api_account_type") or "oauth").strip().lower() or "oauth",
        "enable_ws": bool(cfg.get("sub2api_enable_ws_mode", False)),
        "default_proxy": str(cfg.get("sub2api_default_proxy") or "").strip(),
    }


def parse_sub2api_proxy(proxy_url: str) -> dict[str, Any] | None:
    if not proxy_url:
        return None
    try:
        parsed = urlparse(str(proxy_url).strip())
        protocol = parsed.scheme
        host = parsed.hostname
        port = parsed.port
        username = parsed.username or ""
        password = parsed.password or ""
        if not protocol or not host or not port:
            return None
        proxy_key = f"{protocol}|{host}|{port}|{username}|{password}"
        item: dict[str, Any] = {
            "proxy_key": proxy_key,
            "name": "grok-register",
            "protocol": protocol,
            "host": host,
            "port": port,
            "status": "active",
        }
        if username and password:
            item["username"] = username
            item["password"] = password
        return item
    except Exception:
        return None


def _load_cpa_auth(path_value: str | Path | dict[str, Any] | None) -> tuple[dict[str, Any] | None, Path | None, str]:
    if isinstance(path_value, dict):
        return path_value, None, ""
    path = Path(str(path_value or "")).expanduser()
    if not path.is_file():
        return None, path if str(path_value or "") else None, "file_not_found"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return None, path, f"invalid_json: {exc}"
    if not isinstance(data, dict):
        return None, path, "auth_not_object"
    return data, path, ""



DEFAULT_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
DEFAULT_BASE_URL = "https://cli-chat-proxy.grok.com/v1"
DEFAULT_SCOPE = "openid profile email offline_access grok-cli:access api:access"
PLATFORM_MAP = {
    "xai": "grok",
    "grok": "grok",
    "openai": "openai",
    "chatgpt": "openai",
    "codex": "openai",
}


def _b64url_json(segment: str) -> Any | None:
    import base64

    s = segment + "=" * (-len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(s.encode("ascii")))
    except Exception:
        return None


def _parse_jwt_claims(token: str) -> dict[str, Any]:
    if not token or token.count(".") < 2:
        return {}
    claims = _b64url_json(token.split(".")[1])
    return claims if isinstance(claims, dict) else {}


def _to_rfc3339(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    s = str(value).strip()
    if not s:
        return None
    try:
        ss = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ss)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass
    try:
        return datetime.fromtimestamp(int(float(s)), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def _rfc3339_to_unix(value: str | None) -> int | None:
    if not value:
        return None
    try:
        ss = str(value).replace("Z", "+00:00")
        return int(datetime.fromisoformat(ss).timestamp())
    except Exception:
        return None


def _expires_at_unix(auth: dict[str, Any]) -> int:
    access = str(auth.get("access_token") or "").strip()
    if access.count(".") >= 2:
        try:
            import base64

            pad = "=" * (-len(access.split(".")[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(access.split(".")[1] + pad))
            exp = int(payload.get("exp") or 0)
            if exp > 0:
                return exp
        except Exception:
            pass
    expired = str(auth.get("expired") or "").strip()
    if expired:
        try:
            # 2026-01-01T00:00:00Z
            text = expired.replace("Z", "+00:00")
            return int(datetime.fromisoformat(text).timestamp())
        except Exception:
            pass
    expires_in = _as_int(auth.get("expires_in"), 21600, 0)
    return int(time.time()) + max(expires_in, 60)


def build_sub2api_account_from_cpa(
    auth: dict[str, Any],
    settings: dict[str, Any] | None = None,
    *,
    proxy_obj: dict[str, Any] | None = None,
    file_name: str = "",
) -> dict[str, Any]:
    """Build one Sub2API account item from CPA xAI auth.

    Aligns with sub2api source:
      - service.GrokOAuthService.BuildAccountCredentials
      - handler.CreateAccountRequest (platform/type/credentials/expires_at unix)
      - README: platform=grok, oauth fields access_token/refresh_token/token_type/
        expires_at(RFC3339)/base_url/email/client_id/scope + optional sub/team_id
    """
    push = settings or get_sub2api_push_settings()
    email = str(auth.get("email") or "").strip()
    access_token = str(auth.get("access_token") or "").strip()
    if not access_token and isinstance(auth.get("credentials"), dict):
        access_token = str(auth["credentials"].get("access_token") or "").strip()
    refresh_token = str(auth.get("refresh_token") or "").strip()
    if not refresh_token and isinstance(auth.get("credentials"), dict):
        refresh_token = str(auth["credentials"].get("refresh_token") or "").strip()
    id_token = str(auth.get("id_token") or "").strip()
    if not id_token and isinstance(auth.get("credentials"), dict):
        id_token = str(auth["credentials"].get("id_token") or "").strip()

    claims = _parse_jwt_claims(access_token)
    id_claims = _parse_jwt_claims(id_token)
    if not email:
        for src in (auth, id_claims, claims):
            v = str((src or {}).get("email") or "").strip()
            if v and "@" in v:
                email = v
                break
    if not email:
        email = "unknown"

    # CPA xAI 授权一律推成 platform=grok（sub2api 官方 Grok 平台）。
    # 历史配置里若仍保存 sub2api_platform=openai，会错误显示为 openai，这里强制纠正。
    provider = str(auth.get("type") or auth.get("provider") or auth.get("platform") or "xai").strip().lower()
    base_hint = str(auth.get("base_url") or (auth.get("credentials") or {}).get("base_url") or "").lower()
    is_xai_auth = (
        provider in {"xai", "grok", ""}
        or "cli-chat-proxy.grok.com" in base_hint
        or "api.x.ai" in base_hint
        or "x.ai" in base_hint
        or str(auth.get("auth_kind") or "").lower() in {"oauth", "sso_oauth", ""}
    )
    raw_platform = str(push.get("platform") or "grok").strip().lower() or "grok"
    if is_xai_auth:
        platform = "grok"
        if raw_platform and raw_platform not in {"grok", "xai"}:
            # 忽略错误的 openai 等历史配置，避免推到错误平台
            pass
    elif raw_platform in PLATFORM_MAP:
        platform = PLATFORM_MAP[raw_platform]
    elif provider in PLATFORM_MAP:
        platform = PLATFORM_MAP[provider]
    else:
        platform = raw_platform or "grok"

    account_type = str(push.get("account_type") or "oauth").lower()
    if account_type not in {"oauth", "apikey", "upstream"}:
        account_type = "oauth"
    auth_kind = str(auth.get("auth_kind") or "").strip().lower()
    if auth_kind in {"oauth", "apikey"}:
        account_type = auth_kind

    base_url = str(
        auth.get("base_url")
        or (auth.get("credentials") or {}).get("base_url")
        or DEFAULT_BASE_URL
    ).strip().rstrip("/") or DEFAULT_BASE_URL

    # credentials.expires_at MUST be RFC3339 string (BuildAccountCredentials)
    expires_rfc = _to_rfc3339(
        auth.get("expires_at")
        or auth.get("expired")
        or auth.get("expiry")
        or (auth.get("credentials") or {}).get("expires_at")
        or (auth.get("credentials") or {}).get("expired")
        or claims.get("exp")
    )
    if not expires_rfc:
        expires_rfc = _to_rfc3339(_expires_at_unix(auth))
    expires_unix = _rfc3339_to_unix(expires_rfc) or _expires_at_unix(auth)

    if account_type == "apikey":
        # xAI API key path: api.x.ai style
        if "cli-chat-proxy" in base_url:
            base_url = "https://api.x.ai/v1"
        credentials: dict[str, Any] = {
            "api_key": access_token or refresh_token,
            "base_url": base_url,
        }
        if email and email != "unknown":
            credentials["email"] = email
    else:
        # Mirror GrokOAuthService.BuildAccountCredentials
        token_type = str(auth.get("token_type") or "Bearer").strip() or "Bearer"
        client_id = str(
            auth.get("client_id")
            or claims.get("client_id")
            or (auth.get("credentials") or {}).get("client_id")
            or DEFAULT_CLIENT_ID
        ).strip() or DEFAULT_CLIENT_ID
        scope = str(
            auth.get("scope")
            or claims.get("scope")
            or (auth.get("credentials") or {}).get("scope")
            or DEFAULT_SCOPE
        ).strip() or DEFAULT_SCOPE

        credentials = {
            "access_token": access_token,
            "expires_at": expires_rfc,  # RFC3339 string
            "token_type": token_type,
            "base_url": base_url,
            "client_id": client_id,
            "scope": scope,
        }
        if refresh_token:
            credentials["refresh_token"] = refresh_token
        if id_token:
            credentials["id_token"] = id_token
        if email and email != "unknown":
            credentials["email"] = email

        # optional identity fields from JWT (same as BuildAccountCredentials)
        subject = str(
            auth.get("sub")
            or claims.get("sub")
            or id_claims.get("sub")
            or ""
        ).strip()
        if subject:
            credentials["sub"] = subject
        team_id = str(
            auth.get("team_id")
            or claims.get("team_id")
            or id_claims.get("team_id")
            or ""
        ).strip()
        if team_id:
            credentials["team_id"] = team_id
        for k in ("subscription_tier", "entitlement_status"):
            v = auth.get(k) or claims.get(k)
            if v:
                credentials[k] = v

    if not str(credentials.get("access_token") or credentials.get("api_key") or "").strip():
        raise ValueError("missing access_token/api_key for sub2api account")

    # extra: keep email; load_factor is top-level on CreateAccountRequest
    extra: dict[str, Any] = {}
    if email and email != "unknown":
        extra["email"] = email
    for k in ("subscription_tier", "entitlement_status"):
        if credentials.get(k) and k not in extra:
            extra[k] = credentials[k]

    concurrency = int(push.get("concurrency") or 1)
    if platform == "grok" and account_type == "oauth" and concurrency <= 0:
        concurrency = 1

    item: dict[str, Any] = {
        "name": (email if email != "unknown" else (Path(file_name).stem if file_name else "unknown"))[:100],
        "platform": platform,
        "type": account_type if account_type != "upstream" else "upstream",
        "credentials": credentials,
        "extra": extra,
        "concurrency": concurrency,
        "priority": int(push.get("priority") or 1),
        "rate_multiplier": float(push.get("rate_multiplier") if push.get("rate_multiplier") is not None else 1.0),
        "auto_pause_on_expired": True,
    }
    # CreateAccountRequest.ExpiresAt / DataAccount.ExpiresAt = unix seconds
    if expires_unix and int(expires_unix) > 0:
        item["expires_at"] = int(expires_unix)
    load_factor = push.get("load_factor")
    if load_factor is not None:
        try:
            lf = int(load_factor)
            if lf > 0:
                item["load_factor"] = lf
        except (TypeError, ValueError):
            pass
    if push.get("group_ids"):
        item["group_ids"] = list(push["group_ids"])
    if proxy_obj and proxy_obj.get("proxy_key"):
        item["proxy_key"] = proxy_obj["proxy_key"]
    return item



def build_sub2api_export_bundle(
    auth_items: list[dict[str, Any]],
    settings: dict[str, Any] | None = None,
    *,
    proxy_url: str = "",
) -> dict[str, Any]:
    push = settings or get_sub2api_push_settings()
    proxies_by_key: dict[str, dict[str, Any]] = {}
    accounts: list[dict[str, Any]] = []
    for auth in auth_items:
        proxy_obj = None
        if proxy_url:
            proxy_obj = parse_sub2api_proxy(proxy_url)
        elif push.get("default_proxy"):
            proxy_obj = parse_sub2api_proxy(str(push["default_proxy"]))
        if proxy_obj and proxy_obj.get("proxy_key"):
            proxies_by_key[str(proxy_obj["proxy_key"])] = proxy_obj
        accounts.append(build_sub2api_account_from_cpa(auth, push, proxy_obj=proxy_obj))
    return {
        "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "proxies": list(proxies_by_key.values()),
        "accounts": accounts,
    }


def _response_preview(text: str, limit: int = 240) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    lower = raw[:240].lower()
    if "<!doctype" in lower or "<html" in lower or raw.lstrip().startswith("<"):
        return f"[html/xml body omitted, len={len(raw)}]"
    return raw[:limit]


class Sub2APIClient:
    """Minimal Sub2API admin client (requests, no curl_cffi dependency)."""

    def __init__(self, api_url: str, api_key: str, *, timeout: int = 30):
        self.api_url = _normalize_api_base(api_url)
        self.headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
        }
        self.timeout = max(5, int(timeout or 30))

    def _handle(self, response: requests.Response, success_codes: tuple[int, ...] = (200, 201, 204)) -> tuple[bool, Any]:
        if response.status_code in success_codes:
            if not response.text:
                return True, {}
            try:
                return True, response.json()
            except ValueError:
                return True, response.text
        error_msg = f"HTTP {response.status_code}"
        try:
            detail = response.json()
            if isinstance(detail, dict):
                error_msg = str(detail.get("message") or detail.get("error") or detail.get("detail") or error_msg)
            else:
                error_msg = f"{error_msg}: {_response_preview(str(detail))}"
        except Exception:
            error_msg = f"{error_msg}: {_response_preview(response.text)}"
        return False, error_msg

    def test_connection(self) -> tuple[bool, str]:
        url = f"{self.api_url}/api/v1/admin/accounts/data"
        try:
            response = requests.get(url, headers=self.headers, timeout=min(self.timeout, 15))
            if response.status_code in (200, 201, 204, 405):
                return True, "Sub2API connection OK"
            if response.status_code == 401:
                return False, "Connected but API key invalid (401)"
            if response.status_code == 403:
                return False, "Connected but API key forbidden (403)"
            return False, f"Unexpected status {response.status_code}: {_response_preview(response.text)}"
        except requests.RequestException as exc:
            return False, f"Connection failed: {exc}"

    def create_account(self, account_item: dict[str, Any]) -> tuple[bool, str]:
        """POST /api/v1/admin/accounts — fields match CreateAccountRequest in sub2api."""
        url = f"{self.api_url}/api/v1/admin/accounts"
        # proxy_key is for data-import only; create API uses proxy_id (optional)
        payload: dict[str, Any] = {
            "name": account_item.get("name"),
            "platform": account_item.get("platform"),
            "type": account_item.get("type"),
            "credentials": account_item.get("credentials") or {},
            "extra": account_item.get("extra") or {},
            "concurrency": int(account_item.get("concurrency") or 1),
            "priority": int(account_item.get("priority") if account_item.get("priority") is not None else 1),
            "rate_multiplier": float(
                account_item.get("rate_multiplier") if account_item.get("rate_multiplier") is not None else 1.0
            ),
            "auto_pause_on_expired": bool(account_item.get("auto_pause_on_expired", True)),
        }
        # top-level expires_at: unix seconds (CreateAccountRequest.ExpiresAt *int64)
        exp = account_item.get("expires_at")
        if exp is not None:
            try:
                exp_i = int(exp)
                if exp_i > 0:
                    payload["expires_at"] = exp_i
            except (TypeError, ValueError):
                pass
        if account_item.get("group_ids"):
            payload["group_ids"] = account_item["group_ids"]
        # load_factor top-level (CreateAccountRequest.LoadFactor *int)
        lf = account_item.get("load_factor")
        if lf is None and isinstance(account_item.get("extra"), dict):
            lf = account_item["extra"].get("load_factor")
        if lf is not None:
            try:
                lf_i = int(lf)
                if lf_i > 0:
                    payload["load_factor"] = lf_i
            except (TypeError, ValueError):
                pass
        if account_item.get("proxy_id") is not None:
            payload["proxy_id"] = account_item["proxy_id"]
        try:
            response = requests.post(url, json=payload, headers=self.headers, timeout=self.timeout)
            ok, result = self._handle(response, success_codes=(200, 201))
            if ok:
                return True, "Sub2API account created"
            return False, str(result)
        except requests.RequestException as exc:
            return False, f"Network request failed: {exc}"

    def import_account_bundle(self, bundle: dict[str, Any], *, skip_default_group_bind: bool = False) -> tuple[bool, str]:
        url = f"{self.api_url}/api/v1/admin/accounts/data"
        payload = {
            "data": {
                "type": "sub2api-data",
                "version": 1,
                **bundle,
            },
            "skip_default_group_bind": bool(skip_default_group_bind),
        }
        headers = dict(self.headers)
        headers["Idempotency-Key"] = f"grok-register-{int(time.time() * 1000)}"
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=self.timeout)
            ok, result = self._handle(response, success_codes=(200, 201))
            if ok:
                return True, "Sub2API account import succeeded"
            return False, str(result)
        except requests.RequestException as exc:
            return False, f"Network request failed: {exc}"

    def add_account_from_cpa(self, auth: dict[str, Any], settings: dict[str, Any] | None = None) -> tuple[bool, str]:
        push = settings or get_sub2api_push_settings()
        proxy_obj = None
        if push.get("default_proxy"):
            proxy_obj = parse_sub2api_proxy(str(push["default_proxy"]))
        account_item = build_sub2api_account_from_cpa(auth, push, proxy_obj=proxy_obj)
        # grok-register 只推 xAI 账号：Sub2 平台固定 grok（避免配置残留 openai）
        if str(account_item.get("type") or "oauth").lower() != "apikey":
            account_item["platform"] = "grok"
        else:
            # API Key 账号也用 grok 平台（sub2api: Grok → API Key）
            account_item["platform"] = "grok"
        # Prefer create API when we have enough credentials
        ok, msg = self.create_account(account_item)
        if ok:
            return True, msg

        # Fallback to open-cpa style import bundle (supports proxy_key)
        bundle = build_sub2api_export_bundle([auth], push)
        import_ok, import_msg = self.import_account_bundle(
            bundle,
            skip_default_group_bind=not bool(push.get("group_ids")),
        )
        if import_ok:
            return True, import_msg
        return False, f"create failed: {msg}; import failed: {import_msg}"


def write_local_sub2api_export(
    auth: dict[str, Any],
    config: dict[str, Any],
    *,
    log: LogFn | None = None,
) -> dict[str, Any]:
    log = log or _noop_log
    push = get_sub2api_push_settings(config)
    out_dir = Path(
        str(config.get("sub2api_local_export_dir") or config.get("sub2api_export_dir") or "./sub2api_exports")
    ).expanduser()
    if not out_dir.is_absolute():
        # Prefer next to cpa worker / cwd resolved by caller
        out_dir = (Path.cwd() / out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    email = str(auth.get("email") or "unknown").strip() or "unknown"
    safe = re.sub(r"[^a-zA-Z0-9@._-]+", "-", email).strip("-") or "unknown"
    path = out_dir / f"sub2api-account-xai-{safe}.json"
    bundle = build_sub2api_export_bundle([auth], push)
    path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    log(f"[sub2api] local export -> {path}")
    return {"ok": True, "path": str(path), "bundle": bundle}


def upload_cpa_auth_to_sub2api(
    path_value: str | Path | dict[str, Any] | None,
    config: dict[str, Any],
    log: LogFn | None = None,
) -> dict[str, Any]:
    """Upload one CPA auth to Sub2API (optional local export first)."""
    log = log or _noop_log

    upload_enabled = bool(config.get("sub2api_upload_enabled", False))
    export_enabled = bool(config.get("sub2api_export_enabled", False))
    # Back-compat: older hook used sub2api_export_enabled as master switch
    if not upload_enabled and not export_enabled:
        return {"ok": False, "skipped": True, "reason": "disabled"}

    auth, path, err = _load_cpa_auth(path_value)
    if auth is None:
        return {"ok": False, "error": err or "load_failed", "path": str(path or "")}

    result: dict[str, Any] = {"path": str(path or ""), "email": str(auth.get("email") or "")}

    if export_enabled and bool(config.get("sub2api_local_export", True)):
        try:
            local = write_local_sub2api_export(auth, config, log=log)
            result["local_export"] = local
        except Exception as exc:  # noqa: BLE001
            log(f"[sub2api] local export failed: {exc}")
            result["local_export_error"] = str(exc)

    if not upload_enabled:
        # export-only mode
        if result.get("local_export", {}).get("ok"):
            return {"ok": True, "skipped_upload": True, **result}
        if export_enabled:
            return {"ok": False, "error": result.get("local_export_error") or "export_failed", **result}
        return {"ok": False, "skipped": True, "reason": "upload_disabled", **result}

    api_base = _api_base(config)
    key = _api_key(config)
    if not api_base:
        return {"ok": False, "error": "missing_sub2api_api_base", **result}
    if not key:
        return {"ok": False, "error": "missing_sub2api_api_key", **result}

    timeout = _as_int(config.get("sub2api_upload_timeout", 30), 30, 5, 180)
    retries = _as_int(config.get("sub2api_upload_retries", 3), 3, 1, 10)
    client = Sub2APIClient(api_base, key, timeout=timeout)
    settings = get_sub2api_push_settings(config)
    # 再次保证 xAI → grok
    settings = {**settings, "platform": "grok"}
    log(
        f"[sub2api] push settings platform={settings.get('platform')} "
        f"type={settings.get('account_type')} concurrency={settings.get('concurrency')}"
    )

    last_error = "upload_failed"
    for attempt in range(1, retries + 1):
        ok, msg = client.add_account_from_cpa(auth, settings)
        if ok:
            log(f"[sub2api] uploaded -> {auth.get('email') or path} ({msg})")
            return {"ok": True, "message": msg, **result}
        last_error = str(msg)
        log(f"[sub2api] upload retry {attempt}/{retries}: {last_error}")
        if attempt < retries:
            time.sleep(min(2 * attempt, 8))
    return {"ok": False, "error": last_error, **result}


def export_after_cpa_result(
    result: dict[str, Any],
    config: dict[str, Any] | None = None,
    log_callback: LogFn | None = None,
) -> dict[str, Any]:
    """Hook used by cpa_export.export_cpa_xai_for_account after successful mint."""
    cfg = config or {}
    log = log_callback or _noop_log
    if not (
        bool(cfg.get("sub2api_upload_enabled", False))
        or bool(cfg.get("sub2api_export_enabled", False))
    ):
        return {"ok": False, "skipped": True, "reason": "disabled"}

    path = result.get("cpa_path") or result.get("path")
    # Optional health gate: reuse cloud health failure if present
    cloud = result.get("cloud_cpa_upload") or {}
    if cloud.get("health_failed"):
        log("[sub2api] skip push because CPA health check failed")
        return {
            "ok": False,
            "skipped": True,
            "reason": "health_failed",
            "error": cloud.get("error") or cloud.get("message") or "health_failed",
        }

    return upload_cpa_auth_to_sub2api(path, cfg, log=log)
