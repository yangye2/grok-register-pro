"""Mail helpers (MoeMail / YYDS / GPTMail / CFMail / DuckMail) + proxy normalization.

Kept intentionally small: only the pieces used by ``grok_build_adapter``
(and optional admin proxy smoke tests). The legacy full-session
``email_registration`` flow was removed in favor of grok-build-auth.

Providers:
  - moemail  — beilunyang/moemail style API (``/api/emails/...``)
  - yyds     — vip.215.im / maliapi.215.im YYDS Mail (``/v1/accounts`` …)
  - gptmail  — mail.chatgpt.org.uk GPTMail (``/api/generate-email`` …)
  - cfmail   — dreamhunter2333/cloudflare_temp_email (``/api/new_address`` …)
  - duckmail — DuckMail public API (``https://api.duckmail.sbs``)
"""
from __future__ import annotations

import email
import os
import random
import re
import secrets
import string
from email import policy
from typing import Any
from urllib.parse import quote, unquote, urlparse, urlunparse

import httpx

from register_pro_config import (
    MOEMAIL_API_KEY,
    MOEMAIL_BASE_URL,
    MOEMAIL_DOMAIN,
    MOEMAIL_EXPIRY_MS,
    XAI_PROXY,
    XAI_PROXY_PASSWORD,
    XAI_PROXY_USERNAME,
)

# Official YYDS Mail API host (docs: https://vip.215.im/docs).
YYDS_DEFAULT_BASE_URL = "https://maliapi.215.im"
YYDS_DEFAULT_DOMAIN = ""  # must be chosen from GET /v1/domains or admin config

# Official GPTMail host (docs: https://mail.chatgpt.org.uk/zh/api/).
GPTMAIL_DEFAULT_BASE_URL = "https://mail.chatgpt.org.uk"
# Docs historically mentioned a public test key ``gpt-test``, but it has a daily
# quota and silently masks "missing API key" misconfig. Do not auto-fallback.

# Cloudflare Temp Email (https://github.com/dreamhunter2333/cloudflare_temp_email)
# Self-hosted Workers URL; demo host only for docs/default placeholder.
CFMAIL_DEFAULT_BASE_URL = "https://temp-email-api.awsl.uk"

# DuckMail public API (docs: https://raw.githubusercontent.com/MoonWeSif/DuckMail/main/public/llm-api-docs.txt)
DUCKMAIL_DEFAULT_BASE_URL = "https://api.duckmail.sbs"


def _headers(api_key: str | None = None) -> dict[str, str]:
    key = api_key or MOEMAIL_API_KEY
    if not key:
        return {}
    return {"X-API-Key": key}


def normalize_mail_provider(provider: str | None, *, base_url: str | None = None) -> str:
    """Return ``moemail`` | ``yyds`` | ``gptmail`` | ``cfmail`` | ``duckmail`` | ``outmail``.

    Infer from base_url when provider is empty.
    """
    p = (provider or "").strip().lower()
    if p in {"outmail", "outlook", "outlookemail", "outlook-mail", "outlook_mail"}:
        return "outmail"
    if p in {"yyds", "yydsmail", "yyds_mail", "vip215", "215", "maliapi"}:
        return "yyds"
    if p in {
        "gptmail",
        "gpt-mail",
        "gpt_mail",
        "chatgptmail",
        "chatgpt-mail",
        "mail.chatgpt",
        "chatgpt.org.uk",
    }:
        return "gptmail"
    if p in {
        "cfmail",
        "cf-mail",
        "cf_mail",
        "cloudflare",
        "cloudflare_temp_email",
        "cloudflare-temp-email",
        "temp-email",
        "tempmail_cf",
        "awsl",
    }:
        return "cfmail"
    if p in {
        "duckmail",
        "duck-mail",
        "duck_mail",
        "duck",
        "api.duckmail",
        "duckmail.sbs",
    }:
        return "duckmail"
    if p in {"moemail", "moe", "moe-mail"}:
        return "moemail"
    base = (base_url or "").strip().lower()
    if any(x in base for x in ("maliapi.215.im", "vip.215.im", "215.im/v1", "yyds")):
        return "yyds"
    if any(
        x in base
        for x in (
            "mail.chatgpt.org.uk",
            "chatgpt.org.uk",
            "gptmail",
        )
    ):
        return "gptmail"
    if any(
        x in base
        for x in (
            "temp-email-api",
            "temp-email",
            "cloudflare_temp_email",
            "awsl.uk",
            "/api/new_address",
            "/open_api/settings",
        )
    ):
        return "cfmail"
    if any(x in base for x in ("duckmail.sbs", "api.duckmail", "duckmail")):
        return "duckmail"
    if any(x in base for x in ("outmail", "/api/accounts", "temp-emails")):
        # weak heuristic; prefer explicit provider=outmail
        pass
    return "moemail"


def normalize_yyds_base_url(base_url: str | None = None) -> str:
    """Normalize user input (docs URL / trailing /v1) to API origin."""
    raw = (base_url or "").strip()
    if not raw:
        return YYDS_DEFAULT_BASE_URL
    # Common mistakes: paste docs portal or bare path.
    lower = raw.lower()
    if "vip.215.im" in lower and "maliapi" not in lower:
        return YYDS_DEFAULT_BASE_URL
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    origin = f"{parsed.scheme or 'https'}://{parsed.netloc}".rstrip("/")
    if not parsed.netloc:
        return YYDS_DEFAULT_BASE_URL
    # Strip accidental /v1 /docs suffixes from path-only pastes handled above.
    return origin or YYDS_DEFAULT_BASE_URL


def normalize_gptmail_base_url(base_url: str | None = None) -> str:
    """Normalize docs / language path pastes to GPTMail origin."""
    raw = (base_url or "").strip()
    if not raw:
        return GPTMAIL_DEFAULT_BASE_URL
    lower = raw.lower()
    if "chatgpt.org.uk" in lower or "gptmail" in lower:
        # Always pin to official origin (docs may be /zh/api, /api, etc.).
        return GPTMAIL_DEFAULT_BASE_URL
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    origin = f"{parsed.scheme or 'https'}://{parsed.netloc}".rstrip("/")
    return origin or GPTMAIL_DEFAULT_BASE_URL


def normalize_cfmail_base_url(base_url: str | None = None) -> str:
    """Normalize Cloudflare Temp Email Workers / Pages URL to API origin.

    Accepts worker host, docs host, or accidental ``/api`` / ``/admin`` suffixes.
    Users should deploy their own Workers URL; demo host is only a fallback.
    """
    raw = (base_url or "").strip()
    if not raw:
        return CFMAIL_DEFAULT_BASE_URL
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    origin = f"{parsed.scheme or 'https'}://{parsed.netloc}".rstrip("/")
    if not parsed.netloc:
        return CFMAIL_DEFAULT_BASE_URL
    return origin or CFMAIL_DEFAULT_BASE_URL


def _cfmail_headers(
    *,
    api_key: str | None = None,
    site_password: str | None = None,
    content_type: bool = False,
) -> dict[str, str]:
    """Build CF Temp Email headers.

    - Address JWT (from create / login): ``Authorization: Bearer <jwt>``
    - Admin password (create via admin API): ``x-admin-auth``
    - Optional private-site password: ``x-custom-auth``
    """
    headers: dict[str, str] = {}
    key = (api_key or "").strip()
    if key:
        # Admin create uses x-admin-auth; mailbox read uses Bearer address JWT.
        # We accept either: when key looks like a JWT, send Bearer; otherwise
        # treat as admin password.
        parts = key.split(".")
        if len(parts) == 3 and all(parts):
            headers["Authorization"] = f"Bearer {key}"
        else:
            headers["x-admin-auth"] = key
    site = (site_password or "").strip()
    if site:
        headers["x-custom-auth"] = site
    if content_type:
        headers["Content-Type"] = "application/json"
    return headers


def normalize_proxy_config(
    proxy: str | None = None,
    *,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any] | None:
    """Normalize a proxy URL into curl/httpx-friendly forms."""
    raw = (proxy or XAI_PROXY or "").strip()
    if not raw:
        return None
    env_user = XAI_PROXY_USERNAME
    env_pass = XAI_PROXY_PASSWORD
    lower = raw.lower()
    if lower.startswith("soket5://"):
        raw = "socks5://" + raw.split("://", 1)[1]
    elif lower.startswith("socket5://"):
        raw = "socks5://" + raw.split("://", 1)[1]
    elif "://" not in raw:
        raw = f"http://{raw}"

    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https", "socks5", "socks5h"}:
        raise ValueError("proxy scheme must be http, https, socks5, or socks5h")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("proxy must include host and port")
    try:
        port = parsed.port
    except ValueError as e:
        raise ValueError("proxy port is invalid") from e
    proxy_user = (username if username is not None else "").strip()
    proxy_pass = (password if password is not None else "").strip()
    if not proxy_user and username is None:
        proxy_user = env_user
    if not proxy_pass and password is None:
        proxy_pass = env_pass
    if not proxy_user and parsed.username:
        proxy_user = unquote(parsed.username)
    if not proxy_pass and parsed.password:
        proxy_pass = unquote(parsed.password)

    if proxy_pass and not proxy_user:
        raise ValueError("proxy username is required when proxy password is set")

    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port is not None:
        host = f"{host}:{port}"
    proxy_no_auth = urlunparse(
        (
            parsed.scheme,
            host,
            parsed.path or "",
            parsed.params or "",
            parsed.query or "",
            parsed.fragment or "",
        )
    )
    proxy_auth = (proxy_user, proxy_pass) if proxy_user else None
    proxy_with_auth = proxy_no_auth
    if proxy_user:
        auth = quote(proxy_user, safe="")
        if proxy_pass:
            auth = f"{auth}:{quote(proxy_pass, safe='')}"
        proxy_with_auth = urlunparse(
            (
                parsed.scheme,
                f"{auth}@{host}",
                parsed.path or "",
                parsed.params or "",
                parsed.query or "",
                parsed.fragment or "",
            )
        )
    return {
        "proxy": proxy_with_auth,
        "curl_proxy": proxy_no_auth,
        "proxy_auth": proxy_auth,
    }


# Back-compat alias used by older adapter code paths.
_normalize_proxy_config = normalize_proxy_config


def _extract_codes_and_links(text: str) -> dict[str, list[str]]:
    codes = sorted(set(re.findall(r"(?<!\d)\d{6,8}(?!\d)", text or "")))
    links = sorted(set(re.findall(r"https?://[^\s\"'<>)]+", text or "")))
    return {"codes": codes, "links": links}


def _moemail_infer_domain(
    client: httpx.Client,
    base: str,
    *,
    api_key: str | None = None,
) -> str | None:
    try:
        resp = client.get(f"{base}/api/emails", headers=_headers(api_key))
        if resp.status_code >= 400:
            return None
        data = resp.json()
    except Exception:
        return None
    emails = data.get("emails") if isinstance(data, dict) else None
    if not isinstance(emails, list):
        return None
    for item in emails:
        if not isinstance(item, dict):
            continue
        address = item.get("email") or item.get("address")
        if isinstance(address, str) and "@" in address:
            return address.rsplit("@", 1)[1].strip() or None
    return None


def moemail_create_mailbox(
    *,
    name: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    proxy: str | None = None,  # accepted for API compat; unused by httpx path
    proxy_username: str | None = None,
    proxy_password: str | None = None,
) -> dict[str, Any]:
    if not (api_key or MOEMAIL_API_KEY):
        raise ValueError(
            "MoeMail API key missing. Set GROK2API_MOEMAIL_API_KEY or pass api_key."
        )

    base = (base_url or MOEMAIL_BASE_URL).rstrip("/")
    # MoeMail only accepts official presets: 3600000 / 86400000 / 259200000 / 0.
    # Do not use `expiry_ms or default` — permanent is 0 and must be preserved.
    _OFFICIAL = {3_600_000, 86_400_000, 259_200_000, 0}
    if expiry_ms is None:
        chosen = int(MOEMAIL_EXPIRY_MS)
    else:
        chosen = int(expiry_ms)
    if chosen not in _OFFICIAL:
        # snap to nearest timed preset (never invent permanent from bad input)
        timed = (3_600_000, 86_400_000, 259_200_000)
        chosen = min(timed, key=lambda p: abs(p - chosen))
    payload: dict[str, Any] = {
        "expiryTime": chosen,
        "domain": domain or MOEMAIL_DOMAIN,
    }
    if name:
        payload["name"] = name

    with httpx.Client(timeout=30.0) as client:
        headers = {**_headers(api_key), "Content-Type": "application/json"}
        resp = client.post(f"{base}/api/emails/generate", json=payload, headers=headers)
        if resp.status_code == 400 and "域名" in resp.text and not domain:
            inferred = _moemail_infer_domain(client, base, api_key=api_key)
            if inferred and inferred != payload.get("domain"):
                payload["domain"] = inferred
                resp = client.post(
                    f"{base}/api/emails/generate",
                    json=payload,
                    headers=headers,
                )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"MoeMail create failed {resp.status_code}: {resp.text[:500]}"
            )
        data = resp.json()

    email_id = data.get("id") or data.get("emailId")
    address = data.get("email") or data.get("address")
    if not email_id or not address:
        raise RuntimeError(f"Unexpected MoeMail create response: {data}")
    return {"id": str(email_id), "email": str(address), "raw": data}


def moemail_fetch_messages(
    email_id: str,
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    include_details: bool = True,
) -> list[dict[str, Any]]:
    if not email_id:
        return []
    if not (api_key or MOEMAIL_API_KEY):
        return []

    base = (base_url or MOEMAIL_BASE_URL).rstrip("/")
    with httpx.Client(timeout=30.0) as client:
        resp = client.get(f"{base}/api/emails/{email_id}", headers=_headers(api_key))
        if resp.status_code >= 400:
            raise RuntimeError(
                f"MoeMail list failed {resp.status_code}: {resp.text[:500]}"
            )
        data = resp.json()
        messages = data.get("messages") if isinstance(data, dict) else None
        if not isinstance(messages, list):
            return []

        out: list[dict[str, Any]] = []
        for raw in messages[:20]:
            if not isinstance(raw, dict):
                continue
            item = dict(raw)
            msg_id = item.get("id") or item.get("messageId")
            if include_details and msg_id:
                detail = client.get(
                    f"{base}/api/emails/{email_id}/{msg_id}",
                    headers=_headers(api_key),
                )
                if detail.status_code == 200:
                    d = detail.json()
                    msg = d.get("message") if isinstance(d, dict) else None
                    if isinstance(msg, dict):
                        item.update(msg)
            text = "\n".join(
                str(item.get(k) or "")
                for k in ("subject", "content", "html", "from_address", "from")
            )
            item["extracted"] = _extract_codes_and_links(text)
            out.append(item)
        return out


# Private aliases matching historical names used by grok_build_adapter.
_moemail_create_mailbox = moemail_create_mailbox
_moemail_fetch_messages = moemail_fetch_messages


def yyds_create_mailbox(
    *,
    name: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,  # accepted for API compat; YYDS temp mail is ~24h
    api_key: str | None = None,
    base_url: str | None = None,
    proxy: str | None = None,
    proxy_username: str | None = None,
    proxy_password: str | None = None,
) -> dict[str, Any]:
    """Create a temporary inbox on YYDS Mail (https://vip.215.im/docs)."""
    key = (api_key or MOEMAIL_API_KEY or "").strip()
    if not key:
        raise ValueError(
            "YYDS Mail API key missing. Set GROK2API_MOEMAIL_API_KEY / api_key "
            "(X-API-Key, usually starts with AC-)."
        )
    base = normalize_yyds_base_url(base_url or MOEMAIL_BASE_URL)
    # Never fall back to MOEMAIL_DOMAIN (MoeMail default / example.com). Empty
    # means auto: randomly pick a healthy public domain from GET /v1/domains.
    dom = (domain or "").strip().lstrip("@").strip(".")
    if not dom:
        dom = yyds_pick_domain(api_key=key, base_url=base) or ""
    if not dom:
        raise ValueError(
            "YYDS Mail domain auto-fetch failed. Leave domain empty for random "
            "public domain, or set an explicit domain from GET /v1/domains."
        )
    local = (name or "").strip().lower() or None
    payload: dict[str, Any] = {"domain": dom}
    if local:
        payload["localPart"] = local

    with httpx.Client(timeout=30.0) as client:
        headers = {**_headers(key), "Content-Type": "application/json"}
        resp = client.post(f"{base}/v1/accounts", json=payload, headers=headers)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"YYDS create failed {resp.status_code}: {resp.text[:500]}"
            )
        data = resp.json()

    # Envelope: { success, data: { id, address, token, ... } }
    body = data.get("data") if isinstance(data, dict) and "data" in data else data
    if not isinstance(body, dict):
        raise RuntimeError(f"Unexpected YYDS create response: {data}")
    email_id = body.get("id") or body.get("inboxId") or body.get("accountId")
    address = body.get("address") or body.get("email")
    token = body.get("token") or body.get("tempToken") or ""
    if not email_id or not address:
        raise RuntimeError(f"Unexpected YYDS create response: {data}")
    return {
        "id": str(email_id),
        "email": str(address),
        "token": str(token or ""),
        "provider": "yyds",
        "raw": data,
        # Keep expiry_ms for logging only (service is ~24h temp).
        "expiry_ms": 86_400_000 if expiry_ms is None else int(expiry_ms),
    }


def yyds_list_domains(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    public_only: bool = True,
    ready_only: bool = True,
) -> list[str]:
    """List usable domains from YYDS catalog (``GET /v1/domains``)."""
    key = (api_key or MOEMAIL_API_KEY or "").strip()
    base = normalize_yyds_base_url(base_url or MOEMAIL_BASE_URL)
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(f"{base}/v1/domains", headers=_headers(key) if key else {})
            if resp.status_code >= 400:
                return []
            data = resp.json()
    except Exception:
        return []
    items = data
    if isinstance(data, dict):
        items = data.get("data") or data.get("domains") or data.get("items") or []
    if not isinstance(items, list):
        return []
    preferred: list[str] = []
    fallback: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("domain") or item.get("name") or item.get("host")
        if not isinstance(name, str) or not name.strip():
            continue
        name = name.strip().lstrip("@").strip(".")
        if not name or name in seen:
            continue
        if public_only and item.get("isPublic") is False:
            continue
        if ready_only and (
            item.get("receivingReady") is False or item.get("isMxValid") is False
        ):
            continue
        seen.add(name)
        if item.get("wildcardMxValid") is True or item.get("wildcard_mx_valid") is True:
            preferred.append(name)
        else:
            fallback.append(name)
    # Prefer wildcard-MX domains first so random pick weights healthier ones.
    return preferred + fallback


def yyds_pick_domain(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
) -> str | None:
    """Randomly pick a healthy public domain from YYDS catalog.

    Catalog order is preferred (wildcard MX) then fallback. Randomize across
    the full usable set so batch registration rotates domains.
    Empty admin domain => call this.
    """
    domains = yyds_list_domains(api_key=api_key, base_url=base_url)
    if not domains:
        return None
    return random.choice(domains)


def yyds_fetch_messages(
    email_id: str,
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    include_details: bool = True,
    address: str | None = None,
    token: str | None = None,
) -> list[dict[str, Any]]:
    """List (+ optionally detail) messages for a YYDS inbox."""
    if not email_id and not address:
        return []
    key = (api_key or MOEMAIL_API_KEY or "").strip()
    base = normalize_yyds_base_url(base_url or MOEMAIL_BASE_URL)
    headers = _headers(key) if key else {}
    if token and not key:
        headers = {"Authorization": f"Bearer {token}"}
    elif token and key:
        # Prefer API key; keep bearer as extra only when key missing.
        pass

    with httpx.Client(timeout=30.0) as client:
        # Prefer canonical inbox path when id is known; fall back to address query.
        messages: list[Any] = []
        if email_id:
            resp = client.get(
                f"{base}/v1/inboxes/{email_id}/messages",
                headers=headers,
                params={"limit": 20},
            )
            if resp.status_code >= 400 and address:
                resp = client.get(
                    f"{base}/v1/messages",
                    headers=headers,
                    params={"address": address, "limit": 20},
                )
            elif resp.status_code >= 400:
                raise RuntimeError(
                    f"YYDS list failed {resp.status_code}: {resp.text[:500]}"
                )
        else:
            resp = client.get(
                f"{base}/v1/messages",
                headers=headers,
                params={"address": address, "limit": 20},
            )
            if resp.status_code >= 400:
                raise RuntimeError(
                    f"YYDS list failed {resp.status_code}: {resp.text[:500]}"
                )

        data = resp.json() if resp.content else {}
        body = data.get("data") if isinstance(data, dict) and "data" in data else data
        if isinstance(body, dict):
            messages = body.get("messages") or body.get("items") or []
        elif isinstance(body, list):
            messages = body
        if not isinstance(messages, list):
            return []

        out: list[dict[str, Any]] = []
        for raw in messages[:20]:
            if not isinstance(raw, dict):
                continue
            item = dict(raw)
            msg_id = item.get("id") or item.get("messageId")
            if include_details and msg_id:
                params = {"address": address} if address else None
                detail = client.get(
                    f"{base}/v1/messages/{msg_id}",
                    headers=headers,
                    params=params,
                )
                if detail.status_code == 200:
                    d = detail.json()
                    msg = d.get("data") if isinstance(d, dict) and "data" in d else d
                    if isinstance(msg, dict):
                        # Some envelopes nest { message: {...} }
                        if isinstance(msg.get("message"), dict):
                            item.update(msg["message"])
                        else:
                            item.update(msg)
            # Flatten from.address for code extractors used by the adapter.
            from_obj = item.get("from")
            if isinstance(from_obj, dict):
                item.setdefault("from_address", from_obj.get("address") or "")
                item.setdefault("from", from_obj.get("address") or from_obj.get("name") or "")
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
            item["extracted"] = _extract_codes_and_links(text)
            # Surface server-side OTP when present.
            vc = item.get("verificationCode")
            if vc and isinstance(item.get("extracted"), dict):
                codes = list(item["extracted"].get("codes") or [])
                s = str(vc).strip()
                if s and s not in codes:
                    codes.insert(0, s)
                    item["extracted"]["codes"] = codes
            out.append(item)
        return out


def gptmail_create_mailbox(
    *,
    name: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,  # accepted for API compat; GPTMail retains ~24h
    api_key: str | None = None,
    base_url: str | None = None,
    proxy: str | None = None,
    proxy_username: str | None = None,
    proxy_password: str | None = None,
) -> dict[str, Any]:
    """Create a temporary inbox on GPTMail (https://mail.chatgpt.org.uk/zh/api/)."""
    key = (api_key or MOEMAIL_API_KEY or "").strip()
    if not key:
        raise ValueError(
            "GPTMail API key missing. Set GROK2API_GPTMAIL_API_KEY or pass api_key."
        )
    base = normalize_gptmail_base_url(base_url or MOEMAIL_BASE_URL)
    # Never fall back to MOEMAIL_DOMAIN (MoeMail default). Empty => GPTMail
    # random generate / public domain pick.
    dom = (domain or "").strip().lstrip("@").strip(".")
    pre = (name or "").strip().lower() or None

    # Prefer server-side generate so we get a real active domain when none given.
    # Docs: GET /api/generate-email random; POST with {prefix, domain}.
    with httpx.Client(timeout=30.0) as client:
        headers = {**_headers(key), "Content-Type": "application/json"}
        if pre or dom:
            payload: dict[str, Any] = {}
            if pre:
                payload["prefix"] = pre
            if dom:
                payload["domain"] = dom
            resp = client.post(
                f"{base}/api/generate-email",
                json=payload,
                headers=headers,
            )
        else:
            resp = client.get(f"{base}/api/generate-email", headers=headers)

        if resp.status_code >= 400:
            # Auth / quota failures must surface — composed addresses still need
            # a valid key to poll /api/emails.
            err_l = (resp.text or "").lower()
            if resp.status_code in (401, 403) or (
                "api key" in err_l
                or "api_key" in err_l
                or "无效" in (resp.text or "")
                and "key" in err_l
            ):
                raise RuntimeError(
                    f"GPTMail create failed {resp.status_code}: {resp.text[:500]}"
                )
            # Retry without domain, then compose prefix@public-domain.
            # Docs allow skipping generate when a public domain is known.
            if pre and dom:
                resp2 = client.post(
                    f"{base}/api/generate-email",
                    json={"prefix": pre},
                    headers=headers,
                )
                if resp2.status_code < 400:
                    resp = resp2
                elif resp2.status_code in (401, 403):
                    raise RuntimeError(
                        f"GPTMail create failed {resp2.status_code}: {resp2.text[:500]}"
                    )
                else:
                    picked = gptmail_pick_domain(api_key=key, base_url=base) or dom
                    if pre and picked:
                        address = f"{pre}@{picked}"
                        return {
                            "id": address,
                            "email": address,
                            "token": "",
                            "provider": "gptmail",
                            "raw": {
                                "composed": True,
                                "error": resp.text[:300],
                                "domain": picked,
                            },
                            "expiry_ms": 86_400_000
                            if expiry_ms is None
                            else int(expiry_ms),
                        }
            elif pre and resp.status_code not in (401, 403):
                picked = dom or gptmail_pick_domain(api_key=key, base_url=base)
                if picked:
                    address = f"{pre}@{picked}"
                    return {
                        "id": address,
                        "email": address,
                        "token": "",
                        "provider": "gptmail",
                        "raw": {
                            "composed": True,
                            "error": resp.text[:300],
                            "domain": picked,
                        },
                        "expiry_ms": 86_400_000
                        if expiry_ms is None
                        else int(expiry_ms),
                    }
            if resp.status_code >= 400:
                raise RuntimeError(
                    f"GPTMail create failed {resp.status_code}: {resp.text[:500]}"
                )

        data = resp.json() if resp.content else {}

    body = data.get("data") if isinstance(data, dict) and "data" in data else data
    if not isinstance(body, dict):
        raise RuntimeError(f"Unexpected GPTMail create response: {data}")
    address = body.get("email") or body.get("address")
    if not address or "@" not in str(address):
        raise RuntimeError(f"Unexpected GPTMail create response: {data}")
    address = str(address).strip()
    # GPTMail uses the email address itself as the mailbox key for list/clear.
    return {
        "id": address,
        "email": address,
        "token": "",
        "provider": "gptmail",
        "raw": data,
        "expiry_ms": 86_400_000 if expiry_ms is None else int(expiry_ms),
    }


def gptmail_pick_domain(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
) -> str | None:
    """Pick an active public domain from GPTMail catalog."""
    base = normalize_gptmail_base_url(base_url or MOEMAIL_BASE_URL)
    key = (api_key or MOEMAIL_API_KEY or "").strip()
    try:
        with httpx.Client(timeout=20.0) as client:
            # Public domain list does not require a key.
            resp = client.get(
                f"{base}/api/domains/public",
                headers=_headers(key) if key else {},
            )
            if resp.status_code >= 400:
                return None
            data = resp.json()
    except Exception:
        return None
    body = data.get("data") if isinstance(data, dict) and "data" in data else data
    items = body.get("domains") if isinstance(body, dict) else body
    if not isinstance(items, list):
        return None
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("domain_name") or item.get("domain") or item.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        if item.get("is_active") in (0, False, "0", "false"):
            continue
        return name.strip().lstrip("@").strip(".")
    return None


def gptmail_fetch_messages(
    email_id: str,
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    include_details: bool = True,
    address: str | None = None,
    token: str | None = None,
) -> list[dict[str, Any]]:
    """List messages for a GPTMail inbox.

    GPTMail keys mailboxes by the full email address (``?email=``).
    ``email_id`` may be either the address or a message id when fetching detail.
    """
    addr = (address or email_id or "").strip()
    if not addr or "@" not in addr:
        # If only a message id was passed, we cannot list; need address.
        if address and "@" in address:
            addr = address.strip()
        else:
            return []
    key = (api_key or MOEMAIL_API_KEY or "").strip()
    if not key:
        raise ValueError(
            "GPTMail API key missing. Set GROK2API_GPTMAIL_API_KEY or pass api_key."
        )
    base = normalize_gptmail_base_url(base_url or MOEMAIL_BASE_URL)
    headers = _headers(key)

    with httpx.Client(timeout=30.0) as client:
        resp = client.get(
            f"{base}/api/emails",
            headers=headers,
            params={"email": addr},
        )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"GPTMail list failed {resp.status_code}: {resp.text[:500]}"
            )
        data = resp.json() if resp.content else {}
        body = data.get("data") if isinstance(data, dict) and "data" in data else data
        messages: list[Any] = []
        if isinstance(body, dict):
            messages = body.get("emails") or body.get("messages") or body.get("items") or []
        elif isinstance(body, list):
            messages = body
        if not isinstance(messages, list):
            return []

        out: list[dict[str, Any]] = []
        for raw in messages[:20]:
            if not isinstance(raw, dict):
                continue
            item = dict(raw)
            msg_id = item.get("id") or item.get("messageId") or item.get("email_id")
            # List payload often already includes content; detail is optional.
            if include_details and msg_id and not (
                item.get("content") or item.get("html_content") or item.get("html")
            ):
                detail = client.get(
                    f"{base}/api/email/{msg_id}",
                    headers=headers,
                )
                if detail.status_code == 200:
                    d = detail.json() if detail.content else {}
                    msg = d.get("data") if isinstance(d, dict) and "data" in d else d
                    if isinstance(msg, dict):
                        if isinstance(msg.get("email"), dict):
                            item.update(msg["email"])
                        elif isinstance(msg.get("message"), dict):
                            item.update(msg["message"])
                        else:
                            item.update(msg)
            # Normalize field names for shared code extractors.
            if item.get("html_content") and not item.get("html"):
                item["html"] = item.get("html_content")
            if item.get("content") and not item.get("text"):
                item["text"] = item.get("content")
            if item.get("from_address") and not item.get("from"):
                item["from"] = item.get("from_address")
            text = "\n".join(
                str(item.get(k) or "")
                for k in (
                    "subject",
                    "content",
                    "text",
                    "html",
                    "html_content",
                    "from_address",
                    "from",
                )
            )
            item["extracted"] = _extract_codes_and_links(text)
            out.append(item)
        return out


def cfmail_list_domains(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    site_password: str | None = None,
) -> list[str]:
    """List domains from CF Temp Email public settings (``GET /open_api/settings``)."""
    base = normalize_cfmail_base_url(base_url or MOEMAIL_BASE_URL)
    headers = _cfmail_headers(api_key=api_key, site_password=site_password)
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(f"{base}/open_api/settings", headers=headers)
            if resp.status_code >= 400:
                # Older deploys may expose domains only on authenticated settings.
                resp2 = client.get(f"{base}/api/settings", headers=headers)
                if resp2.status_code >= 400:
                    return []
                data = resp2.json() if resp2.content else {}
            else:
                data = resp.json() if resp.content else {}
    except Exception:
        return []
    body = data.get("data") if isinstance(data, dict) and "data" in data else data
    if not isinstance(body, dict):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for key in (
        "defaultDomains",
        "default_domains",
        "domains",
        "randomSubdomainDomains",
        "random_subdomain_domains",
    ):
        items = body.get(key)
        if isinstance(items, str):
            items = [x.strip() for x in items.split(",") if x.strip()]
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                name = item.get("domain") or item.get("name") or item.get("value")
            else:
                name = item
            if not isinstance(name, str) or not name.strip():
                continue
            name = name.strip().lstrip("@").strip(".")
            if not name or name in seen:
                continue
            seen.add(name)
            out.append(name)
    return out


def cfmail_pick_domain(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    site_password: str | None = None,
) -> str | None:
    """Randomly pick a domain from CF Temp Email public settings."""
    domains = cfmail_list_domains(
        api_key=api_key, base_url=base_url, site_password=site_password
    )
    if not domains:
        return None
    return random.choice(domains)


def _cfmail_parse_raw_rfc822(raw: str) -> dict[str, Any]:
    """Best-effort RFC822 parse for CF Temp Email raw mail bodies."""
    out: dict[str, Any] = {}
    text = (raw or "").strip()
    if not text:
        return out
    try:
        msg = email.message_from_string(text, policy=policy.default)
    except Exception:
        out["text"] = text[:8000]
        return out
    out["subject"] = str(msg.get("subject") or "")
    out["from"] = str(msg.get("from") or "")
    out["to"] = str(msg.get("to") or "")
    texts: list[str] = []
    htmls: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            disp = str(part.get_content_disposition() or "").lower()
            if disp == "attachment":
                continue
            try:
                payload = part.get_content()
            except Exception:
                try:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        payload = payload.decode(
                            part.get_content_charset() or "utf-8",
                            errors="replace",
                        )
                except Exception:
                    payload = None
            if not isinstance(payload, str):
                continue
            if ctype == "text/html":
                htmls.append(payload)
            elif ctype.startswith("text/"):
                texts.append(payload)
    else:
        try:
            payload = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode(
                    msg.get_content_charset() or "utf-8", errors="replace"
                )
        if isinstance(payload, str):
            if (msg.get_content_type() or "").lower() == "text/html":
                htmls.append(payload)
            else:
                texts.append(payload)
    if texts:
        out["text"] = "\n".join(texts)
    if htmls:
        out["html"] = "\n".join(htmls)
    if not texts and not htmls:
        out["text"] = text[:8000]
    return out


def cfmail_create_mailbox(
    *,
    name: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,  # accepted for API compat; CF address is durable
    api_key: str | None = None,
    base_url: str | None = None,
    site_password: str | None = None,
    proxy: str | None = None,
    proxy_username: str | None = None,
    proxy_password: str | None = None,
) -> dict[str, Any]:
    """Create an address on Cloudflare Temp Email.

    Preferred path (automation): ``POST /admin/new_address`` with admin password
    in ``x-admin-auth`` (pass as api_key).

    Fallback: ``POST /api/new_address`` (may require Turnstile / open create).

    Docs: https://github.com/dreamhunter2333/cloudflare_temp_email
    """
    key = (api_key or MOEMAIL_API_KEY or "").strip()
    base = normalize_cfmail_base_url(base_url or MOEMAIL_BASE_URL)
    # Never bleed MoeMail default domain into CF.
    dom = (domain or "").strip().lstrip("@").strip(".")
    if not dom:
        dom = cfmail_pick_domain(
            api_key=key, base_url=base, site_password=site_password
        ) or ""
    if not dom:
        raise ValueError(
            "Cloudflare Temp Email domain missing. Set domain in registration "
            "config, or ensure /open_api/settings returns domains."
        )
    local = (name or "").strip().lower()
    if not local:
        local = secrets_token_hex_local()

    payload: dict[str, Any] = {
        "name": local,
        "domain": dom,
        # Admin API field; public API ignores unknown keys.
        "enablePrefix": False,
    }
    headers = _cfmail_headers(
        api_key=key, site_password=site_password, content_type=True
    )
    # Prefer admin create (no captcha) when we have a non-JWT key.
    use_admin = bool(key) and "Authorization" not in headers

    with httpx.Client(timeout=30.0) as client:
        if use_admin:
            resp = client.post(
                f"{base}/admin/new_address", json=payload, headers=headers
            )
            if resp.status_code >= 400:
                # Fall through to public create for older/non-admin deploys.
                resp = client.post(
                    f"{base}/api/new_address", json=payload, headers=headers
                )
        else:
            resp = client.post(
                f"{base}/api/new_address", json=payload, headers=headers
            )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"CF Temp Email create failed {resp.status_code}: {resp.text[:500]}"
            )
        data = resp.json() if resp.content else {}

    body = data.get("data") if isinstance(data, dict) and "data" in data else data
    if not isinstance(body, dict):
        raise RuntimeError(f"Unexpected CF Temp Email create response: {data}")
    address = (
        body.get("address")
        or body.get("email")
        or body.get("mail")
        or body.get("name")
    )
    jwt = (
        body.get("jwt")
        or body.get("token")
        or body.get("credential")
        or body.get("address_jwt")
        or ""
    )
    address_id = (
        body.get("address_id")
        or body.get("id")
        or body.get("addressId")
        or address
    )
    if not address or "@" not in str(address):
        # Some responses only return jwt + partial; try settings with jwt.
        if jwt:
            try:
                with httpx.Client(timeout=20.0) as client:
                    sresp = client.get(
                        f"{base}/api/settings",
                        headers=_cfmail_headers(api_key=str(jwt)),
                    )
                    if sresp.status_code < 400:
                        sdata = sresp.json() if sresp.content else {}
                        sbody = (
                            sdata.get("data")
                            if isinstance(sdata, dict) and "data" in sdata
                            else sdata
                        )
                        if isinstance(sbody, dict):
                            address = sbody.get("address") or address
            except Exception:
                pass
    if not address or "@" not in str(address):
        raise RuntimeError(f"Unexpected CF Temp Email create response: {data}")
    if not jwt:
        # Without address JWT we cannot poll inbox.
        raise RuntimeError(
            "CF Temp Email create returned no address JWT. "
            "Use admin password (x-admin-auth) via api_key, or enable open create."
        )
    return {
        "id": str(address_id or address),
        "email": str(address).strip(),
        "token": str(jwt),
        "provider": "cfmail",
        "raw": data,
        "expiry_ms": 86_400_000 if expiry_ms is None else int(expiry_ms),
    }


def secrets_token_hex_local() -> str:
    """Local-part generator without importing secrets at module top for clarity."""
    import secrets as _secrets

    return _secrets.token_hex(5).lower()


def cfmail_fetch_messages(
    email_id: str,
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    include_details: bool = True,
    address: str | None = None,
    token: str | None = None,
    site_password: str | None = None,
) -> list[dict[str, Any]]:
    """List messages for a CF Temp Email address JWT.

    Prefers parsed endpoints; falls back to raw RFC822 list/detail.
    ``token`` (address JWT) is required for inbox access. ``api_key`` may also
    be the JWT when the admin key is not needed.
    """
    jwt = (token or api_key or MOEMAIL_API_KEY or "").strip()
    if not jwt:
        return []
    base = normalize_cfmail_base_url(base_url or MOEMAIL_BASE_URL)
    headers = _cfmail_headers(api_key=jwt, site_password=site_password)

    with httpx.Client(timeout=30.0) as client:
        # 1) Parsed list (newer deploys)
        items: list[Any] = []
        used_parsed = False
        resp = client.get(
            f"{base}/api/parsed_mails",
            headers=headers,
            params={"limit": 20, "offset": 0},
        )
        if resp.status_code < 400:
            data = resp.json() if resp.content else {}
            body = data.get("data") if isinstance(data, dict) and "data" in data else data
            if isinstance(body, dict):
                items = body.get("results") or body.get("mails") or body.get("items") or []
            elif isinstance(body, list):
                items = body
            used_parsed = True
        else:
            # 2) Raw list fallback
            resp = client.get(
                f"{base}/api/mails",
                headers=headers,
                params={"limit": 20, "offset": 0},
            )
            if resp.status_code >= 400:
                raise RuntimeError(
                    f"CF Temp Email list failed {resp.status_code}: {resp.text[:500]}"
                )
            data = resp.json() if resp.content else {}
            body = data.get("data") if isinstance(data, dict) and "data" in data else data
            if isinstance(body, dict):
                items = body.get("results") or body.get("mails") or body.get("items") or []
            elif isinstance(body, list):
                items = body

        if not isinstance(items, list):
            return []

        out: list[dict[str, Any]] = []
        for raw in items[:20]:
            if not isinstance(raw, dict):
                continue
            item = dict(raw)
            msg_id = item.get("id") or item.get("mail_id") or item.get("message_id")
            if include_details and msg_id and not used_parsed:
                detail = client.get(
                    f"{base}/api/mail/{msg_id}",
                    headers=headers,
                )
                if detail.status_code == 200:
                    d = detail.json() if detail.content else {}
                    msg = d.get("data") if isinstance(d, dict) and "data" in d else d
                    if isinstance(msg, dict):
                        item.update(msg)
            # Normalize CF shapes → shared extractor fields.
            if not item.get("text") and not item.get("html"):
                raw_rfc = (
                    item.get("raw")
                    or item.get("source")
                    or item.get("message")
                    or item.get("content")
                    or ""
                )
                if isinstance(raw_rfc, str) and ("\n" in raw_rfc or "From:" in raw_rfc):
                    parsed = _cfmail_parse_raw_rfc822(raw_rfc)
                    for k, v in parsed.items():
                        item.setdefault(k, v)
            if item.get("sender") and not item.get("from"):
                item["from"] = item.get("sender")
            if item.get("source") and not item.get("from"):
                # Some rows store envelope sender in source.
                src = item.get("source")
                if isinstance(src, str) and "@" in src and "\n" not in src:
                    item["from"] = src
            text = "\n".join(
                str(item.get(k) or "")
                for k in (
                    "subject",
                    "text",
                    "html",
                    "content",
                    "from",
                    "sender",
                )
            )
            item["extracted"] = _extract_codes_and_links(text)
            if msg_id is not None:
                item["id"] = str(msg_id)
            out.append(item)
        return out


def normalize_duckmail_base_url(base_url: str | None = None) -> str:
    """Normalize DuckMail API origin (default public host)."""
    raw = (base_url or "").strip()
    if not raw:
        return DUCKMAIL_DEFAULT_BASE_URL
    lower = raw.lower()
    if "duckmail.sbs" in lower or "duckmail" in lower:
        # Public SaaS always pins to official API origin.
        if "api.duckmail.sbs" in lower or not urlparse(raw if "://" in raw else f"https://{raw}").netloc:
            return DUCKMAIL_DEFAULT_BASE_URL
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    origin = f"{parsed.scheme or 'https'}://{parsed.netloc}".rstrip("/")
    return origin or DUCKMAIL_DEFAULT_BASE_URL


def _duckmail_headers(
    *,
    bearer: str | None = None,
    api_key: str | None = None,
    content_type: bool = False,
) -> dict[str, str]:
    """DuckMail uses ``Authorization: Bearer <token|dk_key>``."""
    headers: dict[str, str] = {"Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = "application/json"
    token = (bearer or api_key or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _duckmail_hydra_members(data: Any) -> list[Any]:
    if not isinstance(data, dict):
        return list(data) if isinstance(data, list) else []
    members = (
        data.get("hydra:member")
        or data.get("member")
        or data.get("items")
        or data.get("data")
        or []
    )
    return list(members) if isinstance(members, list) else []


def duckmail_list_domains(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    max_pages: int = 5,
) -> list[str]:
    """List verified DuckMail domains (``GET /domains``)."""
    base = normalize_duckmail_base_url(base_url)
    out: list[str] = []
    seen: set[str] = set()
    try:
        with httpx.Client(timeout=20.0) as client:
            for page in range(1, max(1, int(max_pages)) + 1):
                resp = client.get(
                    f"{base}/domains",
                    params={"page": page},
                    headers=_duckmail_headers(api_key=api_key),
                )
                if resp.status_code >= 400:
                    break
                data = resp.json()
                members = _duckmail_hydra_members(data)
                if not members:
                    break
                for item in members:
                    if not isinstance(item, dict):
                        continue
                    # Prefer verified domains only.
                    if item.get("isVerified") is False:
                        continue
                    name = item.get("domain") or item.get("name") or item.get("id")
                    if not isinstance(name, str) or not name.strip():
                        continue
                    name = name.strip().lstrip("@").strip(".").lower()
                    if not name or name in seen:
                        continue
                    seen.add(name)
                    out.append(name)
                # Stop early when page under-filled (default page size 30).
                if len(members) < 30:
                    break
    except Exception:
        return out
    return out


def duckmail_pick_domain(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
) -> str:
    domains = duckmail_list_domains(api_key=api_key, base_url=base_url)
    if not domains:
        return ""
    return random.choice(domains)


def _duckmail_random_password(n: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits
    # Ensure >= 6 chars and mixed for provider validation.
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(max(6, n - 3)))


def duckmail_create_mailbox(
    *,
    name: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    proxy: str | None = None,  # API compat; unused
    proxy_username: str | None = None,
    proxy_password: str | None = None,
) -> dict[str, Any]:
    """Create a DuckMail account and exchange a Bearer token for inbox reads.

    Flow (public docs):
      1. optional ``GET /domains``
      2. ``POST /accounts`` {address, password, expiresIn?}
      3. ``POST /token`` {address, password} → bearer for ``GET /messages``
    """
    base = normalize_duckmail_base_url(base_url)
    key = (api_key or "").strip()  # optional dk_ for private domains
    dom = (domain or "").strip().lstrip("@").strip(".").lower()
    if not dom:
        dom = duckmail_pick_domain(api_key=key or None, base_url=base) or ""
    if not dom:
        raise ValueError(
            "DuckMail domain auto-fetch failed. Leave domain empty for public "
            "catalog pick, or set an explicit verified domain."
        )
    local = (name or "").strip().lower() or secrets.token_hex(5).lower()
    # DuckMail requires local-part length >= 3.
    if len(local) < 3:
        local = (local + secrets.token_hex(2)).lower()
    address = f"{local}@{dom}"
    password = _duckmail_random_password()

    # Map our UI expiry_ms presets → DuckMail expiresIn seconds.
    # omit / None → provider default 24h; 0 → permanent; else seconds.
    expires_in: int | None
    if expiry_ms is None:
        expires_in = 24 * 3600
    else:
        try:
            ms = int(expiry_ms)
        except (TypeError, ValueError):
            ms = 3_600_000
        if ms <= 0:
            expires_in = 0  # never expire
        else:
            expires_in = max(60, ms // 1000)

    payload: dict[str, Any] = {
        "address": address,
        "password": password,
    }
    if expires_in is not None:
        payload["expiresIn"] = expires_in

    with httpx.Client(timeout=30.0) as client:
        headers = _duckmail_headers(api_key=key or None, content_type=True)
        resp = client.post(f"{base}/accounts", json=payload, headers=headers)
        if resp.status_code >= 400:
            # Domain collision / validation — one retry with fresh local-part.
            if resp.status_code in {409, 422}:
                local = secrets.token_hex(5).lower()
                address = f"{local}@{dom}"
                payload["address"] = address
                resp = client.post(f"{base}/accounts", json=payload, headers=headers)
            if resp.status_code >= 400:
                raise RuntimeError(
                    f"DuckMail create failed {resp.status_code}: {resp.text[:500]}"
                )
        data = resp.json() if resp.content else {}
        if not isinstance(data, dict):
            raise RuntimeError(f"Unexpected DuckMail create response: {data}")

        # Exchange password for JWT bearer used by /messages.
        token_resp = client.post(
            f"{base}/token",
            json={"address": address, "password": password},
            headers=_duckmail_headers(content_type=True),
        )
        if token_resp.status_code >= 400:
            raise RuntimeError(
                f"DuckMail token failed {token_resp.status_code}: {token_resp.text[:500]}"
            )
        token_body = token_resp.json() if token_resp.content else {}
        if not isinstance(token_body, dict):
            raise RuntimeError(f"Unexpected DuckMail token response: {token_body}")

    account_id = (
        data.get("id")
        or token_body.get("id")
        or token_body.get("accountId")
        or address
    )
    bearer = (
        token_body.get("token")
        or token_body.get("access_token")
        or token_body.get("jwt")
        or ""
    )
    final_address = data.get("address") or address
    if not account_id or not final_address:
        raise RuntimeError(f"Unexpected DuckMail create response: {data}")
    if not bearer:
        raise RuntimeError(f"DuckMail token missing in response: {token_body}")
    return {
        "id": str(account_id),
        "email": str(final_address),
        "token": str(bearer),
        "password": password,
        "provider": "duckmail",
        "raw": {"account": data, "token": {k: v for k, v in token_body.items() if k != "token"}},
        "expiry_ms": 0 if expires_in == 0 else int((expires_in or 86400) * 1000),
    }


def duckmail_fetch_messages(
    email_id: str,
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    include_details: bool = True,
    address: str | None = None,
    token: str | None = None,
) -> list[dict[str, Any]]:
    """List DuckMail messages (Bearer required). Optionally expand body via detail API."""
    base = normalize_duckmail_base_url(base_url)
    bearer = (token or api_key or "").strip()
    if not bearer:
        raise ValueError("DuckMail mailbox token missing (Bearer from POST /token).")
    out: list[dict[str, Any]] = []
    with httpx.Client(timeout=30.0) as client:
        headers = _duckmail_headers(bearer=bearer)
        resp = client.get(f"{base}/messages", params={"page": 1}, headers=headers)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"DuckMail list messages failed {resp.status_code}: {resp.text[:500]}"
            )
        data = resp.json() if resp.content else {}
        members = _duckmail_hydra_members(data)
        for item in members:
            if not isinstance(item, dict):
                continue
            msg_id = item.get("id") or item.get("msgid")
            from_obj = item.get("from") if isinstance(item.get("from"), dict) else {}
            to_obj = item.get("to") if isinstance(item.get("to"), dict) else {}
            subject = str(item.get("subject") or "")
            from_addr = (
                from_obj.get("address")
                or from_obj.get("email")
                or item.get("from_address")
                or item.get("from")
                or ""
            )
            row: dict[str, Any] = {
                "id": str(msg_id or ""),
                "subject": subject,
                "from": str(from_addr or ""),
                "to": str(to_obj.get("address") or to_obj.get("email") or address or ""),
                "seen": bool(item.get("seen")),
                "created_at": item.get("createdAt") or item.get("created_at"),
                "text": "",
                "html": "",
                "content": "",
            }
            if include_details and msg_id:
                try:
                    detail = client.get(
                        f"{base}/messages/{msg_id}",
                        headers=headers,
                    )
                    if detail.status_code < 400:
                        body = detail.json() if detail.content else {}
                        if isinstance(body, dict):
                            text = str(body.get("text") or body.get("textBody") or "")
                            html_val = body.get("html")
                            if isinstance(html_val, list):
                                html = "\n".join(str(x) for x in html_val if x)
                            else:
                                html = str(html_val or body.get("htmlBody") or "")
                            row["text"] = text
                            row["html"] = html
                            row["content"] = text or html
                            row["subject"] = str(body.get("subject") or subject)
                            if isinstance(body.get("from"), dict):
                                row["from"] = str(
                                    body["from"].get("address")
                                    or body["from"].get("email")
                                    or row["from"]
                                )
                except Exception:
                    pass
            text_blob = "\n".join(
                str(row.get(k) or "")
                for k in ("subject", "text", "html", "content", "from")
            )
            row["extracted"] = _extract_codes_and_links(text_blob)
            out.append(row)
    return out


def create_mailbox(
    *,
    provider: str | None = None,
    name: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    proxy: str | None = None,
    proxy_username: str | None = None,
    proxy_password: str | None = None,
) -> dict[str, Any]:
    """Provider-aware mailbox create (``moemail`` | ``yyds`` | ``gptmail`` | ``cfmail`` | ``duckmail``)."""
    prov = normalize_mail_provider(provider, base_url=base_url)
    if prov == "outmail":
        import outmail_client as om
        om_cfg: dict[str, Any] = {}
        if base_url:
            om_cfg["outmail_api_base"] = base_url
        if api_key:
            om_cfg["outmail_api_key"] = api_key
        try:
            import register_pro_store as _store
            reg = _store.get_registration_config(include_secrets=True)
            om_cfg = {**reg, **om_cfg}
        except Exception:
            pass
        om.configure(om_cfg, merge=False)
        email_addr, token = om.outmail_get_email_and_token()
        return {
            "id": email_addr,
            "email": email_addr,
            "token": token,
            "provider": "outmail",
        }
    if prov == "yyds":
        return yyds_create_mailbox(
            name=name,
            domain=domain,
            expiry_ms=expiry_ms,
            api_key=api_key,
            base_url=base_url,
            proxy=proxy,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
        )
    if prov == "gptmail":
        return gptmail_create_mailbox(
            name=name,
            domain=domain,
            expiry_ms=expiry_ms,
            api_key=api_key,
            base_url=base_url,
            proxy=proxy,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
        )
    if prov == "cfmail":
        return cfmail_create_mailbox(
            name=name,
            domain=domain,
            expiry_ms=expiry_ms,
            api_key=api_key,
            base_url=base_url,
            proxy=proxy,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
        )
    if prov == "duckmail":
        return duckmail_create_mailbox(
            name=name,
            domain=domain,
            expiry_ms=expiry_ms,
            api_key=api_key,
            base_url=base_url,
            proxy=proxy,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
        )
    box = moemail_create_mailbox(
        name=name,
        domain=domain,
        expiry_ms=expiry_ms,
        api_key=api_key,
        base_url=base_url,
        proxy=proxy,
        proxy_username=proxy_username,
        proxy_password=proxy_password,
    )
    box.setdefault("provider", "moemail")
    box.setdefault("token", "")
    return box


def fetch_messages(
    email_id: str,
    *,
    provider: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    include_details: bool = True,
    address: str | None = None,
    token: str | None = None,
) -> list[dict[str, Any]]:
    """Provider-aware message list."""
    prov = normalize_mail_provider(provider, base_url=base_url)
    if prov == "outmail":
        # Outmail polling is handled by outmail_client via wait_for_code.
        # Returning empty list keeps generic pollers from erroring.
        return []
    if prov == "yyds":
        return yyds_fetch_messages(
            email_id,
            api_key=api_key,
            base_url=base_url,
            include_details=include_details,
            address=address,
            token=token,
        )
    if prov == "gptmail":
        return gptmail_fetch_messages(
            email_id,
            api_key=api_key,
            base_url=base_url,
            include_details=include_details,
            address=address or email_id,
            token=token,
        )
    if prov == "cfmail":
        return cfmail_fetch_messages(
            email_id,
            api_key=api_key,
            base_url=base_url,
            include_details=include_details,
            address=address,
            token=token,
        )
    if prov == "duckmail":
        return duckmail_fetch_messages(
            email_id,
            api_key=api_key,
            base_url=base_url,
            include_details=include_details,
            address=address,
            token=token,
        )
    return moemail_fetch_messages(
        email_id,
        api_key=api_key,
        base_url=base_url,
        include_details=include_details,
    )


def probe_egress_ip(
    *,
    proxy: str | None = None,
    proxy_username: str | None = None,
    proxy_password: str | None = None,
    timeout: float = 20.0,
    ignore_env_proxy: bool | None = None,
) -> dict[str, Any]:
    """Return the public egress IP seen through optional proxy (curl_cffi preferred).

    Used by registration preflight so protocol HTTP and local captcha can be
    compared against the same proxy URL.

    When an explicit ``proxy`` is provided, env HTTP(S)_PROXY is cleared for the
    duration of the probe by default so a local front proxy does not hijack the
    connection to the upstream proxy host.
    """
    try:
        proxy_cfg = normalize_proxy_config(
            proxy,
            username=proxy_username,
            password=proxy_password,
        )
    except ValueError as e:
        return {
            "ok": False,
            "ip": "",
            "error": str(e),
            "proxy_enabled": False,
            "transport": "",
        }

    proxy_url = proxy_cfg["proxy"] if proxy_cfg else None
    if ignore_env_proxy is None:
        ignore_env_proxy = bool(proxy_url)
    urls = (
        "https://api.ipify.org?format=json",
        "https://api64.ipify.org?format=json",
        "https://ifconfig.me/ip",
    )
    headers = {
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
        ),
        "accept": "application/json,text/plain,*/*",
    }

    def _parse_ip(text: str) -> str:
        text = (text or "").strip()
        if not text:
            return ""
        if text.startswith("{"):
            try:
                import json as _json

                data = _json.loads(text)
                if isinstance(data, dict):
                    return str(data.get("ip") or data.get("origin") or "").strip()
            except Exception:
                pass
        # plain IP or "ip=..." from cf trace style
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("ip="):
                return line.split("=", 1)[1].strip()
            if line and " " not in line and 3 <= line.count(".") <= 7:
                return line
            if ":" in line and "." not in line and len(line) >= 3:
                # likely IPv6
                return line
        return text.split()[0] if text.split() else ""

    env_keys = (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    )
    saved_env: dict[str, str | None] = {}
    if ignore_env_proxy and proxy_url:
        for key in env_keys:
            saved_env[key] = os.environ.get(key)
            os.environ.pop(key, None)

    last_err = ""
    try:
        from curl_cffi import requests as curl_requests
    except Exception:
        curl_requests = None

    try:
        if curl_requests is not None:
            for url in urls:
                try:
                    kwargs: dict[str, Any] = {
                        "headers": headers,
                        "timeout": timeout,
                        "allow_redirects": True,
                        "impersonate": "chrome",
                    }
                    if proxy_url:
                        kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}
                    resp = curl_requests.get(url, **kwargs)
                    ip = _parse_ip(resp.text or "")
                    if ip:
                        return {
                            "ok": True,
                            "ip": ip,
                            "status_code": int(resp.status_code),
                            "transport": "curl_cffi",
                            "proxy_enabled": bool(proxy_url),
                            "source": url,
                        }
                    last_err = f"empty body from {url} status={resp.status_code}"
                except Exception as e:  # noqa: BLE001
                    last_err = str(e)[:240]
                    continue

        for url in urls:
            try:
                with httpx.Client(
                    timeout=timeout,
                    proxy=proxy_url,
                    follow_redirects=True,
                ) as client:
                    resp = client.get(url, headers=headers)
                    ip = _parse_ip(resp.text or "")
                    if ip:
                        return {
                            "ok": True,
                            "ip": ip,
                            "status_code": int(resp.status_code),
                            "transport": "httpx",
                            "proxy_enabled": bool(proxy_url),
                            "source": url,
                        }
                    last_err = f"empty body from {url} status={resp.status_code}"
            except Exception as e:  # noqa: BLE001
                last_err = str(e)[:240]
                continue

        return {
            "ok": False,
            "ip": "",
            "error": last_err or "egress probe failed",
            "proxy_enabled": bool(proxy_url),
            "transport": "curl_cffi" if curl_requests is not None else "httpx",
        }
    finally:
        for key, val in saved_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val


def test_xai_proxy(
    *,
    proxy: str | None = None,
    proxy_username: str | None = None,
    proxy_password: str | None = None,
    ignore_env_proxy: bool = True,
    timeout: float = 8.0,
    probe_egress: bool = True,
) -> dict[str, Any]:
    """Smoke-test whether a proxy can reach accounts.x.ai.

    When testing an *explicit* upstream proxy (registration pool / egress pool),
    ``ignore_env_proxy=True`` (default) clears HTTP(S)_PROXY for this request so
    a local front proxy (Clash) does not intercept the connection to the
    upstream SOCKS/HTTP proxy host itself.

    Keep ``timeout`` short for pool scans — dead proxies otherwise stall the
    whole "测代理" request and trip reverse-proxy 504s.
    """
    try:
        proxy_cfg = normalize_proxy_config(
            proxy,
            username=proxy_username,
            password=proxy_password,
        )
    except ValueError as e:
        return {"ok": False, "error": str(e), "proxy_enabled": False}

    url = "https://accounts.x.ai/sign-up?redirect=grok-com"
    headers = {
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
        ),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    try:
        from curl_cffi import requests as curl_requests
    except Exception:
        curl_requests = None

    # Isolate this probe from process-level front proxy env when we already
    # have an explicit upstream proxy URL.
    env_keys = (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    )
    saved_env: dict[str, str | None] = {}
    if ignore_env_proxy and proxy_cfg:
        for key in env_keys:
            saved_env[key] = os.environ.get(key)
            os.environ.pop(key, None)

    try:
        # Bound total per-proxy wall time tightly. Dead residential/open proxies
        # must fail fast so a 10~50 pool scan finishes before openresty 504.
        try:
            t_total = max(2.0, min(30.0, float(timeout)))
        except (TypeError, ValueError):
            t_total = 8.0
        egress: dict[str, Any] = {}
        if probe_egress:
            egress = probe_egress_ip(
                proxy=proxy_cfg["proxy"] if proxy_cfg else None,
                timeout=min(4.0, t_total),
            )

        if curl_requests is not None:
            try:
                kwargs: dict[str, Any] = {
                    "headers": headers,
                    "timeout": t_total,
                    "allow_redirects": True,
                    "impersonate": "chrome",
                }
                if proxy_cfg:
                    kwargs["proxies"] = {
                        "http": proxy_cfg["proxy"],
                        "https": proxy_cfg["proxy"],
                    }
                resp = curl_requests.get(url, **kwargs)
                return {
                    "ok": 200 <= int(resp.status_code) < 400,
                    "status_code": int(resp.status_code),
                    "body_preview": (resp.text or "")[:500],
                    "transport": "curl_cffi",
                    "proxy_enabled": bool(proxy_cfg),
                    "egress_ip": egress.get("ip") or "",
                    "egress": egress,
                }
            except Exception as e:  # noqa: BLE001
                return {
                    "ok": False,
                    "status_code": 0,
                    "body_preview": str(e)[:500],
                    "transport": "curl_cffi",
                    "proxy_enabled": bool(proxy_cfg),
                    "egress_ip": egress.get("ip") or "",
                    "egress": egress,
                }

        try:
            with httpx.Client(
                timeout=t_total,
                proxy=proxy_cfg["proxy"] if proxy_cfg else None,
                follow_redirects=True,
            ) as client:
                resp = client.get(url, headers=headers)
                return {
                    "ok": 200 <= int(resp.status_code) < 400,
                    "status_code": int(resp.status_code),
                    "body_preview": (resp.text or "")[:500],
                    "transport": "httpx",
                    "proxy_enabled": bool(proxy_cfg),
                    "egress_ip": egress.get("ip") or "",
                    "egress": egress,
                }
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False,
                "status_code": 0,
                "body_preview": str(e)[:500],
                "transport": "httpx",
                "proxy_enabled": bool(proxy_cfg),
                "egress_ip": egress.get("ip") or "",
                "egress": egress,
            }
    finally:
        for key, val in saved_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
