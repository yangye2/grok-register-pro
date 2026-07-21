#!/usr/bin/env python3
"""Register xAI accounts, write Grok Build auth JSON, and optionally import it into Grok2API.

This is a thin standalone entrypoint around ``grok-build-auth/run.py``. It does
not start any full proxy service or use PostgreSQL/Redis shared stores.
"""

from __future__ import annotations

import argparse
import getpass
import importlib.util
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
REGISTER_RUNTIME = ROOT / "grok-build-auth" / "run.py"
DEFAULT_GROK2API_BASE = "http://127.0.0.1:36214"


def load_register_runtime():
    spec = importlib.util.spec_from_file_location("grok_build_auth_run", REGISTER_RUNTIME)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load register runtime: {REGISTER_RUNTIME}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def grok2api_login(base_url: str, username: str, password: str) -> str:
    body = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        base_url.rstrip("/") + "/api/admin/v1/auth/login",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read())
    return str(payload["data"]["tokens"]["accessToken"])


def build_multipart(files: list[Path], boundary: str) -> bytes:
    chunks: list[bytes] = []
    for path in files:
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="files"; filename="{path.name}"\r\n'
                "Content-Type: application/json\r\n\r\n"
            ).encode()
            + path.read_bytes()
            + b"\r\n"
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks)


def parse_sse_complete(text: str) -> dict[str, Any]:
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


def import_to_grok2api(
    *,
    files: list[Path],
    out_dir: Path,
    base_url: str,
    username: str,
    password: str,
) -> dict[str, Any]:
    if not files:
        return {"skipped": True, "reason": "no auth files", "files": 0}
    token = grok2api_login(base_url, username, password)
    boundary = "----grok-build-auth-import-" + str(int(time.time()))
    body = build_multipart(files, boundary)
    req = urllib.request.Request(
        base_url.rstrip("/") + "/api/admin/v1/accounts/import",
        data=body,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "multipart/form-data; boundary=" + boundary,
            "Content-Length": str(len(body)),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=7200) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    text = raw.decode("utf-8", "replace")
    (out_dir / "grok2api_import_response.txt").write_text(text, encoding="utf-8")
    if status >= 400:
        raise RuntimeError(f"Grok2API import failed HTTP {status}: {text[:500]}")
    result = parse_sse_complete(text)
    result["files"] = len(files)
    return result


def public_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "email": result.get("email") or "",
        "has_password": bool(result.get("password")),
        "has_sso": bool(result.get("sso")),
        "has_oauth": bool(result.get("oauth_refresh_token")),
        "auth_file": result.get("cliproxyapi_auth") or "",
        "account_bundle": result.get("account_bundle") or "",
        "error": result.get("error") or None,
    }


def write_outputs(results: list[dict[str, Any]], out_dir: Path) -> None:
    credentials_dir = out_dir / "credentials"
    sso_dir = out_dir / "sso"
    credentials_dir.mkdir(parents=True, exist_ok=True)
    sso_dir.mkdir(parents=True, exist_ok=True)

    credential_rows = []
    sso_rows = []
    sso_json = []
    for result in results:
        email = str(result.get("email") or "")
        if not email:
            continue
        password = str(result.get("password") or "")
        sso = str(result.get("sso") or "")
        credential_rows.append(f"{email}\t{password}")
        if sso:
            sso_rows.append(f"{email}\t{password}\t{sso}")
            sso_json.append({"email": email, "password": password, "sso": sso})
    (credentials_dir / "accounts.tsv").write_text(
        "email\tpassword\n" + "\n".join(credential_rows) + ("\n" if credential_rows else ""),
        encoding="utf-8",
    )
    (sso_dir / "email_password_sso.tsv").write_text(
        "email\tpassword\tsso\n" + "\n".join(sso_rows) + ("\n" if sso_rows else ""),
        encoding="utf-8",
    )
    (sso_dir / "items.json").write_text(json.dumps(sso_json, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "README.txt").write_text(
        "\n".join(
            [
                "outputs:",
                "- credentials/accounts.tsv: email + password",
                "- sso/email_password_sso.tsv: email + password + SSO",
                "- sso/items.json: structured SSO records",
                "- cpa/: Grok Build / CLIProxyAPI / Grok2API importable auth JSON files",
                "",
                "These files contain secrets. Do not commit or share them.",
            ]
        ),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-n", "--count", type=int, default=1, help="accounts to register")
    parser.add_argument("-t", "--threads", type=int, default=1, help="registration concurrency; OAuth is serialized upstream")
    parser.add_argument("-e", "--email-backend", choices=["tempmail", "cloudflare"], default="tempmail")
    parser.add_argument("--output-root", default=str(ROOT / "generated" / "register_to_grok2api"))
    parser.add_argument("--auth-dir", default="", help="CPA/auth JSON output dir; defaults to <workdir>/cpa")
    parser.add_argument("--no-oauth", action="store_true", help="only register + SSO; cannot import without OAuth auth JSON")
    parser.add_argument("--oauth-timeout", type=float, default=180.0)
    parser.add_argument("--oauth-headed", action="store_true")
    parser.add_argument("--no-oauth-protocol", action="store_true")
    parser.add_argument("--oauth-interactive-fallback", action="store_true")
    parser.add_argument("--oauth-debug", action="store_true")
    parser.add_argument("--no-import", action="store_true", help="write auth JSON only")
    parser.add_argument("--grok2api-url", default=DEFAULT_GROK2API_BASE)
    parser.add_argument("--admin-username", default="admin")
    parser.add_argument("--admin-password", default="", help="prefer GROK2API_ADMIN_PASSWORD env or prompt instead of shell history")
    args = parser.parse_args()

    if args.count < 1:
        raise SystemExit("--count must be >= 1")
    if args.threads < 1:
        raise SystemExit("--threads must be >= 1")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.output_root) / stamp
    auth_dir = Path(args.auth_dir) if args.auth_dir else out_dir / "cpa"
    account_dir = out_dir / "accounts"
    out_dir.mkdir(parents=True, exist_ok=True)
    auth_dir.mkdir(parents=True, exist_ok=True)
    account_dir.mkdir(parents=True, exist_ok=True)

    runtime = load_register_runtime()
    runtime._total = args.count
    runtime._t0 = time.time()

    common = {
        "do_oauth": not args.no_oauth,
        "oauth_headless": not args.oauth_headed,
        "oauth_timeout": args.oauth_timeout,
        "oauth_interactive_fallback": args.oauth_interactive_fallback,
        "oauth_protocol": not args.no_oauth_protocol,
        "oauth_debug": args.oauth_debug,
        "cliproxyapi_auth_dir": auth_dir,
        "accounts_output_dir": account_dir,
    }

    print(json.dumps({"workdir": str(out_dir), "auth_dir": str(auth_dir), "count": args.count}, ensure_ascii=False), flush=True)
    results: list[dict[str, Any]] = []
    workers = min(args.threads, args.count)
    if args.count == 1:
        results.append(runtime.register_one(1, email_backend=args.email_backend, **common))
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(runtime.register_one, index, args.email_backend, **common)
                for index in range(1, args.count + 1)
            ]
            for future in as_completed(futures):
                results.append(future.result())

    auth_files = [Path(r["cliproxyapi_auth"]) for r in results if r.get("cliproxyapi_auth")]
    failures = [r for r in results if r.get("error")]
    write_outputs(results, out_dir)
    (out_dir / "summary.public.json").write_text(
        json.dumps(
            {
                "workdir": str(out_dir),
                "auth_dir": str(auth_dir),
                "registered": len([r for r in results if r.get("email")]),
                "auth_files": len(auth_files),
                "failed": len(failures),
                "items": [public_result(r) for r in results],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    import_result: dict[str, Any] = {"skipped": True, "reason": "no-import"}
    if not args.no_import:
        if args.no_oauth:
            import_result = {"skipped": True, "reason": "no-oauth"}
        else:
            password = args.admin_password
            if not password:
                import os

                password = os.environ.get("GROK2API_ADMIN_PASSWORD", "")
            if not password:
                password = getpass.getpass("Grok2API admin password: ")
            import_result = import_to_grok2api(
                files=auth_files,
                out_dir=out_dir,
                base_url=args.grok2api_url,
                username=args.admin_username,
                password=password,
            )

    final_summary = {
        "workdir": str(out_dir),
        "auth_dir": str(auth_dir),
        "registered": len([r for r in results if r.get("email")]),
        "auth_files": len(auth_files),
        "failed": len(failures),
        "grok2api_import": import_result,
    }
    (out_dir / "summary.json").write_text(json.dumps(final_summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(final_summary, ensure_ascii=False), flush=True)
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
