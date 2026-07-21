import os
import sys
import time
import uuid
import random
import logging
import asyncio
from typing import Optional, Union
from urllib.parse import unquote, urlparse
import argparse
from quart import Quart, request, jsonify
from camoufox.async_api import AsyncNewBrowser
from patchright.async_api import async_playwright
# Camoufox is Firefox-based and must use stock Playwright (not patchright).
from playwright.async_api import async_playwright as camoufox_async_playwright
from db_results import init_db, save_result, load_result, cleanup_old_results
from browser_configs import browser_config
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box


def _normalize_task_proxy(raw: Optional[str]) -> Optional[str]:
    """Normalize a proxy URL / shorthand into a single string for context options."""
    s = (raw or "").strip()
    if not s:
        return None
    lower = s.lower()
    if lower.startswith("soket5://"):
        s = "socks5://" + s.split("://", 1)[1]
    elif lower.startswith("socket5://"):
        s = "socks5://" + s.split("://", 1)[1]
    elif "://" not in s:
        # host:port:user:pass or host:port
        parts = s.split(":")
        if len(parts) >= 4:
            host, port, user = parts[0], parts[1], parts[2]
            password = ":".join(parts[3:])
            s = f"http://{user}:{password}@{host}:{port}"
        else:
            s = f"http://{s}"
    return s


def _proxy_from_task_fields(task: dict) -> Optional[str]:
    """Extract proxy from YesCaptcha / CapSolver-style task fields."""
    if not isinstance(task, dict):
        return None
    direct = (
        task.get("proxy")
        or task.get("proxyUrl")
        or task.get("proxyURL")
        or task.get("proxy_url")
    )
    if isinstance(direct, str) and direct.strip():
        return _normalize_task_proxy(direct)

    # YesCaptcha split fields: proxyType + proxyAddress + proxyPort + login/password
    address = (task.get("proxyAddress") or task.get("proxy_address") or "").strip()
    port = task.get("proxyPort") or task.get("proxy_port")
    if address and port:
        scheme = (
            task.get("proxyType")
            or task.get("proxy_type")
            or "http"
        )
        scheme = str(scheme).strip().lower() or "http"
        if scheme in {"socks5h"}:
            scheme = "socks5"
        user = task.get("proxyLogin") or task.get("proxy_login") or task.get("proxyUsername") or ""
        password = task.get("proxyPassword") or task.get("proxy_password") or ""
        user = str(user or "").strip()
        password = str(password or "")
        if user:
            auth = f"{user}:{password}@" if password != "" else f"{user}@"
            return f"{scheme}://{auth}{address}:{port}"
        return f"{scheme}://{address}:{port}"
    return None


def _proxy_needs_socks_auth_bridge(proxy: Optional[str]) -> bool:
    """Firefox/Camoufox cannot do SOCKS5 username/password auth natively."""
    p = _normalize_task_proxy(proxy)
    if not p:
        return False
    try:
        parsed = urlparse(p)
    except Exception:
        return False
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"socks5", "socks5h", "socks4", "socks4a"}:
        return False
    return bool(parsed.username or (parsed.password is not None and parsed.password != ""))


class _LocalProxyBridge:
    """Local no-auth HTTP CONNECT proxy that tunnels via upstream authenticated SOCKS.

    Playwright/Camoufox (Firefox) rejects ``socks5://user:pass@host`` with:
    ``Browser does not support socks5 proxy authentication``.
    We expose ``http://127.0.0.1:<port>`` (no auth) and open target connections
    through the real upstream SOCKS5 (with auth) via python-socks.
    """

    _bridges: dict = {}
    _lock: Optional[asyncio.Lock] = None

    def __init__(self, upstream_url: str):
        self.upstream_url = upstream_url
        self._server: Optional[asyncio.AbstractServer] = None
        self.host = "127.0.0.1"
        self.port = 0
        self._closed = False

    @property
    def local_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @classmethod
    async def get_or_start(cls, upstream_url: str) -> "_LocalProxyBridge":
        up = _normalize_task_proxy(upstream_url) or (upstream_url or "").strip()
        if not up:
            raise ValueError("empty upstream proxy")
        if cls._lock is None:
            cls._lock = asyncio.Lock()
        async with cls._lock:
            existing = cls._bridges.get(up)
            if existing is not None and not existing._closed and existing.port:
                return existing
            bridge = cls(up)
            await bridge.start()
            cls._bridges[up] = bridge
            return bridge

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self.host, 0
        )
        sockets = self._server.sockets or []
        if not sockets:
            raise RuntimeError("local proxy bridge failed to bind")
        self.port = int(sockets[0].getsockname()[1])
        logger.info(
            f"Local proxy bridge up {self.local_url} -> "
            f"{self._redact(self.upstream_url)}"
        )

    @staticmethod
    def _redact(url: str) -> str:
        try:
            p = urlparse(url)
            if p.username or p.password:
                host = p.hostname or ""
                port = f":{p.port}" if p.port else ""
                return f"{p.scheme}://***:***@{host}{port}"
        except Exception:
            pass
        return url

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        remote_writer = None
        try:
            # Read request line + headers until blank line.
            header_buf = b""
            while b"\r\n\r\n" not in header_buf and len(header_buf) < 65536:
                chunk = await asyncio.wait_for(client_reader.read(4096), timeout=20.0)
                if not chunk:
                    break
                header_buf += chunk
            if not header_buf:
                return
            head_text = header_buf.decode("iso-8859-1", errors="replace")
            first = head_text.split("\r\n", 1)[0]
            parts = first.split()
            if len(parts) < 2:
                client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await client_writer.drain()
                return
            method = parts[0].upper()
            target = parts[1]
            if method != "CONNECT":
                # Only CONNECT is needed for HTTPS browser traffic.
                client_writer.write(
                    b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n"
                )
                await client_writer.drain()
                return
            if ":" not in target:
                client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await client_writer.drain()
                return
            host, port_s = target.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await client_writer.drain()
                return

            # Open connection to destination via upstream authenticated SOCKS/HTTP.
            try:
                from python_socks.async_.asyncio import Proxy
            except ImportError as e:
                client_writer.write(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
                    b"python-socks not installed"
                )
                await client_writer.drain()
                logger.error(f"proxy bridge missing python-socks: {e}")
                return

            try:
                proxy = Proxy.from_url(self.upstream_url)
                sock = await asyncio.wait_for(
                    proxy.connect(dest_host=host, dest_port=port),
                    timeout=30.0,
                )
            except Exception as e:
                client_writer.write(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
                )
                await client_writer.drain()
                if self.debug_bridge():
                    logger.warning(
                        f"proxy bridge connect {host}:{port} via "
                        f"{self._redact(self.upstream_url)} failed: {e}"
                    )
                return

            remote_reader, remote_writer = await asyncio.open_connection(sock=sock)
            client_writer.write(
                b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: grokpro-bridge\r\n\r\n"
            )
            await client_writer.drain()

            # Any leftover body after headers (rare for CONNECT) goes to remote.
            leftover = header_buf.split(b"\r\n\r\n", 1)
            if len(leftover) == 2 and leftover[1]:
                remote_writer.write(leftover[1])
                await remote_writer.drain()

            await asyncio.gather(
                self._pipe(client_reader, remote_writer),
                self._pipe(remote_reader, client_writer),
                return_exceptions=True,
            )
        except Exception:
            pass
        finally:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass
            if remote_writer is not None:
                try:
                    remote_writer.close()
                    await remote_writer.wait_closed()
                except Exception:
                    pass

    @staticmethod
    async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    @staticmethod
    def debug_bridge() -> bool:
        return True

    async def close(self) -> None:
        self._closed = True
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None


COLORS = {
    'MAGENTA': '\033[35m',
    'BLUE': '\033[34m',
    'GREEN': '\033[32m',
    'YELLOW': '\033[33m',
    'RED': '\033[31m',
    'RESET': '\033[0m',
}


class CustomLogger(logging.Logger):
    @staticmethod
    def format_message(level, color, message):
        timestamp = time.strftime('%H:%M:%S')
        return f"[{timestamp}] [{COLORS.get(color)}{level}{COLORS.get('RESET')}] -> {message}"

    def debug(self, message, *args, **kwargs):
        super().debug(self.format_message('DEBUG', 'MAGENTA', message), *args, **kwargs)

    def info(self, message, *args, **kwargs):
        super().info(self.format_message('INFO', 'BLUE', message), *args, **kwargs)

    def success(self, message, *args, **kwargs):
        super().info(self.format_message('SUCCESS', 'GREEN', message), *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        super().warning(self.format_message('WARNING', 'YELLOW', message), *args, **kwargs)

    def error(self, message, *args, **kwargs):
        super().error(self.format_message('ERROR', 'RED', message), *args, **kwargs)


logging.setLoggerClass(CustomLogger)
logger: CustomLogger = logging.getLogger("TurnstileAPIServer")  # type: ignore
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)


class TurnstileAPIServer:

    def __init__(self, headless: bool, useragent: Optional[str], debug: bool, browser_type: str, thread: int, proxy_support: bool, use_random_config: bool = False, browser_name: Optional[str] = None, browser_version: Optional[str] = None):
        self.app = Quart(__name__)
        self.debug = debug
        self.browser_type = browser_type
        self.headless = headless
        self.thread_count = max(1, int(thread or 1))
        self.proxy_support = proxy_support
        self.browser_pool = asyncio.Queue()
        self.use_random_config = use_random_config
        self.browser_name = browser_name
        self.browser_version = browser_version
        self.console = Console()

        # Browser pool policy for registration reliability:
        # - TURNSTILE_LAZY=0 (default): warm browsers at startup so the first
        #   captcha is not stuck on cold start / empty pool.
        # - TURNSTILE_IDLE_SEC=0 (default): never reclaim warm browsers after
        #   idle. A short idle reclaim (old default 30s) caused mass
        #   "waiting for admission" / CAPTCHA_UNSOLVABLE when registration
        #   paused briefly between batches.
        # Opt-in memory reclaim: TURNSTILE_LAZY=1 and/or TURNSTILE_IDLE_SEC=300+
        lazy_raw = (os.getenv("TURNSTILE_LAZY", "0") or "0").strip().lower()
        self.lazy_browsers = lazy_raw not in ("0", "false", "no", "off")
        try:
            self.idle_sec = float(os.getenv("TURNSTILE_IDLE_SEC", "0") or 0)
        except (TypeError, ValueError):
            self.idle_sec = 0.0
        if self.idle_sec < 0:
            self.idle_sec = 0.0
        self._pool_ready = False
        self._pool_lock: Optional[asyncio.Lock] = None
        self._owned_browsers: list = []
        self._playwright = None
        self._camoufox = None
        self._last_used = 0.0
        self._idle_task: Optional[asyncio.Task] = None
        self._in_flight = 0

        # Initialize useragent and sec_ch_ua attributes
        self.useragent = useragent
        self.sec_ch_ua = None


        if self.browser_type in ['chromium', 'chrome', 'msedge']:
            if browser_name and browser_version:
                config = browser_config.get_browser_config(browser_name, browser_version)
                if config:
                    useragent, sec_ch_ua = config
                    self.useragent = useragent
                    self.sec_ch_ua = sec_ch_ua
            elif useragent:
                self.useragent = useragent
            else:
                browser, version, useragent, sec_ch_ua = browser_config.get_random_browser_config(self.browser_type)
                self.browser_name = browser
                self.browser_version = version
                self.useragent = useragent
                self.sec_ch_ua = sec_ch_ua

        self.browser_args = []
        if self.useragent:
            self.browser_args.append(f"--user-agent={self.useragent}")

        self._setup_routes()

    def display_welcome(self):
        """Displays welcome screen with logo."""
        self.console.clear()
        
        combined_text = Text()
        combined_text.append("\n📢 Channel: ", style="bold white")
        combined_text.append("https://t.me/D3_vin", style="cyan")
        combined_text.append("\n💬 Chat: ", style="bold white")
        combined_text.append("https://t.me/D3vin_chat", style="cyan")
        combined_text.append("\n📁 GitHub: ", style="bold white")
        combined_text.append("https://github.com/D3-vin", style="cyan")
        combined_text.append("\n📁 Version: ", style="bold white")
        combined_text.append("1.2a", style="green")
        combined_text.append("\n")

        info_panel = Panel(
            Align.left(combined_text),
            title="[bold blue]Turnstile Solver[/bold blue]",
            subtitle="[bold magenta]Dev by D3vin[/bold magenta]",
            box=box.ROUNDED,
            border_style="bright_blue",
            padding=(0, 1),
            width=50
        )

        self.console.print(info_panel)
        self.console.print()




    def _setup_routes(self) -> None:
        """Set up the application routes."""
        self.app.before_serving(self._startup)
        self.app.route('/turnstile', methods=['GET'])(self.process_turnstile)
        self.app.route('/result', methods=['GET'])(self.get_result)
        # YesCaptcha / CapSolver 兼容协议
        self.app.route('/createTask', methods=['POST'])(self.create_task)
        self.app.route('/getTaskResult', methods=['POST'])(self.get_task_result)
        # Memory/ops helpers
        self.app.route('/health', methods=['GET'])(self.health)
        self.app.route('/reclaim', methods=['POST', 'GET'])(self.reclaim)
        # Hot-resize browser pool size without killing the process.
        self.app.route('/resize', methods=['POST', 'GET'])(self.resize)
        self.app.route('/')(self.index)
        

    async def _startup(self) -> None:
        """Boot HTTP + DB; optionally warm browsers (or wait for first task)."""
        self.display_welcome()
        self._pool_lock = asyncio.Lock()
        try:
            await init_db()
            # Periodic result cleanup (independent of browsers)
            asyncio.create_task(self._periodic_cleanup())

            if self.lazy_browsers:
                logger.info(
                    f"Lazy browser mode ON — pool starts on first captcha "
                    f"(thread={self.thread_count}, idle_reclaim={self.idle_sec:.0f}s)"
                )
                if self.idle_sec > 0:
                    self._idle_task = asyncio.create_task(self._idle_reaper())
            else:
                logger.info("Starting browser initialization (eager)")
                await self._initialize_browser()
                self._pool_ready = True
                self._last_used = time.time()
                if self.idle_sec > 0:
                    self._idle_task = asyncio.create_task(self._idle_reaper())
        except Exception as e:
            logger.error(f"Failed to start turnstile solver: {str(e)}")
            raise

    @staticmethod
    def _browser_is_connected(browser) -> bool:
        """Best-effort liveness check for a pooled browser handle."""
        if browser is None:
            return False
        try:
            if hasattr(browser, "is_connected"):
                return bool(browser.is_connected())
        except Exception:
            return False
        # No is_connected API → assume still usable.
        return True

    def _drop_owned_browser(self, index, browser) -> None:
        """Remove a dead/discarded browser from ownership tracking."""
        owned = list(self._owned_browsers or [])
        kept = []
        for item in owned:
            try:
                i, b, _c = item
            except Exception:
                continue
            if i == index and b is browser:
                continue
            kept.append(item)
        self._owned_browsers = kept
        if not kept:
            # Empty ownership → force next ensure to rebuild.
            self._pool_ready = False

    async def _discard_dead_browser(self, index, browser, browser_config=None) -> None:
        """Close a disconnected browser and do NOT return it to the pool."""
        self._drop_owned_browser(index, browser)
        try:
            await self._close_maybe_async(
                browser, "close", "aclose", label=f"Browser {index}"
            )
        except Exception:
            pass
        try:
            await self._force_kill_browser(browser, index=index)
        except Exception:
            pass
        if self.debug:
            logger.warning(
                f"Browser {index}: discarded disconnected handle "
                f"(owned_left={len(self._owned_browsers or [])})"
            )

    async def _initialize_browser(self) -> None:
        """Initialize the browser and create the page pool."""
        # Drain any leftover entries before rebuilding.
        await self._drain_pool_discard()

        playwright = None
        # One Playwright driver session for the whole pool. Never call
        # AsyncCamoufox.start() N times — that starts N drivers, keeps only the
        # last browser on the wrapper, and leaves dead/orphaned connections.
        if self.browser_type in ['chromium', 'chrome', 'msedge']:
            playwright = await async_playwright().start()
            self._playwright = playwright
            self._camoufox = None
        elif self.browser_type == "camoufox":
            playwright = await camoufox_async_playwright().start()
            self._playwright = playwright
            self._camoufox = None

        browser_configs = []
        for _ in range(self.thread_count):
            if self.browser_type in ['chromium', 'chrome', 'msedge']:
                if self.use_random_config:
                    browser, version, useragent, sec_ch_ua = browser_config.get_random_browser_config(self.browser_type)
                elif self.browser_name and self.browser_version:
                    config = browser_config.get_browser_config(self.browser_name, self.browser_version)
                    if config:
                        useragent, sec_ch_ua = config
                        browser = self.browser_name
                        version = self.browser_version
                    else:
                        browser, version, useragent, sec_ch_ua = browser_config.get_random_browser_config(self.browser_type)
                else:
                    browser = getattr(self, 'browser_name', 'custom')
                    version = getattr(self, 'browser_version', 'custom')
                    useragent = self.useragent
                    sec_ch_ua = getattr(self, 'sec_ch_ua', '')
            else:
                # camoufox / other: default config labels only
                browser = self.browser_type
                version = 'custom'
                useragent = self.useragent
                sec_ch_ua = getattr(self, 'sec_ch_ua', '')


            browser_configs.append({
                'browser_name': browser,
                'browser_version': version,
                'useragent': useragent,
                'sec_ch_ua': sec_ch_ua
            })

        owned = []
        for i in range(self.thread_count):
            config = browser_configs[i]

            browser_args = [
                "--window-position=0,0",
                "--force-device-scale-factor=1"
            ]
            if config['useragent']:
                browser_args.append(f"--user-agent={config['useragent']}")

            browser = None
            if self.browser_type in ['chromium', 'chrome', 'msedge'] and playwright:
                browser = await playwright.chromium.launch(
                    channel=self.browser_type,
                    headless=self.headless,
                    args=browser_args
                )
            elif self.browser_type == "camoufox" and playwright:
                # One shared Playwright + N independent Camoufox processes.
                browser = await AsyncNewBrowser(playwright, headless=self.headless)

            if browser:
                item = (i + 1, browser, config)
                owned.append(item)
                await self.browser_pool.put(item)

            if self.debug:
                logger.info(f"Browser {i + 1} initialized successfully with {config['browser_name']} {config['browser_version']}")

        self._owned_browsers = owned
        self._pool_ready = True
        self._last_used = time.time()
        logger.info(f"Browser pool initialized with {self.browser_pool.qsize()} browsers")

        if self.use_random_config:
            logger.info(f"Each browser in pool received random configuration")
        elif self.browser_name and self.browser_version:
            logger.info(f"All browsers using configuration: {self.browser_name} {self.browser_version}")
        else:
            logger.info("Using custom configuration")

        if self.debug:
            for i, config in enumerate(browser_configs):
                logger.debug(f"Browser {i+1} config: {config['browser_name']} {config['browser_version']}")
                logger.debug(f"Browser {i+1} User-Agent: {config['useragent']}")
                logger.debug(f"Browser {i+1} Sec-CH-UA: {config['sec_ch_ua']}")

    async def _drain_pool_discard(self) -> None:
        """Empty the asyncio queue without closing browsers (caller closes)."""
        while True:
            try:
                self.browser_pool.get_nowait()
            except asyncio.QueueEmpty:
                break
            except Exception:
                break

    async def _close_maybe_async(self, obj, *method_names: str, label: str = "resource") -> bool:
        """Best-effort close helper for browser/driver objects."""
        if obj is None:
            return False
        for meth_name in method_names:
            meth = getattr(obj, meth_name, None)
            if meth is None:
                continue
            try:
                if meth_name == "__aexit__":
                    result = meth(None, None, None)
                else:
                    result = meth()
                if asyncio.iscoroutine(result):
                    await asyncio.wait_for(result, timeout=8.0)
                logger.debug(f"{label}: {meth_name} ok")
                return True
            except Exception as e:
                if self.debug:
                    logger.warning(f"{label}: {meth_name} failed: {e}")
        return False

    @staticmethod
    def _reap_zombie_children(limit: int = 256) -> int:
        """Reap exited child processes (zombies) that belong to this solver.

        Camoufox/Playwright often leave defunct children after kill/close.
        Only the parent can clear them via waitpid. Returns how many reaped.
        """
        import os as _os

        reaped = 0
        for _ in range(max(1, int(limit))):
            try:
                pid, _status = _os.waitpid(-1, _os.WNOHANG)
            except ChildProcessError:
                break
            except Exception:
                break
            if pid <= 0:
                break
            reaped += 1
        return reaped

    @staticmethod
    def _list_child_pids(parent_pid: int) -> list[int]:
        """Direct children of parent_pid (macOS/Linux, best-effort)."""
        import os as _os
        import subprocess as _sp

        parent_pid = int(parent_pid)
        out: list[int] = []
        # pgrep -P is available on macOS + most Linux.
        try:
            raw = _sp.check_output(
                ["pgrep", "-P", str(parent_pid)],
                text=True,
                stderr=_sp.DEVNULL,
            )
            for line in (raw or "").splitlines():
                s = line.strip()
                if s.isdigit():
                    out.append(int(s))
        except Exception:
            pass
        if out:
            return out
        # /proc fallback (Linux)
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
                    # fields after comm: state ppid ...
                    if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) == parent_pid:
                        out.append(int(name))
                except Exception:
                    continue
        except Exception:
            pass
        # never include self
        me = _os.getpid()
        return [p for p in out if p not in (0, 1, me)]

    @classmethod
    def _list_descendant_pids(cls, root_pid: int, *, limit: int = 2000) -> list[int]:
        """BFS descendants of root_pid."""
        seen: set[int] = set()
        queue = [int(root_pid)]
        desc: list[int] = []
        while queue and len(desc) < limit:
            cur = queue.pop(0)
            for child in cls._list_child_pids(cur):
                if child in seen or child == root_pid:
                    continue
                seen.add(child)
                desc.append(child)
                queue.append(child)
        return desc

    @staticmethod
    def _process_cmdline(pid: int) -> str:
        import subprocess as _sp

        try:
            raw = _sp.check_output(
                ["ps", "-p", str(int(pid)), "-o", "command="],
                text=True,
                stderr=_sp.DEVNULL,
            )
            return (raw or "").strip()
        except Exception:
            pass
        try:
            with open(f"/proc/{int(pid)}/cmdline", "rb") as fh:
                return fh.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except Exception:
            return ""

    @classmethod
    def _is_browser_driver_cmd(cls, cmd: str) -> bool:
        """Match Playwright/Patchright *driver* helpers only.

        IMPORTANT: do NOT match live browser binaries (camoufox / firefox /
        chromium). A previous broad marker list killed warm pool browsers
        right after /resize, leaving dead handles in the queue → mass
        CAPTCHA_FAIL / "Browser disconnected".
        """
        low = (cmd or "").lower()
        if not low:
            return False
        # Real orphan leaks are the node driver processes, not the browser UI.
        if "cli.js" in low and "run-driver" in low:
            return True
        if "playwright/driver" in low or "ms-playwright" in low:
            return True
        if "patchright/driver" in low:
            return True
        return False

    def _sweep_orphaned_driver_processes(
        self,
        *,
        force: bool = False,
        keep_max: int | None = None,
    ) -> dict:
        """Kill leaked Playwright/Camoufox helper processes under this solver.

        Root cause of 300+ leftovers: each camoufox.start() may spawn a
        ``cli.js run-driver`` that is NOT closed when the browser object is
        closed / pool resized down. After a full pool shutdown we must sweep
        all driver descendants. When the pool is warm, only excess helpers
        above keep_max are removed (force=True still sweeps all).
        """
        import os as _os
        import signal as _signal
        import time as _time

        me = _os.getpid()
        owned_n = len(self._owned_browsers or [])
        if keep_max is None:
            # Soft budget: a healthy pool should not need many more helpers than threads.
            keep_max = max(int(self.thread_count or 1) * 2, owned_n, 1)
        if force or (not self._pool_ready and owned_n == 0):
            keep_max = 0

        descendants = self._list_descendant_pids(me)
        drivers: list[tuple[int, str]] = []
        for pid in descendants:
            cmd = self._process_cmdline(pid)
            if self._is_browser_driver_cmd(cmd):
                drivers.append((pid, cmd[:180]))

        # Prefer killing oldest PIDs first (usually the leaked ones).
        drivers.sort(key=lambda x: x[0])
        to_kill = drivers if keep_max <= 0 else drivers[0 : max(0, len(drivers) - int(keep_max))]

        killed: list[int] = []
        for pid, _cmd in to_kill:
            if pid in (0, 1, me):
                continue
            try:
                _os.kill(pid, _signal.SIGTERM)
                killed.append(pid)
            except Exception:
                pass
        if killed:
            _time.sleep(0.2)
            for pid in list(killed):
                try:
                    _os.kill(pid, 0)
                except Exception:
                    continue
                try:
                    _os.kill(pid, _signal.SIGKILL)
                except Exception:
                    pass
        reaped = self._reap_zombie_children(limit=max(64, len(killed) * 2 + 16))
        remaining = 0
        for pid in self._list_descendant_pids(me):
            if self._is_browser_driver_cmd(self._process_cmdline(pid)):
                remaining += 1
        if killed and self.debug:
            logger.info(
                f"Driver sweep: killed={len(killed)} reaped={reaped} "
                f"remaining_drivers={remaining} keep_max={keep_max} force={force}"
            )
        elif killed:
            logger.info(
                f"Driver sweep: killed={len(killed)} reaped={reaped} remaining_drivers={remaining}"
            )
        return {
            "killed": len(killed),
            "killed_pids": killed[:50],
            "reaped_zombies": reaped,
            "drivers_before": len(drivers),
            "drivers_after": remaining,
            "keep_max": keep_max,
            "force": bool(force),
        }

    @staticmethod
    def _count_zombie_processes() -> int:
        """Best-effort count of zombie processes visible in this container/host."""
        try:
            with open("/proc/self/stat", "r", encoding="utf-8") as fh:
                _ = fh.read(1)
        except Exception:
            # Non-Linux: skip.
            return 0
        n = 0
        try:
            for name in os.listdir("/proc"):
                if not name.isdigit():
                    continue
                try:
                    with open(f"/proc/{name}/stat", "r", encoding="utf-8", errors="ignore") as fh:
                        stat = fh.read()
                    # comm is in parens and may contain spaces; state is after the last ')'.
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

    def _kill_process_tree(self, proc) -> None:
        """Force-kill a browser child process tree (Camoufox/Chromium leftovers)."""
        if proc is None:
            return
        pid = getattr(proc, "pid", None)
        if not pid:
            return
        try:
            import signal
            import os as _os

            # Prefer process group kill when available.
            try:
                pgid = _os.getpgid(int(pid))
                _os.killpg(pgid, signal.SIGTERM)
            except Exception:
                try:
                    _os.kill(int(pid), signal.SIGTERM)
                except Exception:
                    pass
            try:
                # Give it a moment, then hard kill.
                time.sleep(0.15)
                try:
                    pgid = _os.getpgid(int(pid))
                    _os.killpg(pgid, signal.SIGKILL)
                except Exception:
                    try:
                        _os.kill(int(pid), signal.SIGKILL)
                    except Exception:
                        pass
            except Exception:
                pass
            # Also try Popen.wait if available so the direct child is reaped.
            try:
                wait = getattr(proc, "wait", None)
                if callable(wait):
                    wait(timeout=0.2)
            except Exception:
                pass
            reaped = self._reap_zombie_children()
            if reaped and self.debug:
                logger.debug(f"kill process tree pid={pid}: reaped {reaped} zombie child(ren)")
        except Exception as e:
            if self.debug:
                logger.warning(f"kill process tree pid={pid} failed: {e}")

    async def _force_kill_browser(self, browser, index: int | None = None) -> None:
        """Hard cleanup for browsers that ignore close()/aclose()."""
        label = f"Browser {index}" if index is not None else "Browser"
        # Playwright-style browser process
        for attr in ("process", "_process"):
            proc = getattr(browser, attr, None)
            if proc is not None:
                self._kill_process_tree(proc)
                if self.debug:
                    logger.debug(f"{label}: force-killed via {attr}")
                return
        # Nested browser objects (some wrappers)
        for attr in ("browser", "_browser", "impl_obj", "_impl_obj"):
            nested = getattr(browser, attr, None)
            if nested is None or nested is browser:
                continue
            for nested_attr in ("process", "_process"):
                proc = getattr(nested, nested_attr, None)
                if proc is not None:
                    self._kill_process_tree(proc)
                    if self.debug:
                        logger.debug(f"{label}: force-killed nested {attr}.{nested_attr}")
                    return

    async def _shutdown_browsers(self) -> None:
        """Close every browser and release Playwright/Camoufox drivers."""
        items = list(self._owned_browsers or [])
        self._owned_browsers = []
        await self._drain_pool_discard()

        for index, browser, _config in items:
            closed = await self._close_maybe_async(
                browser, "close", "aclose", label=f"Browser {index}"
            )
            if not closed:
                await self._force_kill_browser(browser, index=index)
            else:
                # Even after close(), Camoufox occasionally leaves zombie children.
                # Best-effort hard cleanup when process handle is still visible.
                try:
                    await self._force_kill_browser(browser, index=index)
                except Exception:
                    pass
            if self.debug:
                logger.debug(f"Browser {index}: closed")

        if self._playwright is not None:
            try:
                await asyncio.wait_for(self._playwright.stop(), timeout=8.0)
            except Exception as e:
                if self.debug:
                    logger.warning(f"Playwright stop failed: {e}")
            self._playwright = None

        if self._camoufox is not None:
            # AsyncCamoufox may expose aclose / __aexit__; best-effort.
            await self._close_maybe_async(
                self._camoufox, "aclose", "close", "__aexit__", label="Camoufox"
            )
            self._camoufox = None

        # Reap any defunct children left after close/kill.
        reaped = self._reap_zombie_children()
        # Critical: Camoufox/Playwright leave cli.js run-driver children alive even
        # after browser.close(). Sweep them here so downsizing/reclaim never piles
        # hundreds of helper processes (root fix for 300+ leftovers).
        sweep = self._sweep_orphaned_driver_processes(force=True, keep_max=0)
        zombies = self._count_zombie_processes()
        if reaped or zombies or sweep.get("killed"):
            logger.info(
                f"Browser shutdown cleanup: reaped={reaped} "
                f"drivers_killed={sweep.get('killed', 0)} "
                f"drivers_left={sweep.get('drivers_after', 0)} "
                f"zombies_visible={zombies}"
            )

        # Idle reclaim must not keep a stuck counter forever.
        # If a solve task crashed without finally, _in_flight could block all future reclaim.
        if self._in_flight != 0:
            logger.warning(
                f"Resetting leaked in-flight counter during reclaim: was {self._in_flight}"
            )
            self._in_flight = 0

        self._pool_ready = False
        # Keep last_used as historical activity; do not bump it here or reclaim loops thrash.
        logger.info("Browser pool reclaimed (idle / rebuild)")

    def _pool_has_live_browsers(self) -> bool:
        """True when ownership still tracks at least one connected browser."""
        if not self._pool_ready:
            return False
        owned = list(self._owned_browsers or [])
        if not owned:
            return False
        for _i, browser, _c in owned:
            if self._browser_is_connected(browser):
                return True
        return False

    async def _ensure_pool(self) -> None:
        """Make sure the browser pool is warm before solving.

        Rebuild when:
        - never warmed
        - queue empty AND no live owned browsers (all disconnected/discarded)
        Do NOT rebuild while every live browser is merely checked out in-flight.
        """
        self._last_used = time.time()
        if self._pool_has_live_browsers() and self.browser_pool.qsize() > 0:
            return
        if self._pool_lock is None:
            self._pool_lock = asyncio.Lock()
        async with self._pool_lock:
            self._last_used = time.time()
            if self._pool_has_live_browsers() and self.browser_pool.qsize() > 0:
                return
            # All live browsers currently checked out — waiters will get them back.
            if self._pool_has_live_browsers() and self.browser_pool.empty() and self._in_flight > 0:
                return
            # Dead pool: queue may still hold disconnected handles. Drain+rebuild.
            logger.info(
                f"Warming browser pool (thread={self.thread_count}, type={self.browser_type}, "
                f"owned={len(self._owned_browsers or [])}, queue={self.browser_pool.qsize()}, "
                f"live={self._pool_has_live_browsers()})"
            )
            if self._pool_ready or self._owned_browsers or self._playwright or self._camoufox:
                await self._shutdown_browsers()
            await self._initialize_browser()

    async def _idle_reaper(self) -> None:
        """Close browsers after TURNSTILE_IDLE_SEC with no captcha activity."""
        # Check more frequently than idle window so reclaim is timely.
        interval = 15.0 if self.idle_sec <= 60 else min(30.0, max(10.0, self.idle_sec / 6.0))
        stuck_since = 0.0
        while True:
            try:
                await asyncio.sleep(interval)
                # Always try to reap any direct-child zombies (cheap WNOHANG).
                reaped = self._reap_zombie_children()
                if reaped and self.debug:
                    logger.debug(f"Idle reaper reaped {reaped} zombie child process(es)")
                # Never sweep drivers while captcha work is in flight / pool warm.
                # Sweeping mid-solve kills Camoufox and produces mass CAPTCHA_FAIL
                # + health timeouts under high concurrency.
                if (
                    int(self._in_flight or 0) == 0
                    and not self._pool_ready
                    and not self._owned_browsers
                ):
                    self._sweep_orphaned_driver_processes(force=True, keep_max=0)
                if self.idle_sec <= 0:
                    continue
                # Nothing warm / owned → nothing to reclaim.
                if not self._pool_ready and not self._owned_browsers:
                    stuck_since = 0.0
                    continue

                idle_for = time.time() - (self._last_used or 0.0)
                if idle_for < self.idle_sec:
                    stuck_since = 0.0
                    continue

                # Guard against leaked in-flight counters: if we have been idle longer
                # than 2x idle window and still see in-flight > 0, force reclaim.
                if self._in_flight > 0:
                    if stuck_since <= 0:
                        stuck_since = time.time()
                    stuck_for = time.time() - stuck_since
                    if stuck_for < max(self.idle_sec * 2.0, 120.0):
                        if self.debug:
                            logger.debug(
                                f"Idle reaper waiting: in_flight={self._in_flight}, "
                                f"idle={idle_for:.0f}s, stuck={stuck_for:.0f}s"
                            )
                        continue
                    logger.warning(
                        f"Idle reaper force-reclaim: in_flight stuck at {self._in_flight} "
                        f"for {stuck_for:.0f}s (idle={idle_for:.0f}s)"
                    )
                else:
                    stuck_since = 0.0

                if self._pool_lock is None:
                    self._pool_lock = asyncio.Lock()
                async with self._pool_lock:
                    idle_for = time.time() - (self._last_used or 0.0)
                    if idle_for < self.idle_sec:
                        continue
                    if self._in_flight > 0 and idle_for < max(self.idle_sec * 2.0, 120.0):
                        continue
                    owned_n = len(self._owned_browsers or [])
                    qsize = self.browser_pool.qsize()
                    logger.info(
                        f"No captcha for {idle_for:.0f}s — reclaiming "
                        f"queue={qsize} owned={owned_n} in_flight={self._in_flight}"
                    )
                    await self._shutdown_browsers()
                    stuck_since = 0.0
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Idle reaper error: {e}")

    async def _periodic_cleanup(self):
        """Periodic cleanup of old results every hour"""
        while True:
            try:
                await asyncio.sleep(3600)
                deleted_count = await cleanup_old_results(days_old=7)
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old results")
            except Exception as e:
                logger.error(f"Error during periodic cleanup: {e}")

    async def _antishadow_inject(self, page):
        await page.add_init_script("""
          (function() {
            const originalAttachShadow = Element.prototype.attachShadow;
            Element.prototype.attachShadow = function(init) {
              const shadow = originalAttachShadow.call(this, init);
              if (init.mode === 'closed') {
                window.__lastClosedShadowRoot = shadow;
              }
              return shadow;
            };
          })();
        """)



    async def _optimized_route_handler(self, route):
        """Оптимизированный обработчик маршрутов для экономии ресурсов."""
        url = route.request.url
        resource_type = route.request.resource_type

        allowed_types = {'document', 'script', 'xhr', 'fetch'}

        allowed_domains = [
            'challenges.cloudflare.com',
            'static.cloudflareinsights.com',
            'cloudflare.com'
        ]
        
        if resource_type in allowed_types:
            await route.continue_()
        elif any(domain in url for domain in allowed_domains):
            await route.continue_() 
        else:
            await route.abort()

    async def _block_rendering(self, page):
        """Блокировка рендеринга для экономии ресурсов"""
        await page.route("**/*", self._optimized_route_handler)

    async def _unblock_rendering(self, page):
        """Разблокировка рендеринга"""
        await page.unroute("**/*", self._optimized_route_handler)

    async def _find_turnstile_elements(self, page, index: int):
        """Умная проверка всех возможных Turnstile элементов"""
        selectors = [
            '.cf-turnstile',
            '[data-sitekey]',
            'iframe[src*="turnstile"]',
            'iframe[title*="widget"]',
            'div[id*="turnstile"]',
            'div[class*="turnstile"]'
        ]
        
        elements = []
        for selector in selectors:
            try:
                # Безопасная проверка count()
                try:
                    count = await page.locator(selector).count()
                except Exception:
                    # Если count() дает ошибку, пропускаем этот селектор
                    continue
                    
                if count > 0:
                    elements.append((selector, count))
                    if self.debug:
                        logger.debug(f"Browser {index}: Found {count} elements with selector '{selector}'")
            except Exception as e:
                if self.debug:
                    logger.debug(f"Browser {index}: Selector '{selector}' failed: {str(e)}")
                continue
        
        return elements

    async def _find_and_click_checkbox(self, page, index: int):
        """Найти и кликнуть по чекбоксу Turnstile CAPTCHA внутри iframe"""
        try:
            # Пробуем разные селекторы iframe с защитой от ошибок
            iframe_selectors = [
                'iframe[src*="challenges.cloudflare.com"]',
                'iframe[src*="turnstile"]',
                'iframe[title*="widget"]'
            ]
            
            iframe_locator = None
            for selector in iframe_selectors:
                try:
                    test_locator = page.locator(selector).first
                    # Безопасная проверка count для iframe
                    try:
                        iframe_count = await test_locator.count()
                    except Exception:
                        iframe_count = 0
                        
                    if iframe_count > 0:
                        iframe_locator = test_locator
                        if self.debug:
                            logger.debug(f"Browser {index}: Found Turnstile iframe with selector: {selector}")
                        break
                except Exception as e:
                    if self.debug:
                        logger.debug(f"Browser {index}: Iframe selector '{selector}' failed: {str(e)}")
                    continue
            
            if iframe_locator:
                try:
                    # Получаем frame из iframe
                    iframe_element = await iframe_locator.element_handle()
                    frame = await iframe_element.content_frame()
                    
                    if frame:
                        # Ищем чекбокс внутри iframe
                        checkbox_selectors = [
                            'input[type="checkbox"]',
                            '.cb-lb input[type="checkbox"]',
                            'label input[type="checkbox"]'
                        ]
                        
                        for selector in checkbox_selectors:
                            try:
                                # Полностью избегаем locator.count() в iframe - используем альтернативный подход
                                try:
                                    # Пробуем кликнуть напрямую без count проверки
                                    checkbox = frame.locator(selector).first
                                    await checkbox.click(timeout=2000)
                                    if self.debug:
                                        logger.debug(f"Browser {index}: Successfully clicked checkbox in iframe with selector '{selector}'")
                                    return True
                                except Exception as click_e:
                                    # Если прямой клик не сработал, записываем в debug но не падаем
                                    if self.debug:
                                        logger.debug(f"Browser {index}: Direct checkbox click failed for '{selector}': {str(click_e)}")
                                    continue
                            except Exception as e:
                                if self.debug:
                                    logger.debug(f"Browser {index}: Iframe checkbox selector '{selector}' failed: {str(e)}")
                                continue
                    
                        # Если нашли iframe, но не смогли кликнуть чекбокс, пробуем клик по iframe
                        try:
                            if self.debug:
                                logger.debug(f"Browser {index}: Trying to click iframe directly as fallback")
                            await iframe_locator.click(timeout=1000)
                            return True
                        except Exception as e:
                            if self.debug:
                                logger.debug(f"Browser {index}: Iframe direct click failed: {str(e)}")
                
                except Exception as e:
                    if self.debug:
                        logger.debug(f"Browser {index}: Failed to access iframe content: {str(e)}")
            
        except Exception as e:
            if self.debug:
                logger.debug(f"Browser {index}: General iframe search failed: {str(e)}")
        
        return False

    async def _try_click_strategies(self, page, index: int):
        strategies = [
            ('checkbox_click', lambda: self._find_and_click_checkbox(page, index)),
            ('direct_widget', lambda: self._safe_click(page, '.cf-turnstile', index)),
            ('iframe_click', lambda: self._safe_click(page, 'iframe[src*="turnstile"]', index)),
            ('js_click', lambda: page.evaluate("document.querySelector('.cf-turnstile')?.click()")),
            ('sitekey_attr', lambda: self._safe_click(page, '[data-sitekey]', index)),
            ('any_turnstile', lambda: self._safe_click(page, '*[class*="turnstile"]', index)),
            ('xpath_click', lambda: self._safe_click(page, "//div[@class='cf-turnstile']", index))
        ]
        
        for strategy_name, strategy_func in strategies:
            try:
                result = await strategy_func()
                if result is True or result is None:  # None означает успех для большинства стратегий
                    if self.debug:
                        logger.debug(f"Browser {index}: Click strategy '{strategy_name}' succeeded")
                    return True
            except Exception as e:
                if self.debug:
                    logger.debug(f"Browser {index}: Click strategy '{strategy_name}' failed: {str(e)}")
                continue
        
        return False

    async def _safe_click(self, page, selector: str, index: int):
        """Полностью безопасный клик с максимальной защитой от ошибок"""
        try:
            # Пробуем кликнуть напрямую без count() проверки
            locator = page.locator(selector).first
            await locator.click(timeout=1000)
            return True
        except Exception as e:
            # Логируем ошибку только в debug режиме
            if self.debug and "Can't query n-th element" not in str(e):
                logger.debug(f"Browser {index}: Safe click failed for '{selector}': {str(e)}")
            return False

    async def _inject_captcha_directly(self, page, websiteKey: str, action: str = '', cdata: str = '', index: int = 0):
        """Inject CAPTCHA directly into the target website"""
        script = f"""
        // Remove any existing turnstile widgets first
        document.querySelectorAll('.cf-turnstile').forEach(el => el.remove());
        document.querySelectorAll('[data-sitekey]').forEach(el => el.remove());
        
        // Create turnstile widget directly on the page
        const captchaDiv = document.createElement('div');
        captchaDiv.className = 'cf-turnstile';
        captchaDiv.setAttribute('data-sitekey', '{websiteKey}');
        captchaDiv.setAttribute('data-callback', 'onTurnstileCallback');
        {f'captchaDiv.setAttribute("data-action", "{action}");' if action else ''}
        {f'captchaDiv.setAttribute("data-cdata", "{cdata}");' if cdata else ''}
        captchaDiv.style.position = 'fixed';
        captchaDiv.style.top = '20px';
        captchaDiv.style.left = '20px';
        captchaDiv.style.zIndex = '9999';
        captchaDiv.style.backgroundColor = 'white';
        captchaDiv.style.padding = '15px';
        captchaDiv.style.border = '2px solid #0f79af';
        captchaDiv.style.borderRadius = '8px';
        captchaDiv.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.3)';
        
        // Add to body immediately
        document.body.appendChild(captchaDiv);
        
        // Load Turnstile script and render widget
        const loadTurnstile = () => {{
            const script = document.createElement('script');
            script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
            script.async = true;
            script.defer = true;
            script.onload = function() {{
                console.log('Turnstile script loaded');
                // Wait a bit for script to initialize
                setTimeout(() => {{
                    if (window.turnstile && window.turnstile.render) {{
                        try {{
                            window.turnstile.render(captchaDiv, {{
                                sitekey: '{websiteKey}',
                                {f'action: "{action}",' if action else ''}
                                {f'cdata: "{cdata}",' if cdata else ''}
                                callback: function(token) {{
                                    console.log('Turnstile solved with token:', token);
                                    // Create hidden input for token
                                    let tokenInput = document.querySelector('input[name="cf-turnstile-response"]');
                                    if (!tokenInput) {{
                                        tokenInput = document.createElement('input');
                                        tokenInput.type = 'hidden';
                                        tokenInput.name = 'cf-turnstile-response';
                                        document.body.appendChild(tokenInput);
                                    }}
                                    tokenInput.value = token;
                                }},
                                'error-callback': function(error) {{
                                    console.log('Turnstile error:', error);
                                }}
                            }});
                        }} catch (e) {{
                            console.log('Turnstile render error:', e);
                        }}
                    }} else {{
                        console.log('Turnstile API not available');
                    }}
                }}, 1000);
            }};
            script.onerror = function() {{
                console.log('Failed to load Turnstile script');
            }};
            document.head.appendChild(script);
        }};
        
        // Check if Turnstile is already loaded
        if (window.turnstile) {{
            console.log('Turnstile already loaded, rendering immediately');
            try {{
                window.turnstile.render(captchaDiv, {{
                    sitekey: '{websiteKey}',
                    {f'action: "{action}",' if action else ''}
                    {f'cdata: "{cdata}",' if cdata else ''}
                    callback: function(token) {{
                        console.log('Turnstile solved with token:', token);
                        let tokenInput = document.querySelector('input[name="cf-turnstile-response"]');
                        if (!tokenInput) {{
                            tokenInput = document.createElement('input');
                            tokenInput.type = 'hidden';
                            tokenInput.name = 'cf-turnstile-response';
                            document.body.appendChild(tokenInput);
                        }}
                        tokenInput.value = token;
                    }},
                    'error-callback': function(error) {{
                        console.log('Turnstile error:', error);
                    }}
                }});
            }} catch (e) {{
                console.log('Immediate render error:', e);
                loadTurnstile();
            }}
        }} else {{
            loadTurnstile();
        }}
        
        // Setup global callback
        window.onTurnstileCallback = function(token) {{
            console.log('Global turnstile callback executed:', token);
        }};
        """

        await page.evaluate(script)
        if self.debug:
            logger.debug(f"Browser {index}: Injected CAPTCHA directly into website with sitekey: {websiteKey}")

    def _build_context_options(self, browser_config: dict, proxy: Optional[str] = None) -> dict:
        """Build browser context options with Camoufox-safe defaults.

        ``proxy`` here must already be browser-safe (no SOCKS5 auth). Callers
        that have authenticated SOCKS should first go through
        ``_prepare_browser_proxy``.
        """
        context_options: dict = {}

        # Camoufox + newer Playwright rejects default viewport.isMobile scheme.
        # Always disable default viewport and set size after page creation.
        context_options["no_viewport"] = True

        useragent = (browser_config or {}).get("useragent")
        if useragent:
            context_options["user_agent"] = useragent

        sec_ch_ua = (browser_config or {}).get("sec_ch_ua")
        if sec_ch_ua and str(sec_ch_ua).strip():
            context_options["extra_http_headers"] = {"sec-ch-ua": str(sec_ch_ua).strip()}

        if proxy:
            proxy = _normalize_task_proxy(proxy) or proxy
            try:
                parsed = urlparse(proxy)
                scheme = (parsed.scheme or "http").lower()
                if scheme in {"socks5h"}:
                    scheme = "socks5"
                host = parsed.hostname or ""
                port = parsed.port
                if not host or port is None:
                    raise ValueError(f"proxy missing host/port: {proxy}")
                server = f"{scheme}://{host}:{port}"
                proxy_opts: dict = {"server": server}
                # HTTP(S) proxies may carry username/password; SOCKS5 auth is
                # not supported by Firefox and must be bridged beforehand.
                if scheme in {"http", "https"}:
                    if parsed.username is not None:
                        proxy_opts["username"] = unquote(parsed.username)
                    if parsed.password is not None:
                        proxy_opts["password"] = unquote(parsed.password)
                elif parsed.username or parsed.password:
                    # Should not happen if bridge ran; fail loud.
                    raise ValueError(
                        "socks proxy with auth must use local bridge first"
                    )
                context_options["proxy"] = proxy_opts
            except Exception:
                # Legacy fallbacks for non-URL forms.
                if "@" in proxy and "://" in proxy:
                    scheme_part, auth_part = proxy.split("://", 1)
                    auth, address = auth_part.rsplit("@", 1)
                    username, password = auth.split(":", 1)
                    if scheme_part.lower().startswith("socks"):
                        raise ValueError(
                            "socks proxy with auth must use local bridge first"
                        )
                    context_options["proxy"] = {
                        "server": f"{scheme_part}://{address}",
                        "username": username,
                        "password": password,
                    }
                else:
                    parts = proxy.split(":")
                    if len(parts) == 5:
                        proxy_scheme, proxy_ip, proxy_port, proxy_user, proxy_pass = parts
                        if str(proxy_scheme).lower().startswith("socks"):
                            raise ValueError(
                                "socks proxy with auth must use local bridge first"
                            )
                        context_options["proxy"] = {
                            "server": f"{proxy_scheme}://{proxy_ip}:{proxy_port}",
                            "username": proxy_user,
                            "password": proxy_pass,
                        }
                    elif "://" in proxy:
                        context_options["proxy"] = {"server": proxy}
                    else:
                        raise ValueError(f"Invalid proxy format: {proxy}")

        return context_options

    def _select_proxy(self, task_proxy: Optional[str] = None) -> Optional[str]:
        """Prefer per-task proxy (registration must share egress); else proxies.txt."""
        explicit = _normalize_task_proxy(task_proxy)
        if explicit:
            return explicit
        if not self.proxy_support:
            return None
        proxy_file_path = os.path.join(os.getcwd(), "proxies.txt")
        try:
            with open(proxy_file_path) as proxy_file:
                proxies = [line.strip() for line in proxy_file if line.strip()]
            return _normalize_task_proxy(random.choice(proxies)) if proxies else None
        except FileNotFoundError:
            return None
        except Exception as e:
            logger.error(f"Error reading proxy file: {str(e)}")
            return None

    async def _prepare_browser_proxy(self, proxy: Optional[str]) -> Optional[str]:
        """Return a Playwright-safe proxy URL for Camoufox.

        Authenticated SOCKS5 is rewritten to a local no-auth HTTP CONNECT
        bridge that tunnels through the real upstream SOCKS.
        """
        p = _normalize_task_proxy(proxy)
        if not p:
            return None
        if not _proxy_needs_socks_auth_bridge(p):
            return p
        try:
            bridge = await _LocalProxyBridge.get_or_start(p)
            if self.debug:
                logger.debug(
                    f"SOCKS5 auth proxy bridged: upstream={_LocalProxyBridge._redact(p)} "
                    f"local={bridge.local_url}"
                )
            return bridge.local_url
        except Exception as e:
            logger.error(f"Failed to start SOCKS5 auth bridge for captcha proxy: {e}")
            raise

    async def _solve_turnstile(
        self,
        task_id: str,
        url: str,
        sitekey: str,
        action: Optional[str] = None,
        cdata: Optional[str] = None,
        proxy: Optional[str] = None,
    ):
        """Solve the Turnstile challenge."""
        context = None
        page = None
        start_time = time.time()
        index = None
        browser = None
        browser_config = None
        acquired = False
        raw_proxy = self._select_proxy(proxy)
        proxy = raw_proxy

        # Mark in-flight before warm-up so the idle reaper cannot reclaim mid-acquire.
        # Always pair with the outer finally decrement — never leave this sticky.
        self._in_flight += 1
        try:
            # Bridge authenticated SOCKS5 → local HTTP CONNECT for Firefox/Camoufox.
            try:
                proxy = await self._prepare_browser_proxy(raw_proxy)
            except Exception as e:
                logger.error(f"Proxy prepare failed: {e}")
                await save_result(
                    task_id,
                    "turnstile",
                    {
                        "value": "CAPTCHA_FAIL",
                        "elapsed_time": 0,
                        "error": f"proxy_prepare_failed: {e}",
                    },
                )
                return

            try:
                await self._ensure_pool()
                self._last_used = time.time()
                index, browser, browser_config = await self.browser_pool.get()
                acquired = True
                self._last_used = time.time()
            except Exception as e:
                logger.error(f"Failed to acquire browser from pool: {e}")
                await save_result(task_id, "turnstile", {"value": "CAPTCHA_FAIL", "elapsed_time": 0, "error": str(e)})
                return

            try:
                if not self._browser_is_connected(browser):
                    # CRITICAL: never put a dead handle back into the pool.
                    # Old code re-queued disconnected browsers → infinite
                    # CAPTCHA_FAIL storm (Browser 1..N disconnected, skipping).
                    logger.warning(
                        f"Browser {index}: Browser disconnected, discarding (not returning to pool)"
                    )
                    await self._discard_dead_browser(index, browser, browser_config)
                    acquired = False
                    # Trigger rebuild on next solve if pool is now empty of live browsers.
                    if not self._pool_has_live_browsers():
                        self._pool_ready = False
                    await save_result(
                        task_id,
                        "turnstile",
                        {"value": "CAPTCHA_FAIL", "elapsed_time": 0, "error": "browser_disconnected"},
                    )
                    return
            except Exception as e:
                if self.debug:
                    logger.warning(f"Browser {index}: Cannot check browser state: {str(e)}")

            if proxy and self.debug:
                # Redact credentials in logs.
                try:
                    p = urlparse(proxy)
                    shown = f"{p.scheme}://{p.hostname}:{p.port}" if p.hostname else "(proxy)"
                except Exception:
                    shown = "(proxy)"
                logger.debug(f"Browser {index}: Creating context with proxy {shown}")
            elif self.debug:
                logger.debug(f"Browser {index}: Creating context without proxy")

            context_options = self._build_context_options(browser_config or {}, proxy)
            try:
                context = await browser.new_context(**context_options)
            except Exception as ctx_err:
                # Fallback for Camoufox protocol mismatches / stricter option sets.
                # If proxy was requested, do NOT silently drop it — fail the task so
                # registration does not mint a Turnstile token on the wrong egress.
                if proxy:
                    logger.error(
                        f"Browser {index}: new_context with proxy failed ({ctx_err}); "
                        f"refusing proxyless fallback to keep egress consistent"
                    )
                    await save_result(
                        task_id,
                        "turnstile",
                        {
                            "value": "CAPTCHA_FAIL",
                            "elapsed_time": 0,
                            "error": f"proxy_context_failed: {ctx_err}",
                        },
                    )
                    if acquired:
                        try:
                            if self._browser_is_connected(browser):
                                await self.browser_pool.put((index, browser, browser_config))
                            else:
                                await self._discard_dead_browser(index, browser, browser_config)
                                if not self._pool_has_live_browsers():
                                    self._pool_ready = False
                            acquired = False
                        except Exception:
                            pass
                    return
                if self.debug:
                    logger.warning(f"Browser {index}: new_context failed ({ctx_err}); retry minimal options")
                context = await browser.new_context(no_viewport=True)

            page = await context.new_page()

            try:
                await page.set_viewport_size({"width": 500, "height": 100})
            except Exception:
                pass

            await self._antishadow_inject(page)
            await self._block_rendering(page)
            await page.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined,
        });

        window.chrome = {
            runtime: {},
            loadTimes: function() {},
            csi: function() {},
        };
        """)

            try:
                if self.debug:
                    logger.debug(f"Browser {index}: Starting Turnstile solve for URL: {url} with Sitekey: {sitekey} | Action: {action} | Cdata: {cdata} | Proxy: {proxy}")
                    logger.debug(f"Browser {index}: Setting up optimized page loading with resource blocking")
                    logger.debug(f"Browser {index}: Loading real website directly: {url}")

                await page.goto(url, wait_until='domcontentloaded', timeout=30000)
                await self._unblock_rendering(page)

                if self.debug:
                    logger.debug(f"Browser {index}: Injecting Turnstile widget directly into target site")

                await self._inject_captcha_directly(page, sitekey, action or '', cdata or '', index)
                await asyncio.sleep(3)

                locator = page.locator('input[name="cf-turnstile-response"]')
                max_attempts = 30
                click_count = 0
                max_clicks = 10

                for attempt in range(max_attempts):
                    try:
                        try:
                            count = await locator.count()
                        except Exception as e:
                            if self.debug:
                                logger.debug(f"Browser {index}: Locator count failed on attempt {attempt + 1}: {str(e)}")
                            count = 0

                        if count == 0:
                            if self.debug and attempt % 5 == 0:
                                logger.debug(f"Browser {index}: No token elements found on attempt {attempt + 1}")
                        elif count == 1:
                            try:
                                token = await locator.input_value(timeout=500)
                                if token:
                                    elapsed_time = round(time.time() - start_time, 3)
                                    logger.success(f"Browser {index}: Successfully solved captcha - {COLORS.get('MAGENTA')}{token[:10]}{COLORS.get('RESET')} in {COLORS.get('GREEN')}{elapsed_time}{COLORS.get('RESET')} Seconds")
                                    await save_result(task_id, "turnstile", {"value": token, "elapsed_time": elapsed_time})
                                    return
                            except Exception as e:
                                if self.debug:
                                    logger.debug(f"Browser {index}: Single token element check failed: {str(e)}")
                        else:
                            if self.debug:
                                logger.debug(f"Browser {index}: Found {count} token elements, checking all")
                            for i in range(count):
                                try:
                                    element_token = await locator.nth(i).input_value(timeout=500)
                                    if element_token:
                                        elapsed_time = round(time.time() - start_time, 3)
                                        logger.success(f"Browser {index}: Successfully solved captcha - {COLORS.get('MAGENTA')}{element_token[:10]}{COLORS.get('RESET')} in {COLORS.get('GREEN')}{elapsed_time}{COLORS.get('RESET')} Seconds")
                                        await save_result(task_id, "turnstile", {"value": element_token, "elapsed_time": elapsed_time})
                                        return
                                except Exception as e:
                                    if self.debug:
                                        logger.debug(f"Browser {index}: Token element {i} check failed: {str(e)}")
                                    continue

                        if attempt > 2 and attempt % 3 == 0 and click_count < max_clicks:
                            click_success = await self._try_click_strategies(page, index)
                            click_count += 1
                            if click_success and self.debug:
                                logger.debug(f"Browser {index}: Click successful (click #{click_count}/{max_clicks})")
                            elif not click_success and self.debug:
                                logger.debug(f"Browser {index}: All click strategies failed on attempt {attempt + 1} (click #{click_count}/{max_clicks})")

                        wait_time = min(0.5 + (attempt * 0.05), 2.0)
                        await asyncio.sleep(wait_time)

                        if self.debug and attempt % 5 == 0:
                            logger.debug(f"Browser {index}: Attempt {attempt + 1}/{max_attempts} - Waiting for token (clicks: {click_count}/{max_clicks})")

                    except Exception as e:
                        if self.debug:
                            logger.debug(f"Browser {index}: Attempt {attempt + 1} error: {str(e)}")
                        continue

                elapsed_time = round(time.time() - start_time, 3)
                await save_result(task_id, "turnstile", {"value": "CAPTCHA_FAIL", "elapsed_time": elapsed_time, "error": "timeout"})
                if self.debug:
                    logger.error(f"Browser {index}: Error solving Turnstile in {COLORS.get('RED')}{elapsed_time}{COLORS.get('RESET')} Seconds")
            except Exception as e:
                elapsed_time = round(time.time() - start_time, 3)
                await save_result(task_id, "turnstile", {"value": "CAPTCHA_FAIL", "elapsed_time": elapsed_time, "error": str(e)})
                logger.error(f"Browser {index}: Error solving Turnstile: {str(e)}")
            finally:
                if self.debug:
                    logger.debug(f"Browser {index}: Closing browser context and cleaning up")

                if context is not None:
                    try:
                        await context.close()
                        if self.debug:
                            logger.debug(f"Browser {index}: Context closed successfully")
                    except Exception as e:
                        if self.debug:
                            logger.warning(f"Browser {index}: Error closing context: {str(e)}")

                try:
                    if acquired and browser is not None and index is not None:
                        if self._browser_is_connected(browser):
                            await self.browser_pool.put((index, browser, browser_config))
                            if self.debug:
                                logger.debug(f"Browser {index}: Browser returned to pool")
                        else:
                            logger.warning(
                                f"Browser {index}: Browser disconnected after solve, discarding"
                            )
                            await self._discard_dead_browser(index, browser, browser_config)
                            if not self._pool_has_live_browsers():
                                self._pool_ready = False
                except Exception as e:
                    if self.debug:
                        logger.warning(f"Browser {index}: Error returning browser to pool: {str(e)}")
        finally:
            # Always release in-flight even on early return / unexpected exception.
            if self._in_flight > 0:
                self._in_flight -= 1
            self._last_used = time.time()






    def _check_client_key(self, client_key: Optional[str]) -> Optional[dict]:
        """校验 clientKey。未设置 API_KEY 时跳过鉴权。"""
        expected = os.getenv("API_KEY", "").strip()
        if not expected:
            return None
        if not client_key or client_key.strip() != expected:
            return {
                "errorId": 1,
                "errorCode": "ERROR_KEY_DOES_NOT_EXIST",
                "errorDescription": "Invalid clientKey"
            }
        return None

    async def _enqueue_turnstile(
        self,
        url: str,
        sitekey: str,
        action: Optional[str] = None,
        cdata: Optional[str] = None,
        proxy: Optional[str] = None,
    ):
        """创建任务并异步求解，返回 (task_id, error_response)。"""
        if not url or not sitekey:
            return None, {
                "errorId": 1,
                "errorCode": "ERROR_WRONG_PAGEURL",
                "errorDescription": "Both 'url' and 'sitekey' are required"
            }

        task_id = str(uuid.uuid4())
        await save_result(task_id, "turnstile", {
            "status": "CAPTCHA_NOT_READY",
            "createTime": int(time.time()),
            "url": url,
            "sitekey": sitekey,
            "action": action,
            "cdata": cdata,
            "proxy": bool(_normalize_task_proxy(proxy)),
        })

        try:
            asyncio.create_task(
                self._solve_turnstile(
                    task_id=task_id,
                    url=url,
                    sitekey=sitekey,
                    action=action,
                    cdata=cdata,
                    proxy=proxy,
                )
            )
            if self.debug:
                logger.debug(f"Request completed with taskid {task_id}.")
            return task_id, None
        except Exception as e:
            logger.error(f"Unexpected error processing request: {str(e)}")
            return None, {
                "errorId": 1,
                "errorCode": "ERROR_UNKNOWN",
                "errorDescription": str(e)
            }

    def _format_task_result(self, task_id: str, result) -> dict:
        """统一格式化任务结果（兼容 YesCaptcha）。"""
        if not result:
            return {
                "errorId": 1,
                "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
                "errorDescription": "Task not found"
            }

        if result == "CAPTCHA_NOT_READY" or (
            isinstance(result, dict) and result.get("status") == "CAPTCHA_NOT_READY"
        ):
            return {
                "errorId": 0,
                "status": "processing",
                "taskId": task_id,
            }

        if isinstance(result, dict) and result.get("value") == "CAPTCHA_FAIL":
            return {
                "errorId": 1,
                "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
                "errorDescription": "Workers could not solve the Captcha"
            }

        if isinstance(result, dict) and result.get("value") and result.get("value") != "CAPTCHA_FAIL":
            return {
                "errorId": 0,
                "status": "ready",
                "taskId": task_id,
                "solution": {
                    "token": result["value"]
                }
            }

        return {
            "errorId": 1,
            "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
            "errorDescription": "Workers could not solve the Captcha"
        }

    async def process_turnstile(self):
        """Handle the /turnstile endpoint requests."""
        url = request.args.get('url')
        sitekey = request.args.get('sitekey')
        action = request.args.get('action')
        cdata = request.args.get('cdata')

        task_id, err = await self._enqueue_turnstile(url, sitekey, action, cdata)
        if err:
            return jsonify(err), 200
        return jsonify({"errorId": 0, "taskId": task_id}), 200

    async def get_result(self):
        """Return solved data"""
        task_id = request.args.get('id')

        if not task_id:
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_WRONG_CAPTCHA_ID",
                "errorDescription": "Invalid task ID/Request parameter"
            }), 200

        result = await load_result(task_id)
        return jsonify(self._format_task_result(task_id, result)), 200

    async def create_task(self):
        """YesCaptcha 兼容：POST /createTask"""
        try:
            body = await request.get_json(force=True, silent=True) or {}
        except Exception:
            body = {}

        auth_err = self._check_client_key(body.get("clientKey"))
        if auth_err:
            return jsonify(auth_err), 200

        task = body.get("task") or {}
        task_type = (task.get("type") or "").strip()
        # Local Camoufox solver only has one Turnstile path. Accept YesCaptcha /
        # CapSolver premium aliases (M1/M2) as Proxyless so registration clients
        # that default premium=True do not fail createTask with
        # ERROR_TASK_NOT_SUPPORTED before falling back.
        supported = {
            "TurnstileTaskProxyless",
            "TurnstileTaskProxylessM1",
            "TurnstileTaskProxylessM2",
            "TurnstileTask",
            "AntiTurnstileTaskProxyLess",
            "AntiTurnstileTaskProxyless",
            "AntiTurnstileTask",
        }
        if task_type and task_type not in supported:
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_TASK_NOT_SUPPORTED",
                "errorDescription": f"Unsupported task type: {task_type}"
            }), 200

        url = task.get("websiteURL") or task.get("websiteUrl") or task.get("url")
        sitekey = task.get("websiteKey") or task.get("sitekey") or task.get("siteKey")
        action = task.get("action") or task.get("pageAction")
        cdata = task.get("cdata") or task.get("data")
        proxy = _proxy_from_task_fields(task)

        # CapSolver 风格 metadata
        metadata = task.get("metadata") or {}
        if isinstance(metadata, dict):
            action = action or metadata.get("action")
            cdata = cdata or metadata.get("cdata")
            if not proxy:
                proxy = _proxy_from_task_fields(metadata)

        task_id, err = await self._enqueue_turnstile(
            url, sitekey, action, cdata, proxy=proxy
        )
        if err:
            return jsonify(err), 200
        return jsonify({"errorId": 0, "taskId": task_id}), 200

    async def get_task_result(self):
        """YesCaptcha 兼容：POST /getTaskResult"""
        try:
            body = await request.get_json(force=True, silent=True) or {}
        except Exception:
            body = {}

        auth_err = self._check_client_key(body.get("clientKey"))
        if auth_err:
            return jsonify(auth_err), 200

        task_id = body.get("taskId") or body.get("id")
        if not task_id:
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_WRONG_CAPTCHA_ID",
                "errorDescription": "Invalid task ID/Request parameter"
            }), 200

        result = await load_result(task_id)
        return jsonify(self._format_task_result(task_id, result)), 200

    

    async def health(self):
        """Lightweight pool status for ops / memory debugging."""
        idle_for = None
        if self._last_used:
            idle_for = round(time.time() - self._last_used, 1)
        # Health must stay cheap: registration polls this under concurrency.
        # Never scan process trees here — that blocked the event loop for seconds
        # and made every worker report "health timed out".
        return jsonify({
            "ok": True,
            "lazy": bool(self.lazy_browsers),
            "idle_sec": self.idle_sec,
            "pool_ready": bool(self._pool_ready),
            "thread": self.thread_count,
            "browser_type": self.browser_type,
            "queue": self.browser_pool.qsize(),
            "owned": len(self._owned_browsers or []),
            "in_flight": int(self._in_flight or 0),
            "idle_for_sec": idle_for,
            "zombies": 0,
        }), 200

    async def reclaim(self):
        """Force reclaim browser pool (manual memory drop).

        Refuses while captcha tasks are in-flight unless ``?force=1`` / body force.
        Auto callers must not pass force during registration.
        """
        from quart import request
        force = False
        try:
            if request.method == "POST":
                payload = await request.get_json(force=True, silent=True) or {}
                if isinstance(payload, dict):
                    force = str(payload.get("force", "")).lower() in {"1", "true", "yes"}
            if not force:
                force = str(request.args.get("force", "")).lower() in {"1", "true", "yes"}
        except Exception:
            force = False

        in_flight = int(self._in_flight or 0)
        if in_flight > 0 and not force:
            return jsonify({
                "ok": False,
                "reclaimed": False,
                "skipped": True,
                "reason": "in_flight",
                "in_flight": in_flight,
                "owned": len(self._owned_browsers or []),
                "pool_ready": bool(self._pool_ready),
                "message": f"refuse reclaim while in_flight={in_flight}; pass force=1 to override",
            }), 409

        if self._pool_lock is None:
            self._pool_lock = asyncio.Lock()
        async with self._pool_lock:
            owned = len(self._owned_browsers or [])
            qsize = self.browser_pool.qsize()
            in_flight = int(self._in_flight or 0)
            await self._shutdown_browsers()
        reaped = self._reap_zombie_children()
        sweep = self._sweep_orphaned_driver_processes(force=True, keep_max=0)
        return jsonify({
            "ok": True,
            "reclaimed": True,
            "owned_before": owned,
            "queue_before": qsize,
            "in_flight_before": in_flight,
            "pool_ready": bool(self._pool_ready),
            "owned": len(self._owned_browsers or []),
            "queue": self.browser_pool.qsize(),
            "in_flight": int(self._in_flight or 0),
            "reaped_zombies": reaped + int(sweep.get("reaped_zombies") or 0),
            "drivers_killed": int(sweep.get("killed") or 0),
            "drivers": int(sweep.get("drivers_after") or 0),
            "zombies": 0,
        }), 200

    async def resize(self):
        """Hot-resize browser pool thread count without process restart.

        Accepts JSON body ``{"thread": N}`` (POST) or query ``?thread=N`` (GET).
        Updates ``thread_count`` and rebuilds/reclaims the pool so the next
        captcha wave uses the new size. Lazy mode only updates the target and
        reclaims any warm browsers; the next solve warms N browsers.
        """
        from quart import request

        previous = int(self.thread_count or 1)
        raw = None
        try:
            if request.method == "POST":
                payload = await request.get_json(force=True, silent=True) or {}
                if isinstance(payload, dict):
                    raw = payload.get("thread", payload.get("threads", payload.get("n")))
            if raw is None:
                raw = request.args.get("thread") or request.args.get("threads") or request.args.get("n")
        except Exception:
            raw = request.args.get("thread") if hasattr(request, "args") else None

        try:
            n = max(1, min(50, int(raw if raw is not None else previous)))
        except (TypeError, ValueError):
            return jsonify({
                "ok": False,
                "error": f"invalid thread value: {raw!r}",
                "thread": previous,
                "previous_thread": previous,
            }), 400

        if n == previous:
            # Already at target; still report success so callers don't process-restart.
            # (Do not require pool_ready — lazy mode often has pool_ready=false while idle.)
            return jsonify({
                "ok": True,
                "resized": False,
                "thread": n,
                "previous_thread": previous,
                "pool_ready": bool(self._pool_ready),
                "owned": len(self._owned_browsers or []),
                "queue": self.browser_pool.qsize(),
                "lazy": bool(self.lazy_browsers),
                "message": "already at target thread count",
            }), 200

        if self._pool_lock is None:
            self._pool_lock = asyncio.Lock()
        async with self._pool_lock:
            self.thread_count = n
            owned_before = len(self._owned_browsers or [])
            # Drop any warm browsers so next ensure uses the new thread_count.
            # Always sweep drivers on downsize; upsize still reclaims warm pool first.
            if self._pool_ready or self._owned_browsers or self._playwright or self._camoufox or n < previous:
                await self._shutdown_browsers()
            else:
                # Even if pool already cold, enforce driver budget for new thread count.
                self._sweep_orphaned_driver_processes(force=True, keep_max=0)
            # Eager mode: rebuild immediately. Lazy mode: warm on first captcha.
            if not self.lazy_browsers:
                await self._initialize_browser()
                self._pool_ready = True
                self._last_used = time.time()

        # Only sweep *driver* helpers (cli.js run-driver). Never match camoufox/
        # firefox browser binaries — that used to kill a freshly warmed pool.
        # On downsize, force-sweep leftover drivers; on upsize leave warm pool alone.
        if n < previous:
            sweep = self._sweep_orphaned_driver_processes(
                force=True,
                keep_max=0 if self.lazy_browsers else max(n * 2, 1),
            )
        else:
            # Upsize/eager warm already produced live browsers — do not kill anything.
            sweep = {
                "killed": 0,
                "drivers_after": 0,
                "reaped_zombies": 0,
                "skipped": "warm_pool_preserved",
            }
        logger.info(
            f"Browser pool resized {previous} -> {n} "
            f"(lazy={self.lazy_browsers}, owned_before={owned_before}, "
            f"drivers_killed={sweep.get('killed', 0)}, drivers_left={sweep.get('drivers_after', 0)})"
        )
        return jsonify({
            "ok": True,
            "resized": True,
            "thread": int(self.thread_count),
            "previous_thread": previous,
            "pool_ready": bool(self._pool_ready),
            "owned": len(self._owned_browsers or []),
            "queue": self.browser_pool.qsize(),
            "lazy": bool(self.lazy_browsers),
            "owned_before": owned_before,
            "drivers_killed": int(sweep.get("killed") or 0),
            "drivers": int(sweep.get("drivers_after") or 0),
            "message": (
                f"resized to {n}; lazy warm on next captcha"
                if self.lazy_browsers
                else f"resized and warmed pool to {n}"
            ),
        }), 200

    @staticmethod
    async def index():
        """Serve the API documentation page."""
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Turnstile Solver API</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-900 text-gray-200 min-h-screen flex items-center justify-center">
                <div class="bg-gray-800 p-8 rounded-lg shadow-md max-w-2xl w-full border border-red-500">
                    <h1 class="text-3xl font-bold mb-6 text-center text-red-500">Welcome to Turnstile Solver API</h1>

                    <p class="mb-4 text-gray-300">支持两套协议：原生 GET，以及 YesCaptcha/CapSolver 兼容 POST。</p>

                    <h2 class="text-xl font-semibold mb-3 text-red-400">1) 原生协议</h2>
                    <ul class="list-disc pl-6 mb-4 text-gray-300">
                        <li><code>GET /turnstile?url=...&amp;sitekey=...</code> → 返回 taskId</li>
                        <li><code>GET /result?id=TASK_ID</code> → 轮询结果</li>
                    </ul>
                    <div class="bg-gray-700 p-4 rounded-lg mb-6 border border-red-500">
                        <p class="font-semibold mb-2 text-red-400">Example:</p>
                        <code class="text-sm break-all text-red-300">/turnstile?url=https://example.com&sitekey=0x4AAAA...</code>
                    </div>

                    <h2 class="text-xl font-semibold mb-3 text-red-400">2) YesCaptcha 兼容协议</h2>
                    <ul class="list-disc pl-6 mb-4 text-gray-300">
                        <li><code>POST /createTask</code></li>
                        <li><code>POST /getTaskResult</code></li>
                    </ul>
                    <div class="bg-gray-700 p-4 rounded-lg mb-6 border border-red-500">
                        <p class="font-semibold mb-2 text-red-400">createTask body:</p>
                        <pre class="text-sm text-red-300 whitespace-pre-wrap">{
  "clientKey": "optional-if-API_KEY-set",
  "task": {
    "type": "TurnstileTaskProxyless",
    "websiteURL": "https://example.com",
    "websiteKey": "0x4AAAA..."
  }
}</pre>
                    </div>


                    <div class="bg-gray-700 p-4 rounded-lg mb-6">
                        <p class="text-gray-200 font-semibold mb-3">📢 Connect with Us</p>
                        <div class="space-y-2 text-sm">
                            <p class="text-gray-300">
                                📢 <strong>Channel:</strong> 
                                <a href="https://t.me/D3_vin" class="text-red-300 hover:underline">https://t.me/D3_vin</a> 
                                - Latest updates and releases
                            </p>
                            <p class="text-gray-300">
                                💬 <strong>Chat:</strong> 
                                <a href="https://t.me/D3vin_chat" class="text-red-300 hover:underline">https://t.me/D3vin_chat</a> 
                                - Community support and discussions
                            </p>
                            <p class="text-gray-300">
                                📁 <strong>GitHub:</strong> 
                                <a href="https://github.com/D3-vin" class="text-red-300 hover:underline">https://github.com/D3-vin</a> 
                                - Source code and development
                            </p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        """


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Turnstile API Server")

    parser.add_argument('--no-headless', action='store_true', help='Run the browser with GUI (disable headless mode). By default, headless mode is enabled.')
    parser.add_argument('--useragent', type=str, help='User-Agent string (if not specified, random configuration is used)')
    parser.add_argument('--debug', action='store_true', help='Enable or disable debug mode for additional logging and troubleshooting information (default: False)')
    parser.add_argument('--browser_type', type=str, default='chromium', help='Specify the browser type for the solver. Supported options: chromium, chrome, msedge, camoufox (default: chromium)')
    parser.add_argument('--thread', type=int, default=1, help='Set the number of browser threads to use for multi-threaded mode. Increasing this will speed up execution but requires more resources (default: 1)')
    parser.add_argument('--proxy', action='store_true', help='Enable proxy support for the solver (Default: False)')
    parser.add_argument('--random', action='store_true', help='Use random User-Agent and Sec-CH-UA configuration from pool')
    parser.add_argument('--browser', type=str, help='Specify browser name to use (e.g., chrome, firefox)')
    parser.add_argument('--version', type=str, help='Specify browser version to use (e.g., 139, 141)')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Specify the IP address where the API solver runs. (Default: 127.0.0.1)')
    parser.add_argument('--port', type=str, default='5072', help='Set the port for the API solver to listen on. (Default: 5072)')
    return parser.parse_args()


def create_app(headless: bool, useragent: str, debug: bool, browser_type: str, thread: int, proxy_support: bool, use_random_config: bool, browser_name: str, browser_version: str) -> Quart:
    server = TurnstileAPIServer(headless=headless, useragent=useragent, debug=debug, browser_type=browser_type, thread=thread, proxy_support=proxy_support, use_random_config=use_random_config, browser_name=browser_name, browser_version=browser_version)
    return server.app


if __name__ == '__main__':
    args = parse_args()
    browser_types = [
        'chromium',
        'chrome',
        'msedge',
        'camoufox',
    ]
    if args.browser_type not in browser_types:
        logger.error(f"Unknown browser type: {COLORS.get('RED')}{args.browser_type}{COLORS.get('RESET')} Available browser types: {browser_types}")
    else:
        app = create_app(
            headless=not args.no_headless, 
            debug=args.debug, 
            useragent=args.useragent, 
            browser_type=args.browser_type, 
            thread=args.thread, 
            proxy_support=args.proxy,
            use_random_config=args.random,
            browser_name=args.browser,
            browser_version=args.version
        )
        app.run(host=args.host, port=int(args.port))
