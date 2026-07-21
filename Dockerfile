# grok-register-pro: app + inline turnstile solver + Camoufox
# One image = app + local turnstile solver + browser
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TZ=Asia/Shanghai \
    DEBIAN_FRONTEND=noninteractive \
    HOME=/root \
    PYTHONPATH=/app/grok-build-auth \
    GROK_REGISTER_PRO=1 \
    GROK2API_STORE_BACKEND=file \
    GROK2API_REQUIRE_SHARED_STORES=0 \
    GROK_REGISTER_PRO_HOST=0.0.0.0 \
    GROK_REGISTER_PRO_PORT=8788 \
    GROK_REGISTER_PRO_DATA_DIR=/data \
    GROK_REGISTER_PRO_DB=/data/register_pro.sqlite3 \
    GROK_REGISTER_PRO_OUTPUT_DIR=/data/outputs \
    GROK2API_CAPTCHA_PROVIDER=local \
    CAPTCHA_PROVIDER=local \
    GROK2API_LOCAL_SOLVER_URL=http://127.0.0.1:5072 \
    LOCAL_SOLVER_URL=http://127.0.0.1:5072 \
    GROK2API_INLINE_SOLVER=1 \
    TURNSTILE_HOST=127.0.0.1 \
    TURNSTILE_PORT=5072 \
    TURNSTILE_THREAD=1 \
    TURNSTILE_BROWSER_TYPE=camoufox \
    TURNSTILE_LAZY=0 \
    TURNSTILE_IDLE_SEC=0 \
    TURNSTILE_BROWSER_AUTO_FETCH=1 \
    # Browser baked into image; runtime can still use /data/cache if present
    XDG_CACHE_HOME=/opt/browser-cache \
    PLAYWRIGHT_BROWSERS_PATH=/opt/browser-cache/ms-playwright

WORKDIR /app

# Browser runtime libs for Camoufox headless
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        fonts-liberation \
        fonts-noto-color-emoji \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libcups2 \
        libdbus-1-3 \
        libdrm2 \
        libgbm1 \
        libgtk-3-0 \
        libnspr4 \
        libnss3 \
        libpango-1.0-0 \
        libx11-6 \
        libx11-xcb1 \
        libxcb1 \
        libxcomposite1 \
        libxdamage1 \
        libxext6 \
        libxfixes3 \
        libxkbcommon0 \
        libxrandr2 \
        libxshmfence1 \
        libxss1 \
        libxtst6 \
        tini \
        tzdata \
        xvfb \
        xauth \
    && ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo Asia/Shanghai > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
COPY turnstile-solver/requirements.txt /app/turnstile-solver-requirements.txt
RUN python -m pip install --no-cache-dir -U pip setuptools wheel \
    && python -m pip install --no-cache-dir -r /app/requirements.txt \
    && python -m pip install --no-cache-dir -r /app/turnstile-solver-requirements.txt \
    && find /usr/local -type d -name '__pycache__' -prune -exec rm -rf {} + \
    && rm -rf /root/.cache/pip

# Bake Camoufox into the image (version chosen by installed camoufox package).
# Fail the build if no binary landed — otherwise every container boot may
# re-download ~600MB when camoufox_ready mis-detects the bake layout.
RUN mkdir -p /opt/browser-cache /opt/browser-cache/ms-playwright \
    && XDG_CACHE_HOME=/opt/browser-cache python -m camoufox fetch \
    && test -n "$(find /opt/browser-cache/camoufox -type f \( -name camoufox-bin -o -name camoufox -o -name camoufox.exe \) 2>/dev/null | head -n 1)" \
    && echo "Camoufox browser baked into image"

COPY . /app
RUN chmod +x /app/entrypoint.sh /app/start.sh /app/scripts/fetch_browsers.sh \
    && mkdir -p /data /data/outputs /data/cache /app/turnstile-solver/logs /app/turnstile-solver/keys \
    && find /app -type d -name '__pycache__' -prune -exec rm -rf {} + \
    && find /app -type f \( -name '*.pyc' -o -name '.DS_Store' -o -name '*.log' \) -delete

VOLUME ["/data"]
EXPOSE 8788

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=8 \
  CMD curl -fsS "http://127.0.0.1:${GROK_REGISTER_PRO_PORT:-8788}${GROK_REGISTER_ADMIN_BASE_PATH:-/admin}/api/session" >/dev/null || exit 1

# tini as PID1 (baked into image): reaps orphaned Camoufox/Playwright zombies
# after browser close/kill so users don't need docker compose `init: true`.
ENTRYPOINT ["tini", "-g", "--", "/app/entrypoint.sh"]
