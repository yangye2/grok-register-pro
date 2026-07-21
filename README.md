# grok-register-pro

协议注册机 Pro：SQLite 账号池、管理后台、SSO/Auth/CPA 导出，支持推送 Grok2API / CPA / Sub2API。

镜像内置：

- 注册 API + Web 管理台
- SQLite 账号库（运行时挂载数据目录）
- Camoufox 过盾浏览器（构建时 bake 到 `/opt/browser-cache`）
- 容器内联 Turnstile Solver（仅 `127.0.0.1:5072`，不对宿主机暴露）

---

## 快速部署（Docker）

```bash
cp .env.example .env
# 编辑 .env：管理员密码、邮箱、代理等

mkdir -p ./data/register_pro
docker compose up -d --build
docker compose logs -f
```

管理台：

```text
http://127.0.0.1:8788/admin/accounts
```

首次可在 Web 设密码，或在 `.env` 预置：

```bash
GROK_REGISTER_ADMIN_BOOTSTRAP_PASSWORD='change-me-strong-password'
```

### 镜像

```bash
docker pull ghcr.io/yangye2/grok-register-pro:latest
# or
docker pull yangye2/grok-register-pro:latest
```

```bash
GROK_REGISTER_IMAGE=ghcr.io/yangye2/grok-register-pro:latest
docker compose up -d
```

---

## 数据目录

默认挂载：`./data/register_pro` -> 容器 `/data`

```text
data/register_pro/
  register_pro.sqlite3   # auto-created on start
  backups/
  outputs/
  cache/
  register_sso/
```

```bash
GROK_REGISTER_HOST_DATA_DIR=/var/lib/grok-register-pro
```

> 数据库与表结构启动时自动初始化。

---

## 常用环境变量

完整示例见 `.env.example`。

| 变量 | 说明 | 默认 |
|------|------|------|
| `GROK_REGISTER_PRO_PORT` | 端口 | `8788` |
| `GROK_REGISTER_HOST_DATA_DIR` | 宿主机数据目录 | `./data/register_pro` |
| `GROK_REGISTER_ADMIN_BOOTSTRAP_PASSWORD` | 首次管理员密码 | empty |
| `GROK2API_XAI_PROXY_POOL` | 注册代理池 | empty |
| `TURNSTILE_THREAD` | 过盾并发 | `1` |
| `TURNSTILE_LAZY` / `TURNSTILE_IDLE_SEC` | Docker 建议 `0`/`0` | `0`/`0` |

---

## 功能

- 协议注册：邮箱验证码 + 本地 Turnstile + SSO -> OAuth
- 邮箱：MoeMail / YYDS / GPTMail / CFMail / DuckMail / Outmail
- 账号池：测活、重登、远端状态
- 导出：SSO / Grok2API Auth / CPA
- 推送：Grok2API、CPA、Sub2API（成功后打已推送标记）

---

## 过盾

- 镜像 bake Camoufox 到 `/opt/browser-cache`
- 需要 `shm_size: 1gb` + `seccomp:unconfined`（compose 已配）
- Solver 仅容器内 `127.0.0.1:5072`

```bash
curl -fsS http://127.0.0.1:8788/admin/api/session
docker compose exec register-pro curl -fsS http://127.0.0.1:5072/health
```

---

## 常用命令

```bash
docker compose up -d --build
docker compose logs -f
docker compose restart
docker compose down
docker compose exec register-pro bash
```

---

## GitHub Actions

`.github/workflows/docker-image.yml`

- push `main`/`master` 或 tag `v*` 自动构建
- 默认推送 `ghcr.io/yangye2/grok-register-pro`
- Docker Hub：Secret `DOCKERHUB_TOKEN`（用户默认 yangye2）

```bash
docker build -t yangye2/grok-register-pro:latest .
docker push yangye2/grok-register-pro:latest
./scripts/publish_dockerhub.sh
```

---

## 本机启动（Linux/macOS）

> Windows 请用 Docker。

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r turnstile-solver/requirements.txt
./turnstile-solver/start.sh
./start.sh
```

- 管理台：http://127.0.0.1:8788/admin/accounts
- 数据：`./data/register_pro/`

---

## 项目结构

```text
register_pro_app.py / register_pro_store.py / register_pro_config.py
grok_build_adapter.py
moemail.py / outmail_client.py / cpa_to_sub2api.py
turnstile-solver/  static/admin/
Dockerfile  docker-compose.yml
```
