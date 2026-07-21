# 管理台 API：自检 / Dry-run 梳理

默认前缀：`ADMIN_BASE = /admin`（可用 `GROK_REGISTER_ADMIN_BASE_PATH` 改写）。

鉴权：

| 路径 | 鉴权 |
|------|------|
| `GET .../api/session` | 公开（探活 / 是否登录） |
| `POST .../api/auth/login` | 公开 |
| 其余 `.../api/*` | 需管理员 Cookie Session |

下文「副作用」指：会不会产生真实外部资源或改库。

---

## 1. 推荐 Dry-run 顺序（不真正批量注册）

```bash
BASE=http://127.0.0.1:8788
ADMIN=/admin

# 0) 应用探活（无需登录）
curl -fsS "$BASE$ADMIN/api/session"

# 1) 登录（首次本机可直接设密码）
curl -fsS -c cookies.txt -H 'Content-Type: application/json' \
  -d '{"password":"你的密码"}' \
  "$BASE$ADMIN/api/auth/login"

# 2) 过盾状态（容器内 5072）
curl -fsS -b cookies.txt "$BASE$ADMIN/api/local-solver/status"

# 3) 注册链路自检（核心 preflight）
curl -fsS -b cookies.txt -H 'Content-Type: application/json' \
  -d '{}' \
  "$BASE$ADMIN/api/accounts/register-email/preflight"

# 4) 代理池探测（可选，不创建账号）
curl -fsS -b cookies.txt -H 'Content-Type: application/json' \
  -d '{}' \
  "$BASE$ADMIN/api/accounts/register-email/test-proxy"

# 5) 下游导入连通性（可选）
curl -fsS -b cookies.txt -H 'Content-Type: application/json' \
  -d '{}' \
  "$BASE$ADMIN/api/grok2api/test-login"
# 或 CPA：
curl -fsS -b cookies.txt -H 'Content-Type: application/json' \
  -d '{}' \
  "$BASE$ADMIN/api/cpa/test"
```

容器内过盾直连（不经管理台）：

```bash
docker compose exec register-pro curl -fsS http://127.0.0.1:5072/health
```

---

## 2. 自检类接口一览

### 2.1 应用 / 会话

#### `GET /admin/api/session` — 应用探活

| 项 | 说明 |
|----|------|
| 鉴权 | 公开 |
| 用途 | Docker healthcheck / 是否需设密 / 是否已登录 |
| 副作用 | 无 |
| 成功示例 | `{"ok":true,"authenticated":false,"setup_required":true,...}` |

**注意**：不能代表过盾或邮箱可用，只证明 FastAPI 起来了。

#### `POST /admin/api/auth/login`

| 项 | 说明 |
|----|------|
| 鉴权 | 公开 |
| 用途 | 拿 Session Cookie；首次未设密时本机可 bootstrap 设密 |
| 副作用 | 首次设密会写 SQLite；远程首次设密默认 403 |

Body：`{"password":"..."}`

---

### 2.2 本地过盾（Turnstile / Camoufox）

#### `GET /admin/api/local-solver/status` — 过盾探活

| 项 | 说明 |
|----|------|
| 鉴权 | 登录后 |
| 用途 | 探测 `http://127.0.0.1:5072` `/health`（失败再试 `/`） |
| 副作用 | 无（只读探测） |
| 关键字段 | `ready`/`ok`、`thread`/`threads`、`pool_ready`、`lazy`、`leftovers` |

#### `POST /admin/api/local-solver/start` — 启动/确认 solver

| 项 | 说明 |
|----|------|
| 副作用 | 若未运行会拉起 `api_solver.py` 进程 |
| Body | `{"thread":1,"browser_type":"camoufox"}` |
| 说明 | Docker 下一般已由 entrypoint 拉起；ready 时 `already_running` |

#### `POST /admin/api/local-solver/cleanup` — 清理浏览器残留

| 项 | 说明 |
|----|------|
| 副作用 | **有**：默认 hard+restart，杀残留 Camoufox/Playwright 再起池 |
| 用途 | 运维按钮，不是 dry-run |

---

### 2.3 注册链路 Preflight（核心自检）

#### `POST /admin/api/accounts/register-email/preflight`

| 项 | 说明 |
|----|------|
| 鉴权 | 登录后 |
| 用途 | 管理台「自检」按钮；真正开始注册前也会跑同一套 `_check_registration_inputs` |
| Body | 与注册相同的 `RegistrationBody` 字段；空 `{}` 则用 SQLite 已存配置 |
| 返回 | `{"ok": bool, "checks": [...], "config": {...}}` |
| `ok` 规则 | 所有 `blocking=true` 的项都 `ok` 才为 true |

**`checks[]` 结构**：

```json
{
  "name": "本地过盾",
  "ok": true,
  "message": "5072 可用",
  "blocking": true,
  "detail": {}
}
```

**检查项（按代码顺序）**：

| name（逻辑） | blocking | 行为 | 是否纯 dry-run |
|--------------|----------|------|----------------|
| 本地过盾 | 是 | `probe_local_solver(5072)` | 是 |
| 邮箱服务 | 是 | 按 `mail_provider` 实测 | **多数会真实建邮箱** |
| 代理配置 | 解析失败才 blocking；无代理不阻断 | 解析代理池 | 是 |
| 协议出口 IP | 否 | `probe_egress_ip`（ipify 类） | 网络探测 |
| 过盾出口对齐 | 否 | 文案说明 local+proxy/direct | 是 |
| xAI 注册页可达 | 是 | `visit_home` + GET signup HTML | **会访问 xAI**（不建号） |

**邮箱子路径副作用（重要）**：

| mail_provider | preflight 行为 |
|---------------|----------------|
| `moemail` | 真实 `create_mailbox`（有副作用） |
| `yyds` | 优先列域名；失败则尝试 create |
| `gptmail` | 选域 + 尝试 create |
| `cfmail` | 优先列域名；否则 create |
| `duckmail` | 列公开域或 create |

> 结论：`preflight` **不是零副作用**。它不做 xAI 注册，但 **可能创建临时邮箱**。  
> 适合「上线前连通性自检」，不适合「每分钟空转」的监控。

**与真正注册的关系**：

```text
POST .../register-email
  → resolve + preflight（同一套 checks）
  → 失败：HTTP 400 + detail.preflight
  → 成功：_ensure_solver_threads → start_registration → 真实注册 worker
```

定时 `schedule/run-now` **不跑** 这套 preflight（只准备 solver + 直接 start）。

---

### 2.4 代理池测试（不注册）

#### `POST /admin/api/accounts/register-email/test-proxy`

| 项 | 说明 |
|----|------|
| 鉴权 | 登录后 |
| 用途 | 管理台「测代理」；逐条测池内代理到 xAI 路径 |
| 副作用 | **网络访问**，不创建账号、不写注册结果 |
| Body | 注册配置字段；空则用已存 proxy |
| 返回 | `ok`（全部可用才 true）、`proxy_results[]`、`available`/`unavailable` |

单条结果大致：`proxy, ok, status_code, transport, egress_ip, error, elapsed_ms`。

---

### 2.5 下游导入连通性（不上传账号也可测）

#### `POST /admin/api/grok2api/test-login`

| 项 | 说明 |
|----|------|
| 用途 | 测 Grok2API 管理登录 |
| 副作用 | 登录远端，不上传本机账号（视 store 实现） |
| Body | 配置字段；可空合并已存 |

#### `POST /admin/api/cpa/test`

| 项 | 说明 |
|----|------|
| 用途 | 测 CPA / 远程管理 Key |
| 副作用 | 访问远端 API |

#### `POST /admin/api/grok2api/remote-status` / `POST /admin/api/cpa/remote-status`

| 项 | 说明 |
|----|------|
| 用途 | 拉远端账号状态同步 |
| 副作用 | **写本地远程状态缓存**（非 dry-run） |

---

### 2.6 配置读取（只读）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `.../register-email/config` | 注册配置（含密钥字段策略以 store 为准） |
| GET | `.../grok2api/config` | Grok2API 配置 |
| GET | `.../cpa/config` | CPA 配置 |
| GET | `.../remote-backend` | 当前远程后端 grok2api/cpa |
| GET | `.../schedule/status` | 定时策略状态 + 系统负载采样 |
| GET | `.../runtime/active-tasks` | 内存中活跃任务视图 |

---

## 3. 会动真格、不算 dry-run 的接口（对照）

| 路径 | 行为 |
|------|------|
| `POST .../register-email` | 真实批量注册 |
| `POST .../schedule/run-now` | 按策略立即开一批 |
| `POST .../accounts/probe` | 对已有账号做模型探活 |
| `POST .../accounts/relogin` | 密码重登 + 过盾 |
| `POST .../grok2api/upload` / `.../cpa/upload` | 上传 Auth |
| `POST .../local-solver/cleanup` | 杀浏览器进程 |
| `DELETE .../accounts` | 删库内账号 |

---

## 4. 判定矩阵（怎么读 preflight）

| 场景 | 你应看到 |
|------|----------|
| 容器刚起、solver 未好 | `本地过盾` ok=false → 等 `/health` 或 start |
| 未配 MoeMail | `邮箱服务` ok=false blocking |
| 只配邮箱、无代理 | preflight 可 ok；`代理配置` 提示直连（非阻断） |
| 代理填了但格式错 | `代理配置` ok=false |
| 代理被墙/不可达 | `协议出口 IP` 失败（非阻断）；xAI 页检查可能 blocking 失败 |
| CF 挡注册页 | xAI 检查项 ok=false（HTML 含 challenge） |
| 全部通过 | `ok: true`，可放心点「开始注册」 |

---

## 5. 缺口与改进建议

| 缺口 | 现状 | 建议 |
|------|------|------|
| 零副作用邮箱探活 | MoeMail 等直接 create | 增加 `dry_run=1`：只鉴权/列域名，不 create |
| 聚合一键自检 | 需前端连点多个 API | 可选 `POST .../selfcheck` 串起 solver+preflight+proxy |
| 定时路径无 preflight | schedule 直接 start | 定时启动前可选轻量 solver ready 检查（已有 ensure_solver）；邮箱可加软检查 |
| 应用级 `/health` | 仅 session 公开；`/admin/api/status` 已退役 | 保持 compose 用 session 即可 |
| 纯协议 dry-run 到 create_account 前 | 无 | 高阶：`dry_run_register` 只做到 solve captcha + 建邮箱后中止 |

---

## 6. 管理台按钮 ↔ API

| UI | API |
|----|-----|
| 自检 | `POST .../register-email/preflight` |
| 测代理 | `POST .../register-email/test-proxy` |
| 开始注册 | `POST .../register-email`（内嵌 preflight） |
| 过盾状态/启动/清理 | `local-solver/*` |
| Grok2API 测登录 | `POST .../grok2api/test-login` |
| CPA 测试 | `POST .../cpa/test` |

前端：`static/admin/accounts.html` 中 `preflightRegistration` / `testProxy` 等。

---

## 7. curl 小脚本（登录后完整自检）

见同目录 `selfcheck-dryrun.sh`（Linux/macOS / Git Bash）。