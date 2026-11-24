# AGENTS.md — LockerBackend 开发与协作指南

本仓库为 Maker 门禁控制台后端与管理台项目，技术栈包括 **Rust (`Axum` + `SQLx` SQLite + `Redis` + `rumqttc`)**、**Vue 3 + TypeScript + Vite**、**EMQX 5.8 (MQTTS mTLS)** 与 **Authentik (OIDC PKCE)**。

开始较大改动前，建议先对照权威设计文档 [docs/design.md](docs/design.md)。

---

## 1. 核心领域模型

- **双层抽象：`Lock`（门锁）→ `Adapter`（门锁适配器）**：
  - `Lock`（数据库表 `locks`）是位于适配器上层的逻辑门锁抽象（如 `101门锁`），拥有显示名称 `name`、描述 `description`、`adapter_id`（1对1 唯一可空外键 `ON DELETE SET NULL`）及 `lock_group_rules`（与 Authentik 用户组的多对多访问控制规则）。
  - `Adapter`（数据库表 `adapters`）负责底层硬件通信与生命周期：显示名称 `name`、审批状态 `approval_status`、在线状态 `online_status`、硬件状态 `reported_state` / `state_reported_at` 与 token 凭证哈希。
- 成员侧业务路由围绕 `lockId`：`/api/me`、`/api/locks/:id/status`、`/api/unlock`；管理端同时提供 `/api/admin/locks/*`（建锁、绑适配器、群组授权、紧急开锁）与 `/api/admin/adapters/*`（硬件审批、密钥轮换、吊销/重置）。

---

## 2. 目录导航

- `src/`：Rust 后端源码
  - `main.rs` / `lib.rs` / `state.rs` / `config.rs` / `error.rs` / `utils.rs`：服务启动、路由装配、应用状态、配置、统一错误码与无状态基础工具函数
  - `db/`（`mod.rs` / `locks.rs` / `adapters.rs` / `users.rs` / `audit.rs` / `config.rs`）：SQLite (`WAL` 模式) 异步数据访问层，启动时通过 `sqlx::migrate!("./migrations")` 自动建表
  - `redis_store.rs`：防重放 `nonce`、JWT/会话吊销、限流计数（`rl:*`）、开锁互斥锁（`adapter:busy:{adapter_id}`）与状态缓存
  - `auth/`（`mod.rs` / `jwt.rs` / `oidc.rs` / `authentik_api.rs` / `adapter_cert.rs`）：Authentik OIDC PKCE 换票、JWT 签发与校验、Back-Channel Logout、Authentik 用户查询与设备证书签名校验
  - `mqtt.rs`：`rumqttc` 纯 MQTTS 传输层、指令信封下发（`unlock` / `query_state` / `refresh_token` / `set_config`）、EMQX 踢人 HTTP 调用与入站报文解码（`InboundMqttEvent`）
  - `audit.rs`：异步审计日志落库与保留期自动清理
  - `services/`：业务编排层
    - `adapter/`（`bootstrap.rs` / `emqx_auth.rs` / `mqtt_events.rs` / `admin.rs`）：设备注册与状态轮询、EMQX Auth/ACL 鉴权、MQTT 事件消费与密钥定时轮换、管理员生命周期管理
    - `lock/`（`dispatch.rs` / `user.rs` / `admin.rs`）：开锁互斥调度与指令下发、成员门锁列表/状态/开锁、管理员建锁/绑定/群组授权/紧急开锁
    - `auth.rs` / `config.rs` / `audit.rs` / `users.rs`：登录刷新/Webhook/注销、系统策略更新、审计查询、成员管理
  - `routes/`：`mod.rs`（路由装配、`ClientIp`/`AdminContext` 提取器与安全响应头）、`user.rs`、`adapter.rs`、`auth.rs`、`internal_mqtt.rs`（EMQX Auth/ACL 回调）、`admin/`（`locks.rs` / `adapters.rs` / `audit.rs` / `users.rs` / `config.rs`）
- `migrations/`：`0001_init.sql`（编译期内嵌进二进制，且 `Containerfile` 构建依赖该目录）
- `tests/`：`backend_tests.rs`（DB/审计/状态投影测试）与 `http_tests.rs`（Axum 路由集成测试与基础配置/鉴权工具单测）
- `frontend/`：Vue 3 前端控制台（由根目录 `Containerfile` 构建后直接交由 Axum `ServeDir` 同源托管于 `backend:8080`）
  - `src/views/AccessView.vue`（`/access` 成员门锁控制页）
  - `src/views/StewardView.vue`（`/steward` 管理员侧边栏控制台，按 Tab 拆分为 `components/steward/{LocksTab,AdaptersTab,AuditLogsTab,UsersTab,PolicyTab}.vue`）
  - `src/lib/api.ts`、`src/lib/adminApi.ts`、`src/stores/session.ts`
- `tools/dummy-adapter/`：`dummy_adapter.py` 硬件模拟器，用于联调注册审批、MQTTS mTLS 上线、QoS 2 开锁及 token 轮换
- `deploy/`：`deploy/emqx/`（EMQX 配置模板）与 `deploy/authentik/blueprints/locker.yaml`
- `scripts/gen-certs.sh`：生成私有 CA、Broker、Backend 及示例 Adapter 证书；`scripts/gen-adapter-cert.sh`：为指定 `adapterId` 签发独立 mTLS 客户端证书

---

## 3. 架构与编码约定

1. **HTTP 接口规范**
   - 外部与管理接口**严格仅使用 `GET` 和 `POST`**（禁止新增 `PUT` / `PATCH` / `DELETE`）。
   - 所有接口返回统一信封 `{ "code": "OK", "message": "success", "data": ..., "requestId": "..." }`。

2. **认证、权限与防重放**
   - 身份认证走 Authentik OIDC + PKCE，**不实现 TOTP**。
   - 管理员角色由 Authentik 群组映射（配置项 `admin_groups`）；普通成员能否操作某个门锁完全由 `lock_group_rules` 中的群组交集决定。
   - `/api/unlock` 必须校验 `ts` 时间窗口、`nonce` 防重放及 `adapter:busy:{adapter_id}` 互斥锁。
   - 审计日志默认保留 90 天，可通过系统配置（`/api/admin/config`）调整。

3. **Adapter 与 EMQX 约束**
   - `adapterId` 必须与设备 mTLS 客户端证书 `CN` 一致，同时配合设备 token 哈希校验。
   - MQTTS（`8883`）发布开锁指令使用 QoS 2，`query_state` 与 `refresh_token` 使用 QoS 1。

4. **前端按需加载与命名规范**
   - `/access` 与 `/steward` 必须保持路由级动态 `import()` 懒加载，`adminApi.ts` 仅由 `StewardView.vue` 引用，确保普通成员不下载管理端 chunk。
   - 界面标题统一为 **Maker 门禁控制台**，设备统一称作**门锁适配器**。

5. **数据库变更策略**
   - 当前系统处于未上线阶段：修改表结构时直接更新 `migrations/0001_init.sql`，本地验证重建 `lockerbackend_backend_data` 卷即可（注意同步检查 `Containerfile` 与 `src/db.rs`）。

6. **敏感文件**
   - 切勿修改或提交真实密钥与证书资产（`.env`、`certs/`、`ca-private/`、`tools/dummy-adapter/.state/`）。

---

## 4. 常用命令

### 后端构建与测试

```bash
# 运行全部 Rust 单元与集成测试（使用 sqlite::memory: 与测试桩）
cargo test --no-fail-fast
```

### 前端类型检查与构建

```bash
cd frontend
npm run typecheck
npm run build
```

### 容器栈编排（Podman Compose）

```bash
# 首次生成 MQTTS mTLS 证书与环境变量
./scripts/gen-certs.sh ./certs
cp .env.example .env

# 启动或全量重建全部服务
uvx podman-compose up -d --build

# 仅重建并重启后端（含前端静态资源）容器
uvx podman-compose up -d --build --no-deps --force-recreate backend

# 查看服务健康状态与后端日志
podman ps --format "table {{.Names}}\t{{.Status}}"
podman logs --tail 50 lockerbackend_backend_1
```

若修改了 `migrations/0001_init.sql` 需要重建本地 SQLite 库卷：

```bash
podman rm -f lockerbackend_backend_1
podman volume rm -f lockerbackend_backend_data
uvx podman-compose up -d --build --no-deps --force-recreate backend
```

### 联调 Dummy Adapter

```bash
uv run tools/dummy-adapter/dummy_adapter.py --adapter-id adapter-demo
```

若高频自动化测试触发 Redis 限流，可按需清理限流键：

```bash
podman exec lockerbackend_redis_1 sh -c 'redis-cli --scan --pattern "rl:*" | xargs -r redis-cli del'
```
