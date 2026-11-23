# LockerBackend

智能门锁后端服务（Rust + Axum + SQLx 异步 SQLite + Redis + EMQX MQTTS + Authentik OIDC）。

设计规范见 [docs/design.md](docs/design.md)。

## 目录结构

- `src/`：Rust 后端源码（`Axum` HTTP API、`SQLx` SQLite 异步层、`Redis` 防重放/JWT 吊销/互斥锁、`rumqttc` MQTTS 客户端、异步审计落库与定期清理）
- `frontend/`：前端控制台（Vue 3 + TypeScript + Vite，构建后由 Rust Axum 服务直接同源托管）
- `tools/dummy-adapter/`：硬件门锁适配器模拟器（HTTP 注册审批 + MQTTS mTLS + QoS 2 开锁响应与密钥轮换）
- `migrations/`：SQLite 数据库迁移脚本（WAL 模式）
- `deploy/emqx/`：EMQX 5.8 配置模板（8883 MQTTS mTLS + HTTP Auth/ACL 回调 + `$SYS` 上下线事件）
- `deploy/authentik/blueprints/`：Authentik OIDC Blueprint（自动初始化 `locker-admins` / `maker-members` 群组、`locker` OIDC 应用及 Back-Channel Logout）
- `scripts/gen-certs.sh`：生成私有根 CA、Broker 服务端证书、后端客户端证书与示例 Adapter 客户端证书
- `compose.yaml` / `Containerfile`：Podman Compose 编排配置（包含 `authentik-db`、`authentik-server`、`authentik-worker`、`redis`、`broker`、`backend`）

## 快速启动（Podman Compose）

1. 生成 MQTTS 证书（私有 CA + 服务端 + 客户端 mTLS 证书）：

```bash
./scripts/gen-certs.sh ./certs
```

2. 准备环境变量（填写实际密钥）：

```bash
cp .env.example .env
```

3. 使用 Podman Compose 拉起全部服务（Authentik SSO + Redis + EMQX + Rust 后端）：

```bash
podman-compose up -d --build
# 若未单独安装 podman-compose，可用 uvx 运行：
# uvx podman-compose up -d --build
```

4. 本机访问入口：
   - **Maker 门禁控制台 / 后端 API**：`http://127.0.0.1:8080/`（健康检查：`http://127.0.0.1:8080/healthz`）
   - **Authentik SSO 控制台**：`http://localhost:9000`（默认管理员用户名 `akadmin`，初始密码见 `.env` 中 `AUTHENTIK_BOOTSTRAP_PASSWORD`）
   - **Authentik OIDC Discovery**：`http://localhost:9000/application/o/locker/.well-known/openid-configuration`
   - **EMQX 控制台**：`http://127.0.0.1:18083`（MQTTS 端口 `8883`）

## 运行测试（容器化 Rust 工具链）

```bash
podman run --rm -v "$(pwd):/app:Z" -w /app docker.io/library/rust:1-slim-bookworm cargo test
```
