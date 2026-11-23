# Locker Frontend (Vue 3 + TypeScript + Vite)

独立前端单页应用（SPA），通过 `/api/*` 与 Rust 后端通信，使用 Authentik OIDC Authorization Code + PKCE 完成身份认证。

## 本地开发

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

开发服务器默认监听 `http://127.0.0.1:5173`，通过 Vite 代理将 `/api` 与 `/healthz` 转发至本地后端 `http://127.0.0.1:8080`。

## 类型检查与生产构建

```bash
npm run typecheck
npm run build
```
