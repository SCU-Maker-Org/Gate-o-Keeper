# Gate-o-Keeper 社团门禁

访客在门口扫描 NTAG 424 DNA 贴纸，打开申请页，转发给有权限的成员。成员能看到门编号，确认后，服务为这次扫描发送一条开门指令。成员本人在门口扫描时，已登录且浏览器能标识直接打开的页面会自动提交；其他浏览器保留确认按钮。所有开门申请都源自通过校验的贴纸数据。

项目使用 Python 3.13、Flask、SQLite 和 uv。登录遵循 OpenID Connect（OIDC），内置 Authentik 和通用 HTTP 权限适配器。默认继电器为模拟实现，页面和数据库均标明模拟结果。

## 安装和运行

```sh
uv sync --locked
uv run pytest -q
cp gate.example.toml gate.toml
```

在 `gate.toml` 填写实际站点域名、认证服务、成员组和贴纸配置。数据库路径相对于该配置文件。进程从环境读取以下密钥，可以在本地未纳入 Git 的 `.env` 中设置。

| 环境变量 | 用途 |
| --- | --- |
| `GATE_SECRET` | 本站页面签名。生成一次并持久保存 |
| `GATE_WEBHOOK_SECRET` | 推送端和门禁共享的独立随机密钥 |
| `GATE_OIDC_SECRET` | 门禁 OIDC 客户端密钥 |
| `GATE_DIRECTORY_TOKEN` | 读取权限目录的服务账号令牌 |
| `GATE_CLUB_META_KEY`、`GATE_CLUB_FILE_KEY` | 示例门对应的两把贴纸密钥，每把 32 个十六进制字符。环境变量名可按门配置 |

前两项各自用 `openssl rand -hex 32` 生成。贴纸密钥必须与实际个性化配置一致。保管好环境文件和数据库，限制服务账号以外的读取权限。

```sh
uv run --env-file .env gate-o-keeper --config gate.toml
```

入口默认监听 `127.0.0.1:8000`，同时启动权限轮询。用 HTTPS 反向代理对外服务，保留原始 Host。浏览器只通过 HTTPS 传送本站会话。一个数据库运行一个服务进程，由 Waitress 线程处理并发请求。代理日志应省略扫描参数、申请链接、认证回调和 Cookie。只运行本地测试无需配置域名、密钥或外部服务。

## 配置 Authentik

1. 建立 OIDC 机密客户端，配置签名密钥、授权码流程和严格匹配的回调地址 `https://你的门禁域名/auth/callback`。示例使用按应用区分的签发者（issuer），末尾斜杠须与发现文档一致。使用全局签发者时，可另设 `oidc.discovery_url` 指向该应用的发现文档。[Authentik OIDC 配置](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)
2. 新增作用域映射（scope mapping），作用域名为 `door-directory`，表达式为 `return {"door_directory_id": str(request.user.pk)}`。将其分配给提供方并启用 **Include claims in id_token**。门禁用已签名的 `sub` 标识账号，用 `door_directory_id` 查询目录，用户名和邮箱都可以变更。[Authentik 属性映射](https://docs.goauthentik.io/add-secure-apps/providers/property-mappings/)
3. 填写有开门权限的组 UUID，并授予服务账号读取相关用户与组成员关系的权限。适配器读取 `GET /api/v3/core/users/{id}/`，要求账号启用且返回的 `groups` 包含配置 UUID。此版本同一站点下的门共用这条授权规则。需要继承组、应用策略或按其他业务条件判断时，可让通用权限接口返回最终授权结果。[Authentik 用户接口](https://api.goauthentik.io/reference/core-users-retrieve/)
4. 在 Authentik 的通知规则中匹配用户停用、删除及成员关系变化等相关事件，关联通用 Webhook 通知传输与接收组。目标地址为 `https://你的门禁域名/webhooks/permissions`。请求头映射返回 `{"Authorization": "Bearer <这里填写独立推送密钥>"}`，请求体映射返回 `{"event": "refresh"}`，两段映射在 Authentik 中均使用 `return`。这会触发对全部有效会话的权限复核，适用于组变动，也无需把事件操作者映射成受影响的成员。[通知传输与映射](https://docs.goauthentik.io/sys-mgmt/events/transports) · [通知规则](https://docs.goauthentik.io/sys-mgmt/events/notifications)

## 配置贴纸

示例门的动态地址为 `https://你的门禁域名/d/club?e=<32位十六进制>&c=<16位十六进制>`。本项目实现 NXP AN12196 表 4 的 AES 安全动态消息（Secure Dynamic Messaging，SDM）配置。开启加密 PICCData 中的七字节 UID 和三字节读取计数镜像，使用空的消息认证码输入区间，即 `SDMMACInputOffset == SDMMACOffset`。写卡时按实际 NDEF 字节布局计算偏移，服务端登记相同 UID 和密钥。测试含官方已知答案向量。其他文件布局需要相应的校验器。[NXP AN12196](https://www.nxp.com/docs/en/application-note/AN12196.pdf)

**贴纸计数和开门记录分开保存。** 芯片在符合条件的读取时递增自己的计数。服务端只有收到控制器确认才推进该贴纸的成功开门计数，允许中间跳号。一次扫描计数为 61 时，访客打开、转发、成员登录都可以使用 61；成功开门后，61 和更早的计数都失效。模拟模式在测试数据库中执行同样的状态转换。

申请的默认有效期为 180 秒，从服务端**首次见到**有效扫描数据开始，重复访问不会延长。SDM 数据没有可信的扫描时间。此前读取、一直没有提交且计数仍领先的原始链接，第一次提交时仍可能有效。因此该设计证明有人读过贴纸，无法单独证明那个人此刻仍在门前。[NTAG 424 DNA 数据手册 §9.3](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf)

## 会话和离线权限

- 新登录使用授权码、代码交换证明密钥（PKCE）、状态值和随机数完成 OIDC 验证，并实时查询权限源。认证令牌不落库。本站签发随机会话 Cookie，SQLite 仅保存其摘要及到期时间。
- 默认会话有效 8 小时，每轮权限复核完成后间隔 60 秒再查。用户退出、查询确认失权或收到撤销事件时，本地会话失效。每次开门前在事务内重新检查会话、授权、期限和扫描状态。
- 成功开门且权限结果近期有效时，响应重新设置 Cookie，数据库写入同一到期时刻。续期上限为最后成功复核权限后的 24 小时。权限查询开始即暂停该账号续期，查询失败保持暂停。老会话在原到期时间和离线上限中较早的时刻失效。轮询本身不会为闲置设备续期。
- 推送支持 `{"event":"refresh"}`（排队复核全部有效会话，返回 202），也支持指定 OIDC 主体的 `{"event":"refresh","subject":"..."}`（同步复核）和 `{"event":"revoke","subject":"..."}`（立即撤销该账号已有会话）。重新登录仍以权限源为准。服务使用版本号丢弃被后续撤销或查询替代的旧响应。

## 更换平台与继电器

任何支持 OIDC 发现、签名身份令牌和 S256 PKCE 的兼容提供方都可以作为登录入口。另一套权限目录可以通过如下配置接入，并按需调整 `oidc.scope`。

```toml
[permissions]
backend = "http"
url = "https://directory.example/door-access"
lookup_claim = "sub"
```

门禁向该地址发送带 Bearer 令牌的 `GET ?subject=...`，预期响应为 `{"subject":"同一查询标识","allowed":true}`。返回 `false` 或 HTTP 404 表示无权限；超时、其他错误状态或响应格式异常按上游不可用处理。Python 集成也可通过 `create_app(settings, source=..., relay=...)` 注入适配器。

继电器接口位于 `src/gate_o_keeper/hardware.py`。实现 `DoorRelay.unlock(door, command_id)`，在配置文件**顶层**填写 `relay_factory = "已安装模块:无参数工厂函数"`。工厂返回适配器实例。MQTTS 主题、载荷及设备应答与硬件方确定后放在这个适配器中。适配器应设置超时、验证 TLS 证书，让设备按指令 ID 去重，并在收到对应的设备执行确认后返回 `RelayResult.CONFIRMED`。

服务先持久化指令编号并占用本次扫描，再调用继电器。超时记为 `unknown`；发送前后进程中断可能留下 `dispatching`。这两种情形均保留审计记录，同一次扫描不会重发，成功计数也不会因此前移。现场可用指令编号对照设备日志。SQLite 中的计数和指令历史需要持久化，恢复旧备份可能使已经使用的计数再次有效。

## 验证

```sh
uv run pytest -q
uv run ruff check src tests
uv build
```

测试使用临时 SQLite、模拟身份提供方和测试继电器，覆盖签名登录回调、官方贴纸向量、转发确认、并发提交、设备超时、离线续期和撤权竞态。真实贴纸、社团 Authentik 实例及 MQTTS 继电器需要在现场联调。
