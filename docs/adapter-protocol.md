# 门锁适配器（Adapter）接入协议规范

本文档定义门锁硬件适配器（Adapter）与 Maker 门禁控制台后端及 EMQX Broker 之间需要实现的完整通信协议。参考实现见 [tools/dummy-adapter/dummy_adapter.py](../tools/dummy-adapter/dummy_adapter.py)。

---

## 1. 整体接入流程

Adapter 的生命周期分为两个阶段：

1. **HTTP 引导与审批（Bootstrap）**：设备首次启动或凭据重置后，通过 HTTP 接口向后端注册自身信息与客户端证书，并轮询等待管理员在管理台（`/steward`）审批通过。
2. **MQTTS 双向长连接**：审批通过后，设备使用 **MQTT v5 + TLS mTLS** 连接 EMQX（默认端口 `8883`），接收后端下发的开锁/查询/轮换密钥/配置指令，并上报执行结果、门锁状态与在线状态。

```text
[Adapter] --(1) POST /api/adapter/register--> [Backend] (写入 pending)
[Adapter] --(2) GET  /api/adapter/status----> [Backend] (轮询直至 approved)
[Adapter] <=(3) MQTTS (MQTT v5 + mTLS)======> [EMQX] <==> [Backend]
```

---

## 2. 阶段一：HTTP 引导与审批协议

所有 HTTP 接口返回统一信封：

```json
{
  "code": "OK",
  "message": "success",
  "data": { ... },
  "requestId": "..."
}
```

### 2.1 设备注册：`POST /api/adapter/register`

设备首次上线或需要重新认领（`reset` 后）时调用。

**请求体（JSON, camelCase）**：

| 字段 | 类型 | 必填 | 约束说明 |
| :--- | :--- | :---: | :--- |
| `adapterId` | string | 是 | 匹配 `^[A-Za-z0-9_-]{1,64}$`，不能与后端保留 ID 冲突，且必须与 `certPem` 中的 Subject `CN` 完全一致 |
| `token` | string | 是 | 设备本地生成的随机密钥；长度 `>= 32`，首尾无空白，去重字节数 `>= 8` |
| `name` | string | 否 | 显示名称，长度 `<= 128`；为空时默认使用 `adapterId` |
| `model` | string | 否 | 硬件型号，长度 `<= 128` |
| `fwVersion` | string | 否 | 固件版本，长度 `<= 128` |
| `certPem` | string | 是 | 设备 X.509 客户端证书 PEM（可含中间证书链，总长 `<= 64 KiB`） |
| `ts` | integer | 是 | 当前 Unix 秒级时间戳，防重放窗口为 `\|server_now - ts\| <= 300` 秒 |
| `signature` | string | 是 | Base64 编码的私钥持有证明（PoP）签名 |

**证书与签名校验规则**：

1. `certPem` 必须由服务端配置的私有 CA（`MQTT_CA_CERT`）签发，具备 `clientAuth`（Extended Key Usage），且证书 Subject 中**有且仅有 1 个 `CN`**，其值等于 `adapterId`。
2. 签名原文为 UTF-8 字符串：
   ```text
   locker-adapter-register:v1:{adapterId}:{sha256_hex(token)}:{ts}
   ```
   其中 `sha256_hex(token)` 为 `token` 的小写十六进制 SHA-256 摘要。
3. 使用 `certPem` 对应私钥对上述原文签名并做标准 Base64 编码；后端支持以下算法：
   - `RSA PKCS#1 v1.5 (SHA-256)`
   - `RSA-PSS (SHA-256)`
   - `ECDSA P-256 (SHA-256)`
   - `ECDSA P-384 (SHA-384)`
   - `Ed25519`

**响应 `data`**：

```json
{
  "adapterId": "adapter-demo",
  "approvalStatus": "pending"
}
```

- 同一 `adapterId` 携带相同 `token` 重复注册为幂等操作，返回当前 `approvalStatus`。
- 若设备已被 `revoked` 或 `rejected`，返回 HTTP `403`（`DEVICE_REVOKED`）；若携带了不同的 `token` 尝试覆盖已存在设备，返回 `409`（`DEVICE_ALREADY_REGISTERED`）。

**设备指纹（供管理员核对）**：

设备可在本地打印指纹，方便管理员在控制台核对：
```text
fingerprint = sha256_hex(f"{adapterId}:{sha256_hex(token)}")[:16]
```

### 2.2 轮询审批状态：`GET /api/adapter/status`

注册后设备应定时（如每 `5s`）携带当前 `token` 轮询审批状态。

- **请求头**：`Authorization: Bearer <token>`
- **响应 `data`**：
  ```json
  {
    "adapterId": "adapter-demo",
    "approvalStatus": "approved",
    "mqttEndpoint": "mqtts://emqx.example.com:8883",
    "stateReportPeriodSec": 60
  }
  ```
- **状态流转**：
  - `pending`：继续等待管理员审批。
  - `approved`：停止轮询，使用返回的 `mqttEndpoint` 与 `stateReportPeriodSec` 建立 MQTTS 连接。
  - `rejected` / `revoked`：不得连接 MQTTS，需等待管理员在后台重置（`reset`）后重新注册。
  - `401 Unauthorized`：说明后台记录已被删除或重置，设备可重新调用 `POST /api/adapter/register`。

---

## 3. 阶段二：MQTTS 连接与鉴权规范

### 3.1 连接参数

- **协议版本**：MQTT **v5.0**
- **传输安全**：TLS + **mTLS 双向认证**
  - 加载私有 CA 证书校验 Broker 服务端证书。
  - 加载设备端证书（`certPem`）与私钥。
- **会话与身份**：
  - `clean_start`: `true`
  - `keepalive`: 建议 `30` 秒
  - `clientid`: 必须等于 `adapterId`
  - `username`: 必须等于 `adapterId`
  - `password`: 当前有效的 `token`（或处于轮换窗口内的 `pending_token`）
  - 注意：EMQX 会把 mTLS 客户端证书 `CN` 透传给后端鉴权接口，后端强制校验 `cert_cn == clientid == username == adapterId`。

### 3.2 遗嘱消息（LWT）

建议在 `CONNECT` 阶段配置遗嘱消息，以便异常断线时 Broker 自动通知后端：

- **Topic**：`adapter/{adapterId}/presence`
- **Payload**：`{"online": false}`
- **QoS**：`1`
- **Retain**：`false`

> **重要**：后端明确忽略所有 `retain = true` 的 MQTT 消息，Adapter 发布任何消息时都应将 `retain` 设为 `false`。

### 3.3 EMQX ACL 权限范围

已审批（`approved`）的 Adapter 仅被授予以下最小权限：

- **允许订阅（Subscribe）**：`adapter/{adapterId}/cmd`
- **允许发布（Publish）**：
  - `adapter/{adapterId}/ack`
  - `adapter/{adapterId}/result`
  - `adapter/{adapterId}/state`
  - `adapter/{adapterId}/presence`
  - `adapter/{adapterId}/error`

订阅或发布任何其他 Topic 均会被 EMQX 拒绝。

---

## 4. 阶段三：MQTT 消息格式与指令集

### 4.1 统一消息信封

除 `presence` 主题外，所有上下行消息均采用如下 JSON 信封（camelCase）：

```json
{
  "v": 1,
  "msgId": "cmd_0195...",
  "ts": 1700000000,
  "payload": { ... }
}
```

### 4.2 下行指令（订阅 `adapter/{adapterId}/cmd`，建议 QoS 2）

#### (1) 开锁指令：`unlock`（后端以 QoS 2 发布）

- **Payload**：
  ```json
  {
    "command": "unlock",
    "timeoutMs": 10000
  }
  ```
  后端同时会设置 MQTT v5 的 `Message Expiry Interval`（向上取整为秒）。
- **处理要求**：
  1. **防重放/过期检查**：校验指令 `ts` 与当前时间的偏差，若已超过有效期（如 `now - ts > max(1, timeoutMs / 1000)` 或时钟超前过多 `ts - now > 30`），不得执行开锁，应向 `/result` 回复过期错误（如 `code: "EXPIRED"`）。
  2. **执行开锁**：驱动门锁执行器开锁，并向 `adapter/{adapterId}/state` 发布最新状态（`state: "unlocked"`, `snapshot: false`）。
  3. **回复结果**：向 `adapter/{adapterId}/result`（QoS 1）发布执行结果，**`msgId` 必须与收到的 `unlock` 指令一致**。
  4. **自动回锁**：若硬件支持自动回锁，回锁后应向 `adapter/{adapterId}/state` 上报 `state: "locked"`, `snapshot: false`。

#### (2) 查询状态：`query_state`（后端以 QoS 1 发布）

- **Payload**：
  ```json
  {
    "command": "query_state"
  }
  ```
- **处理要求**：立即向 `adapter/{adapterId}/state`（QoS 1）上报当前门锁状态快照（`snapshot: true`，可复用原 `msgId`）。

#### (3) 密钥轮换：`refresh_token`（后端以 QoS 1 发布）

- **Payload**：
  ```json
  {
    "command": "refresh_token",
    "token": "<新生成的随机 token>"
  }
  ```
- **处理要求**：
  1. 校验新 `token` 合法（如长度 `>= 32`）后，**原子持久化到本地存储**并更新本地 MQTT 客户端密码。
  2. 向 `adapter/{adapterId}/ack`（QoS 1）回复确认消息，**`msgId` 必须与收到的 `refresh_token` 指令一致**，以通知后端激活新 `token`。
  3. **双凭据过渡窗口**：后端在下发 `refresh_token` 后会保留旧 `token` 与 `pending_token` 共存（默认 `PENDING_TOKEN_TTL_SEC = 600` 秒）；若设备未及发送 `/ack` 即断线，使用新 `token` 重连认证成功时，后端也会自动完成激活。

#### (4) 下发配置：`set_config`（后端以 QoS 1 发布）

后端在设备上线（`$SYS` connected 事件）或管理员修改系统策略时会下发此指令。

- **Payload**：
  ```json
  {
    "command": "set_config",
    "stateReportPeriodSec": 60
  }
  ```
- **处理要求**：更新本地状态定时上报周期为 `stateReportPeriodSec` 秒，并向 `adapter/{adapterId}/ack`（QoS 1）回复确认（复用原 `msgId`）。

---

### 4.3 上行上报（Adapter 发布）

#### (1) 开锁结果：`adapter/{adapterId}/result`（QoS 1，使用信封）

- **Payload**：
  ```json
  {
    "ok": true,
    "code": "OK",
    "message": "door unlocked"
  }
  ```
  失败时 `ok` 为 `false`，`code` 可填 `"EXPIRED"`、`"ACTUATOR_FAULT"` 等简短错误码。`msgId` 必须与对应的 `unlock` 指令一致。

#### (2) 指令确认：`adapter/{adapterId}/ack`（QoS 1，使用信封）

- **Payload**：
  ```json
  {
    "command": "refresh_token"
  }
  ```
  或 `{"command": "set_config"}`。`msgId` 必须与对应的下行指令一致。

#### (3) 门锁状态：`adapter/{adapterId}/state`（QoS 1，使用信封）

- **Payload**：
  ```json
  {
    "state": "locked",
    "snapshot": true
  }
  ```
- **合法 `state` 值**：仅限 `"locked"`、`"unlocked"`、`"unknown"`（其他值会被后端丢弃）。
- **`snapshot` 语义**：
  - `true`：连接建立后的初始上报、响应 `query_state`、或按 `stateReportPeriodSec` 周期定时心跳上报。
  - `false`：门锁实际状态发生主动变化（如开锁、关锁）时的即时上报。

#### (4) 在线状态：`adapter/{adapterId}/presence`（QoS 1，不使用信封）

直接发送裸 JSON（非信封结构）：

- 上线（MQTT `CONNACK` 成功后）：`{"online": true}`
- 正常下线或 LWT 遗嘱：`{"online": false}`

#### (5) 协议/硬件错误：`adapter/{adapterId}/error`（QoS 0，可选）

可用于上报未归属于某次具体指令的协议解析异常或硬件故障信息，后端当前会将其记录为 `warn` 级别日志以便排查。

---

## 5. 异常与断线恢复

- **MQTT 鉴权被拒（如设备在后台被 `revoke` 或 `reset`）**：Adapter 应退出 MQTTS 重连循环，回到阶段一调用 `GET /api/adapter/status` 检查审批状态，必要时等待重置后重新注册。
- **证书签发**：开发测试阶段可使用 [scripts/gen-adapter-cert.sh](../scripts/gen-adapter-cert.sh) 为指定 `adapterId` 签发独立 mTLS 客户端证书，并使用 `uv run tools/dummy-adapter/dummy_adapter.py --adapter-id <id>` 进行联调验证。
