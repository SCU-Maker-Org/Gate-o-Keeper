# Dummy Adapter (门锁适配器模拟器)

用于在没有真实门控硬件（ESP32 / 继电器）的情况下，完整验证服务端的设备接入审批、MQTTS mTLS 双向认证、QoS 2 开锁指令下发、门锁状态上报与自动关锁、以及密钥轮换流程。

在系统模型中，**Adapter 即是对物理门锁设备的统一抽象**，无需额外配置或传入 `lockId`。

## 运行方式

前置条件：宿主机已生成证书（`./scripts/gen-certs.sh ./certs`）且 Podman Compose 服务栈已启动。

```bash
# 直接通过 uv 运行（自动处理 PEP 723 依赖 paho-mqtt + requests）
uv run tools/dummy-adapter/dummy_adapter.py
```

或指定适配器 ID（需与客户端证书 CN 一致）：

```bash
uv run tools/dummy-adapter/dummy_adapter.py --adapter-id adapter-demo
```

## 联调步骤

1. 启动 Dummy Adapter 后，终端会打印 `adapterId` 与 16 位 `fingerprint`（凭证指纹），并向 `/api/adapter/register` 提交接入申请。
2. 登录管理端 `http://localhost:3000/steward`：
   - 在 **门锁适配器** 页面核对指纹后点击 **批准接入**；
   - 点击对应设备的 **编辑** 修改展示名称（如“创客空间主门”），并点击 **群组** 配置允许开锁的 Authentik 群组（如 `locker-admins`、`maker-members`）。
3. 审批通过后，Dummy Adapter 会在 5 秒内自动连上 EMQX `8883`（MQTTS mTLS）并上报状态 `locked`。
4. 切回 **门锁控制** 页面点击 **立即开锁**，模拟器收到 QoS 2 指令后回执 `OK`、将状态切为 `unlocked`，并在 `--relock-delay`（默认 5 秒）后自动恢复 `locked`。

## 常用参数

- `--relock-delay 5`：开锁后自动落锁延迟秒数
- `--state-interval 30`：定期上报状态心跳周期
- `--fail-unlock`：模拟物理执行机构故障，测试失败回执与审计记录
- 凭证与状态保存在 `tools/dummy-adapter/.state/<adapter-id>.json`（已在 `.gitignore` 忽略），如需重新注册请先在后台点击“重置”并删除对应状态文件。
