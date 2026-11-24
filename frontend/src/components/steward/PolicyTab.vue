<script setup lang="ts">
import { reactive, ref, watch } from 'vue'
import { adminApi } from '../../lib/adminApi'
import type { RateLimitConfig, SystemConfig } from '../../types/api'

const props = defineProps<{
  config: SystemConfig
  busy: boolean
}>()

const emit = defineEmits<{
  'update:busy': [val: boolean]
  success: [text: string]
  error: [err: unknown]
  configUpdated: [cfg: SystemConfig]
}>()

function defaultRateLimits(): RateLimitConfig {
  return {
    unlockUser: { max: 5, windowSec: 60 },
    unlockIp: { max: 20, windowSec: 60 },
    ssoExchangeIp: { max: 10, windowSec: 60 },
    adapterRegisterId: { max: 3, windowSec: 3600 },
    adapterRegisterIp: { max: 10, windowSec: 60 },
    adapterStatusId: { max: 12, windowSec: 60 },
    adapterStatusIp: { max: 30, windowSec: 60 },
    mqttConnClient: { max: 10, windowSec: 60 },
  }
}

const RATE_LIMIT_META: {
  key: keyof RateLimitConfig
  label: string
  hint: string
}[] = [
  { key: 'unlockUser', label: '开锁请求（按用户）', hint: 'POST /api/unlock 按成员限制' },
  { key: 'unlockIp', label: '开锁请求（按来源 IP）', hint: 'POST /api/unlock 按客户端 IP 限制' },
  { key: 'ssoExchangeIp', label: 'SSO 换票（按来源 IP）', hint: 'POST /api/auth/sso-exchange 限制' },
  { key: 'adapterRegisterId', label: '适配器注册（按设备 ID）', hint: 'POST /api/adapter/register 单设备限制' },
  { key: 'adapterRegisterIp', label: '适配器注册（按来源 IP）', hint: 'POST /api/adapter/register 单 IP 限制' },
  { key: 'adapterStatusId', label: '适配器状态轮询（按设备 ID）', hint: 'GET /api/adapter/status 轮询频率限制' },
  { key: 'adapterStatusIp', label: '适配器状态轮询（按来源 IP）', hint: 'GET /api/adapter/status 预认证 IP 限制' },
  { key: 'mqttConnClient', label: 'MQTTS 建连鉴权（按 Client ID）', hint: 'EMQX Auth 回调建连频率限制' },
]

const configForm = reactive<SystemConfig>({
  unlockReplayWindowSec: 60,
  commandTimeoutMs: 10000,
  maxDevicesPerUser: 3,
  auditRetentionDays: 90,
  offlineUnknownSec: 300,
  stateReportPeriodSec: 60,
  adminGroups: ['locker-admins'],
  rateLimits: defaultRateLimits(),
})
const adminGroupsInput = ref('locker-admins')

watch(
  () => props.config,
  (cfg) => {
    Object.assign(configForm, JSON.parse(JSON.stringify(cfg)))
    adminGroupsInput.value = cfg.adminGroups.join(', ')
  },
  { immediate: true, deep: true },
)

function splitGroups(input: string): string[] {
  return input
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

async function saveConfigPatch(patch: Partial<SystemConfig>, successText: string) {
  emit('update:busy', true)
  try {
    const updated = await adminApi.updateConfig(patch)
    emit('configUpdated', updated)
    emit('success', successText)
  } catch (err) {
    emit('error', err)
  } finally {
    emit('update:busy', false)
  }
}

async function handleSaveSecurityPolicy() {
  await saveConfigPatch(
    {
      unlockReplayWindowSec: Number(configForm.unlockReplayWindowSec),
      commandTimeoutMs: Number(configForm.commandTimeoutMs),
      maxDevicesPerUser: Number(configForm.maxDevicesPerUser),
      adminGroups: splitGroups(adminGroupsInput.value),
    },
    '系统安全策略已保存。',
  )
}

async function handleSaveAuditAndStatePolicy() {
  await saveConfigPatch(
    {
      auditRetentionDays: Number(configForm.auditRetentionDays),
      offlineUnknownSec: Number(configForm.offlineUnknownSec),
      stateReportPeriodSec: Number(configForm.stateReportPeriodSec),
    },
    '审计保留与状态判定策略已保存。',
  )
}

function resetRateLimitsToDefault() {
  configForm.rateLimits = defaultRateLimits()
}

async function handleSaveRateLimits() {
  const payload = {} as RateLimitConfig
  for (const item of RATE_LIMIT_META) {
    const r = configForm.rateLimits[item.key]
    payload[item.key] = {
      max: Number(r.max),
      windowSec: Number(r.windowSec),
    }
  }
  await saveConfigPatch({ rateLimits: payload }, '接口限流策略已保存并即时生效。')
}
</script>

<template>
  <section class="section-stack">
    <form class="panel inline-form" @submit.prevent="handleSaveSecurityPolicy">
      <h2 class="panel-heading">系统安全策略</h2>
      <div class="form-grid">
        <div class="field">
          <label for="cfg-replay">开锁防重放窗口秒数（10–3600）</label>
          <input
            id="cfg-replay"
            v-model.number="configForm.unlockReplayWindowSec"
            type="number"
            min="10"
            max="3600"
            class="input"
            required
          />
        </div>
        <div class="field">
          <label for="cfg-timeout">开锁指令超时毫秒（1000–60000）</label>
          <input
            id="cfg-timeout"
            v-model.number="configForm.commandTimeoutMs"
            type="number"
            min="1000"
            max="60000"
            class="input"
            required
          />
        </div>
        <div class="field">
          <label for="cfg-devices">单用户最大在线设备数（1–50）</label>
          <input
            id="cfg-devices"
            v-model.number="configForm.maxDevicesPerUser"
            type="number"
            min="1"
            max="50"
            class="input"
            required
          />
        </div>
        <div class="field full-span">
          <label for="cfg-admins">管理员 Authentik 群组（逗号分隔）</label>
          <input id="cfg-admins" v-model="adminGroupsInput" class="input" required />
        </div>
      </div>
      <div class="form-footer">
        <button type="submit" class="btn btn-primary" :disabled="busy">保存安全策略</button>
      </div>
    </form>

    <form class="panel inline-form" @submit.prevent="handleSaveAuditAndStatePolicy">
      <h2 class="panel-heading">审计保留与状态判定</h2>
      <div class="form-grid">
        <div class="field">
          <label for="cfg-retention">审计日志保留天数（1–3650，默认 90 天）</label>
          <input
            id="cfg-retention"
            v-model.number="configForm.auditRetentionDays"
            type="number"
            min="1"
            max="3650"
            class="input"
            required
          />
        </div>
        <div class="field">
          <label for="cfg-offline">离线判定未知状态秒数（30–86400）</label>
          <input
            id="cfg-offline"
            v-model.number="configForm.offlineUnknownSec"
            type="number"
            min="30"
            max="86400"
            class="input"
            required
          />
        </div>
        <div class="field">
          <label for="cfg-period">适配器状态上报周期秒数（10–3600）</label>
          <input
            id="cfg-period"
            v-model.number="configForm.stateReportPeriodSec"
            type="number"
            min="10"
            max="3600"
            class="input"
            required
          />
        </div>
      </div>
      <div class="form-footer">
        <button type="submit" class="btn btn-primary" :disabled="busy">保存保留与状态策略</button>
      </div>
    </form>

    <form class="panel inline-form" @submit.prevent="handleSaveRateLimits">
      <div class="panel-heading-row">
        <div>
          <h2 class="panel-heading" style="margin-bottom: 4px">接口限流策略（Rate Limit）</h2>
          <p class="cell-sub" style="margin: 0">
            采用 Redis 固定时间窗计数，保存后立即作用于后续请求（不追溯清理已存在的计数键）。
          </p>
        </div>
        <button type="button" class="btn btn-sm" :disabled="busy" @click="resetRateLimitsToDefault">
          恢复默认数值
        </button>
      </div>

      <div class="rl-grid">
        <div v-for="item in RATE_LIMIT_META" :key="item.key" class="rl-row">
          <div class="rl-info">
            <div class="cell-title">{{ item.label }}</div>
            <div class="cell-sub">{{ item.hint }}</div>
          </div>
          <div class="rl-inputs">
            <div class="field">
              <label :for="`rl-max-${item.key}`">允许次数（1–100000）</label>
              <input
                :id="`rl-max-${item.key}`"
                v-model.number="configForm.rateLimits[item.key].max"
                type="number"
                min="1"
                max="100000"
                class="input tabular"
                required
              />
            </div>
            <div class="field">
              <label :for="`rl-win-${item.key}`">时间窗口秒数（1–86400）</label>
              <input
                :id="`rl-win-${item.key}`"
                v-model.number="configForm.rateLimits[item.key].windowSec"
                type="number"
                min="1"
                max="86400"
                class="input tabular"
                required
              />
            </div>
          </div>
        </div>
      </div>

      <div class="form-footer">
        <button type="submit" class="btn btn-primary" :disabled="busy">保存限流策略</button>
      </div>
    </form>
  </section>
</template>
