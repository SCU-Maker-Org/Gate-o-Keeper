<script setup lang="ts">
import { reactive, ref, watch } from 'vue'
import { adminApi } from '../../lib/adminApi'
import { splitCommaList } from '../../lib/format'
import type { RateLimitConfig, SystemConfig } from '../../types/api'
import { defaultRateLimits } from './defaults'

const props = defineProps<{
  config: SystemConfig
  configVersion: number
  busy: boolean
  runAction: (fn: () => Promise<void>) => Promise<void>
  onConfigUpdated: (cfg: SystemConfig) => void
  onSuccess: (text: string) => void
}>()

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

const securityForm = reactive({
  unlockReplayWindowSec: 60,
  commandTimeoutMs: 10000,
  maxDevicesPerUser: 3,
})
const adminGroupsInput = ref('locker-admins')

const auditStateForm = reactive({
  auditRetentionDays: 90,
  offlineUnknownSec: 300,
  stateReportPeriodSec: 60,
})

const rateLimitsForm = ref<RateLimitConfig>(defaultRateLimits())

function syncSecurityForm(cfg: SystemConfig) {
  securityForm.unlockReplayWindowSec = cfg.unlockReplayWindowSec
  securityForm.commandTimeoutMs = cfg.commandTimeoutMs
  securityForm.maxDevicesPerUser = cfg.maxDevicesPerUser
  adminGroupsInput.value = cfg.adminGroups.join(', ')
}

function syncAuditStateForm(cfg: SystemConfig) {
  auditStateForm.auditRetentionDays = cfg.auditRetentionDays
  auditStateForm.offlineUnknownSec = cfg.offlineUnknownSec
  auditStateForm.stateReportPeriodSec = cfg.stateReportPeriodSec
}

function syncRateLimitsForm(cfg: SystemConfig) {
  rateLimitsForm.value = JSON.parse(JSON.stringify(cfg.rateLimits))
}

watch(
  () => props.configVersion,
  () => {
    syncSecurityForm(props.config)
    syncAuditStateForm(props.config)
    syncRateLimitsForm(props.config)
  },
  { immediate: true },
)

async function saveConfigPatch(
  patch: Partial<SystemConfig>,
  syncSection: (cfg: SystemConfig) => void,
  successText: string,
) {
  await props.runAction(async () => {
    const updated = await adminApi.updateConfig(patch)
    props.onConfigUpdated(updated)
    syncSection(updated)
    props.onSuccess(successText)
  })
}

async function handleSaveSecurityPolicy() {
  await saveConfigPatch(
    {
      unlockReplayWindowSec: Number(securityForm.unlockReplayWindowSec),
      commandTimeoutMs: Number(securityForm.commandTimeoutMs),
      maxDevicesPerUser: Number(securityForm.maxDevicesPerUser),
      adminGroups: splitCommaList(adminGroupsInput.value),
    },
    syncSecurityForm,
    '系统安全策略已保存。',
  )
}

async function handleSaveAuditAndStatePolicy() {
  await saveConfigPatch(
    {
      auditRetentionDays: Number(auditStateForm.auditRetentionDays),
      offlineUnknownSec: Number(auditStateForm.offlineUnknownSec),
      stateReportPeriodSec: Number(auditStateForm.stateReportPeriodSec),
    },
    syncAuditStateForm,
    '审计保留与状态判定策略已保存。',
  )
}

function resetRateLimitsToDefault() {
  rateLimitsForm.value = defaultRateLimits()
}

async function handleSaveRateLimits() {
  const payload = {} as RateLimitConfig
  for (const item of RATE_LIMIT_META) {
    const r = rateLimitsForm.value[item.key]
    payload[item.key] = {
      max: Number(r.max),
      windowSec: Number(r.windowSec),
    }
  }
  await saveConfigPatch(
    { rateLimits: payload },
    syncRateLimitsForm,
    '接口限流策略已保存并即时生效。',
  )
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
            v-model.number="securityForm.unlockReplayWindowSec"
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
            v-model.number="securityForm.commandTimeoutMs"
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
            v-model.number="securityForm.maxDevicesPerUser"
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
            v-model.number="auditStateForm.auditRetentionDays"
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
            v-model.number="auditStateForm.offlineUnknownSec"
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
            v-model.number="auditStateForm.stateReportPeriodSec"
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
          <h2 class="panel-heading mb-xs">接口限流策略（Rate Limit）</h2>
          <p class="cell-sub m-0">
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
                v-model.number="rateLimitsForm[item.key].max"
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
                v-model.number="rateLimitsForm[item.key].windowSec"
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
