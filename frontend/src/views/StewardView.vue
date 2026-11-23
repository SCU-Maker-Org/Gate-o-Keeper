<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { adminApi } from '../lib/adminApi'
import { describeApiError } from '../lib/api'
import {
  approvalLabel,
  formatTimestamp,
  lockStateLabel,
  parseGroupsJson,
} from '../lib/format'
import { getOidcConfig, loadOidcConfig } from '../lib/pkce'
import { useSession } from '../stores/session'
import type {
  AdminAdapterView,
  AdminLockView,
  AuditLogRow,
  RateLimitConfig,
  SystemConfig,
  UserRow,
} from '../types/api'

type TabKey = 'locks' | 'adapters' | 'audit' | 'users' | 'policy'

const SECTIONS: { key: TabKey; label: string; summary: string }[] = [
  {
    key: 'locks',
    label: '门锁管理',
    summary: '创建与管理抽象门锁，绑定门锁适配器并配置群组授权规则。',
  },
  {
    key: 'adapters',
    label: '门锁适配器',
    summary: '审批设备接入与凭证指纹，管理硬件在线态、状态查询、紧急开锁与密钥轮换。',
  },
  {
    key: 'audit',
    label: '审计日志',
    summary: '按操作者、目标门锁或适配器与结果检索安全事件，查看完整请求明细。',
  },
  {
    key: 'users',
    label: '成员管理',
    summary: '成员账号、停用状态与群组统一在 Authentik SSO 侧维护；本页展示已同步的成员快照与本地强踢入口。',
  },
  {
    key: 'policy',
    label: '系统策略',
    summary: '调整开锁防重放窗口、指令超时、最大设备数、管理员群组及审计保留天数。',
  },
]

const route = useRoute()
const router = useRouter()
const { state: sessionState } = useSession()

function resolveTab(raw: unknown): TabKey {
  if (
    raw === 'locks' ||
    raw === 'adapters' ||
    raw === 'audit' ||
    raw === 'users' ||
    raw === 'policy'
  ) {
    return raw
  }
  return 'locks'
}

const activeTab = ref<TabKey>(resolveTab(route.query.section))
const activeSection = computed(
  () => SECTIONS.find((s) => s.key === activeTab.value) || SECTIONS[0],
)
const pendingAdapterCount = computed(
  () => adapters.value.filter((a) => a.approvalStatus === 'pending').length,
)
const busy = ref(false)
const banner = ref<{ kind: 'success' | 'error'; text: string } | null>(null)

const locks = ref<AdminLockView[]>([])
const adapters = ref<AdminAdapterView[]>([])
const users = ref<UserRow[]>([])
const auditLogs = ref<AuditLogRow[]>([])
function defaultRateLimits(): RateLimitConfig {
  return {
    unlockUser: { max: 5, windowSec: 60 },
    unlockIp: { max: 20, windowSec: 60 },
    ssoExchangeIp: { max: 10, windowSec: 60 },
    adapterRegisterId: { max: 3, windowSec: 3600 },
    adapterRegisterIp: { max: 10, windowSec: 60 },
    adapterStatusId: { max: 12, windowSec: 60 },
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

const createLockOpen = ref(false)
const createLockForm = reactive({
  id: '',
  name: '',
  description: '',
  adapterId: '',
  groupsText: '',
})

const lockAction = ref<{
  mode: 'edit' | 'unlock' | 'delete'
  lock: AdminLockView
  name: string
  description: string
  adapterId: string
  groupsText: string
  reason: string
} | null>(null)

const adapterFilter = reactive({
  onlineStatus: '',
  unapprovedStatus: '',
})

const approvedAdapters = computed(() =>
  adapters.value.filter(
    (ad) =>
      ad.approvalStatus === 'approved' &&
      (!adapterFilter.onlineStatus || ad.onlineStatus === adapterFilter.onlineStatus),
  ),
)

const unapprovedAdapters = computed(() => {
  const rank: Record<string, number> = { pending: 0, rejected: 1, revoked: 2 }
  return adapters.value
    .filter(
      (ad) =>
        ad.approvalStatus !== 'approved' &&
        (!adapterFilter.unapprovedStatus || ad.approvalStatus === adapterFilter.unapprovedStatus),
    )
    .slice()
    .sort((a, b) => (rank[a.approvalStatus] ?? 9) - (rank[b.approvalStatus] ?? 9))
})

const adapterAction = ref<{
  mode: 'edit' | 'unlock' | 'revoke' | 'reset' | 'delete'
  adapter: AdminAdapterView
  name: string
  intervalSec: number
  reason: string
} | null>(null)

const auditFilter = reactive({
  actorId: '',
  targetId: '',
  result: '',
  limit: 50,
  offset: 0,
})
const expandedAuditId = ref<string | null>(null)

function showSuccess(text: string) {
  banner.value = { kind: 'success', text }
}

function showError(err: unknown) {
  banner.value = { kind: 'error', text: describeApiError(err) }
}

function splitGroups(input: string): string[] {
  return input
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

async function loadLocks() {
  locks.value = await adminApi.listLocks()
}

async function loadAdapters() {
  adapters.value = await adminApi.listAdapters()
}

function availableAdaptersFor(currentLockId: string | null): AdminAdapterView[] {
  return adapters.value.filter(
    (ad) =>
      ad.approvalStatus === 'approved' &&
      (!ad.boundLockId || (currentLockId !== null && ad.boundLockId === currentLockId)),
  )
}

async function loadAuditLogs() {
  auditLogs.value = await adminApi.listAuditLogs({
    actorId: auditFilter.actorId.trim() || undefined,
    targetId: auditFilter.targetId.trim() || undefined,
    result: auditFilter.result || undefined,
    limit: auditFilter.limit,
    offset: auditFilter.offset,
  })
}

async function loadUsers() {
  users.value = await adminApi.listUsers()
}

async function loadPolicy() {
  const cfg = await adminApi.getConfig()
  Object.assign(configForm, cfg)
  adminGroupsInput.value = cfg.adminGroups.join(', ')
}

async function switchTab(tab: TabKey, syncUrl = true) {
  activeTab.value = tab
  if (syncUrl && route.query.section !== tab) {
    router.replace({ path: '/steward', query: { ...route.query, section: tab } })
  }
  banner.value = null
  busy.value = true
  try {
    if (tab === 'locks') await Promise.all([loadLocks(), loadAdapters()])
    else if (tab === 'adapters') await loadAdapters()
    else if (tab === 'audit') await Promise.all([loadAuditLogs(), loadAdapters()])
    else if (tab === 'users') await Promise.all([loadUsers(), loadAdapters()])
    else if (tab === 'policy') await Promise.all([loadPolicy(), loadAdapters()])
  } catch (err) {
    showError(err)
  } finally {
    busy.value = false
  }
}

watch(
  () => route.query.section,
  (val) => {
    const next = resolveTab(val)
    if (next !== activeTab.value) {
      switchTab(next, false)
    }
  },
)

function openCreateLock() {
  lockAction.value = null
  createLockForm.id = ''
  createLockForm.name = ''
  createLockForm.description = ''
  createLockForm.adapterId = ''
  createLockForm.groupsText = ''
  createLockOpen.value = true
}

async function submitCreateLock() {
  busy.value = true
  banner.value = null
  try {
    const created = await adminApi.createLock({
      id: createLockForm.id.trim() || undefined,
      name: createLockForm.name.trim(),
      description: createLockForm.description.trim() || undefined,
      adapterId: createLockForm.adapterId || null,
      groups: splitGroups(createLockForm.groupsText),
    })
    createLockOpen.value = false
    showSuccess(`已创建门锁「${created.name}」（${created.id}）。`)
    await Promise.all([loadLocks(), loadAdapters()])
  } catch (err) {
    showError(err)
  } finally {
    busy.value = false
  }
}

function openLockAction(mode: 'edit' | 'unlock' | 'delete', lock: AdminLockView) {
  createLockOpen.value = false
  lockAction.value = {
    mode,
    lock,
    name: lock.name,
    description: lock.description,
    adapterId: lock.adapterId || '',
    groupsText: lock.groups.join(', '),
    reason: '',
  }
}

async function submitLockAction() {
  const act = lockAction.value
  if (!act) return
  busy.value = true
  banner.value = null
  try {
    if (act.mode === 'edit') {
      const nextName = act.name.trim()
      const nextDesc = act.description.trim()
      const nextAdapterId = act.adapterId.trim() || null
      const nextGroups = splitGroups(act.groupsText)

      if (nextName !== act.lock.name || nextDesc !== act.lock.description) {
        await adminApi.updateLock(act.lock.id, {
          name: nextName,
          description: nextDesc,
        })
      }
      if (nextAdapterId !== (act.lock.adapterId || null)) {
        await adminApi.bindLock(act.lock.id, nextAdapterId)
      }
      if (nextGroups.join('\0') !== act.lock.groups.join('\0')) {
        await adminApi.setLockGroups(act.lock.id, nextGroups)
      }
      showSuccess(`已更新门锁「${nextName}」配置。`)
    } else if (act.mode === 'unlock') {
      const res = await adminApi.adminUnlockLock(act.lock.id, act.reason.trim())
      if (res.status === 'success') {
        showSuccess(`紧急开锁指令已执行（${act.lock.name}）。`)
      } else {
        banner.value = {
          kind: 'error',
          text: `紧急开锁未完成（状态：${res.status}${res.deviceCode ? `，代码：${res.deviceCode}` : ''}）。`,
        }
      }
    } else if (act.mode === 'delete') {
      await adminApi.deleteLock(act.lock.id, act.reason.trim())
      showSuccess(`已删除门锁「${act.lock.name}」（${act.lock.id}）。`)
    }
    lockAction.value = null
    await Promise.all([loadLocks(), loadAdapters()])
  } catch (err) {
    showError(err)
  } finally {
    busy.value = false
  }
}

async function handleRefreshLockState(lock: AdminLockView) {
  busy.value = true
  banner.value = null
  try {
    const res = await adminApi.refreshLockState(lock.id)
    showSuccess(`已向门锁「${lock.name}」绑定的适配器下发状态刷新请求（消息编号 ${res.msgId}）。`)
    await loadLocks()
  } catch (err) {
    showError(err)
  } finally {
    busy.value = false
  }
}

function openAdapterAction(
  mode: 'edit' | 'unlock' | 'revoke' | 'reset' | 'delete',
  adapter: AdminAdapterView,
) {
  adapterAction.value = {
    mode,
    adapter,
    name: adapter.name,
    intervalSec: adapter.tokenRefreshInterval,
    reason: '',
  }
}

async function submitAdapterAction() {
  const act = adapterAction.value
  if (!act) return
  busy.value = true
  banner.value = null
  try {
    if (act.mode === 'edit') {
      await adminApi.updateAdapter(act.adapter.id, {
        name: act.name.trim(),
        tokenRefreshInterval: Number(act.intervalSec),
      })
      showSuccess(`已更新门锁适配器 ${act.adapter.id} 配置。`)
    } else if (act.mode === 'unlock') {
      const res = await adminApi.adminUnlock(act.adapter.id, act.reason.trim())
      if (res.status === 'success') {
        showSuccess(`紧急开锁指令已执行（${act.adapter.name}）。`)
      } else {
        banner.value = {
          kind: 'error',
          text: `紧急开锁未完成（状态：${res.status}${res.deviceCode ? `，代码：${res.deviceCode}` : ''}）。`,
        }
      }
    } else if (act.mode === 'revoke') {
      await adminApi.revokeAdapter(act.adapter.id, act.reason.trim())
      showSuccess(`已吊销门锁适配器 ${act.adapter.id} 并断开其 MQTTS 连接。`)
    } else if (act.mode === 'reset') {
      await adminApi.resetAdapter(act.adapter.id, act.reason.trim())
      showSuccess(`已将门锁适配器 ${act.adapter.id} 重置为待审批状态，请在下方列表重新批准接入。`)
    } else if (act.mode === 'delete') {
      await adminApi.deleteAdapter(act.adapter.id, act.reason.trim())
      showSuccess(`已彻底移除门锁适配器 ${act.adapter.id}。`)
    }
    adapterAction.value = null
    await Promise.all([loadAdapters(), loadLocks()])
  } catch (err) {
    showError(err)
  } finally {
    busy.value = false
  }
}

async function handleApprove(adapter: AdminAdapterView) {
  busy.value = true
  banner.value = null
  try {
    await adminApi.approveAdapter(adapter.id)
    showSuccess(`已批准门锁适配器 ${adapter.id} 接入。`)
    await loadAdapters()
  } catch (err) {
    showError(err)
  } finally {
    busy.value = false
  }
}

async function handleReject(adapter: AdminAdapterView) {
  busy.value = true
  banner.value = null
  try {
    await adminApi.rejectAdapter(adapter.id)
    showSuccess(`已拒绝门锁适配器 ${adapter.id} 的注册请求。`)
    await loadAdapters()
  } catch (err) {
    showError(err)
  } finally {
    busy.value = false
  }
}

async function handleRefreshState(adapter: AdminAdapterView) {
  busy.value = true
  banner.value = null
  try {
    const res = await adminApi.refreshAdapterState(adapter.id)
    showSuccess(`已向 ${adapter.id} 下发状态同步请求（消息编号 ${res.msgId}）。`)
    await loadAdapters()
  } catch (err) {
    showError(err)
  } finally {
    busy.value = false
  }
}

async function handleRotateToken(adapter: AdminAdapterView) {
  busy.value = true
  banner.value = null
  try {
    const res = await adminApi.refreshAdapterToken(adapter.id)
    showSuccess(`已向 ${adapter.id} 下发密钥轮换指令（消息编号 ${res.msgId}）。`)
    await loadAdapters()
  } catch (err) {
    showError(err)
  } finally {
    busy.value = false
  }
}

const authentikManageUrl = ref(getOidcConfig().manageUrl)

async function handleKickUser(user: UserRow) {
  busy.value = true
  banner.value = null
  try {
    const res = await adminApi.kickUser(user.id)
    showSuccess(`已强制下线成员 ${user.displayName}（断开 ${res.kickedDevices} 台在线会话）。`)
    await loadUsers()
  } catch (err) {
    showError(err)
  } finally {
    busy.value = false
  }
}

async function saveConfigPatch(patch: Partial<SystemConfig>, successText: string) {
  busy.value = true
  banner.value = null
  try {
    const updated = await adminApi.updateConfig(patch)
    Object.assign(configForm, updated)
    adminGroupsInput.value = updated.adminGroups.join(', ')
    showSuccess(successText)
  } catch (err) {
    showError(err)
  } finally {
    busy.value = false
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

async function changeAuditPage(delta: number) {
  auditFilter.offset = Math.max(0, auditFilter.offset + delta * auditFilter.limit)
  busy.value = true
  try {
    await loadAuditLogs()
  } catch (err) {
    showError(err)
  } finally {
    busy.value = false
  }
}

function approvalBadge(status: string) {
  if (status === 'approved') return 'badge-open'
  if (status === 'pending') return 'badge-warn'
  return 'badge-fault'
}

function auditResultBadge(result: string) {
  if (result === 'success') return 'badge-open'
  if (result === 'denied') return 'badge-warn'
  return 'badge-fault'
}

function prettyJson(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

onMounted(async () => {
  switchTab(activeTab.value, false)
  const oidc = await loadOidcConfig()
  authentikManageUrl.value = oidc.manageUrl
})
</script>

<template>
  <main class="page-wrap steward-wrap">
    <div class="steward-layout">
      <aside class="steward-sidebar panel" aria-label="系统管理导航">
        <div class="sidebar-title">系统管理</div>
        <nav class="sidebar-nav" role="tablist" aria-orientation="vertical">
          <button
            v-for="item in SECTIONS"
            :key="item.key"
            type="button"
            role="tab"
            class="sidebar-item"
            :class="{ active: activeTab === item.key }"
            :aria-selected="activeTab === item.key"
            @click="switchTab(item.key)"
          >
            <span>{{ item.label }}</span>
            <span
              v-if="item.key === 'adapters' && pendingAdapterCount > 0"
              class="badge badge-warn tabular"
            >
              {{ pendingAdapterCount }}
            </span>
          </button>
        </nav>
      </aside>

      <div class="steward-workspace">
        <div class="page-header workspace-header">
          <div>
            <h1 class="page-title">{{ activeSection.label }}</h1>
            <p class="page-subtitle">{{ activeSection.summary }}</p>
          </div>
        </div>

        <div v-if="banner" class="notice-bar" :class="banner.kind" role="status">
          <span>{{ banner.text }}</span>
          <button type="button" class="btn btn-sm" @click="banner = null">关闭</button>
        </div>

        <!-- 门锁管理 -->
        <section v-if="activeTab === 'locks'" class="section-stack">
          <div class="panel filter-bar locks-toolbar">
            <div class="toolbar-note">
              门锁是对物理门禁的逻辑抽象（如“101门锁”），成员权限与开锁入口均绑定在门锁层；更换硬件时只需重新绑定适配器。
            </div>
            <div class="row-actions">
              <button type="button" class="btn" :disabled="busy" @click="loadLocks">
                刷新列表
              </button>
              <button type="button" class="btn btn-primary" :disabled="busy" @click="openCreateLock">
                + 新建门锁
              </button>
            </div>
          </div>

          <div v-if="createLockOpen" class="panel drawer-panel">
            <div class="drawer-head">
              <h3>新建门锁</h3>
              <button type="button" class="btn btn-sm" @click="createLockOpen = false">取消</button>
            </div>
            <form class="drawer-body" @submit.prevent="submitCreateLock">
              <div class="form-grid two-col" style="width: 100%">
                <div class="field">
                  <label for="nl-name">门锁名称（必填）</label>
                  <input
                    id="nl-name"
                    v-model="createLockForm.name"
                    class="input"
                    placeholder="例如 101门锁"
                    required
                  />
                </div>
                <div class="field">
                  <label for="nl-id">门锁 ID（可选，留空自动生成）</label>
                  <input
                    id="nl-id"
                    v-model="createLockForm.id"
                    class="input"
                    placeholder="例如 lock-101"
                  />
                </div>
                <div class="field">
                  <label for="nl-adapter">绑定门锁适配器</label>
                  <select id="nl-adapter" v-model="createLockForm.adapterId" class="select">
                    <option value="">暂不绑定</option>
                    <option
                      v-for="ad in availableAdaptersFor(null)"
                      :key="ad.id"
                      :value="ad.id"
                    >
                      {{ ad.name }} ({{ ad.id }})
                    </option>
                  </select>
                </div>
                <div class="field">
                  <label for="nl-groups">授权 Authentik 群组（逗号分隔，可选）</label>
                  <input
                    id="nl-groups"
                    v-model="createLockForm.groupsText"
                    class="input"
                    placeholder="maker-members, lab-leads"
                  />
                </div>
                <div class="field full-span">
                  <label for="nl-desc">位置或备注说明（可选）</label>
                  <input
                    id="nl-desc"
                    v-model="createLockForm.description"
                    class="input"
                    placeholder="例如 创客空间一楼东门"
                  />
                </div>
              </div>
              <button type="submit" class="btn btn-primary" :disabled="busy">创建门锁</button>
            </form>
          </div>

          <div v-if="lockAction" class="panel drawer-panel">
            <div class="drawer-head">
              <h3>
                <template v-if="lockAction.mode === 'edit'">
                  编辑门锁：{{ lockAction.lock.name }}
                </template>
                <template v-else-if="lockAction.mode === 'unlock'">
                  紧急开锁：{{ lockAction.lock.name }}
                </template>
                <template v-else>删除门锁：{{ lockAction.lock.name }}</template>
              </h3>
              <button type="button" class="btn btn-sm" @click="lockAction = null">取消</button>
            </div>

            <form class="drawer-body" @submit.prevent="submitLockAction">
              <template v-if="lockAction.mode === 'edit'">
                <div class="form-grid two-col" style="width: 100%">
                  <div class="field">
                    <label for="el-name">门锁名称</label>
                    <input id="el-name" v-model="lockAction.name" class="input" required />
                  </div>
                  <div class="field">
                    <label for="el-desc">说明</label>
                    <input id="el-desc" v-model="lockAction.description" class="input" />
                  </div>
                  <div class="field">
                    <label for="el-adapter">绑定门锁适配器（1对1）</label>
                    <select id="el-adapter" v-model="lockAction.adapterId" class="select">
                      <option value="">解除绑定（暂不绑定任何适配器）</option>
                      <option
                        v-for="ad in availableAdaptersFor(lockAction.lock.id)"
                        :key="ad.id"
                        :value="ad.id"
                      >
                        {{ ad.name }} ({{ ad.id }}){{ ad.onlineStatus === 'online' ? ' · 在线' : ' · 离线' }}
                      </option>
                    </select>
                  </div>
                  <div class="field">
                    <label for="el-groups">授权 Authentik 群组（逗号分隔）</label>
                    <input
                      id="el-groups"
                      v-model="lockAction.groupsText"
                      class="input"
                      placeholder="maker-members, lab-leads"
                    />
                  </div>
                </div>
                <button type="submit" class="btn btn-primary" :disabled="busy">保存修改</button>
              </template>

              <template v-else-if="lockAction.mode === 'unlock'">
                <p class="drawer-note">
                  管理员紧急开锁无需 TOTP 二次验证，但必须填写操作原因并记入审计日志。
                </p>
                <div class="field">
                  <label>紧急开锁原因</label>
                  <input
                    v-model="lockAction.reason"
                    class="input"
                    placeholder="例如 设备检修、安全巡查或门禁故障"
                    required
                  />
                </div>
                <button type="submit" class="btn btn-warn" :disabled="busy">执行紧急开锁</button>
              </template>

              <template v-else>
                <p class="drawer-note">
                  删除门锁将移除该门锁及其群组授权规则，不会删除底层门锁适配器硬件记录。
                </p>
                <div class="field">
                  <label>删除原因（必填，记入审计日志）</label>
                  <input
                    v-model="lockAction.reason"
                    class="input"
                    placeholder="例如 房间调整或门禁撤除"
                    required
                  />
                </div>
                <button type="submit" class="btn btn-danger" :disabled="busy">确认删除门锁</button>
              </template>
            </form>
          </div>

          <div class="ledger-wrap">
            <table class="ledger">
              <thead>
                <tr>
                  <th>门锁名称 / ID / 说明</th>
                  <th>绑定门锁适配器</th>
                  <th>状态 / 最近同步</th>
                  <th>授权群组</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-if="locks.length === 0">
                  <td colspan="5" class="empty-cell">暂无门锁记录，点击右上角“新建门锁”开始配置。</td>
                </tr>
                <tr v-for="lk in locks" :key="lk.id">
                  <td>
                    <div class="cell-title">{{ lk.name }}</div>
                    <div class="cell-sub tabular">{{ lk.id }}</div>
                    <div v-if="lk.description" class="cell-sub">{{ lk.description }}</div>
                  </td>
                  <td>
                    <template v-if="lk.bound && lk.adapterId">
                      <div class="cell-title">{{ lk.adapterName || lk.adapterId }}</div>
                      <div class="cell-sub tabular">{{ lk.adapterId }}</div>
                    </template>
                    <span v-else class="badge badge-warn">未绑定适配器</span>
                  </td>
                  <td class="tabular">
                    <div class="chip-wrap">
                      <span
                        class="badge"
                        :class="lk.state === 'unlocked' ? 'badge-open' : lk.state === 'locked' ? 'badge-cobalt' : ''"
                      >
                        {{ lockStateLabel(lk.state) }}
                      </span>
                      <span v-if="lk.stale" class="badge badge-warn">上报超时</span>
                    </div>
                    <div class="cell-sub" style="margin-top: 4px">
                      {{ formatTimestamp(lk.stateReportedAt) }}
                    </div>
                  </td>
                  <td>
                    <div v-if="lk.groups.length" class="chip-wrap">
                      <span v-for="g in lk.groups" :key="g" class="badge">{{ g }}</span>
                    </div>
                    <span v-else class="cell-sub">仅管理员</span>
                  </td>
                  <td>
                    <div class="row-actions">
                      <button
                        type="button"
                        class="btn btn-sm btn-primary"
                        @click="openLockAction('edit', lk)"
                      >
                        编辑
                      </button>
                      <button
                        v-if="lk.bound && lk.online"
                        type="button"
                        class="btn btn-sm"
                        :disabled="busy"
                        @click="handleRefreshLockState(lk)"
                      >
                        状态刷新
                      </button>
                      <button
                        v-if="lk.bound && lk.online"
                        type="button"
                        class="btn btn-sm btn-warn"
                        :disabled="busy"
                        @click="openLockAction('unlock', lk)"
                      >
                        紧急开锁
                      </button>
                      <button
                        type="button"
                        class="btn btn-sm btn-danger"
                        @click="openLockAction('delete', lk)"
                      >
                        删除
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- 门锁适配器 -->
        <section v-if="activeTab === 'adapters'" class="section-stack">
          <div v-if="adapterAction" class="panel drawer-panel">
            <div class="drawer-head">
              <h3>
                <template v-if="adapterAction.mode === 'edit'">
                  编辑门锁适配器：{{ adapterAction.adapter.id }}
                </template>
                <template v-else-if="adapterAction.mode === 'unlock'">
                  紧急开锁：{{ adapterAction.adapter.name }}
                </template>
                <template v-else-if="adapterAction.mode === 'revoke'">
                  吊销门锁适配器：{{ adapterAction.adapter.id }}
                </template>
                <template v-else-if="adapterAction.mode === 'reset'">
                  重置为待审批：{{ adapterAction.adapter.id }}
                </template>
                <template v-else>移除门锁适配器：{{ adapterAction.adapter.id }}</template>
              </h3>
              <button type="button" class="btn btn-sm" @click="adapterAction = null">取消</button>
            </div>

            <form class="drawer-body" @submit.prevent="submitAdapterAction">
              <template v-if="adapterAction.mode === 'edit'">
                <div class="form-grid two-col">
                  <div class="field">
                    <label>显示名称</label>
                    <input v-model="adapterAction.name" class="input" required />
                  </div>
                  <div class="field">
                    <label>密钥轮换周期秒数（60 ~ 2592000）</label>
                    <input
                      v-model.number="adapterAction.intervalSec"
                      type="number"
                      min="60"
                      max="2592000"
                      class="input"
                      required
                    />
                  </div>
                </div>
                <button type="submit" class="btn btn-primary" :disabled="busy">保存修改</button>
              </template>

              <template v-else-if="adapterAction.mode === 'unlock'">
                <p class="drawer-note">
                  管理员紧急开锁无需 TOTP 二次验证，但必须填写操作原因并记入审计日志。
                </p>
                <div class="field">
                  <label>紧急开锁原因</label>
                  <input
                    v-model="adapterAction.reason"
                    class="input"
                    placeholder="例如 设备检修、安全巡查或门禁故障"
                    required
                  />
                </div>
                <button type="submit" class="btn btn-warn" :disabled="busy">执行紧急开锁</button>
              </template>

              <template v-else>
                <p class="drawer-note">
                  <template v-if="adapterAction.mode === 'revoke'">
                    吊销后设备连接将被 Broker 立即踢断且无法重连，可在下方列表中重置为待审批或移除。
                  </template>
                  <template v-else-if="adapterAction.mode === 'reset'">
                    重置将把该适配器恢复为“待审批”状态并断开当前连接，保留设备凭证与门锁绑定关系，可直接在下方列表中重新批准接入。
                  </template>
                  <template v-else>
                    移除将彻底删除该适配器记录与凭证并自动解除门锁绑定，仅用于硬件刷机重绑或设备报废。
                  </template>
                </p>
                <div class="field">
                  <label>操作原因（必填，记入审计日志）</label>
                  <input
                    v-model="adapterAction.reason"
                    class="input"
                    placeholder="例如 设备丢失、更换固件或重新批准"
                    required
                  />
                </div>
                <button
                  type="submit"
                  class="btn"
                  :class="adapterAction.mode === 'reset' ? 'btn-primary' : 'btn-danger'"
                  :disabled="busy"
                >
                  <template v-if="adapterAction.mode === 'revoke'">确认吊销设备</template>
                  <template v-else-if="adapterAction.mode === 'reset'">确认重置为待审批</template>
                  <template v-else>确认移除设备</template>
                </button>
              </template>
            </form>
          </div>

          <!-- 上方：已审批适配器 -->
          <div class="subsection-head">
            <div class="subsection-title-row">
              <h2 class="subsection-title">已审批适配器</h2>
              <span class="badge badge-open tabular">{{ approvedAdapters.length }}</span>
            </div>
            <div class="subsection-controls">
              <div class="field inline-field compact-select">
                <select
                  id="f-online"
                  v-model="adapterFilter.onlineStatus"
                  class="select"
                  aria-label="按在线状态筛选已审批适配器"
                >
                  <option value="">全部在线态</option>
                  <option value="online">仅看在线</option>
                  <option value="offline">仅看离线</option>
                </select>
              </div>
              <button type="button" class="btn btn-sm" :disabled="busy" @click="loadAdapters">
                刷新列表
              </button>
            </div>
          </div>

          <div class="ledger-wrap">
            <table class="ledger">
              <thead>
                <tr>
                  <th>名称 / 适配器 ID / 固件</th>
                  <th>凭证指纹</th>
                  <th>在线 / 门状态</th>
                  <th>绑定门锁</th>
                  <th>最近心跳</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-if="approvedAdapters.length === 0">
                  <td colspan="6" class="empty-cell">暂无已审批的门锁适配器。</td>
                </tr>
                <tr v-for="ad in approvedAdapters" :key="ad.id">
                  <td>
                    <div class="cell-title">{{ ad.name }}</div>
                    <div class="cell-sub tabular">{{ ad.id }}</div>
                    <div class="cell-sub">
                      {{ ad.model || '未填型号' }} / {{ ad.fwVersion || '未知固件' }}
                    </div>
                  </td>
                  <td class="tabular">{{ ad.fingerprint }}</td>
                  <td>
                    <div class="chip-wrap">
                      <span
                        class="badge"
                        :class="ad.onlineStatus === 'online' ? 'badge-open' : ''"
                      >
                        {{ ad.onlineStatus === 'online' ? '在线' : '离线' }}
                      </span>
                      <span
                        class="badge"
                        :class="ad.state === 'unlocked' ? 'badge-open' : ''"
                      >
                        {{ lockStateLabel(ad.state) }}
                      </span>
                    </div>
                  </td>
                  <td>
                    <template v-if="ad.boundLockId">
                      <div class="cell-title">{{ ad.boundLockName || ad.boundLockId }}</div>
                      <div class="cell-sub tabular">{{ ad.boundLockId }}</div>
                    </template>
                    <span v-else class="cell-sub">未绑定门锁</span>
                  </td>
                  <td class="tabular">
                    <div>{{ formatTimestamp(ad.lastSeenAt) }}</div>
                    <div class="cell-sub">轮换：{{ ad.tokenRefreshInterval }}s</div>
                  </td>
                  <td>
                    <div class="row-actions">
                      <button
                        type="button"
                        class="btn btn-sm"
                        @click="openAdapterAction('edit', ad)"
                      >
                        编辑
                      </button>
                      <button
                        v-if="ad.onlineStatus === 'online'"
                        type="button"
                        class="btn btn-sm"
                        :disabled="busy"
                        @click="handleRefreshState(ad)"
                      >
                        状态刷新
                      </button>
                      <button
                        v-if="ad.onlineStatus === 'online'"
                        type="button"
                        class="btn btn-sm btn-warn"
                        :disabled="busy"
                        @click="openAdapterAction('unlock', ad)"
                      >
                        紧急开锁
                      </button>
                      <button
                        v-if="ad.onlineStatus === 'online'"
                        type="button"
                        class="btn btn-sm"
                        :disabled="busy"
                        @click="handleRotateToken(ad)"
                      >
                        轮换密钥
                      </button>
                      <button
                        type="button"
                        class="btn btn-sm btn-danger"
                        @click="openAdapterAction('revoke', ad)"
                      >
                        吊销
                      </button>
                      <button
                        type="button"
                        class="btn btn-sm"
                        @click="openAdapterAction('reset', ad)"
                      >
                        重置
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- 下方：未审批 / 未启用适配器 -->
          <div class="subsection-head subsection-spaced">
            <div class="subsection-title-row">
              <h2 class="subsection-title">未审批与停用适配器</h2>
              <span
                class="badge tabular"
                :class="pendingAdapterCount > 0 ? 'badge-warn' : ''"
              >
                {{ unapprovedAdapters.length }}
              </span>
            </div>
            <div class="subsection-controls">
              <div class="field inline-field compact-select">
                <select
                  id="f-unapproved"
                  v-model="adapterFilter.unapprovedStatus"
                  class="select"
                  aria-label="按审批状态筛选未审批与停用适配器"
                >
                  <option value="">全部未审批/停用</option>
                  <option value="pending">仅待审批</option>
                  <option value="rejected">仅已拒绝</option>
                  <option value="revoked">仅已吊销</option>
                </select>
              </div>
            </div>
          </div>

          <div class="ledger-wrap">
            <table class="ledger">
              <thead>
                <tr>
                  <th>名称 / 适配器 ID / 固件</th>
                  <th>凭证指纹</th>
                  <th>审批状态</th>
                  <th>注册时间</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-if="unapprovedAdapters.length === 0">
                  <td colspan="5" class="empty-cell">暂无待审批或已停用的门锁适配器。</td>
                </tr>
                <tr v-for="ad in unapprovedAdapters" :key="ad.id">
                  <td>
                    <div class="cell-title">{{ ad.name }}</div>
                    <div class="cell-sub tabular">{{ ad.id }}</div>
                    <div class="cell-sub">
                      {{ ad.model || '未填型号' }} / {{ ad.fwVersion || '未知固件' }}
                    </div>
                  </td>
                  <td class="tabular">{{ ad.fingerprint }}</td>
                  <td>
                    <span class="badge" :class="approvalBadge(ad.approvalStatus)">
                      {{ approvalLabel(ad.approvalStatus) }}
                    </span>
                  </td>
                  <td class="tabular">{{ formatTimestamp(ad.createdAt) }}</td>
                  <td>
                    <div class="row-actions">
                      <button
                        v-if="ad.approvalStatus === 'pending'"
                        type="button"
                        class="btn btn-sm btn-primary"
                        :disabled="busy"
                        @click="handleApprove(ad)"
                      >
                        批准接入
                      </button>
                      <button
                        v-if="ad.approvalStatus === 'pending'"
                        type="button"
                        class="btn btn-sm btn-danger"
                        :disabled="busy"
                        @click="handleReject(ad)"
                      >
                        拒绝
                      </button>
                      <button
                        v-if="ad.approvalStatus !== 'revoked'"
                        type="button"
                        class="btn btn-sm btn-danger"
                        @click="openAdapterAction('revoke', ad)"
                      >
                        吊销
                      </button>
                      <button
                        v-if="ad.approvalStatus === 'rejected' || ad.approvalStatus === 'revoked'"
                        type="button"
                        class="btn btn-sm btn-primary"
                        @click="openAdapterAction('reset', ad)"
                      >
                        重置为待审批
                      </button>
                      <button
                        type="button"
                        class="btn btn-sm btn-danger"
                        @click="openAdapterAction('delete', ad)"
                      >
                        移除
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- 审计日志 -->
        <section v-if="activeTab === 'audit'" class="section-stack">
          <form
            class="panel filter-bar"
            @submit.prevent="
              auditFilter.offset = 0;
              loadAuditLogs()
            "
          >
            <div class="field inline-field">
              <label for="a-actor">操作者 ID</label>
              <input id="a-actor" v-model="auditFilter.actorId" class="input" placeholder="可选" />
            </div>
            <div class="field inline-field">
              <label for="a-target">目标门锁 / 适配器 ID</label>
              <input
                id="a-target"
                v-model="auditFilter.targetId"
                class="input"
                placeholder="如 lock-101 或 adapter-demo"
              />
            </div>
            <div class="field inline-field">
              <label for="a-result">结果</label>
              <select id="a-result" v-model="auditFilter.result" class="select">
                <option value="">全部</option>
                <option value="success">success</option>
                <option value="denied">denied</option>
                <option value="failed">failed</option>
                <option value="timeout">timeout</option>
              </select>
            </div>
            <button type="submit" class="btn btn-primary" :disabled="busy">查询日志</button>
          </form>

          <div class="ledger-wrap">
            <table class="ledger">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>操作者</th>
                  <th>动作</th>
                  <th>目标</th>
                  <th>结果</th>
                  <th>详情</th>
                </tr>
              </thead>
              <tbody>
                <tr v-if="auditLogs.length === 0">
                  <td colspan="6" class="empty-cell">当前筛选条件下暂无审计日志。</td>
                </tr>
                <template v-for="row in auditLogs" :key="row.id">
                  <tr>
                    <td class="tabular">{{ formatTimestamp(row.createdAt) }}</td>
                    <td>
                      <div class="cell-title tabular">{{ row.actorId }}</div>
                      <div class="cell-sub">{{ row.actorType }} / {{ row.ip || '-' }}</div>
                    </td>
                    <td>{{ row.action }}</td>
                    <td>
                      <div class="tabular">{{ row.targetId }}</div>
                      <div class="cell-sub">{{ row.targetType }}</div>
                    </td>
                    <td>
                      <span class="badge" :class="auditResultBadge(row.result)">{{ row.result }}</span>
                    </td>
                    <td>
                      <button
                        type="button"
                        class="btn btn-sm"
                        @click="expandedAuditId = expandedAuditId === row.id ? null : row.id"
                      >
                        {{ expandedAuditId === row.id ? '收起' : '查看' }}
                      </button>
                    </td>
                  </tr>
                  <tr v-if="expandedAuditId === row.id">
                    <td colspan="6" class="audit-detail-cell">
                      <div class="tabular">请求编号：{{ row.requestId }}</div>
                      <pre class="detail-pre">{{ prettyJson(row.detailJson) }}</pre>
                    </td>
                  </tr>
                </template>
              </tbody>
            </table>
          </div>

          <div class="pager-bar">
            <button
              type="button"
              class="btn btn-sm"
              :disabled="busy || auditFilter.offset === 0"
              @click="changeAuditPage(-1)"
            >
              上一页
            </button>
            <span class="cell-sub tabular">偏移量：{{ auditFilter.offset }}</span>
            <button
              type="button"
              class="btn btn-sm"
              :disabled="busy || auditLogs.length < auditFilter.limit"
              @click="changeAuditPage(1)"
            >
              下一页
            </button>
          </div>
        </section>

        <!-- 成员管理 -->
        <section v-if="activeTab === 'users'" class="section-stack">
          <div class="panel filter-bar locks-toolbar">
            <div class="toolbar-note">
              变更会通过 Authentik Webhook 实时同步并在令牌续签时兜底校对。
            </div>
            <div class="row-actions">
              <button type="button" class="btn" :disabled="busy" @click="loadUsers">
                刷新列表
              </button>
              <a
                :href="authentikManageUrl"
                target="_blank"
                rel="noopener noreferrer"
                class="btn btn-primary sso-link-btn"
              >
                去 Authentik 管理成员
              </a>
            </div>
          </div>

          <div class="ledger-wrap">
            <table class="ledger">
              <thead>
                <tr>
                  <th>成员名称 / ID</th>
                  <th>Authentik 群组</th>
                  <th>同步角色与状态</th>
                  <th>最近登录</th>
                  <th>会话控制</th>
                </tr>
              </thead>
              <tbody>
                <tr v-if="users.length === 0">
                  <td colspan="5" class="empty-cell">暂无已登录成员记录。</td>
                </tr>
                <tr v-for="u in users" :key="u.id">
                  <td>
                    <div class="cell-title">{{ u.displayName }}</div>
                    <div class="cell-sub tabular">{{ u.id }}</div>
                  </td>
                  <td>
                    <div class="chip-wrap">
                      <span v-for="g in parseGroupsJson(u.groupsJson)" :key="g" class="badge">
                        {{ g }}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div class="chip-wrap">
                      <span class="badge" :class="u.role === 'admin' ? 'badge-cobalt' : ''">
                        {{ u.role === 'admin' ? '管理员' : '成员' }}
                      </span>
                      <span
                        class="badge"
                        :class="u.status === 'active' ? 'badge-open' : 'badge-fault'"
                      >
                        {{ u.status === 'active' ? '正常' : '已停用' }}
                      </span>
                    </div>
                  </td>
                  <td class="tabular">{{ formatTimestamp(u.lastLoginAt) }}</td>
                  <td>
                    <div class="row-actions">
                      <button
                        type="button"
                        class="btn btn-sm btn-danger"
                        :disabled="busy || u.id === sessionState.me?.userId"
                        @click="handleKickUser(u)"
                      >
                        强制下线
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- 系统策略 -->
        <section v-if="activeTab === 'policy'" class="section-stack">
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
              <button type="submit" class="btn btn-primary" :disabled="busy">
                保存保留与状态策略
              </button>
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
              <button
                type="button"
                class="btn btn-sm"
                :disabled="busy"
                @click="resetRateLimitsToDefault"
              >
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
      </div>
    </div>
  </main>
</template>

<style scoped>
.steward-wrap {
  max-width: 1220px;
}

.steward-layout {
  display: grid;
  grid-template-columns: 224px minmax(0, 1fr);
  gap: 24px;
  align-items: start;
}

.steward-sidebar {
  position: sticky;
  top: 24px;
  overflow: hidden;
}

.sidebar-title {
  padding: 14px 16px 12px;
  font-size: 13px;
  font-weight: 600;
  color: var(--ink-muted);
  border-bottom: 1px solid var(--hairline);
  background: var(--surface-subtle);
}

.sidebar-nav {
  display: flex;
  flex-direction: column;
  padding: 6px 0;
}

.sidebar-item {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 10px 16px;
  border: none;
  border-left: 3px solid transparent;
  background: transparent;
  color: var(--ink-muted);
  font-size: 14px;
  font-weight: 500;
  text-align: left;
  cursor: pointer;
}

.sidebar-item:hover {
  background: var(--surface-subtle);
  color: var(--ink);
}

.sidebar-item.active {
  background: var(--cobalt-tint);
  border-left-color: var(--cobalt);
  color: var(--cobalt);
  font-weight: 600;
}

.steward-workspace {
  min-width: 0;
}

.workspace-header {
  margin-bottom: 20px;
  padding-bottom: 14px;
}

@media (max-width: 880px) {
  .steward-layout {
    grid-template-columns: 1fr;
    gap: 16px;
  }

  .steward-sidebar {
    position: static;
  }

  .sidebar-nav {
    flex-direction: row;
    flex-wrap: wrap;
    padding: 6px;
    gap: 4px;
  }

  .sidebar-item {
    width: auto;
    flex: 1 1 140px;
    border-left: none;
    border-bottom: 2px solid transparent;
    border-radius: var(--radius-sm);
    padding: 8px 12px;
  }

  .sidebar-item.active {
    border-left-color: transparent;
    border-bottom-color: var(--cobalt);
  }
}

.section-stack {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.inline-form {
  padding: 20px 22px;
}

.panel-heading {
  margin: 0 0 16px;
  font-size: 17px;
  font-weight: 600;
}

.panel-heading-row {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 16px;
}

.rl-grid {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--hairline);
  border-radius: var(--radius-sm);
}

.rl-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 12px 14px;
  border-bottom: 1px solid var(--row-divider);
}

.rl-row:last-child {
  border-bottom: none;
}

.rl-info {
  flex: 1 1 240px;
}

.rl-inputs {
  display: grid;
  grid-template-columns: repeat(2, minmax(140px, 170px));
  gap: 10px;
}

@media (max-width: 640px) {
  .rl-inputs {
    width: 100%;
    grid-template-columns: 1fr 1fr;
  }
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 14px;
}

.form-grid.two-col {
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
}

.full-span {
  grid-column: 1 / -1;
}

.form-footer {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}

.filter-bar {
  padding: 14px 18px;
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: 12px;
}

.locks-toolbar {
  align-items: center;
  justify-content: space-between;
}

.toolbar-note {
  font-size: 13.5px;
  color: var(--ink-muted);
  flex: 1 1 320px;
}

.sso-link-btn {
  text-decoration: none;
}

.subsection-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.subsection-spaced {
  margin-top: 10px;
}

.subsection-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.subsection-title {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}

.subsection-controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.compact-select {
  min-width: 150px;
  flex: 0 0 auto;
}

.inline-field {
  min-width: 170px;
  flex: 1 1 170px;
}

.drawer-panel {
  padding: 18px 22px;
  border-color: var(--cobalt);
}

.drawer-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.drawer-head h3 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}

.drawer-body {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 14px;
}

.drawer-body .field {
  width: 100%;
}

.drawer-note {
  margin: 0;
  font-size: 14px;
  color: var(--ink-muted);
}

.cell-title {
  font-weight: 500;
}

.cell-sub {
  font-size: 12.5px;
  color: var(--ink-muted);
}

.chip-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.row-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.empty-cell {
  text-align: center;
  color: var(--ink-muted);
  padding: 28px 16px;
}

.audit-detail-cell {
  background: var(--surface-subtle);
  padding: 14px 18px;
}

.detail-pre {
  margin: 8px 0 0;
  padding: 10px 12px;
  background: var(--surface);
  border: 1px solid var(--hairline);
  border-radius: var(--radius-sm);
  font-size: 12.5px;
  overflow-x: auto;
}

.pager-bar {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 12px;
}
</style>
