<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { api, ApiClientError, describeApiError } from '../lib/api'
import { formatRelativeAge, formatTimestamp, lockStateLabel } from '../lib/format'
import { generateUnlockNonce } from '../lib/pkce'
import { useSession } from '../stores/session'
import type { MeLockItem } from '../types/api'

interface LockActionFeedback {
  busy: boolean
  kind: 'idle' | 'pending' | 'success' | 'error'
  message: string
  detail: string
}

const { state, reloadMe } = useSession()
const refreshingAll = ref(false)
const globalError = ref<string | null>(null)
const feedback = reactive<Record<string, LockActionFeedback>>({})

function getFeedback(lockId: string): LockActionFeedback {
  if (!feedback[lockId]) {
    feedback[lockId] = {
      busy: false,
      kind: 'idle',
      message: '',
      detail: '',
    }
  }
  return feedback[lockId]
}

async function handleReloadAll() {
  refreshingAll.value = true
  globalError.value = null
  try {
    await reloadMe()
  } catch (err) {
    globalError.value = describeApiError(err)
  } finally {
    refreshingAll.value = false
  }
}

async function handleRefreshLock(lock: MeLockItem) {
  const fb = getFeedback(lock.id)
  fb.busy = true
  globalError.value = null
  try {
    const view = await api.lockStatus(lock.id)
    lock.name = view.name
    lock.description = view.description
    lock.bound = view.bound
    lock.adapterId = view.adapterId
    lock.adapterName = view.adapterName
    lock.state = view.state
    lock.stateReportedAt = view.stateReportedAt
    lock.online = view.online
    lock.stale = view.stale
  } catch (err) {
    fb.kind = 'error'
    fb.message = describeApiError(err)
    fb.detail = err instanceof ApiClientError && err.requestId ? `请求编号：${err.requestId}` : ''
  } finally {
    fb.busy = false
  }
}

async function handleUnlock(lock: MeLockItem) {
  const fb = getFeedback(lock.id)
  fb.busy = true
  fb.kind = 'pending'
  fb.message = '正在通过 MQTTS 下发 QoS 2 开锁指令并等待适配器回执…'
  fb.detail = ''

  try {
    const nonce = generateUnlockNonce()
    const ts = Math.floor(Date.now() / 1000)
    const res = await api.unlock(lock.id, nonce, ts)

    if (res.status === 'success') {
      fb.kind = 'success'
      fb.message = '门锁指令已执行。'
      fb.detail = res.deviceCode ? `回执代码：${res.deviceCode}` : ''
      // Do not fabricate lock.state locally; refresh actual sensor-reported state from backend.
      void api
        .lockStatus(lock.id)
        .then((view) => {
          lock.name = view.name
          lock.description = view.description
          lock.bound = view.bound
          lock.adapterId = view.adapterId
          lock.adapterName = view.adapterName
          lock.state = view.state
          lock.stateReportedAt = view.stateReportedAt
          lock.online = view.online
          lock.stale = view.stale
        })
        .catch(() => {})
    } else if (res.status === 'timeout') {
      fb.kind = 'error'
      fb.message = '等待适配器确认超时，请刷新状态或现场核实门禁状态。'
      fb.detail = ''
    } else {
      fb.kind = 'error'
      fb.message = '适配器未能完成开锁动作，请检查执行机构状态。'
      fb.detail = res.deviceCode ? `设备状态码：${res.deviceCode}` : ''
    }
  } catch (err) {
    fb.kind = 'error'
    fb.message = describeApiError(err)
    fb.detail = err instanceof ApiClientError && err.requestId ? `请求编号：${err.requestId}` : ''
  } finally {
    fb.busy = false
  }
}

function stateBadgeClass(lock: MeLockItem) {
  if (lock.state === 'unlocked') return 'badge-open'
  if (lock.state === 'locked') return 'badge-cobalt'
  return ''
}

onMounted(() => {
  handleReloadAll()
})
</script>

<template>
  <main class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">门锁控制</h1>
        <p class="page-subtitle">
          当前可见门锁依据你的所属的群组动态授权。
        </p>
      </div>
      <div class="header-actions">
        <button type="button" class="btn" :disabled="refreshingAll" @click="handleReloadAll">
          {{ refreshingAll ? '同步中…' : '刷新全部状态' }}
        </button>
      </div>
    </div>

    <div v-if="globalError" class="notice-bar error">
      <span>{{ globalError }}</span>
      <button type="button" class="btn btn-sm" @click="globalError = null">关闭</button>
    </div>

    <section v-if="state.me && state.me.groups.length > 0" class="group-strip">
      <span class="group-label">当前群组身份</span>
      <div class="group-list">
        <span v-for="g in state.me.groups" :key="g" class="badge">{{ g }}</span>
      </div>
    </section>

    <div v-if="state.me && state.me.locks.length === 0" class="panel empty-state">
      <h2>暂无可开启的门锁</h2>
      <p>
        你所属的 Authentik 群组当前未授权任何门锁。请联系管理员在“系统管理 → 门锁管理”中创建门锁、绑定适配器并为你的群组授权后再刷新此页。
      </p>
      <button type="button" class="btn btn-primary" :disabled="refreshingAll" @click="handleReloadAll">
        重新检查授权
      </button>
    </div>

    <section v-else-if="state.me" class="bay-frame panel" aria-label="授权门锁列表">
      <article v-for="lock in state.me.locks" :key="lock.id" class="bay-row">
        <div class="bay-main">
          <div class="bay-identity">
            <div class="bay-title-line">
              <h2 class="bay-name">{{ lock.name }}</h2>
            </div>

            <p v-if="lock.description" class="bay-desc">{{ lock.description }}</p>

            <div class="bay-telemetry">
              <span class="badge" :class="stateBadgeClass(lock)">
                <span class="badge-dot" aria-hidden="true"></span>
                {{ lockStateLabel(lock.state) }}
              </span>
              <span v-if="!lock.bound" class="badge badge-warn">未绑定适配器</span>
              <span v-else class="badge" :class="lock.online ? 'badge-open' : 'badge-fault'">
                {{ lock.online ? '在线' : '离线' }}
              </span>
              <span v-if="lock.stale" class="badge badge-warn">状态上报已超时</span>
            </div>

            <p class="bay-sync tabular">
              最近同步：{{ formatRelativeAge(lock.stateReportedAt) }}
              <span v-if="lock.stateReportedAt" class="sync-exact">
                （{{ formatTimestamp(lock.stateReportedAt) }}）
              </span>
            </p>
          </div>

          <div class="bay-controls">
            <button
              type="button"
              class="btn bay-action-btn"
              :disabled="getFeedback(lock.id).busy"
              @click="handleRefreshLock(lock)"
            >
              刷新状态
            </button>
            <button
              type="button"
              class="btn btn-primary bay-action-btn actuator-btn"
              :disabled="getFeedback(lock.id).busy || !lock.bound || !lock.online"
              @click="handleUnlock(lock)"
            >
              {{ getFeedback(lock.id).busy ? '执行中…' : '立即开锁' }}
            </button>
          </div>
        </div>

        <div
          v-if="getFeedback(lock.id).kind !== 'idle'"
          class="bay-feedback"
          :class="getFeedback(lock.id).kind"
          role="status"
          aria-live="polite"
        >
          <span>{{ getFeedback(lock.id).message }}</span>
          <span v-if="getFeedback(lock.id).detail" class="feedback-detail tabular">
            {{ getFeedback(lock.id).detail }}
          </span>
        </div>
      </article>
    </section>
  </main>
</template>

<style scoped>
.group-strip {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  margin-bottom: 20px;
}

.group-label {
  font-size: 13px;
  font-weight: 500;
  color: var(--ink-muted);
}

.group-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.empty-state {
  padding: 36px 28px;
}

.empty-state h2 {
  margin: 0 0 8px;
  font-size: 18px;
}

.empty-state p {
  margin: 0 0 18px;
  color: var(--ink-muted);
  max-width: 60ch;
}

.bay-frame {
  overflow: hidden;
}

.bay-row {
  padding: 22px 24px;
  border-bottom: 1px solid var(--hairline);
}

.bay-row:last-child {
  border-bottom: none;
}

.bay-main {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
}

.bay-identity {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.bay-title-line {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 10px;
}

.bay-name {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  letter-spacing: -0.01em;
}

.bay-desc {
  margin: 0;
  font-size: 13.5px;
  color: var(--ink-muted);
}

.bay-telemetry {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.bay-sync {
  margin: 0;
  font-size: 13px;
  color: var(--ink-muted);
}

.sync-exact {
  color: var(--ink-muted);
}

.bay-controls {
  display: flex;
  align-items: center;
  gap: 10px;
}

.bay-action-btn {
  min-width: 136px;
  padding: 11px 20px;
  font-size: 15px;
}

.actuator-btn {
  font-weight: 600;
}

.bay-feedback {
  margin-top: 14px;
  padding: 10px 14px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--hairline);
  background: var(--surface-subtle);
  font-size: 14px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.bay-feedback.success {
  background: var(--relay-open-tint);
  border-color: var(--relay-open-border);
  color: var(--relay-open-ink);
}

.bay-feedback.error {
  background: var(--fault-tint);
  border-color: var(--fault-border);
  color: var(--fault-ink);
}

.bay-feedback.pending {
  background: var(--cobalt-tint);
  border-color: var(--cobalt-border);
  color: var(--cobalt-ink);
}

.feedback-detail {
  font-size: 13px;
  opacity: 0.9;
}

@media (max-width: 640px) {
  .bay-row {
    padding: 18px 16px;
  }
  .bay-controls {
    width: 100%;
  }
  .bay-action-btn {
    flex: 1;
    min-width: 0;
  }
}
</style>
