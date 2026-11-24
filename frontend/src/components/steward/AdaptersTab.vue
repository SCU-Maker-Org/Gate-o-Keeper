<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { adminApi } from '../../lib/adminApi'
import { approvalLabel, formatTimestamp, lockStateLabel } from '../../lib/format'
import type { AdminAdapterView } from '../../types/api'

const props = defineProps<{
  adapters: AdminAdapterView[]
  pendingCount: number
  busy: boolean
}>()

const emit = defineEmits<{
  'update:busy': [val: boolean]
  success: [text: string]
  'error-text': [text: string]
  error: [err: unknown]
  reload: []
  refreshAdapters: []
}>()

const adapterFilter = reactive({
  onlineStatus: '',
  unapprovedStatus: '',
})

const approvedAdapters = computed(() =>
  props.adapters.filter(
    (ad) =>
      ad.approvalStatus === 'approved' &&
      (!adapterFilter.onlineStatus || ad.onlineStatus === adapterFilter.onlineStatus),
  ),
)

const unapprovedAdapters = computed(() => {
  const rank: Record<string, number> = { pending: 0, rejected: 1, revoked: 2 }
  return props.adapters
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
  emit('update:busy', true)
  try {
    if (act.mode === 'edit') {
      await adminApi.updateAdapter(act.adapter.id, {
        name: act.name.trim(),
        tokenRefreshInterval: Number(act.intervalSec),
      })
      emit('success', `已更新门锁适配器 ${act.adapter.id} 配置。`)
    } else if (act.mode === 'unlock') {
      const res = await adminApi.adminUnlock(act.adapter.id, act.reason.trim())
      if (res.status === 'success') {
        emit('success', `紧急开锁指令已执行（${act.adapter.name}）。`)
      } else {
        emit(
          'error-text',
          `紧急开锁未完成（状态：${res.status}${res.deviceCode ? `，代码：${res.deviceCode}` : ''}）。`,
        )
      }
    } else if (act.mode === 'revoke') {
      await adminApi.revokeAdapter(act.adapter.id, act.reason.trim())
      emit('success', `已吊销门锁适配器 ${act.adapter.id} 并断开其 MQTTS 连接。`)
    } else if (act.mode === 'reset') {
      await adminApi.resetAdapter(act.adapter.id, act.reason.trim())
      emit('success', `已将门锁适配器 ${act.adapter.id} 重置为待审批状态，请在下方列表重新批准接入。`)
    } else if (act.mode === 'delete') {
      await adminApi.deleteAdapter(act.adapter.id, act.reason.trim())
      emit('success', `已彻底移除门锁适配器 ${act.adapter.id}。`)
    }
    adapterAction.value = null
    emit('reload')
  } catch (err) {
    emit('error', err)
  } finally {
    emit('update:busy', false)
  }
}

async function handleApprove(adapter: AdminAdapterView) {
  emit('update:busy', true)
  try {
    await adminApi.approveAdapter(adapter.id)
    emit('success', `已批准门锁适配器 ${adapter.id} 接入。`)
    emit('refreshAdapters')
  } catch (err) {
    emit('error', err)
  } finally {
    emit('update:busy', false)
  }
}

async function handleReject(adapter: AdminAdapterView) {
  emit('update:busy', true)
  try {
    await adminApi.rejectAdapter(adapter.id)
    emit('success', `已拒绝门锁适配器 ${adapter.id} 的注册请求。`)
    emit('refreshAdapters')
  } catch (err) {
    emit('error', err)
  } finally {
    emit('update:busy', false)
  }
}

async function handleRefreshState(adapter: AdminAdapterView) {
  emit('update:busy', true)
  try {
    const res = await adminApi.refreshAdapterState(adapter.id)
    emit('success', `已向 ${adapter.id} 下发状态同步请求（消息编号 ${res.msgId}）。`)
    emit('refreshAdapters')
  } catch (err) {
    emit('error', err)
  } finally {
    emit('update:busy', false)
  }
}

async function handleRotateToken(adapter: AdminAdapterView) {
  emit('update:busy', true)
  try {
    const res = await adminApi.refreshAdapterToken(adapter.id)
    emit('success', `已向 ${adapter.id} 下发密钥轮换指令（消息编号 ${res.msgId}）。`)
    emit('refreshAdapters')
  } catch (err) {
    emit('error', err)
  } finally {
    emit('update:busy', false)
  }
}

function approvalBadge(status: string) {
  if (status === 'approved') return 'badge-open'
  if (status === 'pending') return 'badge-warn'
  return 'badge-fault'
}
</script>

<template>
  <section class="section-stack">
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
              重置将把该适配器恢复为“待审批”状态、清除旧凭证并断开当前连接，设备持有效证书重新注册后可再次审批。
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

    <!-- 已审批适配器 -->
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
        <button type="button" class="btn btn-sm" :disabled="busy" @click="emit('refreshAdapters')">
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
                <span class="badge" :class="ad.onlineStatus === 'online' ? 'badge-open' : ''">
                  {{ ad.onlineStatus === 'online' ? '在线' : '离线' }}
                </span>
                <span class="badge" :class="ad.state === 'unlocked' ? 'badge-open' : ''">
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
                <button type="button" class="btn btn-sm" @click="openAdapterAction('edit', ad)">
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
                <button type="button" class="btn btn-sm" @click="openAdapterAction('reset', ad)">
                  重置
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 未审批 / 未启用适配器 -->
    <div class="subsection-head subsection-spaced">
      <div class="subsection-title-row">
        <h2 class="subsection-title">未审批与停用适配器</h2>
        <span class="badge tabular" :class="pendingCount > 0 ? 'badge-warn' : ''">
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
</template>
