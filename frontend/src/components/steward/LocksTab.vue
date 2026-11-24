<script setup lang="ts">
import { reactive, ref } from 'vue'
import { adminApi } from '../../lib/adminApi'
import { formatTimestamp, lockStateLabel } from '../../lib/format'
import type { AdminAdapterView, AdminLockView } from '../../types/api'

const props = defineProps<{
  locks: AdminLockView[]
  adapters: AdminAdapterView[]
  busy: boolean
}>()

const emit = defineEmits<{
  'update:busy': [val: boolean]
  success: [text: string]
  'error-text': [text: string]
  error: [err: unknown]
  reload: []
  refreshLocks: []
}>()

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

function splitGroups(input: string): string[] {
  return input
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

function availableAdaptersFor(currentLockId: string | null): AdminAdapterView[] {
  return props.adapters.filter(
    (ad) =>
      ad.approvalStatus === 'approved' &&
      (!ad.boundLockId || (currentLockId !== null && ad.boundLockId === currentLockId)),
  )
}

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
  emit('update:busy', true)
  try {
    const created = await adminApi.createLock({
      id: createLockForm.id.trim() || undefined,
      name: createLockForm.name.trim(),
      description: createLockForm.description.trim() || undefined,
      adapterId: createLockForm.adapterId || null,
      groups: splitGroups(createLockForm.groupsText),
    })
    createLockOpen.value = false
    emit('success', `已创建门锁「${created.name}」（${created.id}）。`)
    emit('reload')
  } catch (err) {
    emit('error', err)
  } finally {
    emit('update:busy', false)
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
  emit('update:busy', true)
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
      emit('success', `已更新门锁「${nextName}」配置。`)
    } else if (act.mode === 'unlock') {
      const res = await adminApi.adminUnlockLock(act.lock.id, act.reason.trim())
      if (res.status === 'success') {
        emit('success', `紧急开锁指令已执行（${act.lock.name}）。`)
      } else {
        emit(
          'error-text',
          `紧急开锁未完成（状态：${res.status}${res.deviceCode ? `，代码：${res.deviceCode}` : ''}）。`,
        )
      }
    } else if (act.mode === 'delete') {
      await adminApi.deleteLock(act.lock.id, act.reason.trim())
      emit('success', `已删除门锁「${act.lock.name}」（${act.lock.id}）。`)
    }
    lockAction.value = null
    emit('reload')
  } catch (err) {
    emit('error', err)
  } finally {
    emit('update:busy', false)
  }
}

async function handleRefreshLockState(lock: AdminLockView) {
  emit('update:busy', true)
  try {
    const res = await adminApi.refreshLockState(lock.id)
    emit(
      'success',
      `已向门锁「${lock.name}」绑定的适配器下发状态刷新请求（消息编号 ${res.msgId}）。`,
    )
    emit('refreshLocks')
  } catch (err) {
    emit('error', err)
  } finally {
    emit('update:busy', false)
  }
}
</script>

<template>
  <section class="section-stack">
    <div class="panel filter-bar locks-toolbar">
      <div class="toolbar-note">
        门锁是对物理门禁的逻辑抽象（如“101门锁”），成员权限与开锁入口均绑定在门锁层；更换硬件时只需重新绑定适配器。
      </div>
      <div class="row-actions">
        <button type="button" class="btn" :disabled="busy" @click="emit('refreshLocks')">
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
              <option v-for="ad in availableAdaptersFor(null)" :key="ad.id" :value="ad.id">
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
</template>
