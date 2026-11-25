<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { adminApi } from '../../lib/adminApi'
import { formatTimestamp, parseGroupsJson } from '../../lib/format'
import { getOidcConfig } from '../../lib/pkce'
import type { UserPage, UserRow, UserStatus } from '../../types/api'

const props = defineProps<{
  userPage: UserPage
  currentUserId?: string
  busy: boolean
  runAction: (fn: () => Promise<void>) => Promise<void>
  onLoadUsers: (params?: { status: UserStatus; page: number; pageSize: number }) => Promise<void>
  onSuccess: (text: string) => void
}>()

const authentikManageUrl = getOidcConfig().manageUrl

const activeStatus = ref<UserStatus>(props.userPage.status)
const pageSize = ref<number>(props.userPage.pageSize || 20)

watch(
  () => props.userPage,
  (next) => {
    activeStatus.value = next.status
    pageSize.value = next.pageSize
  },
)

const totalPages = computed(() =>
  Math.max(1, Math.ceil(props.userPage.total / Math.max(1, props.userPage.pageSize))),
)

async function selectStatus(status: UserStatus) {
  if (activeStatus.value === status) return
  activeStatus.value = status
  await props.runAction(() =>
    props.onLoadUsers({ status, page: 1, pageSize: pageSize.value }),
  )
}

async function changePage(nextPage: number) {
  const clamped = Math.min(Math.max(1, nextPage), totalPages.value)
  await props.runAction(() =>
    props.onLoadUsers({ status: activeStatus.value, page: clamped, pageSize: pageSize.value }),
  )
}

async function changePageSize() {
  const clampedSize = Math.min(50, Math.max(1, pageSize.value))
  pageSize.value = clampedSize
  await props.runAction(() =>
    props.onLoadUsers({ status: activeStatus.value, page: 1, pageSize: clampedSize }),
  )
}

async function handleKickUser(user: UserRow) {
  await props.runAction(async () => {
    const res = await adminApi.kickUser(user.id)
    await props.onLoadUsers()
    props.onSuccess(
      `已强制下线成员 ${user.displayName}（断开 ${res.kickedDevices} 台在线会话）。`,
    )
  })
}
</script>

<template>
  <section class="section-stack">
    <div class="panel filter-bar locks-toolbar">
      <div class="row-actions">
        <button
          type="button"
          class="btn"
          :class="activeStatus === 'active' ? 'btn-primary' : ''"
          :disabled="busy"
          @click="selectStatus('active')"
        >
          正常成员
        </button>
        <button
          type="button"
          class="btn"
          :class="activeStatus === 'disabled' ? 'btn-primary' : ''"
          :disabled="busy"
          @click="selectStatus('disabled')"
        >
          已停用成员
        </button>
      </div>
      <div class="row-actions">
        <label class="field-inline" for="users-page-size">
          每页条数
          <select
            id="users-page-size"
            v-model.number="pageSize"
            class="select"
            :disabled="busy"
            @change="changePageSize"
          >
            <option :value="10">10</option>
            <option :value="20">20</option>
            <option :value="50">50</option>
          </select>
        </label>
        <button
          type="button"
          class="btn"
          :disabled="busy"
          @click="runAction(() => onLoadUsers())"
        >
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
          <tr v-if="userPage.items.length === 0">
            <td colspan="5" class="empty-cell">
              {{ activeStatus === 'active' ? '暂无正常成员记录。' : '暂无已停用成员记录。' }}
            </td>
          </tr>
          <tr v-for="u in userPage.items" :key="u.id">
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
                <span class="badge" :class="u.status === 'active' ? 'badge-open' : 'badge-fault'">
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
                  :disabled="busy || u.id === currentUserId"
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

    <div class="panel filter-bar">
      <div class="toolbar-note tabular">
        共 {{ userPage.total }} 条 · 第 {{ userPage.page }} / {{ totalPages }} 页
      </div>
      <div class="row-actions">
        <button
          type="button"
          class="btn btn-sm"
          :disabled="busy || userPage.page <= 1"
          @click="changePage(userPage.page - 1)"
        >
          上一页
        </button>
        <button
          type="button"
          class="btn btn-sm"
          :disabled="busy || userPage.page >= totalPages"
          @click="changePage(userPage.page + 1)"
        >
          下一页
        </button>
      </div>
    </div>
  </section>
</template>
