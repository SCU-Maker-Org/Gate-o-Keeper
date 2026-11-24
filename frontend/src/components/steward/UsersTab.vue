<script setup lang="ts">
import { adminApi } from '../../lib/adminApi'
import { formatTimestamp, parseGroupsJson } from '../../lib/format'
import { getOidcConfig } from '../../lib/pkce'
import type { UserRow } from '../../types/api'

const props = defineProps<{
  users: UserRow[]
  currentUserId?: string
  busy: boolean
  runAction: (fn: () => Promise<void>) => Promise<void>
  onRefreshUsers: () => Promise<void>
  onSuccess: (text: string) => void
}>()

const authentikManageUrl = getOidcConfig().manageUrl

async function handleKickUser(user: UserRow) {
  await props.runAction(async () => {
    const res = await adminApi.kickUser(user.id)
    await props.onRefreshUsers()
    props.onSuccess(
      `已强制下线成员 ${user.displayName}（断开 ${res.kickedDevices} 台在线会话）。`,
    )
  })
}
</script>

<template>
  <section class="section-stack">
    <div class="panel filter-bar locks-toolbar">
      <div class="toolbar-note">
        变更会通过 Authentik Webhook 实时同步并在令牌续签时兜底校对。
      </div>
      <div class="row-actions">
        <button
          type="button"
          class="btn"
          :disabled="busy"
          @click="runAction(() => onRefreshUsers())"
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
  </section>
</template>
