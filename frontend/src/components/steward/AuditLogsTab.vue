<script setup lang="ts">
import { reactive, ref } from 'vue'
import { formatTimestamp } from '../../lib/format'
import type { AuditLogRow } from '../../types/api'

export interface AuditFilterParams {
  actorId?: string
  targetId?: string
  result?: string
  limit: number
  offset: number
}

defineProps<{
  auditLogs: AuditLogRow[]
  busy: boolean
}>()

const emit = defineEmits<{
  query: [params: AuditFilterParams]
}>()

const auditFilter = reactive({
  actorId: '',
  targetId: '',
  result: '',
  limit: 50,
  offset: 0,
})
const expandedAuditId = ref<string | null>(null)

function emitQuery() {
  emit('query', {
    actorId: auditFilter.actorId.trim() || undefined,
    targetId: auditFilter.targetId.trim() || undefined,
    result: auditFilter.result || undefined,
    limit: auditFilter.limit,
    offset: auditFilter.offset,
  })
}

function submitSearch() {
  auditFilter.offset = 0
  emitQuery()
}

function changeAuditPage(delta: number) {
  auditFilter.offset = Math.max(0, auditFilter.offset + delta * auditFilter.limit)
  emitQuery()
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
</script>

<template>
  <section class="section-stack">
    <form class="panel filter-bar" @submit.prevent="submitSearch">
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
</template>
