import type {
  AdminAdapterView,
  AdminLockView,
  AuditLogRow,
  SystemConfig,
  UnlockResponse,
  UserPage,
  UserStatus,
} from '../types/api'
import { request } from './api'

export const adminApi = {
  listLocks() {
    return request<AdminLockView[]>('/api/admin/locks')
  },
  createLock(body: {
    id?: string
    name: string
    description?: string
    adapterId?: string | null
    groups?: string[]
  }) {
    return request<AdminLockView>('/api/admin/locks', {
      method: 'POST',
      body,
    })
  },
  updateLock(id: string, body: { name?: string; description?: string }) {
    return request<AdminLockView>(`/api/admin/locks/${encodeURIComponent(id)}/update`, {
      method: 'POST',
      body,
    })
  },
  bindLock(id: string, adapterId: string | null) {
    return request<AdminLockView>(`/api/admin/locks/${encodeURIComponent(id)}/bind`, {
      method: 'POST',
      body: { adapterId },
    })
  },
  deleteLock(id: string, reason: string) {
    return request<{ id: string; deleted: boolean }>(
      `/api/admin/locks/${encodeURIComponent(id)}/delete`,
      { method: 'POST', body: { reason } },
    )
  },
  setLockGroups(id: string, groups: string[]) {
    return request<string[]>(`/api/admin/locks/${encodeURIComponent(id)}/groups`, {
      method: 'POST',
      body: { groups },
    })
  },
  adminUnlockLock(id: string, reason: string) {
    return request<UnlockResponse>(`/api/admin/locks/${encodeURIComponent(id)}/unlock`, {
      method: 'POST',
      body: { reason },
    })
  },
  refreshLockState(id: string) {
    return request<{ msgId: string }>(
      `/api/admin/locks/${encodeURIComponent(id)}/refresh-state`,
      { method: 'POST' },
    )
  },

  listAdapters(filters?: { approvalStatus?: string; onlineStatus?: string }) {
    const params = new URLSearchParams()
    if (filters?.approvalStatus) params.set('approvalStatus', filters.approvalStatus)
    if (filters?.onlineStatus) params.set('onlineStatus', filters.onlineStatus)
    const q = params.toString()
    return request<AdminAdapterView[]>(`/api/admin/adapters${q ? `?${q}` : ''}`)
  },
  approveAdapter(id: string) {
    return request<{ id: string; approvalStatus: string }>(
      `/api/admin/adapters/${encodeURIComponent(id)}/approve`,
      { method: 'POST' },
    )
  },
  rejectAdapter(id: string) {
    return request<{ id: string; approvalStatus: string }>(
      `/api/admin/adapters/${encodeURIComponent(id)}/reject`,
      { method: 'POST' },
    )
  },
  revokeAdapter(id: string, reason: string) {
    return request<{ id: string; approvalStatus: string }>(
      `/api/admin/adapters/${encodeURIComponent(id)}/revoke`,
      { method: 'POST', body: { reason } },
    )
  },
  resetAdapter(id: string, reason: string) {
    return request<{ id: string; approvalStatus: string; reset: boolean }>(
      `/api/admin/adapters/${encodeURIComponent(id)}/reset`,
      { method: 'POST', body: { reason } },
    )
  },
  deleteAdapter(id: string, reason: string) {
    return request<{ id: string; deleted: boolean }>(
      `/api/admin/adapters/${encodeURIComponent(id)}/delete`,
      { method: 'POST', body: { reason } },
    )
  },
  refreshAdapterToken(id: string) {
    return request<{ id: string; msgId: string }>(
      `/api/admin/adapters/${encodeURIComponent(id)}/refresh-token`,
      { method: 'POST' },
    )
  },
  updateAdapter(id: string, body: { name?: string; tokenRefreshInterval?: number }) {
    return request<{ id: string }>(
      `/api/admin/adapters/${encodeURIComponent(id)}/update`,
      { method: 'POST', body },
    )
  },
  adminUnlock(id: string, reason: string) {
    return request<UnlockResponse>(`/api/admin/adapters/${encodeURIComponent(id)}/unlock`, {
      method: 'POST',
      body: { reason },
    })
  },
  refreshAdapterState(id: string) {
    return request<{ msgId: string }>(
      `/api/admin/adapters/${encodeURIComponent(id)}/refresh-state`,
      { method: 'POST' },
    )
  },

  listUsers(params: { status: UserStatus; page: number; pageSize: number }) {
    const q = new URLSearchParams({
      status: params.status,
      page: String(params.page),
      pageSize: String(params.pageSize),
    })
    return request<UserPage>(`/api/admin/users?${q.toString()}`)
  },
  kickUser(id: string) {
    return request<{ id: string; kickedDevices: number }>(
      `/api/admin/users/${encodeURIComponent(id)}/kick`,
      { method: 'POST' },
    )
  },

  listAuditLogs(query: {
    actorId?: string
    targetId?: string
    result?: string
    from?: number
    to?: number
    limit?: number
    offset?: number
  }) {
    const params = new URLSearchParams()
    if (query.actorId) params.set('actorId', query.actorId)
    if (query.targetId) params.set('targetId', query.targetId)
    if (query.result) params.set('result', query.result)
    if (query.from !== undefined) params.set('from', String(query.from))
    if (query.to !== undefined) params.set('to', String(query.to))
    if (query.limit !== undefined) params.set('limit', String(query.limit))
    if (query.offset !== undefined) params.set('offset', String(query.offset))
    const q = params.toString()
    return request<AuditLogRow[]>(`/api/admin/audit-logs${q ? `?${q}` : ''}`)
  },

  getConfig() {
    return request<SystemConfig>('/api/admin/config')
  },
  updateConfig(body: Partial<SystemConfig>) {
    return request<SystemConfig>('/api/admin/config', {
      method: 'POST',
      body,
    })
  },
}
