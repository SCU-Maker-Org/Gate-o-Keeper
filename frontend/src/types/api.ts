export interface ApiEnvelope<T> {
  code: string
  message: string
  data: T | null
  requestId: string
}

export interface AuthTokenResponse {
  accessToken: string
  expiresIn: number
  deviceSessionId: string
}

export type AdapterStateValue = 'locked' | 'unlocked' | 'unknown'

export interface LockStatusView {
  lockId: string
  name: string
  description: string
  bound: boolean
  adapterId: string | null
  adapterName: string | null
  state: AdapterStateValue
  stateReportedAt: number | null
  online: boolean
  stale: boolean
}

export interface MeLockItem {
  id: string
  name: string
  description: string
  bound: boolean
  adapterId: string | null
  adapterName: string | null
  state: AdapterStateValue
  stateReportedAt: number | null
  online: boolean
  stale: boolean
}

export interface MeResponse {
  userId: string
  displayName: string
  role: 'user' | 'admin'
  groups: string[]
  locks: MeLockItem[]
}

export interface UnlockResponse {
  status: 'success' | 'failed' | 'timeout'
  deviceCode: string | null
}

export interface AdminLockView {
  id: string
  name: string
  description: string
  bound: boolean
  adapterId: string | null
  adapterName: string | null
  adapterApprovalStatus: 'pending' | 'approved' | 'rejected' | 'revoked' | null
  adapterOnlineStatus: 'online' | 'offline' | null
  state: AdapterStateValue
  stateReportedAt: number | null
  online: boolean
  stale: boolean
  groups: string[]
  createdBy: string
  createdAt: number
  updatedAt: number
}

export interface AdminAdapterView {
  id: string
  name: string
  fingerprint: string
  approvalStatus: 'pending' | 'approved' | 'rejected' | 'revoked'
  onlineStatus: 'online' | 'offline'
  state: AdapterStateValue
  stateReportedAt: number | null
  stale: boolean
  boundLockId: string | null
  boundLockName: string | null
  model: string
  fwVersion: string
  tokenRefreshInterval: number
  lastSeenAt: number | null
  approvedBy: string | null
  approvedAt: number | null
  createdAt: number
}

export type UserStatus = 'active' | 'disabled'

export interface UserRow {
  id: string
  ssoSubject: string
  displayName: string
  groupsJson: string
  role: 'user' | 'admin'
  status: UserStatus
  createdAt: number
  lastLoginAt: number
}

export interface UserPage {
  items: UserRow[]
  total: number
  page: number
  pageSize: number
  status: UserStatus
}

export interface AuditLogRow {
  id: string
  actorType: string
  actorId: string
  action: string
  targetType: string
  targetId: string
  result: 'success' | 'denied' | 'failed' | 'timeout' | string
  detailJson: string
  ip: string
  requestId: string
  createdAt: number
}

export interface RateLimitRule {
  max: number
  windowSec: number
}

export interface RateLimitConfig {
  unlockUser: RateLimitRule
  unlockIp: RateLimitRule
  ssoExchangeIp: RateLimitRule
  authRefreshIp: RateLimitRule
  authBackchannelLogoutIp: RateLimitRule
  adapterRegisterId: RateLimitRule
  adapterRegisterIp: RateLimitRule
  adapterStatusId: RateLimitRule
  adapterStatusIp: RateLimitRule
  mqttConnClient: RateLimitRule
}

export interface SystemConfig {
  unlockReplayWindowSec: number
  commandTimeoutMs: number
  maxDevicesPerUser: number
  auditRetentionDays: number
  offlineUnknownSec: number
  stateReportPeriodSec: number
  adminGroups: string[]
  rateLimits: RateLimitConfig
}
