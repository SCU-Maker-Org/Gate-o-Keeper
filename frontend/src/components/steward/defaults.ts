import type { RateLimitConfig, SystemConfig } from '../../types/api'

export function defaultRateLimits(): RateLimitConfig {
  return {
    unlockUser: { max: 5, windowSec: 60 },
    unlockIp: { max: 20, windowSec: 60 },
    ssoExchangeIp: { max: 10, windowSec: 60 },
    adapterRegisterId: { max: 3, windowSec: 3600 },
    adapterRegisterIp: { max: 10, windowSec: 60 },
    adapterStatusId: { max: 12, windowSec: 60 },
    adapterStatusIp: { max: 30, windowSec: 60 },
    mqttConnClient: { max: 10, windowSec: 60 },
  }
}

export function defaultSystemConfig(): SystemConfig {
  return {
    unlockReplayWindowSec: 60,
    commandTimeoutMs: 10000,
    maxDevicesPerUser: 3,
    auditRetentionDays: 90,
    offlineUnknownSec: 300,
    stateReportPeriodSec: 60,
    adminGroups: ['locker-admins'],
    rateLimits: defaultRateLimits(),
  }
}
