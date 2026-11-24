import type {
  ApiEnvelope,
  AuthTokenResponse,
  LockStatusView,
  MeResponse,
  UnlockResponse,
} from '../types/api'

export class ApiClientError extends Error {
  readonly code: string
  readonly status: number
  readonly requestId: string

  constructor(code: string, message: string, status: number, requestId = '') {
    super(message)
    this.name = 'ApiClientError'
    this.code = code
    this.status = status
    this.requestId = requestId
  }
}

export function describeApiError(err: unknown): string {
  if (err instanceof ApiClientError) {
    switch (err.code) {
      case 'DEVICE_KICKED':
        return '当前设备已被新登录会话挤下线，请重新登录。'
      case 'LOCK_FORBIDDEN':
        return '当前账号所在群组没有该门锁的操作权限。'
      case 'LOCK_NOT_FOUND':
        return '未找到对应门锁，可能已被管理员删除。'
      case 'LOCK_UNBOUND':
        return '该门锁尚未绑定门锁适配器，请联系管理员绑定后再试。'
      case 'ADAPTER_FORBIDDEN':
        return '当前账号所在群组没有该门锁适配器的操作权限。'
      case 'ADAPTER_OFFLINE':
        return '门锁适配器离线或未就绪，请检查供电与 MQTTS 连接后重试。'
      case 'ADAPTER_BUSY':
        return '该门锁适配器正在执行开锁指令，请稍候数秒后再试。'
      case 'ADAPTER_NOT_FOUND':
        return '未找到对应门锁适配器，可能已被管理员重置或移除。'
      case 'REPLAY_REJECTED':
        return '请求时间戳或一次性令牌无效，请核对本机时间后重新点击开锁。'
      case 'RATE_LIMITED':
        return '操作过于频繁，请稍等片刻后再尝试。'
      case 'DEVICE_TIMEOUT':
        return '网关响应超时，未收到物理执行结果，请查看门锁状态或现场确认。'
      case 'UNAUTHORIZED':
        return '登录会话已失效，请重新登录。'
      default:
        return err.message || `请求失败（${err.code}）`
    }
  }
  if (err instanceof Error) {
    return err.message
  }
  return '网络异常或服务暂不可用，请检查后端连接。'
}

type TokenProvider = {
  getAccessToken: () => string | null
  refreshAccessToken: () => Promise<string | null>
  clearSession: (reason?: string) => void
}

let tokenProvider: TokenProvider | null = null

export function bindTokenProvider(provider: TokenProvider) {
  tokenProvider = provider
}

async function parseEnvelope<T>(res: Response): Promise<T> {
  const text = await res.text()
  let payload: ApiEnvelope<T> | null = null
  try {
    payload = text ? (JSON.parse(text) as ApiEnvelope<T>) : null
  } catch {
    throw new ApiClientError('HTTP_ERROR', `服务端返回异常响应（HTTP ${res.status}）`, res.status)
  }

  if (!res.ok || !payload || payload.code !== 'OK' || payload.data === null) {
    throw new ApiClientError(
      payload?.code || 'HTTP_ERROR',
      payload?.message || `HTTP ${res.status}`,
      res.status,
      payload?.requestId || '',
    )
  }

  return payload.data
}

export async function request<T>(
  path: string,
  options: {
    method?: 'GET' | 'POST'
    body?: unknown
    auth?: boolean
    retryOn401?: boolean
  } = {},
): Promise<T> {
  const { method = 'GET', body, auth = true, retryOn401 = true } = options
  const headers: Record<string, string> = {}

  if (method !== 'GET') {
    headers['X-Requested-With'] = 'fetch'
  }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  if (auth && tokenProvider) {
    const token = tokenProvider.getAccessToken()
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }
  }

  const res = await fetch(path, {
    method,
    headers,
    credentials: 'include',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  try {
    return await parseEnvelope<T>(res)
  } catch (err) {
    if (
      err instanceof ApiClientError &&
      auth &&
      (err.code === 'DEVICE_KICKED' || err.status === 401)
    ) {
      if (err.code !== 'DEVICE_KICKED' && retryOn401 && tokenProvider) {
        const refreshed = await tokenProvider.refreshAccessToken()
        if (refreshed) {
          return request<T>(path, { method, body, auth, retryOn401: false })
        }
      }
      tokenProvider?.clearSession(describeApiError(err))
    }
    throw err
  }
}

export const api = {
  ssoExchange(body: {
    code: string
    codeVerifier: string
    redirectUri: string
    deviceId: string
    deviceName: string
  }) {
    return request<AuthTokenResponse>('/api/auth/sso-exchange', {
      method: 'POST',
      body,
      auth: false,
      retryOn401: false,
    })
  },

  refresh() {
    return request<AuthTokenResponse>('/api/auth/refresh', {
      method: 'POST',
      body: {},
      auth: false,
      retryOn401: false,
    })
  },

  logout() {
    return request<{ loggedOut: boolean }>('/api/auth/logout', {
      method: 'POST',
      retryOn401: false,
    })
  },

  me() {
    return request<MeResponse>('/api/me')
  },

  lockStatus(lockId: string) {
    return request<LockStatusView>(`/api/locks/${encodeURIComponent(lockId)}/status`)
  },

  unlock(lockId: string, nonce: string, ts: number) {
    return request<UnlockResponse>('/api/unlock', {
      method: 'POST',
      body: { lockId, nonce, ts },
    })
  },
}
