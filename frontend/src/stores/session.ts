import { computed, reactive } from 'vue'
import { api, bindTokenProvider } from '../lib/api'
import { beginAuthentikLogin, getOrCreateDeviceId, inferDeviceName } from '../lib/pkce'
import type { MeResponse } from '../types/api'

interface SessionState {
  accessToken: string | null
  deviceSessionId: string | null
  me: MeResponse | null
  initialized: boolean
  notice: string | null
}

const state = reactive<SessionState>({
  accessToken: null,
  deviceSessionId: null,
  me: null,
  initialized: false,
  notice: null,
})

let refreshInFlight: Promise<string | null> | null = null

async function doRefreshAccessToken(): Promise<string | null> {
  if (refreshInFlight) {
    return refreshInFlight
  }

  refreshInFlight = (async () => {
    try {
      const res = await api.refresh()
      state.accessToken = res.accessToken
      state.deviceSessionId = res.deviceSessionId
      return res.accessToken
    } catch {
      state.accessToken = null
      state.deviceSessionId = null
      state.me = null
      return null
    } finally {
      refreshInFlight = null
    }
  })()

  return refreshInFlight
}

bindTokenProvider({
  getAccessToken: () => state.accessToken,
  refreshAccessToken: doRefreshAccessToken,
  clearSession: (reason?: string) => {
    state.accessToken = null
    state.deviceSessionId = null
    state.me = null
    if (reason) {
      state.notice = reason
    }
  },
})

export function useSession() {
  const isAuthenticated = computed(() => Boolean(state.accessToken && state.me))
  const isAdmin = computed(() => state.me?.role === 'admin')

  async function restoreSession(): Promise<boolean> {
    if (state.initialized && state.me) {
      return true
    }
    const token = await doRefreshAccessToken()
    if (!token) {
      state.initialized = true
      return false
    }
    try {
      state.me = await api.me()
      state.initialized = true
      return true
    } catch {
      state.accessToken = null
      state.me = null
      state.initialized = true
      return false
    }
  }

  async function startLogin() {
    state.notice = null
    const url = await beginAuthentikLogin()
    window.location.assign(url)
  }

  async function completeCallback(code: string, verifier: string, redirectUri: string) {
    const tokenRes = await api.ssoExchange({
      code,
      codeVerifier: verifier,
      redirectUri,
      deviceId: getOrCreateDeviceId(),
      deviceName: inferDeviceName(),
    })
    state.accessToken = tokenRes.accessToken
    state.deviceSessionId = tokenRes.deviceSessionId
    state.me = await api.me()
    state.initialized = true
    state.notice = null
  }

  async function reloadMe() {
    state.me = await api.me()
  }

  async function signOut() {
    try {
      if (state.accessToken) {
        await api.logout()
      }
    } finally {
      state.accessToken = null
      state.deviceSessionId = null
      state.me = null
    }
  }

  function clearNotice() {
    state.notice = null
  }

  return {
    state,
    isAuthenticated,
    isAdmin,
    restoreSession,
    startLogin,
    completeCallback,
    reloadMe,
    signOut,
    clearNotice,
  }
}
