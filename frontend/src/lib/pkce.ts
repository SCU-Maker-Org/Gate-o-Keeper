const PKCE_VERIFIER_KEY = 'locker_pkce_verifier'
const PKCE_STATE_KEY = 'locker_pkce_state'
const DEVICE_ID_KEY = 'locker_device_id'

function toBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function randomHex(byteCount: number): string {
  const bytes = new Uint8Array(byteCount)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function getOrCreateDeviceId(): string {
  const existing = localStorage.getItem(DEVICE_ID_KEY)
  if (existing && existing.length >= 8 && existing.length <= 128) {
    return existing
  }
  const created = `web_${randomHex(12)}`
  localStorage.setItem(DEVICE_ID_KEY, created)
  return created
}

export function inferDeviceName(): string {
  const ua = navigator.userAgent
  if (/Mobile|Android|iPhone|iPad/i.test(ua)) {
    return 'Mobile Browser'
  }
  return 'Desktop Browser'
}

export function generateUnlockNonce(): string {
  return `n_${randomHex(16)}`
}

export interface OidcClientConfig {
  authorizeUrl: string
  clientId: string
  redirectUri: string
  manageUrl: string
}

let runtimeOidcConfig: { authorizeUrl: string; clientId: string; manageUrl: string } | null = null
let oidcConfigPromise: Promise<OidcClientConfig> | null = null

function inferManageUrl(authorizeUrl: string): string {
  try {
    const u = new URL(authorizeUrl)
    return `${u.origin}/if/admin/#/identity/users`
  } catch {
    return 'http://localhost:9000/if/admin/#/identity/users'
  }
}

export function getOidcConfig(): OidcClientConfig {
  const authorizeUrl =
    runtimeOidcConfig?.authorizeUrl ||
    import.meta.env.VITE_AUTHENTIK_AUTHORIZE_URL?.trim() ||
    'http://localhost:9000/application/o/authorize/'
  const clientId =
    runtimeOidcConfig?.clientId ||
    import.meta.env.VITE_AUTHENTIK_CLIENT_ID?.trim() ||
    'locker-client-id'
  const redirectUri =
    import.meta.env.VITE_OIDC_REDIRECT_URI?.trim() || `${window.location.origin}/callback`
  const manageUrl = runtimeOidcConfig?.manageUrl || inferManageUrl(authorizeUrl)
  return { authorizeUrl, clientId, redirectUri, manageUrl }
}

export async function loadOidcConfig(): Promise<OidcClientConfig> {
  if (runtimeOidcConfig) {
    return getOidcConfig()
  }
  if (!oidcConfigPromise) {
    oidcConfigPromise = (async () => {
      try {
        const res = await fetch('/api/auth/oidc-config', { credentials: 'omit' })
        if (res.ok) {
          const json = (await res.json()) as {
            code?: string
            data?: { authorizeUrl?: string; clientId?: string; manageUrl?: string } | null
          }
          if (json?.code === 'OK' && json.data?.authorizeUrl && json.data?.clientId) {
            const authorizeUrl = json.data.authorizeUrl.trim()
            runtimeOidcConfig = {
              authorizeUrl,
              clientId: json.data.clientId.trim(),
              manageUrl: json.data.manageUrl?.trim() || inferManageUrl(authorizeUrl),
            }
          }
        }
      } catch {
        // Fallback to Vite build-time env / defaults when backend is unavailable
      }
      return getOidcConfig()
    })()
  }
  return oidcConfigPromise
}

export async function beginAuthentikLogin(): Promise<string> {
  const verifierBytes = new Uint8Array(32)
  crypto.getRandomValues(verifierBytes)
  const verifier = toBase64Url(verifierBytes)

  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  const challenge = toBase64Url(new Uint8Array(digest))
  const state = randomHex(16)

  sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier)
  sessionStorage.setItem(PKCE_STATE_KEY, state)

  const { authorizeUrl, clientId, redirectUri } = await loadOidcConfig()
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid profile email offline_access entitlements',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
  })
  return `${authorizeUrl}?${params.toString()}`
}

export function consumePkceSession(returnedState: string | null): {
  verifier: string
  redirectUri: string
} {
  const expectedState = sessionStorage.getItem(PKCE_STATE_KEY)
  const verifier = sessionStorage.getItem(PKCE_VERIFIER_KEY)
  sessionStorage.removeItem(PKCE_STATE_KEY)
  sessionStorage.removeItem(PKCE_VERIFIER_KEY)

  if (!expectedState || !verifier || !returnedState || returnedState !== expectedState) {
    throw new Error('登录状态校验失败，请重新发起 Authentik 登录。')
  }

  const { redirectUri } = getOidcConfig()
  return { verifier, redirectUri }
}
