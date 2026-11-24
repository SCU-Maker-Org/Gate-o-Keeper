/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AUTHENTIK_AUTHORIZE_URL?: string
  readonly VITE_AUTHENTIK_CLIENT_ID?: string
  readonly VITE_AUTHENTIK_ADMIN_URL?: string
  readonly VITE_OIDC_REDIRECT_URI?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
