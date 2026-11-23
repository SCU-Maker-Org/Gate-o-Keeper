-- Store OIDC refresh_token per device session so /api/auth/refresh can re-sync groups & active status from Authentik
ALTER TABLE user_devices ADD COLUMN sso_refresh_token TEXT;
