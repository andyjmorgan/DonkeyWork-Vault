import { getToken } from './auth'
import type { components } from './api/schema'

// Reuse the generated audit DTO so the page stays in sync with the spec.
export type AuditEvent = components['schemas']['AuditEventDto']
export interface AuditPage { items: AuditEvent[]; total: number; limit: number; offset: number }
export interface AuditQuery { limit?: number; offset?: number; type?: string; outcome?: string; userId?: string; since?: string; until?: string }

async function authed(path: string, init: RequestInit = {}) {
  const token = await getToken()
  const headers = new Headers(init.headers)
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (init.body) headers.set('Content-Type', 'application/json')
  const res = await fetch(`/api/v1${path}`, { ...init, headers })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(text || `${res.status} ${res.statusText}`)
  }
  return res.status === 204 ? null : res.json()
}

export interface OAuthScope { value: string; description?: string; category?: string; sensitive?: boolean }
export interface OAuthProvider {
  key: string; name: string; iconUrl?: string; docsUrl?: string; builtin?: boolean; overridden?: boolean
  authorizationEndpoint: string; tokenEndpoint: string
  userinfoEndpoint: string; scopeDelimiter: string; defaultScopes: string[]; scopes?: OAuthScope[]
}
export type CredentialKind = 'opaque' | 'header_api_key' | 'http_basic' | 'username_password' | 'ssh' | 'connection_string'
export interface ApiKeyItem { id: string; name: string; description?: string; baseUrl?: string; docsUrl?: string; header?: string; prefix?: string; username?: string; kind: CredentialKind; createdAt: string; lastUsedAt: string }
export interface NewApiKey { name: string; secret: string; description?: string; baseUrl?: string; docsUrl?: string; header?: string; prefix?: string; username?: string; kind?: CredentialKind }
export interface OAuthTokenItem { id: string; provider: string; account: string; expiresAt: string; lastRefreshedAt: string; scopes: string[] }
export interface OAuthConfigItem { id: string; provider: string; clientIdMasked: string; scopes: string[]; redirectUri: string; createdAt: string }
export interface Me { userId: string; tenantId: string; email?: string; name?: string }
export type AccessScope = 'vault:read' | 'vault:readwrite' | 'vault:audit'
export interface AccessKey {
  id: string; name: string; description?: string; scopes: AccessScope[]
  enabled: boolean; prefix: string; createdAt: string; lastUsedAt: string
}
export interface NewAccessKey { name: string; description?: string; scopes: AccessScope[] }

export const api = {
  me: () => authed('/me') as Promise<Me>,

  // stored credentials
  apiKeys: () => authed('/api-keys') as Promise<ApiKeyItem[]>,
  createApiKey: (k: NewApiKey) => authed('/api-keys', { method: 'POST', body: JSON.stringify(k) }),
  deleteApiKey: (id: string) => authed(`/api-keys/${id}`, { method: 'DELETE' }),
  revealApiKey: (name: string) => authed(`/api-keys/${encodeURIComponent(name)}/reveal`) as Promise<{ secret: string }>,
  oauthTokens: () => authed('/oauth/tokens') as Promise<OAuthTokenItem[]>,
  deleteOAuthToken: (id: string) => authed(`/oauth/tokens/${id}`, { method: 'DELETE' }),
  revealOAuthToken: (provider: string, account?: string) =>
    authed(`/oauth/${provider}/token${account ? `?account=${encodeURIComponent(account)}` : ''}`) as Promise<{ accessToken: string; expiresAt: string }>,

  // access keys (scoped auth credentials; secret shown once)
  accessKeys: () => authed('/access-keys') as Promise<AccessKey[]>,
  createAccessKey: (k: NewAccessKey) =>
    authed('/access-keys', { method: 'POST', body: JSON.stringify(k) }) as Promise<{ id: string; name: string; scopes: AccessScope[]; secret: string }>,
  setAccessKeyEnabled: (id: string, enabled: boolean) =>
    authed(`/access-keys/${id}`, { method: 'PATCH', body: JSON.stringify({ enabled }) }),
  deleteAccessKey: (id: string) => authed(`/access-keys/${id}`, { method: 'DELETE' }),

  // OAuth provider manifests (catalog CRUD)
  oauthProviders: () => authed('/manifests') as Promise<OAuthProvider[]>,
  upsertOAuthProvider: (m: Partial<OAuthProvider>) =>
    authed('/manifests/oauth', { method: 'POST', body: JSON.stringify(m) }),
  discoverOidc: (url: string) =>
    authed('/manifests/oauth/discover', { method: 'POST', body: JSON.stringify({ url }) }) as Promise<Partial<OAuthProvider>>,
  deleteProvider: (kind: string, key: string) => authed(`/manifests/${kind}/${key}`, { method: 'DELETE' }),

  // oauth provider configs + connect
  oauthConfigs: () => authed('/oauth/configs') as Promise<OAuthConfigItem[]>,
  upsertOAuthConfig: (c: { provider: string; clientId: string; clientSecret?: string; scopes?: string[]; redirectUri?: string }) =>
    authed('/oauth/configs', { method: 'POST', body: JSON.stringify(c) }),
  deleteOAuthConfig: (id: string) => authed(`/oauth/configs/${id}`, { method: 'DELETE' }),
  connect: (provider: string, scopes?: string[]) =>
    authed(`/oauth/${provider}/connect${scopes?.length ? `?scopes=${encodeURIComponent(scopes.join(' '))}` : ''}`) as Promise<{ authorizeUrl: string }>,

  // audit trail (admin-only; same JWT as the other admin pages)
  audit: (q: AuditQuery = {}) => {
    const p = new URLSearchParams()
    for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== '') p.set(k, String(v))
    const qs = p.toString()
    return authed(`/audit${qs ? `?${qs}` : ''}`) as Promise<AuditPage>
  },
}
