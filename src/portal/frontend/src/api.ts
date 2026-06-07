import { keycloak } from './keycloak'

async function authed(path: string, init: RequestInit = {}) {
  await keycloak.updateToken(30).catch(() => keycloak.login())
  const headers = new Headers(init.headers)
  headers.set('Authorization', `Bearer ${keycloak.token}`)
  if (init.body) headers.set('Content-Type', 'application/json')
  const res = await fetch(`/api/v1${path}`, { ...init, headers })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(text || `${res.status} ${res.statusText}`)
  }
  return res.status === 204 ? null : res.json()
}

export interface ProviderField { name: string; label: string; secret: boolean; required: boolean }
export interface ApiKeyProvider {
  key: string; name: string; iconUrl?: string; docsUrl?: string
  authScheme: string; header: string; prefix: string; baseUrl: string
  staticHeaders: Record<string, string>; fields: ProviderField[]
}
export interface OAuthProvider {
  key: string; name: string; authorizationEndpoint: string; tokenEndpoint: string
  userinfoEndpoint: string; scopeDelimiter: string; defaultScopes: string[]
}
export interface ApiKeyItem { id: string; provider: string; name: string; createdAt: string; lastUsedAt: string }
export interface OAuthTokenItem { id: string; provider: string; account: string; expiresAt: string; lastRefreshedAt: string; scopes: string[] }
export interface OAuthConfigItem { id: string; provider: string; clientIdMasked: string; scopes: string[]; redirectUri: string; createdAt: string }
export interface Me { userId: string; tenantId: string; email?: string; name?: string }

export const api = {
  me: () => authed('/me') as Promise<Me>,

  // stored credentials
  apiKeys: () => authed('/api-keys') as Promise<ApiKeyItem[]>,
  createApiKey: (provider: string, name: string, fields: Record<string, string>) =>
    authed('/api-keys', { method: 'POST', body: JSON.stringify({ provider, name, fields }) }),
  deleteApiKey: (id: string) => authed(`/api-keys/${id}`, { method: 'DELETE' }),
  oauthTokens: () => authed('/oauth/tokens') as Promise<OAuthTokenItem[]>,

  // provider manifests (catalog CRUD)
  apiKeyProviders: () => authed('/manifests?kind=apikey') as Promise<ApiKeyProvider[]>,
  oauthProviders: () => authed('/manifests?kind=oauth') as Promise<OAuthProvider[]>,
  upsertApiKeyProvider: (m: Partial<ApiKeyProvider>) =>
    authed('/manifests/apikey', { method: 'POST', body: JSON.stringify(m) }),
  upsertOAuthProvider: (m: Partial<OAuthProvider>) =>
    authed('/manifests/oauth', { method: 'POST', body: JSON.stringify(m) }),
  deleteProvider: (kind: string, key: string) => authed(`/manifests/${kind}/${key}`, { method: 'DELETE' }),

  // oauth provider configs + connect
  oauthConfigs: () => authed('/oauth/configs') as Promise<OAuthConfigItem[]>,
  upsertOAuthConfig: (c: { provider: string; clientId: string; clientSecret?: string; scopes?: string[]; redirectUri?: string }) =>
    authed('/oauth/configs', { method: 'POST', body: JSON.stringify(c) }),
  deleteOAuthConfig: (id: string) => authed(`/oauth/configs/${id}`, { method: 'DELETE' }),
  connect: (provider: string) => authed(`/oauth/${provider}/connect`) as Promise<{ authorizeUrl: string }>,
}
