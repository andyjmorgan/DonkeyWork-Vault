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
export interface Provider {
  key: string; name: string; header: string; prefix: string; baseUrl: string
  authScheme: string; staticHeaders: Record<string, string>; fields: ProviderField[]
}
export interface ApiKeyItem { id: string; provider: string; name: string; createdAt: string; lastUsedAt: string }
export interface Me { userId: string; tenantId: string; email?: string; name?: string }

export const api = {
  me: () => authed('/me') as Promise<Me>,
  providers: () => authed('/providers') as Promise<Provider[]>,
  apiKeys: () => authed('/api-keys') as Promise<ApiKeyItem[]>,
  createApiKey: (provider: string, name: string, fields: Record<string, string>) =>
    authed('/api-keys', { method: 'POST', body: JSON.stringify({ provider, name, fields }) }),
  deleteApiKey: (id: string) => authed(`/api-keys/${id}`, { method: 'DELETE' }),
}
