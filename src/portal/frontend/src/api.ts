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
  id?: string; parentId?: string; key: string; name: string; iconUrl?: string; docsUrl?: string; template?: boolean
  authorizationEndpoint: string; tokenEndpoint: string
  userinfoEndpoint: string; scopeDelimiter: string; defaultScopes: string[]; scopes?: OAuthScope[]
  authorizeParams?: Record<string, string>
}
export type CredentialKind = 'opaque' | 'header_api_key' | 'http_basic' | 'username_password' | 'ssh' | 'connection_string'
export interface ApiKeyItem { id: string; name: string; description?: string; baseUrl?: string; docsUrl?: string; header?: string; prefix?: string; username?: string; kind: CredentialKind; createdAt: string; lastUsedAt: string }
export interface NewApiKey { name: string; secret: string; description?: string; baseUrl?: string; docsUrl?: string; header?: string; prefix?: string; username?: string; kind?: CredentialKind }
export interface OAuthTokenItem { id: string; provider: string; account: string; expiresAt: string; lastRefreshedAt: string; scopes: string[] }
export interface OAuthConfigItem { id: string; provider: string; clientIdMasked: string; scopes: string[]; redirectUri: string; createdAt: string }
export interface Me { userId: string; tenantId: string; email?: string; name?: string }
export type AccessScope = 'vault:read' | 'vault:readwrite' | 'vault:audit' | 'vault:mcp'
export interface AccessKey {
  id: string; name: string; description?: string; scopes: AccessScope[]
  enabled: boolean; prefix: string; createdAt: string; lastUsedAt: string; expiresAt?: string
}
export interface NewAccessKey { name: string; description?: string; scopes: AccessScope[]; expiresAt?: string }
export interface MCPConnection {
  id: string; slug: string; name: string; description?: string; upstreamUrl: string
  authMode: 'none' | 'headers' | 'oauth'; auditMode: 'metadata' | 'redacted'
  protocolVersion: string
  upstreamProtocolMode: 'modern_2026_07' | 'legacy_session'
  legacyProtocolVersion: '2025-03-26' | '2025-06-18' | '2025-11-25'
  protocolEra: 'unknown' | 'modern_2026_07' | 'legacy_session_likely' | 'incompatible'
  probeStatus: 'not_checked' | 'compatible' | 'incompatible' | 'auth_required' | 'unreachable' | 'error'
  probeCheckedAt?: string; probeError?: string; probeDetail?: string; supportedVersions: string[]
  serverName?: string; serverVersion?: string
  enabled: boolean; createdAt: string; updatedAt?: string
}
export interface MCPGrant { id: string; connectionId: string; accessKeyId: string; createdAt: string }
export interface MCPHeaderBinding { id: string; connectionId: string; credentialId: string; headerName?: string; createdAt: string }
export interface MCPToolPolicy { id: string; connectionId: string; method: string; toolName: string; allow: boolean; createdAt: string; updatedAt?: string }
export interface MCPOAuthStatus {
  connectionId: string; configured: boolean; authorized: boolean; issuer?: string; resource?: string; scopes: string[]
  expiresAt?: string; lastRefreshedAt?: string
}
export interface MCPAuditMessage {
  id: string; exchangeId: string; connectionId: string; sequenceNo: number; observedAt: string
  direction: string; messageKind: string; policyDecision: string; jsonrpcIdType?: string
  jsonrpcIdText?: string; method?: string; toolName?: string; policyRule?: string
  resultType?: string; subscriptionId?: string; errorCode?: number; payloadRedacted?: string
  payloadBytes: number; payloadTruncated: boolean; redactionPaths: string[]
}

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

  mcpConnections: () => authed('/mcp/connections') as Promise<MCPConnection[]>,
  saveMcpConnection: (c: Partial<MCPConnection>) =>
    authed(c.id ? `/mcp/connections/${c.id}` : '/mcp/connections', { method: c.id ? 'PUT' : 'POST', body: JSON.stringify(c) }) as Promise<MCPConnection>,
  deleteMcpConnection: (id: string) => authed(`/mcp/connections/${id}`, { method: 'DELETE' }),
  probeMcpConnection: (id: string) =>
    authed(`/mcp/connections/${id}/probe`, { method: 'POST' }) as Promise<MCPConnection>,
  mcpGrants: (connectionId: string) => authed(`/mcp/connections/${connectionId}/grants`) as Promise<MCPGrant[]>,
  createMcpGrant: (connectionId: string, accessKeyId: string) =>
    authed(`/mcp/connections/${connectionId}/grants`, { method: 'POST', body: JSON.stringify({ accessKeyId }) }) as Promise<MCPGrant>,
  deleteMcpGrant: (id: string) => authed(`/mcp/grants/${id}`, { method: 'DELETE' }),
  mcpHeaders: (connectionId: string) => authed(`/mcp/connections/${connectionId}/headers`) as Promise<MCPHeaderBinding[]>,
  createMcpHeader: (connectionId: string, credentialId: string, headerName?: string) =>
    authed(`/mcp/connections/${connectionId}/headers`, { method: 'POST', body: JSON.stringify({ credentialId, headerName }) }) as Promise<MCPHeaderBinding>,
  deleteMcpHeader: (id: string) => authed(`/mcp/headers/${id}`, { method: 'DELETE' }),
  mcpPolicies: (connectionId: string) => authed(`/mcp/connections/${connectionId}/policies`) as Promise<MCPToolPolicy[]>,
  saveMcpPolicy: (connectionId: string, method: string, toolName: string, allow: boolean) =>
    authed(`/mcp/connections/${connectionId}/policies`, { method: 'PUT', body: JSON.stringify({ method, toolName, allow }) }) as Promise<MCPToolPolicy>,
  deleteMcpPolicy: (id: string) => authed(`/mcp/policies/${id}`, { method: 'DELETE' }),
  configureMcpOAuth: (connectionId: string, config: { issuer?: string; clientId: string; clientSecret?: string; scopes: string[] }) =>
    authed(`/mcp/connections/${connectionId}/oauth`, { method: 'PUT', body: JSON.stringify(config) }),
  mcpOAuthStatus: (connectionId: string) => authed(`/mcp/connections/${connectionId}/oauth`) as Promise<MCPOAuthStatus>,
  connectMcpOAuth: (connectionId: string) => authed(`/mcp/connections/${connectionId}/oauth/connect`) as Promise<{ authorizeUrl: string; expiresAt: string }>,
  deleteMcpOAuth: (connectionId: string) => authed(`/mcp/connections/${connectionId}/oauth`, { method: 'DELETE' }),
  mcpAudit: (q: Record<string, string | number | undefined> = {}) => {
    const p = new URLSearchParams()
    for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== '') p.set(k, String(v))
    return authed(`/mcp/audit${p.size ? `?${p}` : ''}`) as Promise<{ items: MCPAuditMessage[]; total: number; limit: number; offset: number }>
  },

  // OAuth provider manifests (catalog CRUD)
  oauthProviders: () => authed('/manifests') as Promise<OAuthProvider[]>,
  oauthTemplates: () => authed('/manifests/templates') as Promise<OAuthProvider[]>,
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
