import { useEffect, useState } from 'react'
import { Trash2, Pencil, Plus, Search } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../ui/components/card'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Label } from '../ui/components/label'
import { Badge } from '../ui/components/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '../ui/components/dialog'
import { ProviderIcon } from '../components/ProviderIcon'
import { CopyButton } from '../components/CopyButton'
import { api, type OAuthProvider, type OAuthScope, type OAuthConfigItem } from '../api'

const lbl = 'mb-1 block text-xs text-muted-foreground'

// The YAML templates are a LIBRARY. Adding one copies the whole template into a self-contained,
// editable provider row (with a parent_id breadcrumb). A provider is connectable only once added.
// All editing lives here; the Connect tab only selects scopes and connects.
export function ProvidersPage() {
  const [providers, setProviders] = useState<OAuthProvider[]>([])
  const [templates, setTemplates] = useState<OAuthProvider[]>([])
  const [configs, setConfigs] = useState<OAuthConfigItem[]>([])
  const [editing, setEditing] = useState<{ value: OAuthProvider; isNew: boolean } | null>(null)
  const load = () => {
    api.oauthProviders().then(setProviders).catch(() => {})
    api.oauthTemplates().then(setTemplates).catch(() => {})
    api.oauthConfigs().then(setConfigs).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const configFor = (key: string) => configs.find((c) => c.provider === key)
  const addedKeys = new Set(providers.map((p) => p.key))
  // A template you've already added (by slug) drops out of the library list.
  const library = templates.filter((t) => !addedKeys.has(t.key))

  const addFromTemplate = (t: OAuthProvider) =>
    setEditing({ value: { ...structuredClone(t), id: undefined, parentId: t.id, template: false }, isNew: true })

  return (
    <>
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Your OAuth providers</CardTitle>
            <CardDescription>Providers you've added. Edit scopes, credentials and authorize-params, then connect on the Connect tab.</CardDescription>
          </div>
          <Button size="sm" onClick={() => setEditing({ value: blankOAuth(), isNew: true })}><Plus className="size-4" /> Add custom</Button>
        </CardHeader>
        <CardContent className="space-y-2">
          {providers.length === 0 && <p className="text-sm text-muted-foreground">No providers yet — add one from the library below or add a custom one.</p>}
          {providers.map((p) => (
            <div key={p.key} className="flex items-center justify-between rounded-xl border border-border p-3">
              <div className="flex min-w-0 items-center gap-2">
                <ProviderIcon src={p.iconUrl} name={p.name} />
                <div className="min-w-0">
                  <div className="font-medium">{p.name} <span className="text-xs text-muted-foreground">({p.key})</span></div>
                  <div className="truncate text-xs text-muted-foreground">{p.authorizationEndpoint}</div>
                </div>
              </div>
              <div className="flex items-center gap-1">
                {configFor(p.key) && <Badge variant="secondary" className="text-success">credentials set</Badge>}
                <Button variant="ghost" size="icon" onClick={() => setEditing({ value: structuredClone(p), isNew: false })}><Pencil className="size-4" /></Button>
                <Button variant="ghost" size="icon" onClick={() => api.deleteProvider('oauth', p.key).then(load)}><Trash2 className="size-4 text-destructive" /></Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {editing && (
        <OAuthEditor
          value={editing.value}
          config={configFor(editing.value.key)}
          isNew={editing.isNew}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); load() }}
        />
      )}

      {library.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Library</CardTitle><CardDescription>Built-in templates. Adding one copies it into your providers, where you set credentials and connect.</CardDescription></CardHeader>
          <CardContent className="space-y-2">
            {library.map((t) => (
              <div key={t.key} className="flex items-center justify-between rounded-xl border border-border p-3">
                <div className="flex min-w-0 items-center gap-2">
                  <ProviderIcon src={t.iconUrl} name={t.name} className="size-6" />
                  <div className="flex items-center gap-2 font-medium">{t.name} <Badge variant="secondary">template</Badge></div>
                </div>
                <Button variant="outline" size="sm" onClick={() => addFromTemplate(t)}><Plus className="size-4" /> Add</Button>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </>
  )
}

function OAuthEditor({ value, config, isNew, onClose, onSaved }: {
  value: OAuthProvider; config?: OAuthConfigItem; isNew: boolean; onClose: () => void; onSaved: () => void
}) {
  const [m, setM] = useState<OAuthProvider>(value)
  const [discoverUrl, setDiscoverUrl] = useState('')
  const [rows, setRows] = useState<OAuthScope[]>(
    value.scopes?.length ? value.scopes : (value.defaultScopes || []).map((v) => ({ value: v, description: '' })))
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [redirect, setRedirect] = useState(config?.redirectUri || '')
  const [aprows, setAprows] = useState<{ key: string; value: string }[]>(
    Object.entries(value.authorizeParams || {}).map(([key, val]) => ({ key, value: val })))
  const [msg, setMsg] = useState<string>()
  const set = (patch: Partial<OAuthProvider>) => setM((cur) => ({ ...cur, ...patch }))
  const redirectHint = 'https://vault.donkeywork.dev/api/oauth/callback'

  const discover = async () => {
    setMsg('Discovering…')
    try {
      const d = await api.discoverOidc(discoverUrl)
      setM((cur) => ({
        ...cur,
        name: cur.name || d.name || '',
        key: cur.key || d.key || '',
        authorizationEndpoint: d.authorizationEndpoint || cur.authorizationEndpoint,
        tokenEndpoint: d.tokenEndpoint || cur.tokenEndpoint,
        userinfoEndpoint: d.userinfoEndpoint || cur.userinfoEndpoint,
      }))
      if (d.scopes?.length) setRows(d.scopes)
      setMsg(`Discovered ${d.scopes?.length || 0} scopes.`)
    } catch (e) { setMsg(String(e)) }
  }

  const addRow = () => setRows((r) => [...r, { value: '', description: '' }])
  const setRow = (i: number, patch: Partial<OAuthScope>) => setRows((r) => r.map((x, j) => (j === i ? { ...x, ...patch } : x)))
  const delRow = (i: number) => setRows((r) => r.filter((_, j) => j !== i))

  const addAp = () => setAprows((r) => [...r, { key: '', value: '' }])
  const setAp = (i: number, patch: Partial<{ key: string; value: string }>) => setAprows((r) => r.map((x, j) => (j === i ? { ...x, ...patch } : x)))
  const delAp = (i: number) => setAprows((r) => r.filter((_, j) => j !== i))

  const removeCredentials = async () => {
    if (!config) return
    setMsg(undefined)
    try { await api.deleteOAuthConfig(config.id); onSaved() } catch (e) { setMsg(String(e)) }
  }

  const save = async () => {
    setMsg(undefined)
    const scopes = rows
      .filter((s) => s.value.trim())
      .map((s) => ({ value: s.value.trim(), description: s.description || '', category: s.category || '', sensitive: !!s.sensitive }))
    const values = scopes.map((s) => s.value)
    const defaultScopes = m.defaultScopes?.length ? m.defaultScopes.filter((v) => values.includes(v)) : values
    const authorizeParams = Object.fromEntries(aprows.filter((p) => p.key.trim()).map((p) => [p.key.trim(), p.value]))
    try {
      await api.upsertOAuthProvider({ ...m, parentId: m.parentId, scopeDelimiter: m.scopeDelimiter || ' ', defaultScopes, scopes, authorizeParams })
      if (clientId.trim()) {
        await api.upsertOAuthConfig({ provider: m.key, clientId: clientId.trim(), clientSecret: clientSecret || undefined, scopes: defaultScopes, redirectUri: redirect || undefined })
      }
      onSaved()
    } catch (e) { setMsg(String(e)) }
  }

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{isNew ? (value.key ? `Add ${value.key}` : 'New custom provider') : `Edit ${value.key}`}</DialogTitle>
          <DialogDescription>Define endpoints, scopes, authorize-params and credentials. Discover from an issuer URL, or fill them in manually.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          {isNew && (
            <div className="flex items-end gap-2">
              <div className="flex-1"><Label className={lbl}>OIDC discovery URL (issuer)</Label><Input value={discoverUrl} onChange={(e) => setDiscoverUrl(e.target.value)} placeholder="https://issuer.example.com" /></div>
              <Button variant="outline" onClick={discover} disabled={!discoverUrl}><Search className="size-4" /> Discover</Button>
            </div>
          )}
          <div className="grid gap-3 sm:grid-cols-2">
            <div><Label className={lbl}>Slug (id)</Label><Input value={m.key} onChange={(e) => set({ key: e.target.value })} disabled={!isNew} placeholder="letters, digits, - or _" /></div>
            <div><Label className={lbl}>Name</Label><Input value={m.name} onChange={(e) => set({ name: e.target.value })} /></div>
            <div className="sm:col-span-2"><Label className={lbl}>Icon URL (optional)</Label><Input value={m.iconUrl || ''} onChange={(e) => set({ iconUrl: e.target.value })} /></div>
            <div className="sm:col-span-2"><Label className={lbl}>Authorization endpoint</Label><Input value={m.authorizationEndpoint} onChange={(e) => set({ authorizationEndpoint: e.target.value })} /></div>
            <div className="sm:col-span-2"><Label className={lbl}>Token endpoint</Label><Input value={m.tokenEndpoint} onChange={(e) => set({ tokenEndpoint: e.target.value })} /></div>
            <div className="sm:col-span-2"><Label className={lbl}>Userinfo endpoint</Label><Input value={m.userinfoEndpoint} onChange={(e) => set({ userinfoEndpoint: e.target.value })} /></div>
          </div>

          <div className="space-y-2 border-t border-border pt-3">
            <div className="text-xs font-medium text-muted-foreground">OAuth app credentials</div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div><Label className={lbl}>Client ID</Label><Input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder={config ? config.clientIdMasked : ''} /></div>
              <div><Label className={lbl}>Client secret</Label><Input type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} placeholder={config ? '(blank keeps existing)' : ''} /></div>
              <div className="sm:col-span-2">
                <Label className={lbl}>Redirect URI</Label>
                <div className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
                  <span>Allow-list this exact URL with the provider:</span>
                  <code className="text-accent">{redirectHint}</code>
                  <CopyButton value={redirectHint} />
                </div>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">Leave Client ID blank to save provider changes only without touching stored credentials.</p>
              {config && <Button variant="ghost" size="sm" onClick={removeCredentials}><Trash2 className="size-4 text-destructive" /> Remove credentials</Button>}
            </div>
          </div>

          <div className="space-y-2 border-t border-border pt-3">
            <div className="flex items-center justify-between">
              <div className="text-xs font-medium text-muted-foreground">Scopes</div>
              <Button variant="outline" size="sm" onClick={addRow}><Plus className="size-4" /> Add scope</Button>
            </div>
            {rows.length === 0 && <p className="text-sm text-muted-foreground">No scopes yet — add the scopes this provider supports.</p>}
            {rows.map((s, i) => (
              <div key={i} className="space-y-1 rounded-lg border border-border p-2">
                <div className="grid gap-1 sm:grid-cols-2">
                  <Input value={s.value} onChange={(e) => setRow(i, { value: e.target.value })} placeholder="scope value (e.g. files.metadata.read)" />
                  <Input value={s.description || ''} onChange={(e) => setRow(i, { description: e.target.value })} placeholder="description (shown on Connect)" />
                </div>
                <div className="flex items-center gap-3">
                  <Input value={s.category || ''} onChange={(e) => setRow(i, { category: e.target.value })} placeholder="category (optional)" className="h-8 flex-1" />
                  <label className="flex cursor-pointer items-center gap-1 text-xs text-muted-foreground">
                    <input type="checkbox" checked={!!s.sensitive} onChange={(e) => setRow(i, { sensitive: e.target.checked })} /> sensitive
                  </label>
                  <Button variant="ghost" size="icon" onClick={() => delRow(i)}><Trash2 className="size-4 text-destructive" /></Button>
                </div>
              </div>
            ))}
          </div>

          <div className="space-y-2 border-t border-border pt-3">
            <div className="flex items-center justify-between">
              <div className="text-xs font-medium text-muted-foreground">Authorization parameters</div>
              <Button variant="outline" size="sm" onClick={addAp}><Plus className="size-4" /> Add parameter</Button>
            </div>
            <p className="text-xs text-muted-foreground">Extra query params on the authorize URL — e.g. <code className="text-accent">token_access_type=offline</code> (Dropbox) or <code className="text-accent">access_type=offline</code> (Google) to be issued a refresh token.</p>
            {aprows.map((p, i) => (
              <div key={i} className="flex items-center gap-2">
                <Input value={p.key} onChange={(e) => setAp(i, { key: e.target.value })} placeholder="param (e.g. token_access_type)" className="flex-1" />
                <span className="text-muted-foreground">=</span>
                <Input value={p.value} onChange={(e) => setAp(i, { value: e.target.value })} placeholder="value (e.g. offline)" className="flex-1" />
                <Button variant="ghost" size="icon" onClick={() => delAp(i)}><Trash2 className="size-4 text-destructive" /></Button>
              </div>
            ))}
          </div>

          {msg && <p className="text-sm text-muted-foreground">{msg}</p>}
          <Button onClick={save} disabled={!m.key}>Save</Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

const blankOAuth = (): OAuthProvider => ({ key: '', parentId: undefined, name: '', iconUrl: '', docsUrl: '', authorizationEndpoint: '', tokenEndpoint: '', userinfoEndpoint: '', scopeDelimiter: ' ', defaultScopes: [], scopes: [] })
