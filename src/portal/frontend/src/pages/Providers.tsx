import { useEffect, useState } from 'react'
import { Trash2, Pencil, Plus, Search, RotateCcw } from 'lucide-react'
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

// Providers is where ALL editing lives: custom providers, per-user overrides of built-in
// templates (add scopes), and OAuth app credentials. The Connect tab only selects scopes
// and connects. Resolution order is custom record → built-in template.
export function ProvidersPage() {
  const [providers, setProviders] = useState<OAuthProvider[]>([])
  const [configs, setConfigs] = useState<OAuthConfigItem[]>([])
  const [editing, setEditing] = useState<{ value: OAuthProvider; builtin: boolean } | null>(null)
  const load = () => {
    api.oauthProviders().then(setProviders).catch(() => {})
    api.oauthConfigs().then(setConfigs).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const custom = providers.filter((p) => !p.builtin)
  const builtin = providers.filter((p) => p.builtin)
  const configFor = (key: string) => configs.find((c) => c.provider === key)

  return (
    <>
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Custom OAuth providers</CardTitle>
            <CardDescription>Add a provider via OIDC discovery, define its scopes and credentials, then connect on the Connect tab.</CardDescription>
          </div>
          <Button size="sm" onClick={() => setEditing({ value: blankOAuth(), builtin: false })}><Plus className="size-4" /> Add</Button>
        </CardHeader>
        <CardContent className="space-y-2">
          {custom.length === 0 && <p className="text-sm text-muted-foreground">No custom providers yet.</p>}
          {custom.map((p) => (
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
                <Button variant="ghost" size="icon" onClick={() => setEditing({ value: structuredClone(p), builtin: false })}><Pencil className="size-4" /></Button>
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
          builtin={editing.builtin}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); load() }}
        />
      )}

      {builtin.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Built-in providers</CardTitle><CardDescription>Seeded templates. Customize one to add scopes or set credentials — your changes are saved as a private override and take precedence over the template.</CardDescription></CardHeader>
          <CardContent className="space-y-2">
            {builtin.map((p) => (
              <div key={p.key} className="flex items-center justify-between rounded-xl border border-border p-3">
                <div className="flex min-w-0 items-center gap-2">
                  <ProviderIcon src={p.iconUrl} name={p.name} className="size-6" />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 font-medium">{p.name}
                      <Badge variant="secondary">built-in</Badge>
                      {p.overridden && <Badge variant="secondary" className="text-accent">customized</Badge>}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  {configFor(p.key) && <Badge variant="secondary" className="text-success">credentials set</Badge>}
                  <Button variant="ghost" size="icon" title="Customize" onClick={() => setEditing({ value: structuredClone(p), builtin: true })}><Pencil className="size-4" /></Button>
                  {p.overridden && (
                    <Button variant="ghost" size="icon" title="Reset to template" onClick={() => api.deleteProvider('oauth', p.key).then(load)}><RotateCcw className="size-4 text-destructive" /></Button>
                  )}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </>
  )
}

function OAuthEditor({ value, config, builtin, onClose, onSaved }: {
  value: OAuthProvider; config?: OAuthConfigItem; builtin: boolean; onClose: () => void; onSaved: () => void
}) {
  const [m, setM] = useState<OAuthProvider>(value)
  const [discoverUrl, setDiscoverUrl] = useState('')
  const [rows, setRows] = useState<OAuthScope[]>(
    value.scopes?.length ? value.scopes : (value.defaultScopes || []).map((v) => ({ value: v, description: '' })))
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [redirect, setRedirect] = useState(config?.redirectUri || '')
  const [msg, setMsg] = useState<string>()
  const set = (patch: Partial<OAuthProvider>) => setM((cur) => ({ ...cur, ...patch }))
  const redirectHint = `https://vault.donkeywork.dev/api/oauth/${m.key}/callback`

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
    // Preserve the template/existing default selection (filtered to surviving scopes); a brand-new
    // provider with no defaults defaults to selecting everything it defines.
    const defaultScopes = m.defaultScopes?.length ? m.defaultScopes.filter((v) => values.includes(v)) : values
    try {
      await api.upsertOAuthProvider({ ...m, scopeDelimiter: m.scopeDelimiter || ' ', defaultScopes, scopes })
      if (clientId.trim()) {
        await api.upsertOAuthConfig({ provider: m.key, clientId: clientId.trim(), clientSecret: clientSecret || undefined, scopes: defaultScopes, redirectUri: redirect || undefined })
      }
      onSaved()
    } catch (e) { setMsg(String(e)) }
  }

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{builtin ? `Customize ${m.key}` : value.key ? `Edit ${value.key}` : 'New custom OAuth provider'}</DialogTitle>
          <DialogDescription>
            {builtin
              ? 'Built-in template: endpoints are fixed. Add scopes and set your OAuth app credentials — saved as a private override.'
              : 'Discover endpoints from an issuer URL, or fill them in manually. Define scopes and credentials below.'}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          {!builtin && (
            <div className="flex items-end gap-2">
              <div className="flex-1"><Label className={lbl}>OIDC discovery URL (issuer)</Label><Input value={discoverUrl} onChange={(e) => setDiscoverUrl(e.target.value)} placeholder="https://issuer.example.com" /></div>
              <Button variant="outline" onClick={discover} disabled={!discoverUrl}><Search className="size-4" /> Discover</Button>
            </div>
          )}
          <div className="grid gap-3 sm:grid-cols-2">
            <div><Label className={lbl}>Key (id)</Label><Input value={m.key} onChange={(e) => set({ key: e.target.value })} disabled={builtin || !!value.key} /></div>
            <div><Label className={lbl}>Name</Label><Input value={m.name} onChange={(e) => set({ name: e.target.value })} disabled={builtin} /></div>
            {!builtin && <div className="sm:col-span-2"><Label className={lbl}>Icon URL (optional)</Label><Input value={m.iconUrl || ''} onChange={(e) => set({ iconUrl: e.target.value })} /></div>}
            <div className="sm:col-span-2"><Label className={lbl}>Authorization endpoint</Label><Input value={m.authorizationEndpoint} onChange={(e) => set({ authorizationEndpoint: e.target.value })} disabled={builtin} /></div>
            <div className="sm:col-span-2"><Label className={lbl}>Token endpoint</Label><Input value={m.tokenEndpoint} onChange={(e) => set({ tokenEndpoint: e.target.value })} disabled={builtin} /></div>
            <div className="sm:col-span-2"><Label className={lbl}>Userinfo endpoint</Label><Input value={m.userinfoEndpoint} onChange={(e) => set({ userinfoEndpoint: e.target.value })} disabled={builtin} /></div>
          </div>

          <div className="space-y-2 border-t border-border pt-3">
            <div className="text-xs font-medium text-muted-foreground">OAuth app credentials</div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div><Label className={lbl}>Client ID</Label><Input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder={config ? config.clientIdMasked : ''} /></div>
              <div><Label className={lbl}>Client secret</Label><Input type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} placeholder={config ? '(blank keeps existing)' : ''} /></div>
              <div className="sm:col-span-2">
                <Label className={lbl}>Redirect URI</Label>
                <Input value={redirect} onChange={(e) => setRedirect(e.target.value)} placeholder={redirectHint} />
                <div className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
                  <span>Allow-list this exact URL with the provider:</span>
                  <code className="text-accent">{redirectHint}</code>
                  <CopyButton value={redirectHint} />
                </div>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">Leave Client ID blank to save scope changes only without touching stored credentials.</p>
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

          {msg && <p className="text-sm text-muted-foreground">{msg}</p>}
          <Button onClick={save} disabled={!m.key}>Save</Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

const blankOAuth = (): OAuthProvider => ({ key: '', name: '', iconUrl: '', docsUrl: '', authorizationEndpoint: '', tokenEndpoint: '', userinfoEndpoint: '', scopeDelimiter: ' ', defaultScopes: [], scopes: [] })
