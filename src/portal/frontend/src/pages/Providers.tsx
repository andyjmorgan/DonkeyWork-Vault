import { useEffect, useState } from 'react'
import { Trash2, Pencil, Plus, Search } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../ui/components/card'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Label } from '../ui/components/label'
import { Badge } from '../ui/components/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '../ui/components/dialog'
import { ProviderIcon } from '../components/ProviderIcon'
import { api, type OAuthProvider } from '../api'

const lbl = 'mb-1 block text-xs text-muted-foreground'

// Providers exist to add CUSTOM OAuth providers (built-ins are seeded + read-only).
// Credentials/scopes for any provider are set on the Connect tab.
export function ProvidersPage() {
  const [providers, setProviders] = useState<OAuthProvider[]>([])
  const [editing, setEditing] = useState<OAuthProvider | null>(null)
  const load = () => api.oauthProviders().then(setProviders).catch(() => {})
  useEffect(() => { load() }, [])

  const custom = providers.filter((p) => !p.builtin)
  const builtin = providers.filter((p) => p.builtin)

  return (
    <>
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Custom OAuth providers</CardTitle>
            <CardDescription>Add a provider via OIDC discovery, then set credentials on the Connect tab.</CardDescription>
          </div>
          <Button size="sm" onClick={() => setEditing(blankOAuth())}><Plus className="size-4" /> Add</Button>
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
              <div className="flex gap-1">
                <Button variant="ghost" size="icon" onClick={() => setEditing(structuredClone(p))}><Pencil className="size-4" /></Button>
                <Button variant="ghost" size="icon" onClick={() => api.deleteProvider('oauth', p.key).then(load)}><Trash2 className="size-4 text-destructive" /></Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {editing && <OAuthEditor value={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); load() }} />}

      {builtin.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Built-in providers</CardTitle><CardDescription>Seeded and read-only — set credentials on the Connect tab.</CardDescription></CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {builtin.map((p) => (
              <div key={p.key} className="flex items-center gap-2 rounded-xl border border-border px-3 py-2">
                <ProviderIcon src={p.iconUrl} name={p.name} className="size-6" />
                <span className="text-sm">{p.name}</span>
                <Badge variant="secondary">built-in</Badge>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </>
  )
}

function OAuthEditor({ value, onClose, onSaved }: { value: OAuthProvider; onClose: () => void; onSaved: () => void }) {
  const [m, setM] = useState<OAuthProvider>(value)
  const [discoverUrl, setDiscoverUrl] = useState('')
  const [scopes, setScopes] = useState((value.defaultScopes || []).join(' '))
  const [msg, setMsg] = useState<string>()
  const set = (patch: Partial<OAuthProvider>) => setM((cur) => ({ ...cur, ...patch }))

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
        scopes: d.scopes || [],
      }))
      if (d.defaultScopes) setScopes(d.defaultScopes.join(' '))
      setMsg(`Discovered ${d.scopes?.length || 0} scopes.`)
    } catch (e) { setMsg(String(e)) }
  }

  const save = async () => {
    await api.upsertOAuthProvider({ ...m, scopeDelimiter: m.scopeDelimiter || ' ', defaultScopes: scopes.split(/\s+/).filter(Boolean) })
    onSaved()
  }

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{value.key ? `Edit ${value.key}` : 'New custom OAuth provider'}</DialogTitle>
          <DialogDescription>Discover endpoints from an issuer URL, or fill them in manually. Set credentials on the Connect tab.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="flex items-end gap-2">
            <div className="flex-1"><Label className={lbl}>OIDC discovery URL (issuer)</Label><Input value={discoverUrl} onChange={(e) => setDiscoverUrl(e.target.value)} placeholder="https://issuer.example.com" /></div>
            <Button variant="outline" onClick={discover} disabled={!discoverUrl}><Search className="size-4" /> Discover</Button>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div><Label className={lbl}>Key (id)</Label><Input value={m.key} onChange={(e) => set({ key: e.target.value })} /></div>
            <div><Label className={lbl}>Name</Label><Input value={m.name} onChange={(e) => set({ name: e.target.value })} /></div>
            <div className="sm:col-span-2"><Label className={lbl}>Icon URL (optional)</Label><Input value={m.iconUrl || ''} onChange={(e) => set({ iconUrl: e.target.value })} /></div>
            <div className="sm:col-span-2"><Label className={lbl}>Authorization endpoint</Label><Input value={m.authorizationEndpoint} onChange={(e) => set({ authorizationEndpoint: e.target.value })} /></div>
            <div className="sm:col-span-2"><Label className={lbl}>Token endpoint</Label><Input value={m.tokenEndpoint} onChange={(e) => set({ tokenEndpoint: e.target.value })} /></div>
            <div className="sm:col-span-2"><Label className={lbl}>Userinfo endpoint</Label><Input value={m.userinfoEndpoint} onChange={(e) => set({ userinfoEndpoint: e.target.value })} /></div>
            <div className="sm:col-span-2"><Label className={lbl}>Default scopes (space-separated)</Label><Input value={scopes} onChange={(e) => setScopes(e.target.value)} /></div>
          </div>
          {msg && <p className="text-sm text-muted-foreground">{msg}</p>}
          <Button onClick={save} disabled={!m.key}>Save provider</Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

const blankOAuth = (): OAuthProvider => ({ key: '', name: '', iconUrl: '', docsUrl: '', authorizationEndpoint: '', tokenEndpoint: '', userinfoEndpoint: '', scopeDelimiter: ' ', defaultScopes: [], scopes: [] })
