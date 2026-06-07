import { useEffect, useState } from 'react'
import { Trash2, Pencil, Plus } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '../ui/components/card'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Label } from '../ui/components/label'
import { api, type OAuthProvider } from '../api'

const lbl = 'mb-1 block text-xs text-muted-foreground'

// API keys are free-form / self-describing (see the Credentials tab), so "Providers"
// here manages OAuth providers only.
export function ProvidersPage() {
  const [providers, setProviders] = useState<OAuthProvider[]>([])
  const [editing, setEditing] = useState<OAuthProvider | null>(null)
  const load = () => api.oauthProviders().then(setProviders).catch(() => {})
  useEffect(() => { load() }, [])

  return (
    <>
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>OAuth providers</CardTitle>
          <Button size="sm" onClick={() => setEditing(blankOAuth())}><Plus className="size-4" /> New</Button>
        </CardHeader>
        <CardContent className="space-y-2">
          {providers.map((p) => (
            <div key={p.key} className="flex items-center justify-between rounded-xl border border-border p-3">
              <div className="min-w-0">
                <div className="font-medium">{p.name} <span className="text-xs text-muted-foreground">({p.key})</span></div>
                <div className="truncate text-xs text-muted-foreground">{p.authorizationEndpoint}</div>
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
    </>
  )
}

function OAuthEditor({ value, onClose, onSaved }: { value: OAuthProvider; onClose: () => void; onSaved: () => void }) {
  const [m, setM] = useState<OAuthProvider>(value)
  const [scopes, setScopes] = useState((value.defaultScopes || []).join(' '))
  const set = (patch: Partial<OAuthProvider>) => setM({ ...m, ...patch })
  const save = async () => {
    await api.upsertOAuthProvider({ ...m, scopeDelimiter: m.scopeDelimiter || ' ', defaultScopes: scopes.split(/\s+/).filter(Boolean) })
    onSaved()
  }
  return (
    <Card>
      <CardHeader><CardTitle>{value.key ? `Edit ${value.key}` : 'New OAuth provider'}</CardTitle></CardHeader>
      <CardContent className="grid gap-3 sm:grid-cols-2">
        <div><Label className={lbl}>Key (id)</Label><Input value={m.key} onChange={(e) => set({ key: e.target.value })} /></div>
        <div><Label className={lbl}>Name</Label><Input value={m.name} onChange={(e) => set({ name: e.target.value })} /></div>
        <div className="sm:col-span-2"><Label className={lbl}>Authorization endpoint</Label><Input value={m.authorizationEndpoint} onChange={(e) => set({ authorizationEndpoint: e.target.value })} /></div>
        <div className="sm:col-span-2"><Label className={lbl}>Token endpoint</Label><Input value={m.tokenEndpoint} onChange={(e) => set({ tokenEndpoint: e.target.value })} /></div>
        <div className="sm:col-span-2"><Label className={lbl}>Userinfo endpoint</Label><Input value={m.userinfoEndpoint} onChange={(e) => set({ userinfoEndpoint: e.target.value })} /></div>
        <div className="sm:col-span-2"><Label className={lbl}>Default scopes (space-separated)</Label><Input value={scopes} onChange={(e) => setScopes(e.target.value)} /></div>
        <div className="flex gap-2 sm:col-span-2">
          <Button onClick={save} disabled={!m.key}>Save provider</Button>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
        </div>
      </CardContent>
    </Card>
  )
}

const blankOAuth = (): OAuthProvider => ({ key: '', name: '', authorizationEndpoint: '', tokenEndpoint: '', userinfoEndpoint: '', scopeDelimiter: ' ', defaultScopes: [] })
