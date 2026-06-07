import { useEffect, useState } from 'react'
import { Trash2, Pencil, Plus } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../ui/components/card'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../ui/components/tabs'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Label } from '../ui/components/label'
import { api, type ApiKeyProvider, type OAuthProvider } from '../api'

const lbl = 'mb-1 block text-xs text-muted-foreground'

export function ProvidersPage() {
  return (
    <Tabs defaultValue="apikey">
      <TabsList>
        <TabsTrigger value="apikey">API-key providers</TabsTrigger>
        <TabsTrigger value="oauth">OAuth providers</TabsTrigger>
      </TabsList>
      <TabsContent value="apikey" className="space-y-6 pt-4"><ApiKeySection /></TabsContent>
      <TabsContent value="oauth" className="space-y-6 pt-4"><OAuthSection /></TabsContent>
    </Tabs>
  )
}

function ApiKeySection() {
  const [providers, setProviders] = useState<ApiKeyProvider[]>([])
  const [editing, setEditing] = useState<ApiKeyProvider | null>(null)
  const load = () => api.apiKeyProviders().then(setProviders).catch(() => {})
  useEffect(() => { load() }, [])

  return (
    <>
      <StoreKeyCard providers={providers} onStored={() => {}} />
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>Providers</CardTitle>
          <Button size="sm" onClick={() => setEditing(blankApiKey())}><Plus className="size-4" /> New</Button>
        </CardHeader>
        <CardContent className="space-y-2">
          {providers.map((p) => (
            <div key={p.key} className="flex items-center justify-between rounded-xl border border-border p-3">
              <div className="min-w-0">
                <div className="font-medium">{p.name} <span className="text-xs text-muted-foreground">({p.key})</span></div>
                <div className="text-xs text-muted-foreground">
                  {p.header}{p.prefix ? ` · “${p.prefix}”` : ''}
                  {Object.keys(p.staticHeaders || {}).length > 0 ? ` · +${Object.keys(p.staticHeaders).length} static` : ''}
                  {p.docsUrl ? <> · <a className="text-accent hover:underline" href={p.docsUrl} target="_blank" rel="noreferrer">docs</a></> : null}
                </div>
              </div>
              <div className="flex gap-1">
                <Button variant="ghost" size="icon" onClick={() => setEditing(structuredClone(p))}><Pencil className="size-4" /></Button>
                <Button variant="ghost" size="icon" onClick={() => api.deleteProvider('apikey', p.key).then(load)}><Trash2 className="size-4 text-destructive" /></Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
      {editing && <ApiKeyEditor value={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); load() }} />}
    </>
  )
}

function StoreKeyCard({ providers }: { providers: ApiKeyProvider[]; onStored: () => void }) {
  const [provider, setProvider] = useState('')
  const [name, setName] = useState('')
  const [values, setValues] = useState<Record<string, string>>({})
  const [msg, setMsg] = useState<string>()
  useEffect(() => { if (providers[0] && !provider) setProvider(providers[0].key) }, [providers])
  const current = providers.find((p) => p.key === provider)

  const submit = async () => {
    setMsg(undefined)
    try { await api.createApiKey(provider, name || 'default', values); setMsg('Saved.'); setName(''); setValues({}) }
    catch (e) { setMsg(String(e)) }
  }

  return (
    <Card>
      <CardHeader><CardTitle>Store an API key</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <div>
          <label className={lbl}>Provider</label>
          <select className="w-full rounded-xl border border-input bg-background px-3 py-2 text-sm" value={provider} onChange={(e) => { setProvider(e.target.value); setValues({}) }}>
            {providers.map((p) => <option key={p.key} value={p.key}>{p.name}</option>)}
          </select>
        </div>
        <div><Label className={lbl}>Name</Label><Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. prod" /></div>
        {current?.fields.map((f) => (
          <div key={f.name}>
            <Label className={lbl}>{f.label || f.name}{f.required ? ' *' : ''}</Label>
            <Input type={f.secret ? 'password' : 'text'} value={values[f.name] || ''} onChange={(e) => setValues({ ...values, [f.name]: e.target.value })} />
          </div>
        ))}
        {msg && <p className="text-sm text-muted-foreground">{msg}</p>}
        <Button onClick={submit}>Save key</Button>
      </CardContent>
    </Card>
  )
}

function ApiKeyEditor({ value, onClose, onSaved }: { value: ApiKeyProvider; onClose: () => void; onSaved: () => void }) {
  const [m, setM] = useState<ApiKeyProvider>(value)
  const [staticText, setStaticText] = useState(Object.entries(value.staticHeaders || {}).map(([k, v]) => `${k}: ${v}`).join('\n'))
  const field = m.fields[0] || { name: 'api_key', label: 'API Key', secret: true, required: true }
  const set = (patch: Partial<ApiKeyProvider>) => setM({ ...m, ...patch })

  const save = async () => {
    const staticHeaders: Record<string, string> = {}
    for (const line of staticText.split('\n')) { const i = line.indexOf(':'); if (i > 0) staticHeaders[line.slice(0, i).trim()] = line.slice(i + 1).trim() }
    await api.upsertApiKeyProvider({ ...m, authScheme: 'header', staticHeaders, fields: [field] })
    onSaved()
  }

  return (
    <Card>
      <CardHeader><CardTitle>{value.key ? `Edit ${value.key}` : 'New API-key provider'}</CardTitle><CardDescription>How the key is presented on outbound requests.</CardDescription></CardHeader>
      <CardContent className="grid gap-3 sm:grid-cols-2">
        <div><Label className={lbl}>Key (id)</Label><Input value={m.key} onChange={(e) => set({ key: e.target.value })} placeholder="e.g. my-service" /></div>
        <div><Label className={lbl}>Name</Label><Input value={m.name} onChange={(e) => set({ name: e.target.value })} /></div>
        <div><Label className={lbl}>Header</Label><Input value={m.header} onChange={(e) => set({ header: e.target.value })} placeholder="Authorization" /></div>
        <div><Label className={lbl}>Prefix</Label><Input value={m.prefix} onChange={(e) => set({ prefix: e.target.value })} placeholder="Bearer " /></div>
        <div><Label className={lbl}>Docs / example URL</Label><Input value={m.docsUrl} onChange={(e) => set({ docsUrl: e.target.value })} /></div>
        <div><Label className={lbl}>Base URL</Label><Input value={m.baseUrl} onChange={(e) => set({ baseUrl: e.target.value })} /></div>
        <div className="sm:col-span-2"><Label className={lbl}>Static headers (one per line, "Name: value")</Label>
          <textarea className="w-full rounded-xl border border-input bg-background px-3 py-2 text-sm" rows={2} value={staticText} onChange={(e) => setStaticText(e.target.value)} placeholder="anthropic-version: 2023-06-01" /></div>
        <div><Label className={lbl}>Field name</Label><Input value={field.name} onChange={(e) => set({ fields: [{ ...field, name: e.target.value }] })} /></div>
        <div><Label className={lbl}>Field label</Label><Input value={field.label} onChange={(e) => set({ fields: [{ ...field, label: e.target.value }] })} /></div>
        <div className="flex gap-2 sm:col-span-2">
          <Button onClick={save} disabled={!m.key}>Save provider</Button>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
        </div>
      </CardContent>
    </Card>
  )
}

function OAuthSection() {
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

const blankApiKey = (): ApiKeyProvider => ({ key: '', name: '', iconUrl: '', docsUrl: '', authScheme: 'header', header: 'Authorization', prefix: 'Bearer ', baseUrl: '', staticHeaders: {}, fields: [{ name: 'api_key', label: 'API Key', secret: true, required: true }] })
const blankOAuth = (): OAuthProvider => ({ key: '', name: '', authorizationEndpoint: '', tokenEndpoint: '', userinfoEndpoint: '', scopeDelimiter: ' ', defaultScopes: [] })
