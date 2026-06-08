import { useEffect, useState } from 'react'
import { Trash2, Plus, Pencil, Eye, EyeOff } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../ui/components/card'
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '../ui/components/table'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Label } from '../ui/components/label'
import { Badge } from '../ui/components/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '../ui/components/dialog'
import { Tabs, TabsList, TabsTrigger } from '../ui/components/tabs'
import { CopyButton } from '../components/CopyButton'
import { api, type ApiKeyItem, type OAuthTokenItem } from '../api'

const lbl = 'mb-1 block text-xs text-muted-foreground'

export function CredentialsPage() {
  const [keys, setKeys] = useState<ApiKeyItem[]>([])
  const [tokens, setTokens] = useState<OAuthTokenItem[]>([])
  const [err, setErr] = useState<string>()
  const [form, setForm] = useState<{ open: boolean; item?: ApiKeyItem }>({ open: false })

  const load = () => {
    api.apiKeys().then(setKeys).catch((e) => setErr(String(e)))
    api.oauthTokens().then(setTokens).catch(() => {})
  }
  useEffect(() => { load() }, [])

  return (
    <>
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>API keys</CardTitle>
            <CardDescription>What's stored and how to use each.</CardDescription>
          </div>
          <Button size="icon" variant="outline" aria-label="Add API key" onClick={() => setForm({ open: true })}><Plus className="size-4" /></Button>
        </CardHeader>
        <CardContent>
          {err && <p className="text-sm text-destructive">{err}</p>}
          {keys.length === 0 ? (
            <p className="text-sm text-muted-foreground">No API keys yet — add one with the + button.</p>
          ) : (
            <Table>
              <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Description</TableHead><TableHead>Header</TableHead><TableHead>Base URL</TableHead><TableHead>Secret</TableHead><TableHead /></TableRow></TableHeader>
              <TableBody>
                {keys.map((k) => (
                  <TableRow key={k.id}>
                    <TableCell className="font-medium">{k.name}</TableCell>
                    <TableCell className="text-muted-foreground">{k.description}</TableCell>
                    <TableCell className="text-muted-foreground">{k.username ? `Basic · ${k.username}` : `${k.header}${k.prefix ? ` · ${k.prefix.trim()}` : ''}`}</TableCell>
                    <TableCell className="text-muted-foreground">{k.docsUrl ? <a className="text-accent hover:underline" href={k.docsUrl} target="_blank" rel="noreferrer">{k.baseUrl || 'docs'}</a> : k.baseUrl}</TableCell>
                    <TableCell><RevealCell load={() => api.revealApiKey(k.name).then((r) => r.secret)} /></TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon" aria-label="Edit" onClick={() => setForm({ open: true, item: k })}><Pencil className="size-4" /></Button>
                      <Button variant="ghost" size="icon" aria-label="Delete" onClick={() => api.deleteApiKey(k.id).then(load)}><Trash2 className="size-4 text-destructive" /></Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={form.open} onOpenChange={(o) => setForm({ open: o, item: o ? form.item : undefined })}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>{form.item ? `Edit ${form.item.name}` : 'Add a credential'}</DialogTitle>
            <DialogDescription>Pick how it authenticates. Self-describing — description / host / docs help agents use it.</DialogDescription>
          </DialogHeader>
          <StoreKey initial={form.item} onStored={() => { load(); setForm({ open: false }) }} />
        </DialogContent>
      </Dialog>

      <Card>
        <CardHeader><CardTitle>Connected OAuth accounts</CardTitle></CardHeader>
        <CardContent>
          {tokens.length === 0 ? (
            <p className="text-sm text-muted-foreground">No OAuth tokens — connect a provider from the OAuth Connect tab.</p>
          ) : (
            <Table>
              <TableHeader><TableRow><TableHead>Provider</TableHead><TableHead>Account</TableHead><TableHead>Expires</TableHead><TableHead>Scopes</TableHead><TableHead>Token</TableHead></TableRow></TableHeader>
              <TableBody>
                {tokens.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-medium">{t.provider}</TableCell>
                    <TableCell>{t.account}</TableCell>
                    <TableCell className="text-muted-foreground">{t.expiresAt ? new Date(t.expiresAt).toLocaleString() : '—'}</TableCell>
                    <TableCell><div className="flex max-w-[16rem] flex-wrap gap-1">{t.scopes.slice(0, 3).map((s) => <Badge key={s} variant="secondary">{s}</Badge>)}{t.scopes.length > 3 && <Badge variant="secondary">+{t.scopes.length - 3}</Badge>}</div></TableCell>
                    <TableCell><RevealCell load={() => api.revealOAuthToken(t.provider, t.account).then((r) => r.accessToken)} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  )
}

function RevealCell({ load }: { load: () => Promise<string> }) {
  const [val, setVal] = useState<string>()
  const [busy, setBusy] = useState(false)
  if (val !== undefined) {
    return (
      <span className="flex items-center gap-1">
        <code className="max-w-[14rem] truncate text-xs">{val}</code>
        <CopyButton value={val} />
        <Button variant="ghost" size="icon" aria-label="Hide" onClick={() => setVal(undefined)}><EyeOff className="size-4" /></Button>
      </span>
    )
  }
  return (
    <Button variant="ghost" size="icon" aria-label="Reveal" disabled={busy}
      onClick={async () => { setBusy(true); try { setVal(await load()) } catch { /* ignore */ } finally { setBusy(false) } }}>
      <Eye className="size-4" />
    </Button>
  )
}

type Scheme = 'header' | 'basic'

function StoreKey({ initial, onStored }: { initial?: ApiKeyItem; onStored: () => void }) {
  // Scheme is chosen explicitly, not inferred from a field. Pre-select Basic when editing
  // a credential that already has a username.
  const [mode, setMode] = useState<Scheme>(initial?.username ? 'basic' : 'header')
  const [k, setK] = useState({
    name: initial?.name ?? '', secret: '', description: initial?.description ?? '',
    baseUrl: initial?.baseUrl ?? '', docsUrl: initial?.docsUrl ?? '', header: initial?.header ?? '', prefix: initial?.prefix ?? '',
    username: initial?.username ?? '',
  })
  const [msg, setMsg] = useState<string>()
  const set = (patch: Partial<typeof k>) => setK({ ...k, ...patch })
  const editing = !!initial
  const basic = mode === 'basic'

  const submit = async () => {
    setMsg(undefined)
    // Send only the fields for the chosen scheme so the other mode's values can't leak through:
    // Basic clears header/prefix (auto-assembled); a token credential clears username.
    const payload = basic
      ? { ...k, username: k.username.trim(), header: '', prefix: '' }
      : { ...k, username: '' }
    try { await api.createApiKey(payload); onStored() } catch (e) { setMsg(String(e)) }
  }

  return (
    <div className="grid gap-3">
      <Tabs value={mode} onValueChange={(v) => setMode(v as Scheme)}>
        <TabsList>
          <TabsTrigger value="header" className="flex-1">API key / token</TabsTrigger>
          <TabsTrigger value="basic" className="flex-1">Username + password</TabsTrigger>
        </TabsList>
      </Tabs>

      <div className="grid gap-3 sm:grid-cols-2">
        <div><Label className={lbl}>Name *</Label><Input value={k.name} readOnly={editing} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. grafana-prod" /></div>

        {basic ? (
          <>
            <div><Label className={lbl}>Username *</Label><Input value={k.username} onChange={(e) => set({ username: e.target.value })} placeholder="e.g. admin" /></div>
            <div className="sm:col-span-2"><Label className={lbl}>Password {editing ? '' : '*'}</Label><Input type="password" value={k.secret} onChange={(e) => set({ secret: e.target.value })} placeholder={editing ? '(leave blank to keep)' : ''} /></div>
          </>
        ) : (
          <div><Label className={lbl}>Secret {editing ? '' : '*'}</Label><Input type="password" value={k.secret} onChange={(e) => set({ secret: e.target.value })} placeholder={editing ? '(leave blank to keep)' : ''} /></div>
        )}

        <div className="sm:col-span-2"><Label className={lbl}>Description</Label><Input value={k.description} onChange={(e) => set({ description: e.target.value })} placeholder="what this credential is for" /></div>
        <div><Label className={lbl}>Base URL / host</Label><Input value={k.baseUrl} onChange={(e) => set({ baseUrl: e.target.value })} placeholder="https://api.example.com" /></div>
        <div><Label className={lbl}>API docs link</Label><Input value={k.docsUrl} onChange={(e) => set({ docsUrl: e.target.value })} placeholder="https://docs.example.com" /></div>

        {basic ? (
          <p className="text-xs text-muted-foreground sm:col-span-2">Sent as <code>Authorization: Basic base64(username:password)</code> — header and prefix are handled for you.</p>
        ) : (
          <>
            <div><Label className={lbl}>Header (optional)</Label><Input value={k.header} onChange={(e) => set({ header: e.target.value })} placeholder="Authorization" /></div>
            <div><Label className={lbl}>Prefix (optional)</Label><Input value={k.prefix} onChange={(e) => set({ prefix: e.target.value })} placeholder="Bearer " /></div>
          </>
        )}

        {msg && <p className="text-sm text-destructive sm:col-span-2">{msg}</p>}
        <div className="sm:col-span-2"><Button onClick={submit} disabled={!k.name || (!editing && !k.secret) || (basic && !k.username.trim())}>{editing ? 'Save changes' : 'Save key'}</Button></div>
      </div>
    </div>
  )
}
