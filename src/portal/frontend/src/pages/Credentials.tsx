import { useEffect, useState } from 'react'
import { Trash2, Plus, Pencil, Eye } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../ui/components/card'
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '../ui/components/table'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Label } from '../ui/components/label'
import { Badge } from '../ui/components/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '../ui/components/dialog'
import { CopyButton } from '../components/CopyButton'
import { Field } from '../components/Field'
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
            <>
              {/* Desktop: table. */}
              <div className="hidden sm:block">
                <Table>
                  <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Header</TableHead><TableHead>Base URL</TableHead><TableHead>Secret</TableHead><TableHead /></TableRow></TableHeader>
                  <TableBody>
                    {keys.map((k) => (
                      <TableRow key={k.id}>
                        <TableCell>
                          <div className="font-medium">{k.name}</div>
                          {k.description && <div className="max-w-[14rem] truncate text-xs text-muted-foreground" title={k.description}>{k.description}</div>}
                        </TableCell>
                        <TableCell className="whitespace-nowrap text-muted-foreground">{k.header}{k.prefix ? ` · ${k.prefix.trim()}` : ''}</TableCell>
                        <TableCell className="max-w-[12rem] truncate text-muted-foreground">{k.docsUrl ? <a className="text-accent hover:underline" href={k.docsUrl} target="_blank" rel="noreferrer">{k.baseUrl || 'docs'}</a> : k.baseUrl}</TableCell>
                        <TableCell><RevealButton title={k.name} load={() => api.revealApiKey(k.name).then((r) => r.secret)} /></TableCell>
                        <TableCell className="text-right">
                          <Button variant="ghost" size="icon" aria-label="Edit" onClick={() => setForm({ open: true, item: k })}><Pencil className="size-4" /></Button>
                          <Button variant="ghost" size="icon" aria-label="Delete" onClick={() => api.deleteApiKey(k.id).then(load)}><Trash2 className="size-4 text-destructive" /></Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {/* Mobile: a card per key with a two-column detail grid. */}
              <div className="space-y-3 sm:hidden">
                {keys.map((k) => (
                  <div key={k.id} className="rounded-xl border border-border p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="font-medium">{k.name}</div>
                        {k.description && <div className="truncate text-xs text-muted-foreground" title={k.description}>{k.description}</div>}
                      </div>
                      <div className="-mr-1 flex shrink-0">
                        <Button variant="ghost" size="icon" aria-label="Edit" onClick={() => setForm({ open: true, item: k })}><Pencil className="size-4" /></Button>
                        <Button variant="ghost" size="icon" aria-label="Delete" onClick={() => api.deleteApiKey(k.id).then(load)}><Trash2 className="size-4 text-destructive" /></Button>
                      </div>
                    </div>
                    <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2">
                      <Field label="Header">{k.header ? `${k.header}${k.prefix ? ` · ${k.prefix.trim()}` : ''}` : '—'}</Field>
                      <Field label="Base URL">{k.docsUrl ? <a className="text-accent hover:underline" href={k.docsUrl} target="_blank" rel="noreferrer">{k.baseUrl || 'docs'}</a> : (k.baseUrl || '—')}</Field>
                    </div>
                    <div className="mt-2 flex items-center gap-2">
                      <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Secret</span>
                      <RevealButton title={k.name} load={() => api.revealApiKey(k.name).then((r) => r.secret)} />
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Dialog open={form.open} onOpenChange={(o) => setForm({ open: o, item: o ? form.item : undefined })}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>{form.item ? `Edit ${form.item.name}` : 'Add an API key'}</DialogTitle>
            <DialogDescription>Self-describing — no fixed provider type. Description / host / docs / header help agents use it.</DialogDescription>
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
            <>
              {/* Desktop: table. */}
              <div className="hidden sm:block">
                <Table>
                  <TableHeader><TableRow><TableHead>Provider</TableHead><TableHead>Account</TableHead><TableHead>Expires</TableHead><TableHead>Scopes</TableHead><TableHead>Token</TableHead></TableRow></TableHeader>
                  <TableBody>
                    {tokens.map((t) => (
                      <TableRow key={t.id}>
                        <TableCell className="font-medium">{t.provider}</TableCell>
                        <TableCell>{t.account}</TableCell>
                        <TableCell className="text-muted-foreground">{t.expiresAt ? new Date(t.expiresAt).toLocaleString() : '—'}</TableCell>
                        <TableCell><div className="flex max-w-[16rem] flex-wrap gap-1">{t.scopes.slice(0, 3).map((s) => <Badge key={s} variant="secondary">{s}</Badge>)}{t.scopes.length > 3 && <Badge variant="secondary">+{t.scopes.length - 3}</Badge>}</div></TableCell>
                        <TableCell><RevealButton title={`${t.provider}${t.account ? ` · ${t.account}` : ''}`} load={() => api.revealOAuthToken(t.provider, t.account).then((r) => r.accessToken)} /></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {/* Mobile: a card per connected account. */}
              <div className="space-y-3 sm:hidden">
                {tokens.map((t) => (
                  <div key={t.id} className="rounded-xl border border-border p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="font-medium">{t.provider}</div>
                        {t.account && <div className="truncate text-xs text-muted-foreground">{t.account}</div>}
                      </div>
                      <RevealButton title={`${t.provider}${t.account ? ` · ${t.account}` : ''}`} load={() => api.revealOAuthToken(t.provider, t.account).then((r) => r.accessToken)} />
                    </div>
                    <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2">
                      <Field label="Expires">{t.expiresAt ? new Date(t.expiresAt).toLocaleString() : '—'}</Field>
                      <Field label="Scopes" truncate={false}>
                        <div className="flex flex-wrap gap-1">{t.scopes.slice(0, 3).map((s) => <Badge key={s} variant="secondary">{s}</Badge>)}{t.scopes.length > 3 && <Badge variant="secondary">+{t.scopes.length - 3}</Badge>}</div>
                      </Field>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </>
  )
}

// Reveal a secret in a modal (not inline) so long values can't push the row off-screen on
// mobile. The value is fetched on click and discarded when the dialog closes.
function RevealButton({ title, load }: { title: string; load: () => Promise<string> }) {
  const [open, setOpen] = useState(false)
  const [val, setVal] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string>()

  const reveal = async () => {
    setBusy(true); setErr(undefined)
    try { setVal(await load()); setOpen(true) }
    catch (e) { setErr(String(e)); setOpen(true) }
    finally { setBusy(false) }
  }

  return (
    <>
      <Button variant="ghost" size="icon" aria-label="Reveal" disabled={busy} onClick={reveal}><Eye className="size-4" /></Button>
      <Dialog open={open} onOpenChange={(o) => { setOpen(o); if (!o) setVal(undefined) }}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="break-all">{title}</DialogTitle>
            <DialogDescription>Copy the value — keep it secret.</DialogDescription>
          </DialogHeader>
          {err ? (
            <p className="text-sm text-destructive">{err}</p>
          ) : (
            <div className="flex items-start gap-2 rounded-xl border border-border bg-muted/40 p-3">
              <code className="min-w-0 flex-1 break-all text-sm">{val}</code>
              {val !== undefined && <CopyButton value={val} />}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}

function StoreKey({ initial, onStored }: { initial?: ApiKeyItem; onStored: () => void }) {
  const [k, setK] = useState({
    name: initial?.name ?? '', secret: '', description: initial?.description ?? '',
    baseUrl: initial?.baseUrl ?? '', docsUrl: initial?.docsUrl ?? '', header: initial?.header ?? '', prefix: initial?.prefix ?? '',
  })
  const [msg, setMsg] = useState<string>()
  const set = (patch: Partial<typeof k>) => setK({ ...k, ...patch })
  const editing = !!initial

  const submit = async () => {
    setMsg(undefined)
    try { await api.createApiKey(k); onStored() } catch (e) { setMsg(String(e)) }
  }

  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <div><Label className={lbl}>Name *</Label><Input value={k.name} readOnly={editing} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. grafana-prod" /></div>
      <div><Label className={lbl}>Secret {editing ? '' : '*'}</Label><Input type="password" value={k.secret} onChange={(e) => set({ secret: e.target.value })} placeholder={editing ? '(leave blank to keep)' : ''} /></div>
      <div className="sm:col-span-2"><Label className={lbl}>Description</Label><Input value={k.description} onChange={(e) => set({ description: e.target.value })} placeholder="what this credential is for" /></div>
      <div><Label className={lbl}>Base URL / host</Label><Input value={k.baseUrl} onChange={(e) => set({ baseUrl: e.target.value })} placeholder="https://api.example.com" /></div>
      <div><Label className={lbl}>API docs link</Label><Input value={k.docsUrl} onChange={(e) => set({ docsUrl: e.target.value })} placeholder="https://docs.example.com" /></div>
      <div><Label className={lbl}>Header (optional)</Label><Input value={k.header} onChange={(e) => set({ header: e.target.value })} placeholder="Authorization" /></div>
      <div><Label className={lbl}>Prefix (optional)</Label><Input value={k.prefix} onChange={(e) => set({ prefix: e.target.value })} placeholder="Bearer " /></div>
      {msg && <p className="text-sm text-destructive sm:col-span-2">{msg}</p>}
      <div className="sm:col-span-2"><Button onClick={submit} disabled={!k.name || (!editing && !k.secret)}>{editing ? 'Save changes' : 'Save key'}</Button></div>
    </div>
  )
}
