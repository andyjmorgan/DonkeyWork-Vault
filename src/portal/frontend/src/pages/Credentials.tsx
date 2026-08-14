import { useEffect, useMemo, useState } from 'react'
import { Trash2, Plus, Pencil, Eye, Search, ChevronLeft, ChevronRight } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../ui/components/card'
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '../ui/components/table'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Textarea } from '../ui/components/textarea'
import { Label } from '../ui/components/label'
import { Badge } from '../ui/components/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '../ui/components/dialog'
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '../ui/components/select'
import { CopyButton } from '../components/CopyButton'
import { Field } from '../components/Field'
import { api, type ApiKeyItem, type NewApiKey, type OAuthTokenItem, type CredentialKind } from '../api'

const lbl = 'mb-1 block text-xs text-muted-foreground'
const PAGE_SIZE = 10

// Flatten only values, not property names, so every text field returned for a credential is
// searchable without making implementation details such as "baseUrl" produce false matches.
const textValues = (value: unknown): string[] => {
  if (typeof value === 'string') return [value]
  if (Array.isArray(value)) return value.flatMap(textValues)
  if (value && typeof value === 'object') return Object.values(value).flatMap(textValues)
  return []
}

const matchesSearch = (value: unknown, query: string, extra: string[] = []) => {
  const terms = query.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean)
  if (terms.length === 0) return true
  const searchable = [...textValues(value), ...extra].join(' ').toLocaleLowerCase()
  return terms.every((term) => searchable.includes(term))
}

// Localize the internal kind discriminator to a human label for the console.
const kindLabel: Record<CredentialKind, string> = {
  opaque: 'Opaque',
  header_api_key: 'Header API key',
  http_basic: 'HTTP Basic',
  username_password: 'Username + password',
  ssh: 'SSH',
  connection_string: 'Connection string',
}
const prettyKind = (k: CredentialKind) => kindLabel[k] ?? k

// Each credential shape needs a different field set. This config drives the add/edit form body so it
// reflects the chosen kind, rather than the old binary header/basic switch.
type FieldConf = {
  username?: boolean      // show (and require) a username input
  secretLabel: string     // label for the secret input
  headerPrefix?: boolean  // show the Header + Prefix inputs (header_api_key only)
  baseUrlLabel: string    // label for the base URL / host input
  note?: string           // helper line rendered under the fields
}
const shapeConf: Record<CredentialKind, FieldConf> = {
  opaque: { secretLabel: 'Secret', baseUrlLabel: 'Base URL / host' },
  header_api_key: { secretLabel: 'Secret', headerPrefix: true, baseUrlLabel: 'Base URL' },
  http_basic: { username: true, secretLabel: 'Password', baseUrlLabel: 'Base URL', note: 'Sent as Authorization: Basic base64(username:password) — header and prefix are handled for you.' },
  username_password: { username: true, secretLabel: 'Password', baseUrlLabel: 'Base URL / host' },
  ssh: { username: true, secretLabel: 'Password / private key', baseUrlLabel: 'Host' },
  connection_string: { secretLabel: 'Connection string', baseUrlLabel: 'Base URL' },
}

// One-line "how it authenticates" summary for the list, keyed off kind so username-bearing shapes
// (ssh, username_password) read sensibly instead of being mislabelled as Basic.
const authSummary = (k: ApiKeyItem): string => {
  if (k.username) return `${prettyKind(k.kind)} · ${k.username}`
  if (k.header) return `${k.header}${k.prefix ? ` · ${k.prefix.trim()}` : ''}`
  return '—'
}

// Google-style OAuth scopes are full URLs (https://www.googleapis.com/auth/calendar) that overflow
// the pill; show the meaningful tail. Short scopes (gist, Calendars.Read) are shown as-is.
const shortScope = (s: string) => (s.includes('://') ? (s.replace(/\/+$/, '').split('/').pop() || s) : s)

function ScopeBadges({ scopes, className = '' }: { scopes: string[]; className?: string }) {
  return (
    <div className={`flex flex-wrap gap-1 ${className}`}>
      {scopes.slice(0, 3).map((s) => (
        <Badge key={s} variant="secondary" title={s} className="max-w-[10rem] truncate">{shortScope(s)}</Badge>
      ))}
      {scopes.length > 3 && <Badge variant="secondary">+{scopes.length - 3}</Badge>}
    </div>
  )
}

export function CredentialsPage() {
  const [keys, setKeys] = useState<ApiKeyItem[]>([])
  const [tokens, setTokens] = useState<OAuthTokenItem[]>([])
  const [search, setSearch] = useState('')
  const [keyPage, setKeyPage] = useState(0)
  const [tokenPage, setTokenPage] = useState(0)
  const [err, setErr] = useState<string>()
  const [form, setForm] = useState<{ open: boolean; item?: ApiKeyItem; kind: CredentialKind; view?: boolean }>({ open: false, kind: 'header_api_key' })
  const [deleting, setDeleting] = useState<{ kind: 'apiKey'; item: ApiKeyItem } | { kind: 'oauthToken'; item: OAuthTokenItem }>()
  const [deleteBusy, setDeleteBusy] = useState(false)
  const [deleteErr, setDeleteErr] = useState<string>()

  const load = () => {
    api.apiKeys().then((items) => { setKeys(items); setErr(undefined) }).catch((e) => setErr(String(e)))
    api.oauthTokens().then(setTokens).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const filteredKeys = useMemo(
    () => keys.filter((key) => matchesSearch(key, search, [prettyKind(key.kind)])),
    [keys, search],
  )
  const filteredTokens = useMemo(
    () => tokens.filter((token) => matchesSearch(token, search)),
    [tokens, search],
  )
  const keyPageCount = Math.max(1, Math.ceil(filteredKeys.length / PAGE_SIZE))
  const tokenPageCount = Math.max(1, Math.ceil(filteredTokens.length / PAGE_SIZE))
  const currentKeyPage = Math.min(keyPage, keyPageCount - 1)
  const currentTokenPage = Math.min(tokenPage, tokenPageCount - 1)
  const visibleKeys = filteredKeys.slice(currentKeyPage * PAGE_SIZE, (currentKeyPage + 1) * PAGE_SIZE)
  const visibleTokens = filteredTokens.slice(currentTokenPage * PAGE_SIZE, (currentTokenPage + 1) * PAGE_SIZE)

  // Keep page state valid after deleting the last item on a page or narrowing the result set.
  useEffect(() => setKeyPage((page) => Math.min(page, keyPageCount - 1)), [keyPageCount])
  useEffect(() => setTokenPage((page) => Math.min(page, tokenPageCount - 1)), [tokenPageCount])

  const updateSearch = (value: string) => {
    setSearch(value)
    setKeyPage(0)
    setTokenPage(0)
  }

  const edit = (item: ApiKeyItem) => setForm({ open: true, item, kind: item.kind })
  const view = (item: ApiKeyItem) => setForm({ open: true, item, kind: item.kind, view: true })
  const requestDelete = (target: NonNullable<typeof deleting>) => {
    setForm({ open: false, kind: 'header_api_key' })
    setDeleteErr(undefined)
    setDeleting(target)
  }
  const remove = async () => {
    if (!deleting) return
    setDeleteBusy(true); setDeleteErr(undefined)
    try {
      if (deleting.kind === 'apiKey') await api.deleteApiKey(deleting.item.id)
      else await api.deleteOAuthToken(deleting.item.id)
      setDeleting(undefined)
      load()
    } catch (e) {
      setDeleteErr(String(e))
    } finally {
      setDeleteBusy(false)
    }
  }

  // When editing/viewing, the kind is fixed by the stored credential; when adding, it's the default
  // the dialog opens with — the user changes it via the Kind selector inside the form.
  const formKind: CredentialKind = form.item?.kind ?? form.kind

  return (
    <>
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          type="search"
          value={search}
          onChange={(event) => updateSearch(event.target.value)}
          placeholder="Search credentials"
          aria-label="Search credentials"
          className="pl-9"
        />
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>API keys</CardTitle>
            <CardDescription>What's stored and how to use each.</CardDescription>
          </div>
          <Button size="icon" variant="outline" aria-label="Add credential" onClick={() => setForm({ open: true, kind: 'header_api_key' })}><Plus className="size-4" /></Button>
        </CardHeader>
        <CardContent>
          {err && <p className="text-sm text-destructive">{err}</p>}
          {filteredKeys.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {keys.length === 0 ? 'No API keys yet — add one with the + button.' : 'No API keys match your search.'}
            </p>
          ) : (
            <>
              {/* Desktop: table. */}
              <div className="hidden sm:block">
                <Table>
                  <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Kind</TableHead><TableHead>Auth</TableHead><TableHead>Base URL</TableHead><TableHead>Secret</TableHead><TableHead /></TableRow></TableHeader>
                  <TableBody>
                    {visibleKeys.map((k) => (
                      <TableRow key={k.id} className="cursor-pointer" onClick={() => view(k)}>
                        <TableCell>
                          <div className="font-medium">{k.name}</div>
                          {k.description && <div className="max-w-[14rem] truncate text-xs text-muted-foreground" title={k.description}>{k.description}</div>}
                        </TableCell>
                        <TableCell className="whitespace-nowrap"><Badge variant="secondary">{prettyKind(k.kind)}</Badge></TableCell>
                        <TableCell className="whitespace-nowrap text-muted-foreground">{authSummary(k)}</TableCell>
                        <TableCell className="max-w-[12rem] truncate text-muted-foreground">{k.docsUrl ? <a className="text-accent hover:underline" href={k.docsUrl} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>{k.baseUrl || 'docs'}</a> : k.baseUrl}</TableCell>
                        <TableCell onClick={(e) => e.stopPropagation()}><RevealButton title={k.name} load={() => api.revealApiKey(k.name).then((r) => r.secret)} /></TableCell>
                        <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                          <Button variant="ghost" size="icon" aria-label={`Edit ${k.name}`} onClick={() => edit(k)}><Pencil className="size-4" /></Button>
                          <Button variant="ghost" size="icon" aria-label={`Delete ${k.name}`} onClick={() => requestDelete({ kind: 'apiKey', item: k })}><Trash2 className="size-4 text-destructive" /></Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {/* Mobile: a card per key with a two-column detail grid. */}
              <div className="space-y-3 sm:hidden">
                {visibleKeys.map((k) => (
                  <div key={k.id} className="cursor-pointer rounded-xl border border-border p-3" onClick={() => view(k)}>
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="font-medium">{k.name}</div>
                        {k.description && <div className="truncate text-xs text-muted-foreground" title={k.description}>{k.description}</div>}
                      </div>
                      <div className="-mr-1 flex shrink-0" onClick={(e) => e.stopPropagation()}>
                        <Button variant="ghost" size="icon" aria-label={`Edit ${k.name}`} onClick={() => edit(k)}><Pencil className="size-4" /></Button>
                        <Button variant="ghost" size="icon" aria-label={`Delete ${k.name}`} onClick={() => requestDelete({ kind: 'apiKey', item: k })}><Trash2 className="size-4 text-destructive" /></Button>
                      </div>
                    </div>
                    <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2">
                      <Field label="Kind">{prettyKind(k.kind)}</Field>
                      <Field label="Auth">{authSummary(k)}</Field>
                      <Field label="Base URL">{k.docsUrl ? <a className="text-accent hover:underline" href={k.docsUrl} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>{k.baseUrl || 'docs'}</a> : (k.baseUrl || '—')}</Field>
                    </div>
                    <div className="mt-2 flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                      <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Secret</span>
                      <RevealButton title={k.name} load={() => api.revealApiKey(k.name).then((r) => r.secret)} />
                    </div>
                  </div>
                ))}
              </div>
              <CredentialPager
                total={filteredKeys.length}
                page={currentKeyPage}
                onPage={setKeyPage}
                label="API keys"
              />
            </>
          )}
        </CardContent>
      </Card>

      <Dialog open={form.open} onOpenChange={(o) => { if (!o) setForm({ open: false, kind: 'header_api_key' }) }}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>{form.item ? (form.view ? form.item.name : `Edit ${form.item.name}`) : 'Add a credential'}</DialogTitle>
            <DialogDescription>{form.view ? 'Read-only view of this credential.' : 'Self-describing — description / host / docs help agents discover how to use it.'}</DialogDescription>
          </DialogHeader>
          <StoreKey
            key={`${form.item?.id ?? 'new'}-${form.view ? 'view' : 'edit'}`}
            initial={form.item}
            kind={formKind}
            readOnly={!!form.view}
            onClose={() => setForm({ open: false, kind: 'header_api_key' })}
            onEdit={form.item ? () => edit(form.item!) : undefined}
            onDelete={form.item ? () => requestDelete({ kind: 'apiKey', item: form.item! }) : undefined}
            onStored={() => { load(); setForm({ open: false, kind: 'header_api_key' }) }}
          />
        </DialogContent>
      </Dialog>

      <Dialog open={!!deleting} onOpenChange={(open) => { if (!open && !deleteBusy) setDeleting(undefined) }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Delete credential?</DialogTitle>
            <DialogDescription>
              {deleting?.kind === 'apiKey'
                ? `This permanently deletes ${deleting.item.name}.`
                : `This permanently deletes the ${deleting?.item.provider}${deleting?.item.account ? ` connection for ${deleting.item.account}` : ' connection'}.`}
            </DialogDescription>
          </DialogHeader>
          {deleteErr && <p className="text-sm text-destructive">{deleteErr}</p>}
          <div className="flex justify-end gap-2">
            <Button variant="outline" disabled={deleteBusy} onClick={() => setDeleting(undefined)}>Cancel</Button>
            <Button variant="destructive" disabled={deleteBusy} onClick={remove}>{deleteBusy ? 'Deleting…' : 'Delete'}</Button>
          </div>
        </DialogContent>
      </Dialog>

      <Card>
        <CardHeader><CardTitle>Connected OAuth accounts</CardTitle></CardHeader>
        <CardContent>
          {filteredTokens.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {tokens.length === 0 ? 'No OAuth tokens — connect a provider from the OAuth Connect tab.' : 'No OAuth accounts match your search.'}
            </p>
          ) : (
            <>
              {/* Desktop: table. */}
              <div className="hidden sm:block">
                <Table>
                  <TableHeader><TableRow><TableHead>Provider</TableHead><TableHead>Account</TableHead><TableHead>Expires</TableHead><TableHead>Scopes</TableHead><TableHead>Token</TableHead><TableHead /></TableRow></TableHeader>
                  <TableBody>
                    {visibleTokens.map((t) => (
                      <TableRow key={t.id}>
                        <TableCell className="font-medium">{t.provider}</TableCell>
                        <TableCell>{t.account}</TableCell>
                        <TableCell className="text-muted-foreground">{t.expiresAt ? new Date(t.expiresAt).toLocaleString() : '—'}</TableCell>
                        <TableCell><ScopeBadges scopes={t.scopes} className="max-w-[16rem]" /></TableCell>
                        <TableCell><RevealButton title={`${t.provider}${t.account ? ` · ${t.account}` : ''}`} load={() => api.revealOAuthToken(t.provider, t.account).then((r) => r.accessToken)} /></TableCell>
                        <TableCell className="text-right"><Button variant="ghost" size="icon" aria-label={`Delete ${t.provider} connection`} onClick={() => requestDelete({ kind: 'oauthToken', item: t })}><Trash2 className="size-4 text-destructive" /></Button></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {/* Mobile: a card per connected account. */}
              <div className="space-y-3 sm:hidden">
                {visibleTokens.map((t) => (
                  <div key={t.id} className="rounded-xl border border-border p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="font-medium">{t.provider}</div>
                        {t.account && <div className="truncate text-xs text-muted-foreground">{t.account}</div>}
                      </div>
                      <div className="-mr-1 flex shrink-0">
                        <RevealButton title={`${t.provider}${t.account ? ` · ${t.account}` : ''}`} load={() => api.revealOAuthToken(t.provider, t.account).then((r) => r.accessToken)} />
                        <Button variant="ghost" size="icon" aria-label={`Delete ${t.provider} connection`} onClick={() => requestDelete({ kind: 'oauthToken', item: t })}><Trash2 className="size-4 text-destructive" /></Button>
                      </div>
                    </div>
                    <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2">
                      <Field label="Expires">{t.expiresAt ? new Date(t.expiresAt).toLocaleString() : '—'}</Field>
                      <Field label="Scopes" truncate={false}>
                        <ScopeBadges scopes={t.scopes} />
                      </Field>
                    </div>
                  </div>
                ))}
              </div>
              <CredentialPager
                total={filteredTokens.length}
                page={currentTokenPage}
                onPage={setTokenPage}
                label="OAuth accounts"
              />
            </>
          )}
        </CardContent>
      </Card>
    </>
  )
}

function CredentialPager({ total, page, onPage, label }: {
  total: number
  page: number
  onPage: (page: number) => void
  label: string
}) {
  const from = page * PAGE_SIZE + 1
  const to = Math.min((page + 1) * PAGE_SIZE, total)
  const canNext = to < total

  return (
    <div className="mt-4 flex items-center justify-between">
      <span className="text-xs text-muted-foreground">{from}–{to} of {total}</span>
      <div className="flex items-center gap-1">
        <Button variant="outline" size="icon" aria-label={`Previous ${label} page`} disabled={page === 0} onClick={() => onPage(page - 1)}>
          <ChevronLeft className="size-4" />
        </Button>
        <Button variant="outline" size="icon" aria-label={`Next ${label} page`} disabled={!canNext} onClick={() => onPage(page + 1)}>
          <ChevronRight className="size-4" />
        </Button>
      </div>
    </div>
  )
}

// Middle-truncate a long secret for display so a giant value (e.g. a Microsoft JWT, which
// can run thousands of chars) can't push the reveal modal off-screen. The full value is
// still what the CopyButton copies — this only affects what's shown.
const middleTruncate = (s: string, max = 64) =>
  s.length > max ? `${s.slice(0, max / 2 - 1)}…${s.slice(-(max / 2 - 1))}` : s

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
              <code className="min-w-0 flex-1 break-all text-sm" title={val}>{val !== undefined ? middleTruncate(val) : ''}</code>
              {val !== undefined && <CopyButton value={val} />}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}

function StoreKey({ initial, kind: initialKind, readOnly = false, onClose, onEdit, onDelete, onStored }: { initial?: ApiKeyItem; kind: CredentialKind; readOnly?: boolean; onClose?: () => void; onEdit?: () => void; onDelete?: () => void; onStored: () => void }) {
  // Read-only view is always opened with a stored credential. Guarding here keeps a stray render
  // with no `initial` (e.g. the brief frame as the dialog clears its item on close) from throwing.
  const view = readOnly && !!initial
  // The kind is editable while adding (the selector swaps the form body live); once stored it's fixed,
  // so on edit/view it's shown read-only. The parent remounts this only on item/view changes.
  const [kind, setKind] = useState<CredentialKind>(initialKind)
  const conf = shapeConf[kind]
  const [k, setK] = useState({
    name: initial?.name ?? '', secret: '', description: initial?.description ?? '',
    baseUrl: initial?.baseUrl ?? '', docsUrl: initial?.docsUrl ?? '', header: initial?.header ?? '', prefix: initial?.prefix ?? '',
    username: initial?.username ?? '',
  })
  const [msg, setMsg] = useState<string>()
  const [busy, setBusy] = useState(false)
  const set = (patch: Partial<typeof k>) => setK({ ...k, ...patch })
  const editing = !!initial

  // In read-only view, fields render as muted, non-editable surfaces and the secret is fetched
  // on demand via the reveal flow rather than shown as a blank password box.
  const ro = readOnly ? 'cursor-default bg-muted/40 focus-visible:ring-0 focus-visible:border-input' : ''
  const fieldProps = (value: string) => readOnly ? { value, readOnly: true, className: ro } : undefined

  const submit = async () => {
    setBusy(true); setMsg(undefined)
    // Send only the fields this shape uses so another shape's values can't leak through: clear the
    // username for shapes without one, and header/prefix for shapes that don't expose them.
    const payload: NewApiKey = {
      ...k, kind,
      username: conf.username ? k.username.trim() : '',
      header: conf.headerPrefix ? k.header : '',
      prefix: conf.headerPrefix ? k.prefix : '',
    }
    try { await api.createApiKey(payload); onStored() }
    catch (e) { setMsg(String(e)) }
    finally { setBusy(false) }
  }

  return (
    <div className="grid gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label className={lbl}>Kind</Label>
          {editing || readOnly ? (
            <Input value={prettyKind(kind)} readOnly className={ro} />
          ) : (
            <Select value={kind} onValueChange={(v) => setKind(v as CredentialKind)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {(Object.keys(kindLabel) as CredentialKind[]).map((kk) => (
                  <SelectItem key={kk} value={kk}>{kindLabel[kk]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>

        <div><Label className={lbl}>Name{readOnly ? '' : ' *'}</Label><Input value={k.name} readOnly={editing || readOnly} className={ro} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. grafana-prod" /></div>

        {conf.username && (
          <div><Label className={lbl}>Username{readOnly ? '' : ' *'}</Label><Input value={k.username} readOnly={readOnly} className={ro} onChange={(e) => set({ username: e.target.value })} placeholder="e.g. admin" /></div>
        )}

        <div className={conf.username ? 'sm:col-span-2' : ''}><Label className={lbl}>{conf.secretLabel}</Label>{view ? <RevealField title={initial!.name} load={() => api.revealApiKey(initial!.name).then((r) => r.secret)} /> : <Input type="password" value={k.secret} onChange={(e) => set({ secret: e.target.value })} placeholder={editing ? '(leave blank to keep)' : ''} />}</div>

        <div className="sm:col-span-2"><Label className={lbl}>Description</Label><Textarea {...fieldProps(k.description)} rows={3} value={k.description} onChange={(e) => set({ description: e.target.value })} placeholder="what this credential is for" /></div>
        <div><Label className={lbl}>{conf.baseUrlLabel}</Label><Input value={k.baseUrl} readOnly={readOnly} className={ro} onChange={(e) => set({ baseUrl: e.target.value })} placeholder="https://api.example.com" /></div>
        <div><Label className={lbl}>API docs link</Label><Input value={k.docsUrl} readOnly={readOnly} className={ro} onChange={(e) => set({ docsUrl: e.target.value })} placeholder="https://docs.example.com" /></div>

        {conf.headerPrefix && (
          <>
            <div><Label className={lbl}>Header (optional)</Label><Input value={k.header} readOnly={readOnly} className={ro} onChange={(e) => set({ header: e.target.value })} placeholder="Authorization" /></div>
            <div><Label className={lbl}>Prefix (optional)</Label><Input value={k.prefix} readOnly={readOnly} className={ro} onChange={(e) => set({ prefix: e.target.value })} placeholder="Bearer " /></div>
          </>
        )}
        {conf.note && <p className="text-xs text-muted-foreground sm:col-span-2">{conf.note}</p>}

        {msg && <p className="text-sm text-destructive sm:col-span-2">{msg}</p>}
        {readOnly ? (
          <div className="flex flex-wrap justify-end gap-2 sm:col-span-2">
            {onDelete && <Button variant="ghost" className="mr-auto text-destructive hover:text-destructive" onClick={onDelete}><Trash2 className="size-4" /> Delete</Button>}
            {onEdit && <Button variant="outline" onClick={onEdit}><Pencil className="size-4" /> Edit</Button>}
            <Button variant="outline" onClick={onClose}>Close</Button>
          </div>
        ) : (
          <div className="sm:col-span-2"><Button onClick={submit} disabled={busy || !k.name || (!editing && !k.secret) || (!!conf.username && !k.username.trim())}>{busy ? 'Saving…' : (editing ? 'Save changes' : 'Save key')}</Button></div>
        )}
      </div>
    </div>
  )
}

// The secret slot in the read-only view: a muted box with an inline reveal button, mirroring the
// reveal-in-modal flow used in the credential table so a plaintext secret is fetched only on demand.
function RevealField({ title, load }: { title: string; load: () => Promise<string> }) {
  return (
    <div className="flex min-h-10 items-center justify-between rounded-xl border border-input bg-muted/40 pl-3 pr-1">
      <code className="text-sm text-muted-foreground">••••••••</code>
      <RevealButton title={title} load={load} />
    </div>
  )
}
