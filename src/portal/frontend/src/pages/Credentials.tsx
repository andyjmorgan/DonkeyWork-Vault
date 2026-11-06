import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import {
  Database,
  Eye,
  KeyRound,
  Lock,
  Pencil,
  Plug,
  Plus,
  Search,
  ShieldCheck,
  Terminal,
  Trash2,
  UserRound,
  type LucideIcon,
} from 'lucide-react'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Textarea } from '../ui/components/textarea'
import { Badge } from '../ui/components/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogBody, DialogFooter } from '../ui/components/dialog'
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '../ui/components/select'
import { PageHeader } from '../components/PageHeader'
import { Tabs, TabPanel } from '../components/Tabs'
import { ListCard, ListBar, ListHead, ListRows, ListRow, Cell, RowActions, ListEmpty, ListPager, Primary } from '../components/ListCard'
import { IconTile } from '../components/IconTile'
import { ProviderIcon } from '../components/ProviderIcon'
import { CopyButton } from '../components/CopyButton'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { FormField } from '../components/FormField'
import { Callout } from '../components/Callout'
import { absoluteTime, relativeTime } from '../lib'
import { api, type ApiKeyItem, type NewApiKey, type OAuthTokenItem, type OAuthProvider, type CredentialKind } from '../api'

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

// Localize the internal kind discriminator to a human label and an icon for the console.
const kinds: Record<CredentialKind, { label: string; icon: LucideIcon }> = {
  header_api_key: { label: 'Header API key', icon: KeyRound },
  opaque: { label: 'Opaque secret', icon: Lock },
  http_basic: { label: 'HTTP Basic', icon: ShieldCheck },
  username_password: { label: 'Username + password', icon: UserRound },
  ssh: { label: 'SSH', icon: Terminal },
  connection_string: { label: 'Connection string', icon: Database },
}
const prettyKind = (k: CredentialKind) => kinds[k]?.label ?? k
const kindIcon = (k: CredentialKind) => kinds[k]?.icon ?? Lock

// Each credential shape needs a different field set. This config drives the add/edit form body so it
// reflects the chosen kind.
type FieldConf = {
  username?: boolean // show (and require) a username input
  secretLabel: string // label for the secret input
  headerPrefix?: boolean // show the Header + Prefix inputs (header_api_key only)
  baseUrlLabel: string // label for the base URL / host input
  note?: string // helper line rendered under the fields
}
const shapeConf: Record<CredentialKind, FieldConf> = {
  opaque: { secretLabel: 'Secret', baseUrlLabel: 'Base URL / host' },
  header_api_key: { secretLabel: 'Secret', headerPrefix: true, baseUrlLabel: 'Base URL' },
  http_basic: {
    username: true,
    secretLabel: 'Password',
    baseUrlLabel: 'Base URL',
    note: 'Sent as Authorization: Basic base64(username:password) — the header and prefix are handled for you.',
  },
  username_password: { username: true, secretLabel: 'Password', baseUrlLabel: 'Base URL / host' },
  ssh: { username: true, secretLabel: 'Password / private key', baseUrlLabel: 'Host' },
  connection_string: { secretLabel: 'Connection string', baseUrlLabel: 'Base URL' },
}

// One-line "how it authenticates" summary for the list, keyed off kind so username-bearing shapes
// (ssh, username_password) read sensibly instead of being mislabelled as Basic.
const authSummary = (k: ApiKeyItem): string => {
  if (k.username) return k.username
  if (k.header) return `${k.header}${k.prefix ? `: ${k.prefix.trim()} …` : ''}`
  return '—'
}

// Google-style OAuth scopes are full URLs (https://www.googleapis.com/auth/calendar) that overflow
// the tag; show the meaningful tail. Short scopes (gist, Calendars.Read) are shown as-is.
const shortScope = (s: string) => (s.includes('://') ? s.replace(/\/+$/, '').split('/').pop() || s : s)

function ScopeBadges({ scopes, max = 3 }: { scopes: string[]; max?: number }) {
  if (!scopes?.length) return <span className="text-xs text-muted-foreground">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {scopes.slice(0, max).map((s) => (
        <Badge key={s} mono title={s} className="max-w-40 truncate">
          {shortScope(s)}
        </Badge>
      ))}
      {scopes.length > max && (
        <Badge mono title={scopes.slice(max).join('\n')}>
          +{scopes.length - max}
        </Badge>
      )}
    </div>
  )
}

const KEY_COLS = 'minmax(0,1.7fr) 160px minmax(0,1.1fr) minmax(0,1.1fr) 132px'
const TOKEN_COLS = 'minmax(0,1.5fr) minmax(0,1.6fr) 170px 100px'

type FormState = { open: boolean; item?: ApiKeyItem; kind: CredentialKind; view?: boolean }
const closedForm: FormState = { open: false, kind: 'header_api_key' }

type TabKey = 'secrets' | 'oauth'
const TAB_PARAM = 'tab'

export function CredentialsPage() {
  const [keys, setKeys] = useState<ApiKeyItem[]>([])
  const [tokens, setTokens] = useState<OAuthTokenItem[]>([])
  const [providers, setProviders] = useState<OAuthProvider[]>([])
  const [loaded, setLoaded] = useState(false)
  const [params, setParams] = useSearchParams()
  // The active tab lives in the URL so a reload or a shared link lands on the same view.
  const tab: TabKey = params.get(TAB_PARAM) === 'oauth' ? 'oauth' : 'secrets'
  const setTab = (next: TabKey) => {
    const nextParams = new URLSearchParams(params)
    if (next === 'secrets') nextParams.delete(TAB_PARAM)
    else nextParams.set(TAB_PARAM, next)
    setParams(nextParams, { replace: true })
  }
  const [search, setSearch] = useState('')
  const [keyPage, setKeyPage] = useState(0)
  const [tokenPage, setTokenPage] = useState(0)
  const [err, setErr] = useState<string>()
  const [form, setForm] = useState<FormState>(closedForm)
  const [deleting, setDeleting] = useState<{ kind: 'apiKey'; item: ApiKeyItem } | { kind: 'oauthToken'; item: OAuthTokenItem }>()
  const [deleteBusy, setDeleteBusy] = useState(false)
  const [deleteErr, setDeleteErr] = useState<string>()

  const load = () => {
    api
      .apiKeys()
      .then((items) => { setKeys(items); setErr(undefined) })
      .catch((e) => setErr(String(e)))
      .finally(() => setLoaded(true))
    api.oauthTokens().then(setTokens).catch(() => {})
    api.oauthProviders().then(setProviders).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const providerOf = (key: string) => providers.find((p) => p.key === key)

  const filteredKeys = useMemo(() => keys.filter((key) => matchesSearch(key, search, [prettyKind(key.kind)])), [keys, search])
  const filteredTokens = useMemo(() => tokens.filter((token) => matchesSearch(token, search)), [tokens, search])
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
    setForm(closedForm)
    setDeleteErr(undefined)
    setDeleting(target)
  }
  const remove = async () => {
    if (!deleting) return
    setDeleteBusy(true)
    setDeleteErr(undefined)
    try {
      if (deleting.kind === 'apiKey') await api.deleteApiKey(deleting.item.id)
      else await api.deleteOAuthToken(deleting.item.id)
      toast.success(deleting.kind === 'apiKey' ? `Deleted ${deleting.item.name}` : `Disconnected ${deleting.item.provider}`)
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
    <div className="space-y-6">
      <PageHeader
        title="Credentials"
        description="Stored secrets and OAuth connections your agents can use. Each one is self-describing, so an agent knows how to send it."
        actions={
          tab === 'secrets' ? (
            <Button variant="primary" onClick={() => setForm({ open: true, kind: 'header_api_key' })}>
              <Plus /> New credential
            </Button>
          ) : (
            <Button variant="primary" asChild>
              <Link to="/oauthconnect">
                <Plug /> Connect account
              </Link>
            </Button>
          )
        }
      />

      {err && <Callout tone="danger">{err}</Callout>}

      <Tabs
        label="Credential type"
        value={tab}
        onChange={setTab}
        tabs={[
          { key: 'secrets', label: 'Secrets', count: loaded ? keys.length : undefined },
          { key: 'oauth', label: 'OAuth accounts', count: loaded ? tokens.length : undefined },
        ]}
      />

      {tab === 'secrets' && (
        <TabPanel tabKey="secrets">
          <ListCard>
            <ListBar>
              <span>
                {filteredKeys.length.toLocaleString()} {filteredKeys.length === 1 ? 'secret' : 'secrets'}
                {search && keys.length !== filteredKeys.length ? ` of ${keys.length}` : ''}
              </span>
              <SearchBox value={search} onChange={updateSearch} placeholder="Search secrets" />
            </ListBar>
            {visibleKeys.length > 0 && (
              <ListHead cols={KEY_COLS}>
                <span>Credential</span>
                <span>Kind</span>
                <span>Auth</span>
                <span>Base URL</span>
                <span className="text-right">Actions</span>
              </ListHead>
            )}
            {filteredKeys.length === 0 ? (
              <ListEmpty
                icon={KeyRound}
                title={keys.length === 0 ? (loaded ? 'No secrets stored yet' : 'Loading…') : 'No secrets match your search'}
                hint={keys.length === 0 && loaded ? 'Store an API key, password, SSH key, or connection string and agents can fetch it by name.' : undefined}
                action={
                  keys.length === 0 && loaded ? (
                    <Button variant="secondary" onClick={() => setForm({ open: true, kind: 'header_api_key' })}>
                      <Plus /> New credential
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <>
                <ListRows>
                  {visibleKeys.map((k) => (
                    <ListRow key={k.id} cols={KEY_COLS} onClick={() => view(k)}>
                      <div className="flex min-w-0 items-center gap-3">
                        <IconTile icon={kindIcon(k.kind)} />
                        <Primary title={k.name} subtitle={k.description || undefined} />
                      </div>
                      <Cell label="Kind">
                        <Badge>{prettyKind(k.kind)}</Badge>
                      </Cell>
                      <Cell label="Auth">
                        <span className="block truncate font-mono text-xs text-muted-foreground" title={authSummary(k)}>
                          {authSummary(k)}
                        </span>
                      </Cell>
                      <Cell label="Base URL">
                        {k.baseUrl || k.docsUrl ? (
                          <a
                            className="block truncate font-mono text-xs text-foreground underline decoration-accent/60 underline-offset-[3px] hover:text-accent"
                            href={k.docsUrl || k.baseUrl}
                            target="_blank"
                            rel="noreferrer"
                            title={k.docsUrl ? `Docs: ${k.docsUrl}` : k.baseUrl}
                            onClick={(e) => e.stopPropagation()}
                          >
                            {k.baseUrl || 'docs'}
                          </a>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </Cell>
                      <RowActions>
                        <RevealButton title={k.name} load={() => api.revealApiKey(k.name).then((r) => r.secret)} />
                        <Button variant="ghost" size="icon" aria-label={`Edit ${k.name}`} title="Edit" onClick={() => edit(k)}>
                          <Pencil />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="hover:text-danger"
                          aria-label={`Delete ${k.name}`}
                          title="Delete"
                          onClick={() => requestDelete({ kind: 'apiKey', item: k })}
                        >
                          <Trash2 />
                        </Button>
                      </RowActions>
                    </ListRow>
                  ))}
                </ListRows>
                {filteredKeys.length > PAGE_SIZE && (
                  <ListPager
                    from={currentKeyPage * PAGE_SIZE + 1}
                    to={Math.min((currentKeyPage + 1) * PAGE_SIZE, filteredKeys.length)}
                    total={filteredKeys.length}
                    canPrev={currentKeyPage > 0}
                    canNext={(currentKeyPage + 1) * PAGE_SIZE < filteredKeys.length}
                    onPrev={() => setKeyPage(currentKeyPage - 1)}
                    onNext={() => setKeyPage(currentKeyPage + 1)}
                  />
                )}
              </>
            )}
          </ListCard>
        </TabPanel>
      )}

      {tab === 'oauth' && (
        <TabPanel tabKey="oauth">
          <ListCard>
            <ListBar>
              <span>
                {filteredTokens.length.toLocaleString()} connected {filteredTokens.length === 1 ? 'account' : 'accounts'}
                {search && tokens.length !== filteredTokens.length ? ` of ${tokens.length}` : ''}
              </span>
              <SearchBox value={search} onChange={updateSearch} placeholder="Search accounts" />
            </ListBar>
            {visibleTokens.length > 0 && (
              <ListHead cols={TOKEN_COLS}>
                <span>Account</span>
                <span>Scopes</span>
                <span>Expires</span>
                <span className="text-right">Actions</span>
              </ListHead>
            )}
            {filteredTokens.length === 0 ? (
              <ListEmpty
                icon={Plug}
                title={tokens.length === 0 ? (loaded ? 'No OAuth accounts connected' : 'Loading…') : 'No accounts match your search'}
                hint={tokens.length === 0 && loaded ? 'Connect a provider and the vault will keep its access token fresh for you.' : undefined}
                action={
                  tokens.length === 0 && loaded ? (
                    <Button variant="secondary" asChild>
                      <Link to="/oauthconnect">
                        <Plug /> Connect account
                      </Link>
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <>
                <ListRows>
                  {visibleTokens.map((t) => {
                    const p = providerOf(t.provider)
                    const title = `${p?.name ?? t.provider}${t.account ? ` · ${t.account}` : ''}`
                    return (
                      <ListRow key={t.id} cols={TOKEN_COLS}>
                        <div className="flex min-w-0 items-center gap-3">
                          <ProviderIcon src={p?.iconUrl} name={p?.name ?? t.provider} />
                          <Primary title={t.account || p?.name || t.provider} subtitle={t.account ? p?.name ?? t.provider : undefined} />
                        </div>
                        <Cell label="Scopes">
                          <ScopeBadges scopes={t.scopes} />
                        </Cell>
                        <Cell label="Expires">
                          <Expiry at={t.expiresAt} />
                        </Cell>
                        <RowActions>
                          <RevealButton title={title} load={() => api.revealOAuthToken(t.provider, t.account).then((r) => r.accessToken)} />
                          <Button
                            variant="ghost"
                            size="icon"
                            className="hover:text-danger"
                            aria-label={`Disconnect ${title}`}
                            title="Disconnect"
                            onClick={() => requestDelete({ kind: 'oauthToken', item: t })}
                          >
                            <Trash2 />
                          </Button>
                        </RowActions>
                      </ListRow>
                    )
                  })}
                </ListRows>
                {filteredTokens.length > PAGE_SIZE && (
                  <ListPager
                    from={currentTokenPage * PAGE_SIZE + 1}
                    to={Math.min((currentTokenPage + 1) * PAGE_SIZE, filteredTokens.length)}
                    total={filteredTokens.length}
                    canPrev={currentTokenPage > 0}
                    canNext={(currentTokenPage + 1) * PAGE_SIZE < filteredTokens.length}
                    onPrev={() => setTokenPage(currentTokenPage - 1)}
                    onNext={() => setTokenPage(currentTokenPage + 1)}
                  />
                )}
              </>
            )}
          </ListCard>
        </TabPanel>
      )}

      <Dialog open={form.open} onOpenChange={(o) => { if (!o) setForm(closedForm) }}>
        <DialogContent className="max-w-xl">
          {form.view && form.item ? (
            <CredentialDetail
              item={form.item}
              onClose={() => setForm(closedForm)}
              onEdit={() => edit(form.item!)}
              onDelete={() => requestDelete({ kind: 'apiKey', item: form.item! })}
            />
          ) : (
            <CredentialForm
              key={`${form.item?.id ?? 'new'}-${formKind}`}
              initial={form.item}
              kind={formKind}
              onClose={() => setForm(closedForm)}
              onStored={(name) => {
                toast.success(form.item ? `Saved ${name}` : `Stored ${name}`)
                load()
                setForm(closedForm)
              }}
            />
          )}
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!deleting}
        title={deleting?.kind === 'apiKey' ? 'Delete credential?' : 'Disconnect account?'}
        description={
          deleting?.kind === 'apiKey'
            ? `This permanently deletes ${deleting.item.name}. Agents using it by name will start failing.`
            : deleting
              ? `This removes the stored ${providerOf(deleting.item.provider)?.name ?? deleting.item.provider} token${deleting.item.account ? ` for ${deleting.item.account}` : ''}. You can reconnect later.`
              : undefined
        }
        confirmLabel={deleting?.kind === 'apiKey' ? 'Delete' : 'Disconnect'}
        busy={deleteBusy}
        error={deleteErr}
        onCancel={() => setDeleting(undefined)}
        onConfirm={remove}
      />
    </div>
  )
}

function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (value: string) => void; placeholder: string }) {
  return (
    <div className="relative w-full sm:w-72">
      <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className="h-9 pl-9"
      />
    </div>
  )
}

/** Relative expiry with the absolute time on hover; past expiries read as warnings. */
function Expiry({ at }: { at?: string | null }) {
  if (!at) return <span className="text-xs text-muted-foreground">No expiry</span>
  const expired = new Date(at).getTime() < Date.now()
  return (
    <span className={`block truncate font-mono text-xs ${expired ? 'text-warning' : 'text-muted-foreground'}`} title={absoluteTime(at)}>
      {expired ? 'expired ' : ''}
      {relativeTime(at)}
    </span>
  )
}

// Middle-truncate a long secret for display so a giant value (e.g. a Microsoft JWT, which
// can run thousands of chars) can't push the reveal modal off-screen. The full value is
// still what the CopyButton copies — this only affects what's shown.
const middleTruncate = (s: string, max = 64) => (s.length > max ? `${s.slice(0, max / 2 - 1)}…${s.slice(-(max / 2 - 1))}` : s)

// Reveal a secret in a dialog (not inline) so long values can't push the row off-screen on
// mobile. The value is fetched on click and discarded when the dialog closes.
function RevealButton({ title, load }: { title: string; load: () => Promise<string> }) {
  const [open, setOpen] = useState(false)
  const [val, setVal] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string>()

  const reveal = async () => {
    setBusy(true)
    setErr(undefined)
    try {
      setVal(await load())
      setOpen(true)
    } catch (e) {
      setErr(String(e))
      setOpen(true)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button variant="ghost" size="icon" aria-label={`Reveal ${title}`} title="Reveal" disabled={busy} onClick={reveal}>
        <Eye />
      </Button>
      <Dialog open={open} onOpenChange={(o) => { setOpen(o); if (!o) setVal(undefined) }}>
        <DialogContent className="max-w-lg" onOpenAutoFocus={(e) => { e.preventDefault(); (e.currentTarget as HTMLElement).querySelector<HTMLElement>('[data-reveal]')?.focus() }}>
          <DialogHeader>
            <DialogTitle className="break-all">{title}</DialogTitle>
            <DialogDescription>Copy the value and keep it out of transcripts, logs, and commits.</DialogDescription>
          </DialogHeader>
          <DialogBody>
            {err ? (
              <Callout tone="danger">{err}</Callout>
            ) : (
              <div data-reveal tabIndex={-1} className="flex items-start gap-2 rounded-xl border border-border bg-code p-3 outline-none">
                <code className="min-w-0 flex-1 break-all font-mono text-sm text-code-foreground" title={val}>
                  {val !== undefined ? middleTruncate(val) : ''}
                </code>
                {val !== undefined && <CopyButton value={val} />}
              </div>
            )}
          </DialogBody>
        </DialogContent>
      </Dialog>
    </>
  )
}

/** A label/value row in the read-only credential view. */
function DetailRow({ label, children, mono = false }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid gap-1 py-3 sm:grid-cols-[140px_minmax(0,1fr)] sm:gap-4">
      <dt className="text-xs font-semibold text-muted-foreground sm:pt-0.5">{label}</dt>
      <dd className={`min-w-0 break-words text-sm ${mono ? 'font-mono text-[13px]' : ''}`}>{children}</dd>
    </div>
  )
}

function CredentialDetail({ item, onClose, onEdit, onDelete }: { item: ApiKeyItem; onClose: () => void; onEdit: () => void; onDelete: () => void }) {
  const conf = shapeConf[item.kind]
  const Icon = kindIcon(item.kind)
  const link = (url?: string) =>
    url ? (
      <a className="underline decoration-accent/60 underline-offset-[3px] hover:text-accent" href={url} target="_blank" rel="noreferrer">
        {url}
      </a>
    ) : (
      <span className="text-muted-foreground">—</span>
    )
  return (
    <>
      <DialogHeader>
        <div className="flex items-center gap-3">
          <IconTile icon={Icon} className="size-10" />
          <div className="min-w-0">
            <DialogTitle className="truncate">{item.name}</DialogTitle>
            <DialogDescription className="mt-0.5">{prettyKind(item.kind)}</DialogDescription>
          </div>
        </div>
      </DialogHeader>
      <DialogBody className="space-y-0">
        <dl className="divide-y divide-border">
          {item.description && <DetailRow label="Description">{item.description}</DetailRow>}
          {conf.username && (
            <DetailRow label="Username" mono>
              {item.username || '—'}
            </DetailRow>
          )}
          <DetailRow label={conf.secretLabel}>
            <div className="flex items-center justify-between gap-2 rounded-lg border border-border bg-code pl-3 pr-1">
              <code className="font-mono text-sm text-muted-foreground">••••••••••••</code>
              <RevealButton title={item.name} load={() => api.revealApiKey(item.name).then((r) => r.secret)} />
            </div>
          </DetailRow>
          {conf.headerPrefix && (
            <DetailRow label="Header" mono>
              {item.header ? (
                <>
                  {item.header}
                  {item.prefix && <span className="text-muted-foreground">: {item.prefix.trim()} …</span>}
                </>
              ) : (
                <span className="text-muted-foreground">Default (Authorization: Bearer)</span>
              )}
            </DetailRow>
          )}
          <DetailRow label={conf.baseUrlLabel} mono>
            {link(item.baseUrl)}
          </DetailRow>
          <DetailRow label="API docs" mono>
            {link(item.docsUrl)}
          </DetailRow>
          <DetailRow label="Created" mono>
            <span title={absoluteTime(item.createdAt)}>{relativeTime(item.createdAt)}</span>
          </DetailRow>
          <DetailRow label="Last used" mono>
            <span title={absoluteTime(item.lastUsedAt)}>{item.lastUsedAt ? relativeTime(item.lastUsedAt) : 'Never'}</span>
          </DetailRow>
        </dl>
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" className="mr-auto text-danger hover:text-danger" onClick={onDelete}>
          <Trash2 /> Delete
        </Button>
        <Button variant="outline" onClick={onClose}>Close</Button>
        <Button variant="primary" onClick={onEdit}>
          <Pencil /> Edit
        </Button>
      </DialogFooter>
    </>
  )
}

function CredentialForm({
  initial,
  kind: initialKind,
  onClose,
  onStored,
}: {
  initial?: ApiKeyItem
  kind: CredentialKind
  onClose: () => void
  onStored: (name: string) => void
}) {
  // The kind is editable while adding (the selector swaps the form body live); once stored it's fixed.
  const [kind, setKind] = useState<CredentialKind>(initialKind)
  const conf = shapeConf[kind]
  const [k, setK] = useState({
    name: initial?.name ?? '',
    secret: '',
    description: initial?.description ?? '',
    baseUrl: initial?.baseUrl ?? '',
    docsUrl: initial?.docsUrl ?? '',
    header: initial?.header ?? '',
    prefix: initial?.prefix ?? '',
    username: initial?.username ?? '',
  })
  const [msg, setMsg] = useState<string>()
  const [busy, setBusy] = useState(false)
  const set = (patch: Partial<typeof k>) => setK({ ...k, ...patch })
  const editing = !!initial
  const canSave = !!k.name && (editing || !!k.secret) && (!conf.username || !!k.username.trim())

  const submit = async () => {
    if (!canSave) return
    setBusy(true)
    setMsg(undefined)
    // Send only the fields this shape uses so another shape's values can't leak through: clear the
    // username for shapes without one, and header/prefix for shapes that don't expose them.
    const payload: NewApiKey = {
      ...k,
      kind,
      username: conf.username ? k.username.trim() : '',
      header: conf.headerPrefix ? k.header : '',
      prefix: conf.headerPrefix ? k.prefix : '',
    }
    try {
      await api.createApiKey(payload)
      onStored(k.name)
    } catch (e) {
      setMsg(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form
      className="contents"
      onSubmit={(e) => {
        e.preventDefault()
        void submit()
      }}
    >
      <DialogHeader>
        <DialogTitle>{editing ? `Edit ${initial.name}` : 'New credential'}</DialogTitle>
        <DialogDescription>
          {editing
            ? 'Leave the secret blank to keep the stored value.'
            : 'Self-describing: the description, host, and docs link tell agents how to use it.'}
        </DialogDescription>
      </DialogHeader>
      <DialogBody>
        <div className="grid gap-4 sm:grid-cols-2">
          <FormField label="Kind" className="sm:col-span-2">
            {editing ? (
              <Input value={prettyKind(kind)} readOnly />
            ) : (
              <Select value={kind} onValueChange={(v) => setKind(v as CredentialKind)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(Object.keys(kinds) as CredentialKind[]).map((kk) => (
                    <SelectItem key={kk} value={kk}>
                      {kinds[kk].label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </FormField>

          <FormField label="Name" required className={conf.username ? '' : 'sm:col-span-2'}>
            <Input value={k.name} readOnly={editing} autoFocus={!editing} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. grafana-prod" />
          </FormField>

          {conf.username && (
            <FormField label="Username" required>
              <Input value={k.username} onChange={(e) => set({ username: e.target.value })} placeholder="e.g. admin" autoComplete="off" />
            </FormField>
          )}

          <FormField label={conf.secretLabel} required={!editing} className="sm:col-span-2">
            <Input
              type="password"
              value={k.secret}
              onChange={(e) => set({ secret: e.target.value })}
              placeholder={editing ? 'Leave blank to keep the current value' : ''}
              autoComplete="new-password"
              className="font-mono"
            />
          </FormField>

          <FormField label="Description" className="sm:col-span-2">
            <Textarea rows={2} value={k.description} onChange={(e) => set({ description: e.target.value })} placeholder="What this credential is for" />
          </FormField>
          <FormField label={conf.baseUrlLabel}>
            <Input value={k.baseUrl} onChange={(e) => set({ baseUrl: e.target.value })} placeholder="https://api.example.com" className="font-mono" />
          </FormField>
          <FormField label="API docs link">
            <Input value={k.docsUrl} onChange={(e) => set({ docsUrl: e.target.value })} placeholder="https://docs.example.com" className="font-mono" />
          </FormField>

          {conf.headerPrefix && (
            <>
              <FormField label="Header" hint="Defaults to Authorization.">
                <Input value={k.header} onChange={(e) => set({ header: e.target.value })} placeholder="Authorization" className="font-mono" />
              </FormField>
              <FormField label="Prefix" hint="Placed before the secret, e.g. Bearer.">
                <Input value={k.prefix} onChange={(e) => set({ prefix: e.target.value })} placeholder="Bearer " className="font-mono" />
              </FormField>
            </>
          )}
        </div>
        {conf.note && <Callout>{conf.note}</Callout>}
        {msg && <Callout tone="danger">{msg}</Callout>}
      </DialogBody>
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>Cancel</Button>
        <Button type="submit" variant="primary" disabled={busy || !canSave}>
          {busy ? 'Saving…' : editing ? 'Save changes' : 'Store credential'}
        </Button>
      </DialogFooter>
    </form>
  )
}
