import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { Boxes, Pencil, Plus, Search, Trash2 } from 'lucide-react'
import { Button } from '../ui/components/button'
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '../ui/components/select'
import { Input } from '../ui/components/input'
import { Badge } from '../ui/components/badge'
import { Checkbox } from '../ui/components/checkbox'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogBody, DialogFooter } from '../ui/components/dialog'
import { PageHeader } from '../components/PageHeader'
import { ListCard, ListBar, ListHead, ListRows, ListRow, Cell, RowActions, ListEmpty, Primary } from '../components/ListCard'
import { ProviderIcon } from '../components/ProviderIcon'
import { CopyButton } from '../components/CopyButton'
import { StatusPill } from '../components/StatusPill'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { FormField, FormSection } from '../components/FormField'
import { Callout } from '../components/Callout'
import { api, type OAuthProvider, type OAuthScope, type OAuthConfigItem } from '../api'

const COLS = 'minmax(0,1.5fr) minmax(0,1.7fr) 150px 100px'

// The YAML templates are a LIBRARY. Adding one copies the whole template into a self-contained,
// editable provider row (with a parent_id breadcrumb). A provider is connectable only once added.
// All editing lives here; the Connect page only selects scopes and connects.
export function ProvidersPage() {
  const [providers, setProviders] = useState<OAuthProvider[]>([])
  const [templates, setTemplates] = useState<OAuthProvider[]>([])
  const [configs, setConfigs] = useState<OAuthConfigItem[]>([])
  const [loaded, setLoaded] = useState(false)
  const [editing, setEditing] = useState<{ value: OAuthProvider; isNew: boolean } | null>(null)
  const [deleting, setDeleting] = useState<OAuthProvider>()
  const [deleteBusy, setDeleteBusy] = useState(false)
  const [deleteErr, setDeleteErr] = useState<string>()
  const load = () => {
    api.oauthProviders().then(setProviders).catch(() => {}).finally(() => setLoaded(true))
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

  const remove = async () => {
    if (!deleting) return
    setDeleteBusy(true)
    setDeleteErr(undefined)
    try {
      await api.deleteProvider('oauth', deleting.key)
      toast.success(`Removed ${deleting.name}`)
      setDeleting(undefined)
      load()
    } catch (e) {
      setDeleteErr(String(e))
    } finally {
      setDeleteBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="OAuth providers"
        description="The identity providers agents can connect accounts through. Add one from the library or define a custom OIDC provider, set its app credentials, then connect on the Connect page."
        actions={
          <Button variant="primary" onClick={() => setEditing({ value: blankOAuth(), isNew: true })}>
            <Plus /> Custom provider
          </Button>
        }
      />

      <ListCard>
        <ListBar>
          <span>
            {providers.length.toLocaleString()} {providers.length === 1 ? 'provider' : 'providers'}
          </span>
        </ListBar>
        {providers.length > 0 && (
          <ListHead cols={COLS}>
            <span>Provider</span>
            <span>Authorization endpoint</span>
            <span>App credentials</span>
            <span className="text-right">Actions</span>
          </ListHead>
        )}
        {providers.length === 0 ? (
          <ListEmpty
            icon={Boxes}
            title={loaded ? 'No providers yet' : 'Loading…'}
            hint={loaded ? 'Pick one from the library below or add a custom provider.' : undefined}
          />
        ) : (
          <ListRows>
            {providers.map((p) => (
              <ListRow key={p.key} cols={COLS} onClick={() => setEditing({ value: structuredClone(p), isNew: false })}>
                <div className="flex min-w-0 items-center gap-3">
                  <ProviderIcon src={p.iconUrl} name={p.name} />
                  <Primary title={p.name} subtitle={p.key} mono />
                </div>
                <Cell label="Authorization endpoint">
                  <span className="block truncate font-mono text-xs text-muted-foreground" title={p.authorizationEndpoint}>
                    {p.authorizationEndpoint || '—'}
                  </span>
                </Cell>
                <Cell label="App credentials">
                  {configFor(p.key) ? <StatusPill tone="success">Configured</StatusPill> : <StatusPill tone="muted">Not set</StatusPill>}
                </Cell>
                <RowActions>
                  <Button variant="ghost" size="icon" aria-label={`Edit ${p.name}`} title="Edit" onClick={() => setEditing({ value: structuredClone(p), isNew: false })}>
                    <Pencil />
                  </Button>
                  <Button variant="ghost" size="icon" className="hover:text-danger" aria-label={`Remove ${p.name}`} title="Remove" onClick={() => { setDeleteErr(undefined); setDeleting(p) }}>
                    <Trash2 />
                  </Button>
                </RowActions>
              </ListRow>
            ))}
          </ListRows>
        )}
      </ListCard>

      {library.length > 0 && (
        <section className="space-y-3">
          <div>
            <h2 className="text-base font-semibold">Library</h2>
            <p className="mt-1 text-sm text-muted-foreground">Built-in templates. Adding one copies it into your providers, where you set credentials and connect.</p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {library.map((t) => (
              <div key={t.key} className="flex items-center justify-between gap-3 rounded-2xl border border-border bg-card p-4 transition-colors hover:border-accent/40">
                <div className="flex min-w-0 items-center gap-3">
                  <ProviderIcon src={t.iconUrl} name={t.name} />
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium">{t.name}</div>
                    <div className="mt-0.5 truncate font-mono text-xs text-muted-foreground">{t.key}</div>
                  </div>
                </div>
                <Button variant="secondary" size="sm" onClick={() => addFromTemplate(t)}>
                  <Plus /> Add
                </Button>
              </div>
            ))}
          </div>
        </section>
      )}

      {editing && (
        <OAuthEditor
          value={editing.value}
          config={configFor(editing.value.key)}
          isNew={editing.isNew}
          onClose={() => setEditing(null)}
          onSaved={(name) => {
            toast.success(`Saved ${name}`)
            setEditing(null)
            load()
          }}
        />
      )}

      <ConfirmDialog
        open={!!deleting}
        title="Remove provider?"
        description={deleting ? `This removes ${deleting.name} and its app credentials. Connected accounts will stop refreshing.` : undefined}
        confirmLabel="Remove"
        busy={deleteBusy}
        error={deleteErr}
        onCancel={() => setDeleting(undefined)}
        onConfirm={remove}
      />
    </div>
  )
}

const REDIRECT_HINT = 'https://vault.donkeywork.dev/api/oauth/callback'

function OAuthEditor({
  value,
  config,
  isNew,
  onClose,
  onSaved,
}: {
  value: OAuthProvider
  config?: OAuthConfigItem
  isNew: boolean
  onClose: () => void
  onSaved: (name: string) => void
}) {
  const [m, setM] = useState<OAuthProvider>(value)
  const [discoverUrl, setDiscoverUrl] = useState('')
  const [discovering, setDiscovering] = useState(false)
  const [rows, setRows] = useState<OAuthScope[]>(
    value.scopes?.length ? value.scopes : (value.defaultScopes || []).map((v) => ({ value: v, description: '' })),
  )
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [redirect, setRedirect] = useState(config?.redirectUri || '')
  const [aprows, setAprows] = useState<{ key: string; value: string }[]>(
    Object.entries(value.authorizeParams || {}).map(([key, val]) => ({ key, value: val })),
  )
  const [msg, setMsg] = useState<string>()
  const [busy, setBusy] = useState(false)
  const set = (patch: Partial<OAuthProvider>) => setM((cur) => ({ ...cur, ...patch }))

  const discover = async () => {
    setDiscovering(true)
    setMsg(undefined)
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
      toast.success(`Discovered ${d.scopes?.length || 0} scopes`)
    } catch (e) {
      setMsg(String(e))
    } finally {
      setDiscovering(false)
    }
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
    try {
      await api.deleteOAuthConfig(config.id)
      toast.success('Removed app credentials')
      onSaved(m.name || m.key)
    } catch (e) {
      setMsg(String(e))
    }
  }

  const save = async () => {
    setMsg(undefined)
    setBusy(true)
    const scopes = rows
      .filter((s) => s.value.trim())
      .map((s) => ({ value: s.value.trim(), description: s.description || '', category: s.category || '', sensitive: !!s.sensitive }))
    const values = scopes.map((s) => s.value)
    const defaultScopes = m.defaultScopes?.length ? m.defaultScopes.filter((v) => values.includes(v)) : values
    const authorizeParams = Object.fromEntries(aprows.filter((p) => p.key.trim()).map((p) => [p.key.trim(), p.value]))
    try {
      await api.upsertOAuthProvider({ ...m, parentId: m.parentId, scopeDelimiter: m.scopeDelimiter || ' ', defaultScopes, scopes, authorizeParams })
      if (clientId.trim()) {
        await api.upsertOAuthConfig({
          provider: m.key,
          clientId: clientId.trim(),
          clientSecret: clientSecret || undefined,
          scopes: defaultScopes,
          redirectUri: redirect || undefined,
        })
      }
      onSaved(m.name || m.key)
    } catch (e) {
      setMsg(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="max-w-3xl">
        <form
          className="contents"
          onSubmit={(e) => {
            e.preventDefault()
            void save()
          }}
        >
          <DialogHeader>
            <div className="flex items-center gap-3">
              <ProviderIcon src={m.iconUrl} name={m.name || m.key || '?'} className="size-10" />
              <div className="min-w-0">
                <DialogTitle className="truncate">{isNew ? (value.key ? `Add ${value.name || value.key}` : 'New custom provider') : `Edit ${value.name || value.key}`}</DialogTitle>
                <DialogDescription className="mt-0.5">Endpoints, scopes, authorize parameters, and the OAuth app credentials.</DialogDescription>
              </div>
            </div>
          </DialogHeader>
          <DialogBody className="space-y-7">
            {isNew && (
              <FormSection title="Discover">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
                  <FormField label="OIDC issuer URL" className="flex-1" hint="Fills the endpoints and scopes from the issuer's discovery document.">
                    <Input value={discoverUrl} onChange={(e) => setDiscoverUrl(e.target.value)} placeholder="https://issuer.example.com" className="font-mono" />
                  </FormField>
                  <Button variant="secondary" className="sm:mb-[26px]" onClick={discover} disabled={!discoverUrl || discovering}>
                    <Search /> {discovering ? 'Discovering…' : 'Discover'}
                  </Button>
                </div>
              </FormSection>
            )}

            <FormSection title="Provider">
              <div className="grid gap-4 sm:grid-cols-2">
                <FormField label="Slug" required hint="Letters, digits, - or _. Agents reference the provider by this.">
                  <Input value={m.key} onChange={(e) => set({ key: e.target.value })} disabled={!isNew} placeholder="e.g. github" className="font-mono" />
                </FormField>
                <FormField label="Name">
                  <Input value={m.name} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. GitHub" />
                </FormField>
                <FormField label="Icon URL" className="sm:col-span-2">
                  <Input value={m.iconUrl || ''} onChange={(e) => set({ iconUrl: e.target.value })} placeholder="https://…/logo.svg" className="font-mono" />
                </FormField>
                <FormField label="Authorization endpoint" className="sm:col-span-2">
                  <Input value={m.authorizationEndpoint} onChange={(e) => set({ authorizationEndpoint: e.target.value })} className="font-mono" />
                </FormField>
                <FormField label="Token endpoint" className="sm:col-span-2">
                  <Input value={m.tokenEndpoint} onChange={(e) => set({ tokenEndpoint: e.target.value })} className="font-mono" />
                </FormField>
                <FormField label="Userinfo endpoint" className="sm:col-span-2">
                  <Input value={m.userinfoEndpoint} onChange={(e) => set({ userinfoEndpoint: e.target.value })} className="font-mono" />
                </FormField>
                <FormField label="Token endpoint authentication">
                  <Select value={m.tokenEndpointAuthMethod || 'client_secret_post'} onValueChange={(v) => set({ tokenEndpointAuthMethod: v })}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="client_secret_post">Client secret in request body</SelectItem>
                      <SelectItem value="client_secret_basic">HTTP Basic (X confidential apps)</SelectItem>
                    </SelectContent>
                  </Select>
                </FormField>
                <FormField label="Account field" hint="Path into the userinfo response naming the account, e.g. data.username.">
                  <Input value={m.userinfoAccountPath || ''} onChange={(e) => set({ userinfoAccountPath: e.target.value })} placeholder="email" className="font-mono" />
                </FormField>
              </div>
            </FormSection>

            <FormSection
              title="OAuth app credentials"
              actions={
                config && (
                  <Button variant="ghost" size="sm" className="text-danger hover:text-danger" onClick={removeCredentials}>
                    <Trash2 /> Remove credentials
                  </Button>
                )
              }
            >
              <div className="grid gap-4 sm:grid-cols-2">
                <FormField label="Client ID" hint={config ? 'Leave blank to keep the stored credentials untouched.' : undefined}>
                  <Input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder={config ? config.clientIdMasked : ''} autoComplete="off" className="font-mono" />
                </FormField>
                <FormField label="Client secret">
                  <Input type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} placeholder={config ? 'Blank keeps the existing secret' : ''} autoComplete="new-password" className="font-mono" />
                </FormField>
                <FormField label="Redirect URI" className="sm:col-span-2" hint="Allow-list this exact URL in the provider's OAuth app settings.">
                  <div className="flex items-center gap-2">
                    <Input value={redirect} onChange={(e) => setRedirect(e.target.value)} placeholder={REDIRECT_HINT} className="font-mono" />
                    <CopyButton value={redirect || REDIRECT_HINT} label="Copy redirect URI" />
                  </div>
                </FormField>
              </div>
            </FormSection>

            <FormSection
              title="Scopes"
              actions={
                <Button variant="secondary" size="sm" onClick={addRow}>
                  <Plus /> Add scope
                </Button>
              }
            >
              {rows.length === 0 ? (
                <p className="text-sm text-muted-foreground">No scopes yet. Add the scopes this provider supports so they can be picked on Connect.</p>
              ) : (
                <div className="space-y-2">
                  {rows.map((s, i) => (
                    <div key={i} className="grid gap-2 rounded-xl border border-border bg-elevated/40 p-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,0.7fr)_auto_auto] sm:items-center">
                      <Input value={s.value} onChange={(e) => setRow(i, { value: e.target.value })} placeholder="scope, e.g. repo" className="h-9 font-mono" aria-label="Scope value" />
                      <Input value={s.description || ''} onChange={(e) => setRow(i, { description: e.target.value })} placeholder="Description shown on Connect" className="h-9" aria-label="Scope description" />
                      <Input value={s.category || ''} onChange={(e) => setRow(i, { category: e.target.value })} placeholder="Category" className="h-9" aria-label="Scope category" />
                      <label className="flex cursor-pointer items-center gap-2 whitespace-nowrap text-xs text-muted-foreground">
                        <Checkbox checked={!!s.sensitive} onCheckedChange={(v) => setRow(i, { sensitive: v === true })} /> Sensitive
                      </label>
                      <Button variant="ghost" size="iconSm" className="hover:text-danger" aria-label="Remove scope" onClick={() => delRow(i)}>
                        <Trash2 />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </FormSection>

            <FormSection
              title="Authorization parameters"
              actions={
                <Button variant="secondary" size="sm" onClick={addAp}>
                  <Plus /> Add parameter
                </Button>
              }
            >
              <p className="text-xs leading-5 text-muted-foreground">
                Extra query parameters on the authorize URL. <code className="rounded bg-code px-1 py-0.5 text-code-foreground">token_access_type=offline</code> (Dropbox) or{' '}
                <code className="rounded bg-code px-1 py-0.5 text-code-foreground">access_type=offline</code> (Google) ask for a refresh token.
              </p>
              {aprows.map((p, i) => (
                <div key={i} className="flex items-center gap-2">
                  <Input value={p.key} onChange={(e) => setAp(i, { key: e.target.value })} placeholder="parameter" className="h-9 flex-1 font-mono" aria-label="Parameter name" />
                  <span className="font-mono text-muted-foreground">=</span>
                  <Input value={p.value} onChange={(e) => setAp(i, { value: e.target.value })} placeholder="value" className="h-9 flex-1 font-mono" aria-label="Parameter value" />
                  <Button variant="ghost" size="iconSm" className="hover:text-danger" aria-label="Remove parameter" onClick={() => delAp(i)}>
                    <Trash2 />
                  </Button>
                </div>
              ))}
            </FormSection>

            {msg && <Callout tone="danger">{msg}</Callout>}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={!m.key || busy}>
              {busy ? 'Saving…' : isNew ? 'Add provider' : 'Save changes'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

const blankOAuth = (): OAuthProvider => ({
  key: '',
  parentId: undefined,
  name: '',
  iconUrl: '',
  docsUrl: '',
  authorizationEndpoint: '',
  tokenEndpoint: '',
  userinfoEndpoint: '',
  scopeDelimiter: ' ',
  defaultScopes: [],
  scopes: [],
})
