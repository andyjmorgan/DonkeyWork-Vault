import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { ExternalLink, Plug, Trash2 } from 'lucide-react'
import { Button } from '../ui/components/button'
import { Badge } from '../ui/components/badge'
import { Checkbox } from '../ui/components/checkbox'
import { PageHeader } from '../components/PageHeader'
import { ProviderIcon } from '../components/ProviderIcon'
import { StatusPill } from '../components/StatusPill'
import { Callout } from '../components/Callout'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { ListEmpty } from '../components/ListCard'
import { cn, absoluteTime, relativeTime } from '../lib'
import { api, type OAuthProvider, type OAuthScope, type OAuthConfigItem, type OAuthTokenItem } from '../api'

export function ConnectPage() {
  const [providers, setProviders] = useState<OAuthProvider[]>([])
  const [configs, setConfigs] = useState<OAuthConfigItem[]>([])
  const [tokens, setTokens] = useState<OAuthTokenItem[]>([])
  const [loaded, setLoaded] = useState(false)
  const [selected, setSelected] = useState<string>()
  const [params, setParams] = useSearchParams()

  const load = () => {
    api.oauthProviders().then(setProviders).catch(() => {}).finally(() => setLoaded(true))
    api.oauthConfigs().then(setConfigs).catch(() => {})
    api.oauthTokens().then(setTokens).catch(() => {})
  }
  useEffect(() => { load() }, [])

  // The OAuth callback redirects back to /oauthconnect with the outcome.
  useEffect(() => {
    const connected = params.get('connected')
    const error = params.get('oauth_error')
    if (connected) {
      toast.success(`Connected ${connected}`)
      setSelected(connected)
    } else if (error) toast.error('OAuth error', { description: error })
    if (connected || error) {
      params.delete('connected')
      params.delete('oauth_error')
      setParams(params, { replace: true })
    }
  }, [params, setParams])

  const statusOf = (key: string) =>
    tokens.some((t) => t.provider === key) ? 'connected' : configs.some((c) => c.provider === key) ? 'configured' : 'new'

  const sel = providers.find((p) => p.key === selected)

  return (
    <div className="space-y-6">
      <PageHeader
        title="Connect"
        description="Pick a provider, choose the scopes the token should carry, and authorize. The vault stores the refresh token and keeps the access token fresh."
      />

      {providers.length === 0 ? (
        <div className="rounded-2xl border border-border bg-card">
          <ListEmpty
            icon={Plug}
            title={loaded ? 'No OAuth providers' : 'Loading…'}
            hint={loaded ? 'Add one from the library or define a custom provider first.' : undefined}
            action={
              loaded ? (
                <Button variant="secondary" asChild>
                  <Link to="/providers">Go to providers</Link>
                </Button>
              ) : undefined
            }
          />
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
          {providers.map((p) => {
            const st = statusOf(p.key)
            const active = selected === p.key
            return (
              <button
                key={p.key}
                type="button"
                onClick={() => setSelected(p.key)}
                aria-pressed={active}
                className={cn(
                  'flex flex-col gap-3 rounded-2xl border bg-card p-4 text-left transition-all duration-200 hover:border-accent/50',
                  active ? 'border-accent ring-[3px] ring-accent/15' : 'border-border',
                )}
              >
                <div className="flex items-center gap-3">
                  <ProviderIcon src={p.iconUrl} name={p.name} />
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium">{p.name}</div>
                    <div className="truncate font-mono text-xs text-muted-foreground">{p.key}</div>
                  </div>
                </div>
                {st === 'connected' ? (
                  <StatusPill tone="success" className="w-fit">Connected</StatusPill>
                ) : st === 'configured' ? (
                  <StatusPill tone="info" className="w-fit">Ready</StatusPill>
                ) : (
                  <StatusPill tone="muted" className="w-fit">Needs credentials</StatusPill>
                )}
              </button>
            )
          })}
        </div>
      )}

      {sel && (
        <ProviderConnect
          key={sel.key}
          provider={sel}
          config={configs.find((c) => c.provider === sel.key)}
          tokens={tokens.filter((t) => t.provider === sel.key)}
          onChanged={load}
        />
      )}
    </div>
  )
}

function ProviderConnect({
  provider,
  config,
  tokens,
  onChanged,
}: {
  provider: OAuthProvider
  config?: OAuthConfigItem
  tokens: OAuthTokenItem[]
  onChanged: () => void
}) {
  const [scopes, setScopes] = useState<string[]>(config?.scopes?.length ? config.scopes : provider.defaultScopes || [])
  const [msg, setMsg] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [removing, setRemoving] = useState<OAuthTokenItem>()
  const [removeBusy, setRemoveBusy] = useState(false)
  const [removeErr, setRemoveErr] = useState<string>()

  const toggle = (v: string) => setScopes((s) => (s.includes(v) ? s.filter((x) => x !== v) : [...s, v]))

  // What the user can pick: the provider's scope catalog, falling back to its default scopes
  // as plain rows. Scopes are defined on the Providers page — never edited here.
  const catalog: OAuthScope[] = useMemo(
    () => (provider.scopes?.length ? provider.scopes : (provider.defaultScopes || []).map((v) => ({ value: v }))),
    [provider],
  )
  const groups = useMemo(() => {
    const g: Record<string, OAuthScope[]> = {}
    for (const s of catalog) (g[s.category || 'Scopes'] ??= []).push(s)
    return g
  }, [catalog])
  const grouped = Object.keys(groups).length > 1 || !groups['Scopes']

  const connect = async () => {
    setMsg(undefined)
    setBusy(true)
    try {
      const r = await api.connect(provider.key, scopes)
      window.location.href = r.authorizeUrl
    } catch (e) {
      setMsg(String(e))
      setBusy(false)
    }
  }
  const removeToken = async () => {
    if (!removing) return
    setRemoveBusy(true)
    setRemoveErr(undefined)
    try {
      await api.deleteOAuthToken(removing.id)
      toast.success(`Disconnected ${removing.account || provider.name}`)
      setRemoving(undefined)
      onChanged()
    } catch (e) {
      setRemoveErr(String(e))
    } finally {
      setRemoveBusy(false)
    }
  }

  return (
    <div className="overflow-hidden rounded-2xl border border-border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border p-5">
        <div className="flex min-w-0 items-center gap-3">
          <ProviderIcon src={provider.iconUrl} name={provider.name} className="size-10" />
          <div className="min-w-0">
            <h2 className="truncate text-base font-semibold">{provider.name}</h2>
            {provider.docsUrl ? (
              <a
                className="inline-flex items-center gap-1 text-xs text-muted-foreground underline decoration-accent/60 underline-offset-[3px] hover:text-accent"
                href={provider.docsUrl}
                target="_blank"
                rel="noreferrer"
              >
                Scopes &amp; docs <ExternalLink className="size-3" />
              </a>
            ) : (
              <span className="font-mono text-xs text-muted-foreground">{provider.key}</span>
            )}
          </div>
        </div>
        <Button variant="primary" onClick={connect} disabled={!config || busy}>
          <Plug /> {busy ? 'Redirecting…' : tokens.length ? 'Connect another account' : 'Connect'}
        </Button>
      </div>

      <div className="space-y-5 p-5">
        {!config && (
          <Callout tone="warning">
            No app credentials yet. Set the client ID and secret for <span className="font-medium">{provider.name}</span> on the{' '}
            <Link to="/providers" className="underline decoration-accent/60 underline-offset-[3px] hover:text-accent">
              Providers
            </Link>{' '}
            page before connecting.
          </Callout>
        )}

        {catalog.length === 0 ? (
          <p className="text-sm text-muted-foreground">This provider defines no scopes. Add them on the Providers page.</p>
        ) : (
          <div className="space-y-4">
            {Object.entries(groups).map(([cat, items]) => (
              <div key={cat}>
                <div className="mb-2 flex items-center justify-between">
                  <h3 className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">{grouped ? cat : 'Scopes'}</h3>
                  <span className="font-mono text-xs text-muted-foreground">
                    {items.filter((s) => scopes.includes(s.value)).length}/{items.length}
                  </span>
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  {items.map((s) => {
                    const on = scopes.includes(s.value)
                    return (
                      <label
                        key={s.value}
                        className={cn(
                          'flex cursor-pointer items-start gap-3 rounded-xl border p-3 text-sm transition-colors hover:bg-elevated/60',
                          on ? 'border-accent/40 bg-accent/5' : 'border-border',
                        )}
                      >
                        <Checkbox className="mt-0.5" checked={on} onCheckedChange={() => toggle(s.value)} />
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-2">
                            <span className="font-medium">{s.description || s.value}</span>
                            {s.sensitive && <Badge variant="warning">Sensitive</Badge>}
                          </span>
                          {s.description && <span className="mt-0.5 block truncate font-mono text-xs text-muted-foreground">{s.value}</span>}
                        </span>
                      </label>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        )}

        {msg && <Callout tone="danger">{msg}</Callout>}

        {tokens.length > 0 && (
          <div className="border-t border-border pt-5">
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">Connected accounts</h3>
            <div className="divide-y divide-border rounded-xl border border-border">
              {tokens.map((t) => (
                <div key={t.id} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                  <span className="min-w-0 truncate font-medium">{t.account || provider.name}</span>
                  <div className="flex items-center gap-2">
                    <span className="hidden font-mono text-xs text-muted-foreground sm:inline" title={absoluteTime(t.expiresAt)}>
                      {t.expiresAt ? `expires ${relativeTime(t.expiresAt)}` : 'no expiry'}
                    </span>
                    <Button variant="ghost" size="iconSm" className="hover:text-danger" aria-label={`Disconnect ${t.account}`} title="Disconnect" onClick={() => { setRemoveErr(undefined); setRemoving(t) }}>
                      <Trash2 />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={!!removing}
        title="Disconnect account?"
        description={removing ? `This removes the stored ${provider.name} token${removing.account ? ` for ${removing.account}` : ''}. You can reconnect later.` : undefined}
        confirmLabel="Disconnect"
        busy={removeBusy}
        error={removeErr}
        onCancel={() => setRemoving(undefined)}
        onConfirm={removeToken}
      />
    </div>
  )
}
