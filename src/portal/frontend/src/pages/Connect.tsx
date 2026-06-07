import { useEffect, useMemo, useState } from 'react'
import { Plug, Trash2, ExternalLink } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../ui/components/card'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Label } from '../ui/components/label'
import { Badge } from '../ui/components/badge'
import { ProviderIcon } from '../components/ProviderIcon'
import { cn } from '../ui/lib/utils'
import { api, type OAuthProvider, type OAuthConfigItem, type OAuthTokenItem } from '../api'

const lbl = 'mb-1 block text-xs text-muted-foreground'

export function ConnectPage() {
  const [providers, setProviders] = useState<OAuthProvider[]>([])
  const [configs, setConfigs] = useState<OAuthConfigItem[]>([])
  const [tokens, setTokens] = useState<OAuthTokenItem[]>([])
  const [selected, setSelected] = useState<string>()

  const load = () => {
    api.oauthProviders().then(setProviders).catch(() => {})
    api.oauthConfigs().then(setConfigs).catch(() => {})
    api.oauthTokens().then(setTokens).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const statusOf = (key: string) =>
    tokens.some((t) => t.provider === key) ? 'connected'
      : configs.some((c) => c.provider === key) ? 'configured' : 'new'

  const sel = providers.find((p) => p.key === selected)

  return (
    <>
      <Card>
        <CardHeader><CardTitle>Connect a provider</CardTitle><CardDescription>Pick a provider, add your OAuth app credentials, choose scopes, then connect.</CardDescription></CardHeader>
        <CardContent>
          {providers.length === 0 ? (
            <p className="text-sm text-muted-foreground">No OAuth providers. Add a custom one from the Providers tab.</p>
          ) : (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              {providers.map((p) => {
                const st = statusOf(p.key)
                return (
                  <button key={p.key} onClick={() => setSelected(p.key)}
                    className={cn('flex flex-col gap-3 rounded-2xl border p-4 text-left transition-all duration-200 hover:border-accent/50',
                      selected === p.key ? 'border-accent bg-accent/5' : 'border-border')}>
                    <div className="flex items-center gap-2">
                      <ProviderIcon src={p.iconUrl} name={p.name} />
                      <div className="min-w-0">
                        <div className="truncate font-medium">{p.name}</div>
                        <div className="text-xs text-muted-foreground">{p.builtin ? 'built-in' : 'custom'}</div>
                      </div>
                    </div>
                    {st === 'connected' ? <Badge variant="secondary" className="w-fit text-success">● Connected</Badge>
                      : st === 'configured' ? <Badge variant="secondary" className="w-fit">Configured</Badge>
                      : <span className="text-xs text-muted-foreground">Not set up</span>}
                  </button>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {sel && (
        <ProviderSetup
          key={sel.key}
          provider={sel}
          config={configs.find((c) => c.provider === sel.key)}
          tokens={tokens.filter((t) => t.provider === sel.key)}
          onChanged={load}
        />
      )}
    </>
  )
}

function ProviderSetup({ provider, config, tokens, onChanged }: {
  provider: OAuthProvider; config?: OAuthConfigItem; tokens: OAuthTokenItem[]; onChanged: () => void
}) {
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [redirect, setRedirect] = useState(config?.redirectUri || '')
  const [scopes, setScopes] = useState<string[]>(config?.scopes?.length ? config.scopes : provider.defaultScopes || [])
  const [extra, setExtra] = useState('')
  const [msg, setMsg] = useState<string>()
  const redirectHint = `https://vault.donkeywork.dev/api/oauth/${provider.key}/callback`

  const toggle = (v: string) => setScopes((s) => (s.includes(v) ? s.filter((x) => x !== v) : [...s, v]))

  const groups = useMemo(() => {
    const g: Record<string, NonNullable<OAuthProvider['scopes']>> = {}
    for (const s of provider.scopes || []) (g[s.category || 'Other'] ??= []).push(s)
    return g
  }, [provider])
  const hasCatalog = (provider.scopes?.length || 0) > 0

  const saveConfig = async () => {
    setMsg(undefined)
    const all = Array.from(new Set([...scopes, ...extra.split(/\s+/).filter(Boolean)]))
    try {
      await api.upsertOAuthConfig({ provider: provider.key, clientId, clientSecret: clientSecret || undefined, scopes: all, redirectUri: redirect || undefined })
      setMsg('Saved.'); setClientSecret(''); onChanged()
    } catch (e) { setMsg(String(e)) }
  }
  const connect = async () => {
    try { const r = await api.connect(provider.key); window.location.href = r.authorizeUrl } catch (e) { setMsg(String(e)) }
  }
  const removeConfig = async () => { if (config) { await api.deleteOAuthConfig(config.id); onChanged() } }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-3">
          <ProviderIcon src={provider.iconUrl} name={provider.name} className="size-10" />
          <div>
            <CardTitle>{provider.name}</CardTitle>
            {provider.docsUrl && <a className="inline-flex items-center gap-1 text-xs text-accent hover:underline" href={provider.docsUrl} target="_blank" rel="noreferrer">scopes &amp; docs <ExternalLink className="size-3" /></a>}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <div><Label className={lbl}>Client ID</Label><Input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder={config ? config.clientIdMasked : ''} /></div>
          <div><Label className={lbl}>Client secret</Label><Input type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} placeholder={config ? '(blank keeps existing)' : ''} /></div>
          <div className="sm:col-span-2">
            <Label className={lbl}>Redirect URI</Label>
            <Input value={redirect} onChange={(e) => setRedirect(e.target.value)} placeholder={redirectHint} />
            <p className="mt-1 text-xs text-muted-foreground">Allow-list this exact URL with the provider: <code className="text-accent">{redirectHint}</code></p>
          </div>
        </div>

        <div>
          <Label className={lbl}>Scopes</Label>
          {hasCatalog ? (
            <div className="space-y-3">
              {Object.entries(groups).map(([cat, items]) => (
                <div key={cat}>
                  <div className="mb-1 text-xs font-medium text-muted-foreground">{cat}</div>
                  <div className="grid gap-1 sm:grid-cols-2">
                    {items.map((s) => (
                      <label key={s.value} className="flex cursor-pointer items-start gap-2 rounded-lg border border-border p-2 text-sm">
                        <input type="checkbox" className="mt-1" checked={scopes.includes(s.value)} onChange={() => toggle(s.value)} />
                        <span className="min-w-0">
                          <span className="flex items-center gap-1">{s.description || s.value}{s.sensitive && <Badge variant="secondary" className="text-warning">sensitive</Badge>}</span>
                          <span className="block truncate text-xs text-muted-foreground">{s.value}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                </div>
              ))}
              <div><Label className={lbl}>Additional scopes (space-separated)</Label><Input value={extra} onChange={(e) => setExtra(e.target.value)} /></div>
            </div>
          ) : (
            <Input value={scopes.join(' ')} onChange={(e) => setScopes(e.target.value.split(/\s+/).filter(Boolean))} placeholder="space-separated scopes" />
          )}
        </div>

        {msg && <p className="text-sm text-muted-foreground">{msg}</p>}
        <div className="flex flex-wrap gap-2">
          <Button onClick={saveConfig} disabled={!clientId && !config}>Save config</Button>
          <Button variant="secondary" onClick={connect} disabled={!config}><Plug className="size-4" /> Connect</Button>
          {config && <Button variant="ghost" onClick={removeConfig}><Trash2 className="size-4 text-destructive" /> Remove config</Button>}
        </div>

        {tokens.length > 0 && (
          <div className="space-y-2 border-t border-border pt-3">
            <div className="text-xs font-medium text-muted-foreground">Connected accounts</div>
            {tokens.map((t) => (
              <div key={t.id} className="flex items-center justify-between rounded-xl border border-border p-2 text-sm">
                <span>{t.account}</span>
                <span className="text-xs text-muted-foreground">{t.expiresAt ? `expires ${new Date(t.expiresAt).toLocaleString()}` : 'no expiry'}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
