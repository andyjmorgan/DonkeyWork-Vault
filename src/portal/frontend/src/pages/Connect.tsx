import { useEffect, useState } from 'react'
import { Trash2, Plug } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../ui/components/card'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Label } from '../ui/components/label'
import { Badge } from '../ui/components/badge'
import { api, type OAuthConfigItem, type OAuthProvider, type OAuthTokenItem } from '../api'

const lbl = 'mb-1 block text-xs text-muted-foreground'

export function ConnectPage() {
  const [providers, setProviders] = useState<OAuthProvider[]>([])
  const [configs, setConfigs] = useState<OAuthConfigItem[]>([])
  const [tokens, setTokens] = useState<OAuthTokenItem[]>([])
  const [provider, setProvider] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [scopes, setScopes] = useState('')
  const [redirect, setRedirect] = useState('')
  const [msg, setMsg] = useState<string>()

  const load = () => {
    api.oauthProviders().then(setProviders).catch(() => {})
    api.oauthConfigs().then(setConfigs).catch(() => {})
    api.oauthTokens().then(setTokens).catch(() => {})
  }
  useEffect(() => { load() }, [])
  useEffect(() => { if (providers[0] && !provider) setProvider(providers[0].key) }, [providers])

  const redirectHint = provider ? `https://vault.donkeywork.dev/api/oauth/${provider}/callback` : ''

  const addConfig = async () => {
    setMsg(undefined)
    try {
      await api.upsertOAuthConfig({ provider, clientId, clientSecret: clientSecret || undefined, scopes: scopes.split(/\s+/).filter(Boolean), redirectUri: redirect || undefined })
      setClientId(''); setClientSecret(''); setScopes(''); setRedirect(''); load()
    } catch (e) { setMsg(String(e)) }
  }
  const connect = async (p: string) => {
    try { const r = await api.connect(p); window.location.href = r.authorizeUrl }
    catch (e) { setMsg(String(e)) }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>OAuth app configs</CardTitle>
          <CardDescription>Register the OAuth app (client id/secret) per provider, then Connect to authorize.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className={lbl}>Provider</label>
              <select className="w-full rounded-xl border border-input bg-background px-3 py-2 text-sm" value={provider} onChange={(e) => setProvider(e.target.value)}>
                {providers.map((p) => <option key={p.key} value={p.key}>{p.name}</option>)}
              </select>
            </div>
            <div><Label className={lbl}>Client ID</Label><Input value={clientId} onChange={(e) => setClientId(e.target.value)} /></div>
            <div><Label className={lbl}>Client secret</Label><Input type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} placeholder="(blank keeps existing)" /></div>
            <div><Label className={lbl}>Scopes (space-separated)</Label><Input value={scopes} onChange={(e) => setScopes(e.target.value)} /></div>
            <div className="sm:col-span-2">
              <Label className={lbl}>Redirect URI</Label>
              <Input value={redirect} onChange={(e) => setRedirect(e.target.value)} placeholder={redirectHint} />
              {redirectHint && <p className="mt-1 text-xs text-muted-foreground">Allow-list this exact URL with the provider: <code className="text-accent">{redirectHint}</code></p>}
            </div>
          </div>
          {msg && <p className="text-sm text-destructive">{msg}</p>}
          <Button onClick={addConfig} disabled={!provider || !clientId}>Save config</Button>

          <div className="space-y-2 pt-2">
            {configs.map((c) => (
              <div key={c.id} className="flex items-center justify-between rounded-xl border border-border p-3">
                <div className="min-w-0">
                  <div className="font-medium">{c.provider}</div>
                  <div className="text-xs text-muted-foreground">{c.clientIdMasked} · {c.scopes.join(' ') || '(default scopes)'}</div>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" onClick={() => connect(c.provider)}><Plug className="size-4" /> Connect</Button>
                  <Button variant="ghost" size="icon" onClick={() => api.deleteOAuthConfig(c.id).then(load)}><Trash2 className="size-4 text-destructive" /></Button>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Connected accounts</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {tokens.length === 0 ? (
            <p className="text-sm text-muted-foreground">Nothing connected yet.</p>
          ) : tokens.map((t) => (
            <div key={t.id} className="flex items-center justify-between rounded-xl border border-border p-3">
              <div className="min-w-0">
                <div className="font-medium">{t.provider} <span className="text-xs text-muted-foreground">{t.account}</span></div>
                <div className="flex flex-wrap gap-1 pt-1">{t.scopes.slice(0, 5).map((s) => <Badge key={s} variant="secondary">{s}</Badge>)}</div>
              </div>
              <div className="text-xs text-muted-foreground">{t.expiresAt ? `expires ${new Date(t.expiresAt).toLocaleString()}` : 'no expiry'}</div>
            </div>
          ))}
        </CardContent>
      </Card>
    </>
  )
}
