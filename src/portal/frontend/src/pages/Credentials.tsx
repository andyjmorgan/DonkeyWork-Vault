import { useEffect, useState } from 'react'
import { Trash2 } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../ui/components/card'
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '../ui/components/table'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Label } from '../ui/components/label'
import { Badge } from '../ui/components/badge'
import { api, type ApiKeyItem, type OAuthTokenItem } from '../api'

const lbl = 'mb-1 block text-xs text-muted-foreground'

export function CredentialsPage() {
  const [keys, setKeys] = useState<ApiKeyItem[]>([])
  const [tokens, setTokens] = useState<OAuthTokenItem[]>([])
  const [err, setErr] = useState<string>()

  const load = () => {
    api.apiKeys().then(setKeys).catch((e) => setErr(String(e)))
    api.oauthTokens().then(setTokens).catch(() => {})
  }
  useEffect(() => { load() }, [])

  return (
    <>
      <StoreKey onStored={load} />

      <Card>
        <CardHeader><CardTitle>API keys</CardTitle><CardDescription>What's stored and how to use each.</CardDescription></CardHeader>
        <CardContent>
          {err && <p className="text-sm text-destructive">{err}</p>}
          {keys.length === 0 ? (
            <p className="text-sm text-muted-foreground">No API keys yet.</p>
          ) : (
            <Table>
              <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Description</TableHead><TableHead>Header</TableHead><TableHead>Prefix</TableHead><TableHead>Base URL</TableHead><TableHead /></TableRow></TableHeader>
              <TableBody>
                {keys.map((k) => (
                  <TableRow key={k.id}>
                    <TableCell className="font-medium">{k.name}</TableCell>
                    <TableCell className="text-muted-foreground">{k.description}</TableCell>
                    <TableCell>{k.header}</TableCell>
                    <TableCell className="text-muted-foreground">{k.prefix}</TableCell>
                    <TableCell className="text-muted-foreground">{k.docsUrl ? <a className="text-accent hover:underline" href={k.docsUrl} target="_blank" rel="noreferrer">{k.baseUrl || 'docs'}</a> : k.baseUrl}</TableCell>
                    <TableCell className="text-right"><Button variant="ghost" size="icon" onClick={() => api.deleteApiKey(k.id).then(load)}><Trash2 className="size-4 text-destructive" /></Button></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Connected OAuth accounts</CardTitle></CardHeader>
        <CardContent>
          {tokens.length === 0 ? (
            <p className="text-sm text-muted-foreground">No OAuth tokens — connect a provider from the OAuth Connect tab.</p>
          ) : (
            <Table>
              <TableHeader><TableRow><TableHead>Provider</TableHead><TableHead>Account</TableHead><TableHead>Expires</TableHead><TableHead>Scopes</TableHead></TableRow></TableHeader>
              <TableBody>
                {tokens.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-medium">{t.provider}</TableCell>
                    <TableCell>{t.account}</TableCell>
                    <TableCell className="text-muted-foreground">{t.expiresAt ? new Date(t.expiresAt).toLocaleString() : '—'}</TableCell>
                    <TableCell><div className="flex max-w-[18rem] flex-wrap gap-1">{t.scopes.slice(0, 4).map((s) => <Badge key={s} variant="secondary">{s}</Badge>)}{t.scopes.length > 4 && <Badge variant="secondary">+{t.scopes.length - 4}</Badge>}</div></TableCell>
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

function StoreKey({ onStored }: { onStored: () => void }) {
  const [k, setK] = useState({ name: '', secret: '', description: '', baseUrl: '', docsUrl: '', header: 'Authorization', prefix: 'Bearer ' })
  const [msg, setMsg] = useState<string>()
  const set = (patch: Partial<typeof k>) => setK({ ...k, ...patch })

  const submit = async () => {
    setMsg(undefined)
    try {
      await api.createApiKey(k)
      setMsg('Saved.')
      setK({ name: '', secret: '', description: '', baseUrl: '', docsUrl: '', header: 'Authorization', prefix: 'Bearer ' })
      onStored()
    } catch (e) { setMsg(String(e)) }
  }

  return (
    <Card>
      <CardHeader><CardTitle>Add an API key</CardTitle><CardDescription>Self-describing — no fixed provider type. The description/host/docs/header help agents use it.</CardDescription></CardHeader>
      <CardContent className="grid gap-3 sm:grid-cols-2">
        <div><Label className={lbl}>Name *</Label><Input value={k.name} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. grafana-prod" /></div>
        <div><Label className={lbl}>Secret *</Label><Input type="password" value={k.secret} onChange={(e) => set({ secret: e.target.value })} /></div>
        <div className="sm:col-span-2"><Label className={lbl}>Description</Label><Input value={k.description} onChange={(e) => set({ description: e.target.value })} placeholder="what this credential is for" /></div>
        <div><Label className={lbl}>Base URL / host</Label><Input value={k.baseUrl} onChange={(e) => set({ baseUrl: e.target.value })} placeholder="https://api.example.com" /></div>
        <div><Label className={lbl}>API docs link</Label><Input value={k.docsUrl} onChange={(e) => set({ docsUrl: e.target.value })} placeholder="https://docs.example.com" /></div>
        <div><Label className={lbl}>Header name</Label><Input value={k.header} onChange={(e) => set({ header: e.target.value })} placeholder="Authorization" /></div>
        <div><Label className={lbl}>Prefix (optional)</Label><Input value={k.prefix} onChange={(e) => set({ prefix: e.target.value })} placeholder="Bearer " /></div>
        {msg && <p className="text-sm text-muted-foreground sm:col-span-2">{msg}</p>}
        <div className="sm:col-span-2"><Button onClick={submit} disabled={!k.name || !k.secret}>Save key</Button></div>
      </CardContent>
    </Card>
  )
}
