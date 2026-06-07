import { useEffect, useState } from 'react'
import { Trash2 } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '../ui/components/card'
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '../ui/components/table'
import { Button } from '../ui/components/button'
import { Badge } from '../ui/components/badge'
import { api, type ApiKeyItem, type OAuthTokenItem } from '../api'

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
      <Card>
        <CardHeader><CardTitle>API keys</CardTitle></CardHeader>
        <CardContent>
          {err && <p className="text-sm text-destructive">{err}</p>}
          {keys.length === 0 ? (
            <p className="text-sm text-muted-foreground">No API keys yet — add one from the Providers tab.</p>
          ) : (
            <Table>
              <TableHeader><TableRow><TableHead>Provider</TableHead><TableHead>Name</TableHead><TableHead>Created</TableHead><TableHead /></TableRow></TableHeader>
              <TableBody>
                {keys.map((k) => (
                  <TableRow key={k.id}>
                    <TableCell className="font-medium">{k.provider}</TableCell>
                    <TableCell>{k.name}</TableCell>
                    <TableCell className="text-muted-foreground">{new Date(k.createdAt).toLocaleString()}</TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon" onClick={() => api.deleteApiKey(k.id).then(load)}>
                        <Trash2 className="size-4 text-destructive" />
                      </Button>
                    </TableCell>
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
                    <TableCell>
                      <div className="flex max-w-[18rem] flex-wrap gap-1">
                        {t.scopes.slice(0, 4).map((s) => <Badge key={s} variant="secondary">{s}</Badge>)}
                        {t.scopes.length > 4 && <Badge variant="secondary">+{t.scopes.length - 4}</Badge>}
                      </div>
                    </TableCell>
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
