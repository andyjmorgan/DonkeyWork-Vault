import { useEffect, useState } from 'react'
import { Trash2, Plus, KeyRound, ShieldAlert } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../ui/components/card'
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '../ui/components/table'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Label } from '../ui/components/label'
import { Badge } from '../ui/components/badge'
import { Switch } from '../ui/components/switch'
import { Checkbox } from '../ui/components/checkbox'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '../ui/components/dialog'
import { CopyButton } from '../components/CopyButton'
import { api, type AccessKey, type AccessScope, type Me } from '../api'

const lbl = 'mb-1 block text-xs text-muted-foreground'

const SCOPES: { value: AccessScope; label: string; hint: string }[] = [
  { value: 'frontend:read', label: 'frontend:read', hint: 'Read the portal API (GET).' },
  { value: 'frontend:readwrite', label: 'frontend:readwrite', hint: 'Read + write the portal API.' },
  { value: 'vault:read', label: 'vault:read', hint: 'Read credentials/tokens via gRPC.' },
  { value: 'vault:readwrite', label: 'vault:readwrite', hint: 'Read + write the vault via gRPC.' },
]

export function ProfilePage({ me }: { me: Me | null }) {
  const [keys, setKeys] = useState<AccessKey[]>([])
  const [err, setErr] = useState<string>()
  const [open, setOpen] = useState(false)
  const [created, setCreated] = useState<{ name: string; secret: string }>()

  const load = () => api.accessKeys().then(setKeys).catch((e) => setErr(String(e)))
  useEffect(() => { load() }, [])

  const toggle = async (k: AccessKey) => {
    await api.setAccessKeyEnabled(k.id, !k.enabled).catch((e) => setErr(String(e)))
    load()
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>Your identity as the vault sees it.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <IdRow label="User ID" value={me?.userId} />
          <IdRow label="Tenant ID" value={me?.tenantId || '(default)'} copyable={!!me?.tenantId} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>API keys</CardTitle>
            <CardDescription>Scoped credentials for the CLI and agents. The secret is shown once.</CardDescription>
          </div>
          <Button size="icon" variant="outline" aria-label="Add API key" onClick={() => setOpen(true)}><Plus className="size-4" /></Button>
        </CardHeader>
        <CardContent>
          {err && <p className="mb-2 text-sm text-destructive">{err}</p>}
          {keys.length === 0 ? (
            <p className="text-sm text-muted-foreground">No API keys yet — add one with the + button.</p>
          ) : (
            <Table>
              <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Key</TableHead><TableHead>Scopes</TableHead><TableHead>Last used</TableHead><TableHead>Enabled</TableHead><TableHead /></TableRow></TableHeader>
              <TableBody>
                {keys.map((k) => (
                  <TableRow key={k.id}>
                    <TableCell>
                      <div className="font-medium">{k.name}</div>
                      {k.description && <div className="max-w-[14rem] truncate text-xs text-muted-foreground" title={k.description}>{k.description}</div>}
                    </TableCell>
                    <TableCell><code className="text-xs text-muted-foreground">{k.prefix}…</code></TableCell>
                    <TableCell><div className="flex max-w-[18rem] flex-wrap gap-1">{k.scopes.map((s) => <Badge key={s} variant="secondary">{s}</Badge>)}</div></TableCell>
                    <TableCell className="text-muted-foreground">{k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : '—'}</TableCell>
                    <TableCell><Switch checked={k.enabled} onCheckedChange={() => toggle(k)} aria-label="Enabled" /></TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon" aria-label="Delete" onClick={() => api.deleteAccessKey(k.id).then(load)}><Trash2 className="size-4 text-destructive" /></Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>Create an API key</DialogTitle>
            <DialogDescription>Pick a name and the scopes it may use. The secret is shown only once.</DialogDescription>
          </DialogHeader>
          <CreateKey onCreated={(c) => { setOpen(false); setCreated(c); load() }} />
        </DialogContent>
      </Dialog>

      <Dialog open={!!created} onOpenChange={(o) => { if (!o) setCreated(undefined) }}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><KeyRound className="size-4 text-accent" /> {created?.name}</DialogTitle>
            <DialogDescription>Copy it now — it won't be shown again. If you lose it, delete the key and make a new one.</DialogDescription>
          </DialogHeader>
          <div className="flex items-center gap-2 rounded-xl border border-border bg-muted/40 p-3">
            <code className="min-w-0 flex-1 break-all text-sm">{created?.secret}</code>
            {created && <CopyButton value={created.secret} />}
          </div>
          <p className="flex items-center gap-1.5 text-xs text-warning"><ShieldAlert className="size-3.5" /> Store it in your secret manager or the CLI's VAULT_API_KEY.</p>
        </DialogContent>
      </Dialog>
    </>
  )
}

function IdRow({ label, value, copyable = true }: { label: string; value?: string; copyable?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-24 shrink-0 text-xs text-muted-foreground">{label}</span>
      <code className="min-w-0 flex-1 truncate text-sm">{value ?? '—'}</code>
      {copyable && value && <CopyButton value={value} />}
    </div>
  )
}

function CreateKey({ onCreated }: { onCreated: (c: { name: string; secret: string }) => void }) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [scopes, setScopes] = useState<AccessScope[]>([])
  const [msg, setMsg] = useState<string>()
  const [busy, setBusy] = useState(false)

  const toggleScope = (s: AccessScope) =>
    setScopes((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]))

  const submit = async () => {
    setMsg(undefined)
    setBusy(true)
    try {
      const r = await api.createAccessKey({ name, description: description || undefined, scopes })
      onCreated({ name: r.name, secret: r.secret })
    } catch (e) {
      setMsg(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid gap-3">
      <div><Label className={lbl}>Name *</Label><Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. agent-bot" /></div>
      <div><Label className={lbl}>Description</Label><Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="what this key is for" /></div>
      <div>
        <Label className={lbl}>Scopes *</Label>
        <div className="grid gap-2 sm:grid-cols-2">
          {SCOPES.map((s) => (
            <label key={s.value} className="flex cursor-pointer items-start gap-2 rounded-xl border border-border p-2.5 transition-all duration-200 hover:bg-muted">
              <Checkbox checked={scopes.includes(s.value)} onCheckedChange={() => toggleScope(s.value)} className="mt-0.5" />
              <span className="min-w-0">
                <span className="block font-mono text-xs">{s.label}</span>
                <span className="block text-xs text-muted-foreground">{s.hint}</span>
              </span>
            </label>
          ))}
        </div>
      </div>
      {msg && <p className="text-sm text-destructive">{msg}</p>}
      <div><Button onClick={submit} disabled={busy || !name || scopes.length === 0}>Create key</Button></div>
    </div>
  )
}
