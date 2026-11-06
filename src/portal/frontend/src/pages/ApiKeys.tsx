import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { KeyRound, KeySquare, Plus, Trash2 } from 'lucide-react'
import { Button } from '../ui/components/button'
import { Input } from '../ui/components/input'
import { Badge } from '../ui/components/badge'
import { Switch } from '../ui/components/switch'
import { Checkbox } from '../ui/components/checkbox'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogBody, DialogFooter } from '../ui/components/dialog'
import { PageHeader } from '../components/PageHeader'
import { ListCard, ListBar, ListHead, ListRows, ListRow, Cell, RowActions, ListEmpty, Primary } from '../components/ListCard'
import { IconTile } from '../components/IconTile'
import { CopyButton } from '../components/CopyButton'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { FormField } from '../components/FormField'
import { Callout } from '../components/Callout'
import { cn, absoluteTime, relativeTime } from '../lib'
import { api, type AccessKey, type AccessScope } from '../api'

const SCOPES: { value: AccessScope; hint: string }[] = [
  { value: 'vault:read', hint: 'Read credentials, tokens, and config.' },
  { value: 'vault:readwrite', hint: 'Read plus create, update, and delete credentials.' },
  { value: 'vault:audit', hint: 'Read the audit trail.' },
]

const COLS = 'minmax(0,1.5fr) minmax(0,1.3fr) 130px 130px 110px'

// Access keys authenticate the CLI and agents in place of a browser session. The secret is
// shown exactly once, right after creation.
export function ApiKeysPage() {
  const [keys, setKeys] = useState<AccessKey[]>([])
  const [loaded, setLoaded] = useState(false)
  const [err, setErr] = useState<string>()
  const [open, setOpen] = useState(false)
  const [created, setCreated] = useState<{ name: string; secret: string }>()
  const [deleting, setDeleting] = useState<AccessKey>()
  const [deleteBusy, setDeleteBusy] = useState(false)
  const [deleteErr, setDeleteErr] = useState<string>()

  const load = () =>
    api
      .accessKeys()
      .then((items) => { setKeys(items); setErr(undefined) })
      .catch((e) => setErr(String(e)))
      .finally(() => setLoaded(true))
  useEffect(() => { load() }, [])

  const toggle = async (k: AccessKey) => {
    try {
      await api.setAccessKeyEnabled(k.id, !k.enabled)
      toast.success(`${k.enabled ? 'Disabled' : 'Enabled'} ${k.name}`)
    } catch (e) {
      toast.error('Could not update key', { description: String(e) })
    }
    load()
  }

  const remove = async () => {
    if (!deleting) return
    setDeleteBusy(true)
    setDeleteErr(undefined)
    try {
      await api.deleteAccessKey(deleting.id)
      toast.success(`Deleted ${deleting.name}`)
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
        title="API keys"
        description="Scoped credentials for the dwvault CLI and agents. Each key acts as you, limited to the scopes you grant it."
        actions={
          <Button variant="primary" onClick={() => setOpen(true)}>
            <Plus /> New API key
          </Button>
        }
      />

      {err && <Callout tone="danger">{err}</Callout>}

      <ListCard>
        <ListBar>
          <span>
            {keys.length.toLocaleString()} {keys.length === 1 ? 'key' : 'keys'}
            {keys.some((k) => !k.enabled) ? ` · ${keys.filter((k) => !k.enabled).length} disabled` : ''}
          </span>
        </ListBar>
        {keys.length > 0 && (
          <ListHead cols={COLS}>
            <span>Key</span>
            <span>Scopes</span>
            <span>Created</span>
            <span>Last used</span>
            <span className="text-right">Enabled</span>
          </ListHead>
        )}
        {keys.length === 0 ? (
          <ListEmpty
            icon={KeySquare}
            title={loaded ? 'No API keys yet' : 'Loading…'}
            hint={loaded ? 'Create one to let the CLI or an agent call the vault without a browser session.' : undefined}
            action={
              loaded ? (
                <Button variant="secondary" onClick={() => setOpen(true)}>
                  <Plus /> New API key
                </Button>
              ) : undefined
            }
          />
        ) : (
          <ListRows>
            {keys.map((k) => (
              <ListRow key={k.id} cols={COLS} className={cn(!k.enabled && 'opacity-70')}>
                <div className="flex min-w-0 items-center gap-3">
                  <IconTile icon={KeyRound} tone={k.enabled ? 'success' : 'muted'} />
                  <Primary title={k.name} subtitle={<span className="font-mono">{k.prefix}…</span>} />
                </div>
                <Cell label="Scopes">
                  <div className="flex flex-wrap gap-1">
                    {k.scopes.map((s) => (
                      <Badge key={s} mono variant="accent">
                        {s}
                      </Badge>
                    ))}
                  </div>
                </Cell>
                <Cell label="Created">
                  <span className="block truncate font-mono text-xs text-muted-foreground" title={absoluteTime(k.createdAt)}>
                    {relativeTime(k.createdAt)}
                  </span>
                </Cell>
                <Cell label="Last used">
                  <span className="block truncate font-mono text-xs text-muted-foreground" title={absoluteTime(k.lastUsedAt)}>
                    {k.lastUsedAt ? relativeTime(k.lastUsedAt) : 'Never'}
                  </span>
                </Cell>
                <RowActions>
                  <Switch checked={k.enabled} onCheckedChange={() => toggle(k)} aria-label={`${k.name} enabled`} />
                  <Button variant="ghost" size="icon" className="hover:text-danger" aria-label={`Delete ${k.name}`} title="Delete" onClick={() => { setDeleteErr(undefined); setDeleting(k) }}>
                    <Trash2 />
                  </Button>
                </RowActions>
              </ListRow>
            ))}
          </ListRows>
        )}
      </ListCard>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-xl">
          <CreateKey
            onClose={() => setOpen(false)}
            onCreated={(c) => {
              setOpen(false)
              setCreated(c)
              load()
            }}
          />
        </DialogContent>
      </Dialog>

      <Dialog open={!!created} onOpenChange={(o) => { if (!o) setCreated(undefined) }}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <div className="flex items-center gap-3">
              <IconTile icon={KeyRound} tone="success" className="size-10" />
              <div className="min-w-0">
                <DialogTitle className="truncate">{created?.name}</DialogTitle>
                <DialogDescription className="mt-0.5">Copy it now. It won't be shown again.</DialogDescription>
              </div>
            </div>
          </DialogHeader>
          <DialogBody>
            <div className="flex items-center gap-2 rounded-xl border border-border bg-code p-3">
              <code className="min-w-0 flex-1 break-all font-mono text-sm text-code-foreground">{created?.secret}</code>
              {created && <CopyButton value={created.secret} />}
            </div>
            <Callout tone="warning">
              Store it in your secret manager or hand it to the CLI as <code className="rounded bg-code px-1 py-0.5 font-mono text-xs text-code-foreground">VAULT_API_KEY</code>. If you lose it,
              delete the key and create a new one.
            </Callout>
          </DialogBody>
          <DialogFooter>
            <Button variant="primary" onClick={() => setCreated(undefined)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!deleting}
        title="Delete API key?"
        description={deleting ? `Anything still using ${deleting.name} (${deleting.prefix}…) will be refused immediately.` : undefined}
        busy={deleteBusy}
        error={deleteErr}
        onCancel={() => setDeleting(undefined)}
        onConfirm={remove}
      />
    </div>
  )
}

function CreateKey({ onClose, onCreated }: { onClose: () => void; onCreated: (c: { name: string; secret: string }) => void }) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [scopes, setScopes] = useState<AccessScope[]>(['vault:read'])
  const [msg, setMsg] = useState<string>()
  const [busy, setBusy] = useState(false)
  const canCreate = !!name.trim() && scopes.length > 0

  const toggleScope = (s: AccessScope) => setScopes((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]))

  const submit = async () => {
    if (!canCreate) return
    setMsg(undefined)
    setBusy(true)
    try {
      const r = await api.createAccessKey({ name: name.trim(), description: description || undefined, scopes })
      onCreated({ name: r.name, secret: r.secret })
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
        <DialogTitle>New API key</DialogTitle>
        <DialogDescription>Name it after what will hold it, and grant only the scopes it needs.</DialogDescription>
      </DialogHeader>
      <DialogBody>
        <FormField label="Name" required>
          <Input value={name} autoFocus onChange={(e) => setName(e.target.value)} placeholder="e.g. agent-bot" />
        </FormField>
        <FormField label="Description">
          <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What this key is for" />
        </FormField>
        <FormField label="Scopes" required>
          <div className="grid gap-2">
            {SCOPES.map((s) => {
              const on = scopes.includes(s.value)
              return (
                <label
                  key={s.value}
                  className={cn(
                    'flex cursor-pointer items-start gap-3 rounded-xl border p-3 transition-colors hover:bg-elevated/60',
                    on ? 'border-accent/40 bg-accent/5' : 'border-border',
                  )}
                >
                  <Checkbox checked={on} onCheckedChange={() => toggleScope(s.value)} className="mt-0.5" />
                  <span className="min-w-0">
                    <span className="block font-mono text-sm">{s.value}</span>
                    <span className="mt-0.5 block text-xs text-muted-foreground">{s.hint}</span>
                  </span>
                </label>
              )
            })}
          </div>
        </FormField>
        {msg && <Callout tone="danger">{msg}</Callout>}
      </DialogBody>
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>Cancel</Button>
        <Button type="submit" variant="primary" disabled={busy || !canCreate}>
          {busy ? 'Creating…' : 'Create key'}
        </Button>
      </DialogFooter>
    </form>
  )
}
