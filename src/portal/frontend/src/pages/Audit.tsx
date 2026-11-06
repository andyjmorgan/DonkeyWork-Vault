import { useCallback, useEffect, useState } from 'react'
import { Activity, RotateCw } from 'lucide-react'
import { Button } from '../ui/components/button'
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '../ui/components/select'
import { PageHeader } from '../components/PageHeader'
import { ListCard, ListBar, ListHead, ListRows, ListRow, Cell, ListEmpty, ListPager } from '../components/ListCard'
import { StatusPill } from '../components/StatusPill'
import { Callout } from '../components/Callout'
import { absoluteTime, relativeTime } from '../lib'
import { api, type AuditEvent } from '../api'

const PAGE = 25

// Known event types from the spec; "all" clears the filter.
const TYPES = ['TokenAccessed', 'TokenRefreshed', 'TokenAdded', 'CredentialCreated', 'AuthSucceeded', 'AuthFailed', 'AuditAccessed'] as const

const ALL = '__all__'
const COLS = '150px minmax(0,1.5fr) 110px minmax(0,1.4fr) 150px minmax(0,1fr)'

// A single line describing what was acted on, combining the target fields that are present.
function target(e: AuditEvent): string {
  const parts = [e.targetKind, e.targetProvider, e.targetAccount, e.targetName].filter(Boolean)
  return parts.length ? parts.join(' · ') : '—'
}

function accessKey(e: AuditEvent): string {
  if (!e.accessKeyPrefix && !e.accessKeyName) return '—'
  return [e.accessKeyName, e.accessKeyPrefix ? `${e.accessKeyPrefix}…` : undefined].filter(Boolean).join(' · ')
}

// "TokenAccessed" → "Token accessed", so the event column reads as prose while the raw type stays
// in the filter.
const prettyType = (t: string) => t.replace(/([a-z])([A-Z])/g, (_, a: string, b: string) => `${a} ${b.toLowerCase()}`)

function Outcome({ outcome }: { outcome: string }) {
  const fail = outcome?.toLowerCase() === 'failure'
  return <StatusPill tone={fail ? 'danger' : 'success'}>{fail ? 'Failure' : 'Success'}</StatusPill>
}

export function AuditPage() {
  const [items, setItems] = useState<AuditEvent[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [type, setType] = useState<string>(ALL)
  const [outcome, setOutcome] = useState<string>(ALL)
  const [err, setErr] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [loaded, setLoaded] = useState(false)

  const load = useCallback(() => {
    setBusy(true)
    setErr(undefined)
    api
      .audit({ limit: PAGE, offset, type: type === ALL ? undefined : type, outcome: outcome === ALL ? undefined : outcome })
      .then((p) => {
        setItems(p.items ?? [])
        setTotal(Number(p.total) || 0)
      })
      .catch((e) => setErr(String(e)))
      .finally(() => {
        setBusy(false)
        setLoaded(true)
      })
  }, [offset, type, outcome])

  useEffect(() => { load() }, [load])

  // Changing a filter resets to the first page.
  const onFilter = (set: (v: string) => void) => (v: string) => {
    setOffset(0)
    set(v)
  }

  const from = total === 0 ? 0 : offset + 1
  const to = Math.min(offset + PAGE, total)

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit trail"
        description="Every credential read, token refresh, and sign-in, newest first. Entries name the access key or user and where the request came from."
        actions={
          <Button variant="secondary" disabled={busy} onClick={load}>
            <RotateCw className={busy ? 'animate-spin' : undefined} /> Refresh
          </Button>
        }
      />

      {err && <Callout tone="danger">{err}</Callout>}

      <ListCard>
        <ListBar>
          <span>
            {total.toLocaleString()} {total === 1 ? 'event' : 'events'}
          </span>
          <div className="flex w-full flex-wrap gap-2 sm:w-auto">
            <Select value={type} onValueChange={onFilter(setType)}>
              <SelectTrigger className="h-9 sm:w-48" aria-label="Event type">
                <SelectValue placeholder="All types" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All types</SelectItem>
                {TYPES.map((t) => (
                  <SelectItem key={t} value={t}>
                    {prettyType(t)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={outcome} onValueChange={onFilter(setOutcome)}>
              <SelectTrigger className="h-9 sm:w-40" aria-label="Outcome">
                <SelectValue placeholder="All outcomes" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All outcomes</SelectItem>
                <SelectItem value="Success">Success</SelectItem>
                <SelectItem value="Failure">Failure</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </ListBar>

        {items.length > 0 && (
          <ListHead cols={COLS} at="lg">
            <span>Time</span>
            <span>Event</span>
            <span>Outcome</span>
            <span>Target</span>
            <span>Source</span>
            <span>Access key</span>
          </ListHead>
        )}

        {items.length === 0 ? (
          <ListEmpty icon={Activity} title={loaded && !busy ? 'No audit events match these filters' : 'Loading…'} />
        ) : (
          <ListRows className={busy ? 'opacity-60 transition-opacity' : 'transition-opacity'}>
            {items.map((e) => (
              <ListRow key={e.id} cols={COLS} at="lg" className="lg:py-4">
                <Cell label="Time" at="lg">
                  <span className="block font-mono text-xs text-muted-foreground" title={absoluteTime(e.createdAt)}>
                    {relativeTime(e.createdAt)}
                  </span>
                </Cell>
                <Cell label="Event" at="lg">
                  <div className="truncate text-sm font-medium">{prettyType(e.type)}</div>
                  {e.detail && (
                    <div className="mt-0.5 truncate text-xs text-muted-foreground" title={e.detail}>
                      {e.detail}
                    </div>
                  )}
                </Cell>
                <Cell label="Outcome" at="lg">
                  <Outcome outcome={e.outcome} />
                </Cell>
                <Cell label="Target" at="lg">
                  <span className="block truncate font-mono text-xs" title={target(e)}>
                    {target(e)}
                  </span>
                </Cell>
                <Cell label="Source" at="lg">
                  <span className="block truncate font-mono text-xs text-muted-foreground">
                    {e.sourceIp || '—'}
                    {e.method ? <span className="text-faint-foreground"> · {e.method}</span> : null}
                  </span>
                </Cell>
                <Cell label="Access key" at="lg">
                  <span className="block truncate font-mono text-xs text-muted-foreground" title={accessKey(e)}>
                    {accessKey(e)}
                  </span>
                </Cell>
              </ListRow>
            ))}
          </ListRows>
        )}

        <ListPager
          from={from}
          to={to}
          total={total}
          canPrev={offset > 0}
          canNext={offset + PAGE < total}
          busy={busy}
          onPrev={() => setOffset(Math.max(0, offset - PAGE))}
          onNext={() => setOffset(offset + PAGE)}
        />
      </ListCard>
    </div>
  )
}
