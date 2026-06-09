import { useCallback, useEffect, useState } from 'react'
import { ChevronLeft, ChevronRight, RotateCw } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../ui/components/card'
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '../ui/components/table'
import { Button } from '../ui/components/button'
import { Badge } from '../ui/components/badge'
import { Label } from '../ui/components/label'
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from '../ui/components/select'
import { Field } from '../components/Field'
import { api, type AuditEvent } from '../api'

const PAGE = 25

// Known event types from the spec; "all" clears the filter.
const TYPES = [
  'TokenAccessed', 'TokenRefreshed', 'TokenAdded', 'CredentialCreated',
  'AuthSucceeded', 'AuthFailed', 'AuditAccessed',
] as const

const lbl = 'mb-1 block text-xs text-muted-foreground'
const ALL = '__all__'

const fmt = (s?: string | null) => (s ? new Date(s).toLocaleString() : '—')

// A single line describing what was acted on, combining the target fields that are present.
function target(e: AuditEvent): string {
  const parts = [e.targetKind, e.targetProvider, e.targetAccount, e.targetName].filter(Boolean)
  return parts.length ? parts.join(' · ') : '—'
}

function accessKey(e: AuditEvent): string {
  if (!e.accessKeyPrefix && !e.accessKeyName) return '—'
  return [e.accessKeyName, e.accessKeyPrefix ? `${e.accessKeyPrefix}…` : undefined].filter(Boolean).join(' · ')
}

function OutcomeBadge({ outcome }: { outcome: string }) {
  const fail = outcome?.toLowerCase() === 'failure'
  return <Badge variant={fail ? 'destructive' : 'success'}>{outcome}</Badge>
}

export function AuditPage() {
  const [items, setItems] = useState<AuditEvent[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [type, setType] = useState<string>(ALL)
  const [outcome, setOutcome] = useState<string>(ALL)
  const [err, setErr] = useState<string>()
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    setBusy(true); setErr(undefined)
    api.audit({
      limit: PAGE,
      offset,
      type: type === ALL ? undefined : type,
      outcome: outcome === ALL ? undefined : outcome,
    })
      .then((p) => { setItems(p.items ?? []); setTotal(Number(p.total) || 0) })
      .catch((e) => setErr(String(e)))
      .finally(() => setBusy(false))
  }, [offset, type, outcome])

  useEffect(() => { load() }, [load])

  // Changing a filter resets to the first page.
  const onFilter = (set: (v: string) => void) => (v: string) => { setOffset(0); set(v) }

  const from = total === 0 ? 0 : offset + 1
  const to = Math.min(offset + PAGE, total)
  const canPrev = offset > 0
  const canNext = offset + PAGE < total

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-3">
        <div>
          <CardTitle>Audit trail</CardTitle>
          <CardDescription>Credential access and auth events, newest first.</CardDescription>
        </div>
        <Button variant="outline" size="icon" aria-label="Refresh" disabled={busy} onClick={load}>
          <RotateCw className="size-4" />
        </Button>
      </CardHeader>
      <CardContent>
        {/* Filters. */}
        <div className="mb-4 grid gap-3 sm:grid-cols-2 sm:max-w-md">
          <div>
            <Label className={lbl}>Type</Label>
            <Select value={type} onValueChange={onFilter(setType)}>
              <SelectTrigger><SelectValue placeholder="All types" /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All types</SelectItem>
                {TYPES.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className={lbl}>Outcome</Label>
            <Select value={outcome} onValueChange={onFilter(setOutcome)}>
              <SelectTrigger><SelectValue placeholder="All outcomes" /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All outcomes</SelectItem>
                <SelectItem value="Success">Success</SelectItem>
                <SelectItem value="Failure">Failure</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {err && <p className="mb-2 text-sm text-destructive">{err}</p>}

        {items.length === 0 ? (
          <p className="text-sm text-muted-foreground">{busy ? 'Loading…' : 'No audit events match these filters.'}</p>
        ) : (
          <>
            {/* Desktop: table. */}
            <div className="hidden lg:block">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead><TableHead>Type</TableHead><TableHead>Outcome</TableHead>
                    <TableHead>Target</TableHead><TableHead>Source IP</TableHead><TableHead>Access key</TableHead>
                    <TableHead>Method</TableHead><TableHead>Detail</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((e) => (
                    <TableRow key={e.id}>
                      <TableCell className="whitespace-nowrap text-muted-foreground">{fmt(e.createdAt)}</TableCell>
                      <TableCell className="whitespace-nowrap font-medium">{e.type}</TableCell>
                      <TableCell><OutcomeBadge outcome={e.outcome} /></TableCell>
                      <TableCell className="max-w-[16rem] truncate" title={target(e)}>{target(e)}</TableCell>
                      <TableCell className="whitespace-nowrap text-muted-foreground">{e.sourceIp || '—'}</TableCell>
                      <TableCell className="max-w-[12rem] truncate text-muted-foreground" title={accessKey(e)}>{accessKey(e)}</TableCell>
                      <TableCell className="whitespace-nowrap text-muted-foreground">{e.method || '—'}</TableCell>
                      <TableCell className="max-w-[16rem] truncate text-muted-foreground" title={e.detail || undefined}>{e.detail || '—'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            {/* Mobile / narrow: a card per event. */}
            <div className="space-y-3 lg:hidden">
              {items.map((e) => (
                <div key={e.id} className="rounded-xl border border-border p-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="font-medium">{e.type}</div>
                      <div className="text-xs text-muted-foreground">{fmt(e.createdAt)}</div>
                    </div>
                    <OutcomeBadge outcome={e.outcome} />
                  </div>
                  <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2">
                    <Field label="Target">{target(e)}</Field>
                    <Field label="Source IP">{e.sourceIp || '—'}</Field>
                    <Field label="Access key">{accessKey(e)}</Field>
                    <Field label="Method">{e.method || '—'}</Field>
                  </div>
                  {e.detail && <div className="mt-2"><Field label="Detail" truncate={false}>{e.detail}</Field></div>}
                </div>
              ))}
            </div>
          </>
        )}

        {/* Paging. */}
        <div className="mt-4 flex items-center justify-between">
          <span className="text-xs text-muted-foreground">{total > 0 ? `${from}–${to} of ${total}` : '—'}</span>
          <div className="flex items-center gap-1">
            <Button variant="outline" size="icon" aria-label="Previous page" disabled={!canPrev || busy} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
              <ChevronLeft className="size-4" />
            </Button>
            <Button variant="outline" size="icon" aria-label="Next page" disabled={!canNext || busy} onClick={() => setOffset(offset + PAGE)}>
              <ChevronRight className="size-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
