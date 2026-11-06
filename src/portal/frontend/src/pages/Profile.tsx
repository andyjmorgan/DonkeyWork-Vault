import { Link, useOutletContext } from 'react-router-dom'
import { KeySquare } from 'lucide-react'
import { Button } from '../ui/components/button'
import { PageHeader } from '../components/PageHeader'
import { CopyButton } from '../components/CopyButton'
import { cn, initials } from '../lib'
import type { Me } from '../api'

export function ProfilePage() {
  const { me } = useOutletContext<{ me: Me | null }>()
  return (
    <div className="space-y-6">
      <PageHeader
        title="Profile"
        description="Your identity as the vault sees it. Credentials you store and accounts you connect are scoped to this user."
        actions={
          <Button variant="secondary" asChild>
            <Link to="/access-keys">
              <KeySquare /> Manage API keys
            </Link>
          </Button>
        }
      />
      <div className="overflow-hidden rounded-2xl border border-border bg-card">
        <div className="flex items-center gap-4 border-b border-border p-5">
          <span className="grid size-12 place-items-center rounded-full bg-elevated text-sm font-semibold">{initials(me?.name, me?.email)}</span>
          <div className="min-w-0">
            <div className="truncate text-base font-semibold">{me?.name || me?.email || 'Signed in'}</div>
            {me?.email && me.name && <div className="truncate text-sm text-muted-foreground">{me.email}</div>}
          </div>
        </div>
        <dl className="divide-y divide-border">
          <Row label="User ID" value={me?.userId} mono />
          <Row label="Tenant" value={me?.tenantId || 'default'} mono copyable={!!me?.tenantId} />
          <Row label="Email" value={me?.email} />
        </dl>
      </div>
    </div>
  )
}

function Row({ label, value, mono = false, copyable = true }: { label: string; value?: string; mono?: boolean; copyable?: boolean }) {
  return (
    <div className="grid gap-1 px-5 py-3 sm:grid-cols-[140px_minmax(0,1fr)_auto] sm:items-center sm:gap-4">
      <dt className="text-xs font-semibold text-muted-foreground">{label}</dt>
      <dd className={cn('min-w-0 truncate text-sm', mono && 'font-mono text-[13px]')}>{value ?? '—'}</dd>
      <dd className="hidden sm:block">{copyable && value ? <CopyButton value={value} /> : <span className="inline-block size-8" />}</dd>
    </div>
  )
}
