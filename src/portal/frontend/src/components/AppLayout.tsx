import type { ReactNode } from 'react'
import { Header } from './Header'
import { Sidebar, type Tab } from './Sidebar'
import type { Me } from '../api'

export function AppLayout({ me, active, onSelect, children }: {
  me: Me | null
  active: Tab
  onSelect: (t: Tab) => void
  children: ReactNode
}) {
  return (
    <div className="flex h-full flex-col">
      <Header me={me} />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar active={active} onSelect={onSelect} />
        <main className="flex-1 overflow-auto p-4 sm:p-6">
          <div className="mx-auto max-w-4xl space-y-6">{children}</div>
        </main>
      </div>
    </div>
  )
}
