import type { ReactNode } from 'react'
import { Header } from './Header'
import { Sidebar } from './Sidebar'
import type { Me } from '../api'

export function AppLayout({ me, children }: {
  me: Me | null
  children: ReactNode
}) {
  return (
    <div className="flex h-full flex-col">
      <Header me={me} />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-auto p-4 sm:p-6">
          <div className="mx-auto max-w-6xl space-y-6">{children}</div>
        </main>
      </div>
    </div>
  )
}
