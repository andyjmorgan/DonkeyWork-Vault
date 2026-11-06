import { useState } from 'react'
import { cn } from '../lib'

/** A provider's logo in a tile, falling back to its initial when there's no icon or it fails. */
export function ProviderIcon({ src, name, className }: { src?: string; name: string; className?: string }) {
  const [err, setErr] = useState(false)
  if (!src || err) {
    return (
      <div className={cn('grid size-9 shrink-0 place-items-center rounded-xl bg-accent/10 text-sm font-semibold text-accent', className)}>
        {(name || '?').charAt(0).toUpperCase()}
      </div>
    )
  }
  return (
    <div className={cn('grid size-9 shrink-0 place-items-center overflow-hidden rounded-xl border border-border bg-white', className)}>
      <img src={src} alt="" className="size-[62%] object-contain" onError={() => setErr(true)} />
    </div>
  )
}
