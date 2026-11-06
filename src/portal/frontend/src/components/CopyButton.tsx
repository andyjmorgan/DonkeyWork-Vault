import { useState } from 'react'
import { Copy, Check } from 'lucide-react'
import { Button } from '../ui/components/button'
import { cn } from '../lib'

export function CopyButton({ value, label = 'Copy', className }: { value: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false)
  const copy = async (e: React.MouseEvent) => {
    e.stopPropagation()
    try {
      await navigator.clipboard.writeText(value)
      setDone(true)
      setTimeout(() => setDone(false), 1500)
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <Button variant="ghost" size="iconSm" aria-label={label} title={label} onClick={copy} className={cn(className)}>
      {done ? <Check className="text-success" /> : <Copy />}
    </Button>
  )
}
