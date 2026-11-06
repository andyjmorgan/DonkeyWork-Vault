import type { ReactNode } from 'react'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogBody, DialogFooter } from '../ui/components/dialog'
import { Button } from '../ui/components/button'
import { Callout } from './Callout'

/** A yes/no dialog for destructive actions. The confirm button is tinted danger by default. */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = 'Delete',
  busy = false,
  error,
  onCancel,
  onConfirm,
  children,
}: {
  open: boolean
  title: string
  description?: ReactNode
  confirmLabel?: string
  busy?: boolean
  error?: string
  onCancel: () => void
  onConfirm: () => void
  children?: ReactNode
}) {
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o && !busy) onCancel() }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        {(children || error) && (
          <DialogBody>
            {children}
            {error && <Callout tone="danger">{error}</Callout>}
          </DialogBody>
        )}
        <DialogFooter>
          <Button variant="outline" autoFocus disabled={busy} onClick={onCancel}>Cancel</Button>
          <Button variant="danger" disabled={busy} onClick={onConfirm}>{busy ? 'Working…' : confirmLabel}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
