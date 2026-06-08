import { useState } from 'react'
import { Github, Moon, Sun, User, LogOut } from 'lucide-react'
import { Button } from '../ui/components/button'
import {
  DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator,
} from '../ui/components/dropdown-menu'
import { keycloak } from '../keycloak'
import { getTheme, toggleTheme } from '../theme'
import type { Me } from '../api'
import type { Tab } from './Sidebar'

export function Header({ me, onSelect }: { me: Me | null; onSelect: (t: Tab) => void }) {
  const [theme, setTheme] = useState(getTheme())
  return (
    <header className="flex h-14 items-center justify-between border-b border-border px-4">
      <div className="flex items-center gap-2 font-semibold">
        <img src="/donkeywork.png" alt="DonkeyWork" className="h-8 w-8 shrink-0" />
        <span>DonkeyWork <span className="text-accent">Vault</span></span>
      </div>
      <div className="flex items-center gap-1">
        <Button variant="ghost" size="icon" asChild aria-label="GitHub">
          <a href="https://github.com/andyjmorgan/DonkeyWork-Vault" target="_blank" rel="noreferrer"><Github /></a>
        </Button>
        <Button variant="ghost" size="icon" aria-label="Toggle theme" onClick={() => setTheme(toggleTheme())}>
          {theme === 'dark' ? <Sun /> : <Moon />}
        </Button>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label="Profile"><User /></Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel>{me?.name || me?.email || 'Signed in'}</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => onSelect('profile')}>
              <User className="mr-2 size-4" /> Profile &amp; API keys
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => keycloak.logout()}>
              <LogOut className="mr-2 size-4" /> Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
