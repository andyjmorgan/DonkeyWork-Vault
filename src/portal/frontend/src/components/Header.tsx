import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Github, Moon, Sun, User, LogOut, Menu } from 'lucide-react'
import { Button } from '../ui/components/button'
import {
  DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator,
} from '../ui/components/dropdown-menu'
import { Sheet, SheetContent, SheetTrigger, SheetHeader, SheetTitle } from '../ui/components/sheet'
import { NavList } from './Sidebar'
import { logout } from '../auth'
import { getTheme, toggleTheme } from '../theme'
import type { Me } from '../api'

export function Header({ me }: { me: Me | null }) {
  const [theme, setTheme] = useState(getTheme())
  const [navOpen, setNavOpen] = useState(false)
  const navigate = useNavigate()
  return (
    <header className="flex h-14 items-center justify-between border-b border-border px-4">
      <div className="flex items-center gap-2 font-semibold">
        {/* Mobile nav: the sidebar is hidden below `sm`, so reveal it from a hamburger drawer. */}
        <Sheet open={navOpen} onOpenChange={setNavOpen}>
          <SheetTrigger asChild>
            <Button variant="ghost" size="icon" className="sm:hidden" aria-label="Open menu"><Menu /></Button>
          </SheetTrigger>
          <SheetContent side="left" className="w-64 p-3">
            <SheetHeader className="mb-2 px-1">
              <SheetTitle className="text-sm">Menu</SheetTitle>
            </SheetHeader>
            <NavList onNavigate={() => setNavOpen(false)} />
          </SheetContent>
        </Sheet>
        <Link to="/" className="flex items-center gap-2">
          <img src="/donkeywork.png" alt="DonkeyWork" className="h-8 w-8 shrink-0" />
          <span>DonkeyWork <span className="text-accent">Vault</span></span>
        </Link>
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
            <DropdownMenuItem onClick={() => navigate('/profile')}>
              <User className="mr-2 size-4" /> Profile &amp; API keys
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => logout()}>
              <LogOut className="mr-2 size-4" /> Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
