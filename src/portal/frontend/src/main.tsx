import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import { App } from './App'
import { initAuth } from './auth'
import { initTheme } from './theme'

initTheme()

initAuth()
  .then(() => {
    createRoot(document.getElementById('root')!).render(
      <React.StrictMode>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </React.StrictMode>,
    )
  })
  .catch((err) => {
    const root = document.getElementById('root')!
    root.className = 'grid h-full place-items-center p-6'
    const card = document.createElement('div')
    card.className = 'max-w-sm rounded-2xl border border-border bg-card p-6 text-sm'
    const title = document.createElement('h1')
    title.className = 'text-lg font-semibold'
    title.textContent = 'Could not reach the sign-in service'
    const body = document.createElement('p')
    body.className = 'mt-2 text-muted-foreground'
    body.textContent = String(err)
    card.append(title, body)
    root.replaceChildren(card)
  })
