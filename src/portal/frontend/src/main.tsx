import React from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import { App } from './App'
import { initAuth } from './keycloak'
import { initTheme } from './theme'

initTheme()

initAuth()
  .then(() => {
    createRoot(document.getElementById('root')!).render(
      <React.StrictMode>
        <App />
      </React.StrictMode>,
    )
  })
  .catch((err) => {
    document.getElementById('root')!.innerHTML =
      `<div style="padding:2rem;font-family:Inter,sans-serif">Authentication failed: ${err}</div>`
  })
