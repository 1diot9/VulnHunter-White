import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { initLocale } from './i18n/locale'
import './index.css'

initLocale()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
