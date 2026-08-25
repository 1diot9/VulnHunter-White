import { lazy, Suspense } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import AppLayout from './components/AppLayout'
import AuthGate from './components/AuthGate'
import HomePage from './pages/HomePage'

const ProjectDetailPage = lazy(() => import('./pages/ProjectDetailPage'))
const SettingsPage = lazy(() => import('./pages/SettingsPage'))
const VulnsPage = lazy(() => import('./pages/VulnsPage'))
const VerifierConsentPage = lazy(() => import('./pages/VerifierConsentPage'))
const ContainersPage = lazy(() => import('./pages/ContainersPage'))
const DiscoverPage = lazy(() => import('./pages/DiscoverPage'))

function RouteFallback() {
  return (
    <div className="flex min-h-[40vh] items-center justify-center text-sm text-muted-foreground">
      加载中…
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthGate>
        <Suspense fallback={<RouteFallback />}>
          <Routes>
            <Route element={<AppLayout />}>
              <Route path="/" element={<HomePage />} />
              <Route path="/discover" element={<DiscoverPage />} />
              <Route path="/projects/:id" element={<ProjectDetailPage />} />
              <Route path="/vulns" element={<VulnsPage />} />
              <Route path="/vulns/:id" element={<VulnsPage />} />
              <Route path="/verifier-consent" element={<VerifierConsentPage />} />
              <Route path="/containers" element={<ContainersPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </AuthGate>
    </BrowserRouter>
  )
}
