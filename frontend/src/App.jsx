import { useState, useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import Analysis from './pages/Analysis'
import Contacts from './pages/Contacts'
import Community from './pages/Community'
import PropagationMap from './pages/PropagationMap'
import Scanner from './pages/Scanner'
import Settings from './pages/Settings'
import Notifications from './pages/Notifications'
import Performance from './pages/Performance'
import Landing from './pages/Landing'
import NotFound from './pages/NotFound'
import Layout from './components/Layout'
import Toast from './components/Toast'
import Onboarding from './components/Onboarding'
import LoadingScreen from './components/LoadingScreen'
import { AlertsToaster, useRealTimeAlerts } from './components/RealTimeAlerts'

const isAuthenticated = () => !!localStorage.getItem('token')

function PrivateRoute({ children }) {
  return isAuthenticated() ? children : <Navigate to="/login" />
}

function AppContent() {
  const [showOnboarding, setShowOnboarding] = useState(false)
  const [loading, setLoading] = useState(!sessionStorage.getItem('loaded'))
  useRealTimeAlerts()

  useEffect(() => {
    const done = localStorage.getItem('onboarding_done')
    const token = localStorage.getItem('token')
    if (token && !done) setShowOnboarding(true)
  }, [])

  const handleLoadingDone = () => {
    sessionStorage.setItem('loaded', 'true')
    setLoading(false)
  }

  if (loading) return <LoadingScreen onDone={handleLoadingDone} />

  return (
    <>
      <Toast />
      <AlertsToaster />
      {showOnboarding && <Onboarding onComplete={() => setShowOnboarding(false)} />}
      <Routes>
        <Route path="/" element={isAuthenticated() ? <Navigate to="/dashboard" /> : <Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/dashboard" element={<PrivateRoute><Layout /></PrivateRoute>}>
          <Route index element={<Dashboard />} />
        </Route>
        <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
          <Route path="analysis" element={<Analysis />} />
          <Route path="scanner" element={<Scanner />} />
          <Route path="propagation" element={<PropagationMap />} />
          <Route path="contacts" element={<Contacts />} />
          <Route path="community" element={<Community />} />
          <Route path="settings" element={<Settings />} />
          <Route path="notifications" element={<Notifications />} />
          <Route path="performance" element={<Performance />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
    </>
  )
}

export default function App() {
  return <AppContent />
}