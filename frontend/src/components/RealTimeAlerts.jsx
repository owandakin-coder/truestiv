import { useEffect, useState, useRef } from 'react'
import { AlertTriangle, Shield, CheckCircle, X, Bell } from 'lucide-react'
import toast, { Toaster } from 'react-hot-toast'

const mockAlerts = [
  { type: 'threat', title: 'Phishing Detected', message: 'Email from paypa1.com blocked', color: '#ff3b3b' },
  { type: 'warning', title: 'Suspicious URL', message: 'amazon-verify.xyz flagged', color: '#fbbf24' },
  { type: 'safe', title: 'Scan Complete', message: 'newsletter@github.com verified safe', color: '#00e5a0' },
  { type: 'threat', title: 'Malware Blocked', message: 'invoice.exe attachment removed', color: '#ff3b3b' },
  { type: 'warning', title: 'IP Flagged', message: '185.220.101.42 blocked', color: '#fbbf24' },
]

export function useRealTimeAlerts() {
  useEffect(() => {
    let index = 0
    const interval = setInterval(() => {
      if (Math.random() > 0.6) {
        const alert = mockAlerts[index % mockAlerts.length]
        index++

        const icons = {
          threat: '🚨',
          warning: '⚠️',
          safe: '✅'
        }

        toast.custom((t) => (
          <div style={{
            display: 'flex', alignItems: 'flex-start', gap: 12,
            padding: '14px 16px', borderRadius: 16, minWidth: 300, maxWidth: 380,
            background: 'rgba(10,10,12,0.98)',
            border: `1px solid ${alert.color}30`,
            boxShadow: `0 8px 32px rgba(0,0,0,0.5), 0 0 20px ${alert.color}15`,
            animation: t.visible ? 'fadeInUp 0.3s ease' : 'fadeOut 0.2s ease',
            backdropFilter: 'blur(20px)'
          }}>
            <div style={{ fontSize: 20, flexShrink: 0 }}>{icons[alert.type]}</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 3 }}>{alert.title}</div>
              <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.4)' }}>{alert.message}</div>
            </div>
            <button onClick={() => toast.dismiss(t.id)} style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.2)', cursor: 'pointer', padding: 2, flexShrink: 0 }}>
              <X size={13} />
            </button>
          </div>
        ), {
          duration: 4000,
          position: 'bottom-right',
        })
      }
    }, 8000)

    return () => clearInterval(interval)
  }, [])
}

export function AlertsToaster() {
  return (
    <Toaster
      position="bottom-right"
      toastOptions={{
        style: { background: 'transparent', boxShadow: 'none', padding: 0 }
      }}
    />
  )
}