import { useEffect, useState } from 'react'
import { CheckCircle, AlertTriangle, X, Info } from 'lucide-react'

let toastFn = null

export function showToast(message, type = 'info') {
  if (toastFn) toastFn(message, type)
}

export default function Toast() {
  const [toasts, setToasts] = useState([])

  useEffect(() => {
    toastFn = (message, type) => {
      const id = Date.now()
      setToasts(prev => [...prev, { id, message, type }])
      setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3500)
    }
    return () => { toastFn = null }
  }, [])

  const icons = {
    success: <CheckCircle size={16} />,
    error: <AlertTriangle size={16} />,
    info: <Info size={16} />
  }

  const colors = {
    success: { color: '#00e5a0', bg: 'rgba(0,229,160,0.1)', border: 'rgba(0,229,160,0.2)' },
    error: { color: '#ff3b3b', bg: 'rgba(255,59,59,0.1)', border: 'rgba(255,59,59,0.2)' },
    info: { color: '#3b82f6', bg: 'rgba(59,130,246,0.1)', border: 'rgba(59,130,246,0.2)' }
  }

  return (
    <div style={{ position: 'fixed', bottom: 24, right: 24, zIndex: 9999, display: 'flex', flexDirection: 'column', gap: 10 }}>
      {toasts.map(toast => {
        const cfg = colors[toast.type] || colors.info
        return (
          <div key={toast.id} style={{
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '12px 16px', borderRadius: 14,
            background: 'rgba(10,10,12,0.95)', border: `1px solid ${cfg.border}`,
            boxShadow: `0 8px 32px rgba(0,0,0,0.4), 0 0 20px ${cfg.color}15`,
            backdropFilter: 'blur(20px)', minWidth: 280, maxWidth: 380,
            animation: 'fadeInUp 0.3s ease forwards', color: cfg.color
          }}>
            {icons[toast.type]}
            <span style={{ fontSize: 13, fontWeight: 600, color: '#fff', flex: 1 }}>{toast.message}</span>
            <button onClick={() => setToasts(prev => prev.filter(t => t.id !== toast.id))}
              style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.3)', cursor: 'pointer', padding: 2 }}>
              <X size={14} />
            </button>
          </div>
        )
      })}
    </div>
  )
}