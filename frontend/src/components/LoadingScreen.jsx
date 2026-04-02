import { useEffect, useState } from 'react'
import { Zap } from 'lucide-react'

export default function LoadingScreen({ onDone }) {
  const [progress, setProgress] = useState(0)
  const [text, setText] = useState('Initializing security engine...')

  const messages = [
    'Initializing security engine...',
    'Loading threat database...',
    'Connecting to AI service...',
    'Verifying authentication...',
    'Ready!',
  ]

  useEffect(() => {
    let p = 0
    const interval = setInterval(() => {
      p += Math.random() * 20 + 8
      if (p >= 100) {
        p = 100
        clearInterval(interval)
        setTimeout(onDone, 400)
      }
      setProgress(Math.min(100, p))
      setText(messages[Math.min(Math.floor(p / 22), messages.length - 1)])
    }, 180)
    return () => clearInterval(interval)
  }, [])

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 99999,
      background: '#050507', display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center',
      backgroundImage: 'radial-gradient(rgba(255,255,255,0.03) 1px, transparent 1px)',
      backgroundSize: '28px 28px'
    }}>
      <div style={{ position: 'absolute', top: '20%', left: '20%', width: '60%', height: '60%', background: 'radial-gradient(circle, rgba(255,107,53,0.06) 0%, transparent 70%)', pointerEvents: 'none' }} />

      <div style={{ position: 'relative', marginBottom: 40 }}>
        <div style={{ width: 80, height: 80, borderRadius: 24, background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 60px rgba(255,107,53,0.5)', animation: 'glow-pulse 2s ease-in-out infinite' }}>
          <Zap size={40} color="#fff" fill="#fff" />
        </div>
        <div style={{ position: 'absolute', inset: -8, borderRadius: 32, border: '2px solid rgba(255,107,53,0.2)', animation: 'pulse 1.5s ease-in-out infinite' }} />
      </div>

      <h1 style={{ fontSize: 28, fontWeight: 900, color: '#fff', marginBottom: 8 }}>Trustive AI</h1>
      <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.3)', marginBottom: 40, letterSpacing: 1 }}>{text}</p>

      <div style={{ width: 280, height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${progress}%`, background: 'linear-gradient(90deg, #ff6b35, #ff3b3b)', borderRadius: 2, transition: 'width 0.2s ease', boxShadow: '0 0 12px rgba(255,107,53,0.6)' }} />
      </div>
      <div style={{ marginTop: 12, fontSize: 12, color: 'rgba(255,255,255,0.2)', fontFamily: 'monospace' }}>{Math.floor(progress)}%</div>
    </div>
  )
}