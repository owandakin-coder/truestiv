import { useNavigate } from 'react-router-dom'
import { Zap, ArrowLeft, Shield } from 'lucide-react'
import { useEffect, useState } from 'react'

export default function NotFound() {
  const navigate = useNavigate()
  const [particles, setParticles] = useState([])

  useEffect(() => {
    setParticles(Array.from({ length: 15 }, (_, i) => ({
      id: i, x: Math.random() * 100, y: Math.random() * 100,
      size: Math.random() * 3 + 1, duration: Math.random() * 4 + 3, delay: Math.random() * 2
    })))
  }, [])

  return (
    <div style={{ minHeight: '100vh', background: '#050507', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', overflow: 'hidden' }}>
      {particles.map(p => (
        <div key={p.id} style={{ position: 'absolute', left: `${p.x}%`, top: `${p.y}%`, width: p.size, height: p.size, borderRadius: '50%', background: 'rgba(255,107,53,0.3)', animation: `float ${p.duration}s ease-in-out ${p.delay}s infinite`, pointerEvents: 'none' }} />
      ))}

      <div className="grid-dots" style={{ position: 'fixed', inset: 0, pointerEvents: 'none' }} />
      <div style={{ position: 'absolute', top: '20%', left: '30%', width: '40%', height: '40%', background: 'radial-gradient(circle, rgba(255,107,53,0.06) 0%, transparent 70%)', pointerEvents: 'none' }} />

      <div style={{ textAlign: 'center', position: 'relative', zIndex: 1, padding: 40 }} className="fade-in">
        <div className="float" style={{ marginBottom: 32 }}>
          <div style={{ fontSize: 120, fontWeight: 900, lineHeight: 1, background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
            404
          </div>
        </div>

        <div style={{ width: 80, height: 80, borderRadius: 24, background: 'rgba(255,107,53,0.1)', border: '1px solid rgba(255,107,53,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 24px', boxShadow: '0 0 40px rgba(255,107,53,0.15)' }}>
          <Shield size={36} color="#ff6b35" />
        </div>

        <h1 style={{ fontSize: 32, fontWeight: 900, color: '#fff', marginBottom: 12 }}>Page Not Found</h1>
        <p style={{ fontSize: 16, color: 'rgba(255,255,255,0.4)', marginBottom: 40, maxWidth: 400, margin: '0 auto 40px', lineHeight: 1.6 }}>
          The page you are looking for does not exist or has been moved.
        </p>

        <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
          <button onClick={() => navigate(-1)} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 24px', borderRadius: 12, background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', color: 'rgba(255,255,255,0.7)', cursor: 'pointer', fontSize: 14, fontWeight: 700, transition: 'all 0.2s' }}
            onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.1)'}
            onMouseLeave={e => e.currentTarget.style.background = 'rgba(255,255,255,0.06)'}
          >
            <ArrowLeft size={16} /> Go Back
          </button>
          <button onClick={() => navigate('/')} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 24px', borderRadius: 12, background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)', border: 'none', color: '#fff', cursor: 'pointer', fontSize: 14, fontWeight: 700, boxShadow: '0 4px 20px rgba(255,107,53,0.35)', transition: 'all 0.2s' }}
            onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-1px)'; e.currentTarget.style.boxShadow = '0 8px 28px rgba(255,107,53,0.5)' }}
            onMouseLeave={e => { e.currentTarget.style.transform = 'none'; e.currentTarget.style.boxShadow = '0 4px 20px rgba(255,107,53,0.35)' }}
          >
            <Zap size={16} /> Dashboard
          </button>
        </div>
      </div>
    </div>
  )
}