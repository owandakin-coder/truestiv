import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Zap, Mail, Lock, Shield, Activity, Globe } from 'lucide-react'
import axios from 'axios'

export default function Login() {
  const [form, setForm] = useState({ email: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [particles, setParticles] = useState([])
  const navigate = useNavigate()

  useEffect(() => {
    setParticles(Array.from({ length: 20 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: Math.random() * 3 + 1,
      duration: Math.random() * 4 + 3,
      delay: Math.random() * 2
    })))
  }, [])

  const submit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await axios.post('http://localhost:8000/api/auth/login', form)
      localStorage.setItem('token', res.data.access_token)
      navigate('/')
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid credentials')
    } finally { setLoading(false) }
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', background: '#050507', position: 'relative', overflow: 'hidden' }}>

      {/* Animated particles */}
      {particles.map(p => (
        <div key={p.id} style={{
          position: 'absolute', left: `${p.x}%`, top: `${p.y}%`,
          width: p.size, height: p.size, borderRadius: '50%',
          background: 'rgba(255,107,53,0.4)',
          animation: `float ${p.duration}s ease-in-out ${p.delay}s infinite`,
          pointerEvents: 'none'
        }} />
      ))}

      {/* Gradient blobs */}
      <div style={{ position: 'absolute', top: '-20%', left: '-10%', width: '60%', height: '60%', background: 'radial-gradient(circle, rgba(255,107,53,0.08) 0%, transparent 70%)', pointerEvents: 'none' }} />
      <div style={{ position: 'absolute', bottom: '-20%', right: '-10%', width: '50%', height: '50%', background: 'radial-gradient(circle, rgba(59,130,246,0.06) 0%, transparent 70%)', pointerEvents: 'none' }} />
      <div className="grid-dots" style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }} />

      {/* Left Panel */}
      <div style={{
        flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center',
        padding: '60px 80px', position: 'relative', zIndex: 1
      }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 80 }}>
          <div style={{
            width: 48, height: 48, borderRadius: 16,
            background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 40px rgba(255,107,53,0.5)', animation: 'glow-pulse 3s ease-in-out infinite'
          }}>
            <Zap size={26} color="#fff" fill="#fff" />
          </div>
          <div>
            <div style={{ fontSize: 20, fontWeight: 900, color: '#fff' }}>Trustive AI</div>
            <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', letterSpacing: 2 }}>SECURITY PLATFORM</div>
          </div>
        </div>

        <div className="fade-in" style={{ maxWidth: 520 }}>
          <div style={{ fontSize: 12, color: '#ff6b35', fontWeight: 700, letterSpacing: 2, marginBottom: 16, textTransform: 'uppercase' }}>
            Enterprise Security
          </div>
          <h1 style={{ fontSize: 58, fontWeight: 900, lineHeight: 1.05, marginBottom: 20, color: '#fff' }}>
            Protect your<br />
            <span className="gradient-text">digital world.</span>
          </h1>
          <p style={{ fontSize: 16, color: 'rgba(255,255,255,0.35)', lineHeight: 1.8, marginBottom: 52, maxWidth: 420 }}>
            AI-powered threat detection for emails, SMS and WhatsApp. Real-time protection trusted by enterprise teams.
          </p>

          {/* Features */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {[
              { icon: <Shield size={18} />, text: 'AI-powered phishing detection', color: '#ff6b35' },
              { icon: <Zap size={18} />, text: 'Real-time threat analysis in seconds', color: '#fbbf24' },
              { icon: <Globe size={18} />, text: 'Multi-channel: Email, SMS, WhatsApp', color: '#00e5a0' },
              { icon: <Activity size={18} />, text: 'Community threat intelligence sharing', color: '#3b82f6' },
            ].map(({ icon, text, color }) => (
              <div key={text} style={{ display: 'flex', alignItems: 'center', gap: 14 }} className="fade-in">
                <div style={{ color, background: `${color}15`, padding: 10, borderRadius: 10, flexShrink: 0 }}>{icon}</div>
                <span style={{ fontSize: 14, color: 'rgba(255,255,255,0.5)', fontWeight: 500 }}>{text}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Stats bar */}
        <div style={{ display: 'flex', gap: 40, marginTop: 60 }}>
          {[
            { value: '99.9%', label: 'Accuracy' },
            { value: '<1s', label: 'Response time' },
            { value: '10M+', label: 'Threats blocked' },
          ].map(({ value, label }) => (
            <div key={label}>
              <div style={{ fontSize: 24, fontWeight: 900, color: '#fff', marginBottom: 2 }}>{value}</div>
              <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)', fontWeight: 500 }}>{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Right Panel */}
      <div style={{
        width: 520, display: 'flex', alignItems: 'center', justifyContent: 'center',
        padding: '40px 60px', position: 'relative', zIndex: 1
      }}>
        <div style={{
          width: '100%', background: 'rgba(255,255,255,0.03)',
          border: '1px solid rgba(255,255,255,0.08)', borderRadius: 28,
          padding: '44px', backdropFilter: 'blur(20px)',
          boxShadow: '0 40px 80px rgba(0,0,0,0.4)'
        }}>
          {/* Form header */}
          <div style={{ marginBottom: 32 }}>
            <h2 style={{ fontSize: 30, fontWeight: 900, color: '#fff', marginBottom: 6 }}>Welcome back 👋</h2>
            <p style={{ fontSize: 14, color: 'rgba(255,255,255,0.3)' }}>Sign in to your security dashboard</p>
          </div>

          {error && (
            <div style={{
              background: 'rgba(255,59,59,0.08)', border: '1px solid rgba(255,59,59,0.2)',
              color: '#ff6b6b', padding: '12px 16px', borderRadius: 12, marginBottom: 24,
              fontSize: 13, display: 'flex', alignItems: 'center', gap: 8
            }}>
              ⚠️ {error}
            </div>
          )}

          <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <div>
              <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Email Address</label>
              <div style={{ position: 'relative' }}>
                <Mail size={15} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'rgba(255,255,255,0.2)' }} />
                <input className="input" type="email" value={form.email}
                  onChange={e => setForm({ ...form, email: e.target.value })}
                  style={{ paddingLeft: 42 }} placeholder="you@company.com" required />
              </div>
            </div>

            <div>
              <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Password</label>
              <div style={{ position: 'relative' }}>
                <Lock size={15} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'rgba(255,255,255,0.2)' }} />
                <input className="input" type="password" value={form.password}
                  onChange={e => setForm({ ...form, password: e.target.value })}
                  style={{ paddingLeft: 42 }} placeholder="••••••••" required />
              </div>
            </div>

            <button className="btn btn-primary" type="submit" disabled={loading} style={{
              marginTop: 8, padding: '15px', fontSize: 16, fontWeight: 800,
              borderRadius: 14, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8
            }}>
              {loading ? (
                <>
                  <div style={{ width: 18, height: 18, border: '2px solid rgba(255,255,255,0.3)', borderTop: '2px solid #fff', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
                  Signing in...
                </>
              ) : (
                <><Zap size={18} /> Sign In</>
              )}
            </button>
          </form>

          <div style={{ margin: '24px 0', display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.06)' }} />
            <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.2)' }}>or</span>
            <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.06)' }} />
          </div>

          <p style={{ textAlign: 'center', fontSize: 14, color: 'rgba(255,255,255,0.3)' }}>
            No account?{' '}
            <Link to="/register" style={{ color: '#ff6b35', fontWeight: 700, textDecoration: 'none' }}>
              Create one free →
            </Link>
          </p>
        </div>
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}