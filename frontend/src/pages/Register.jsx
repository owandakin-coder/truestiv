import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Zap, Mail, Lock, User, Shield } from 'lucide-react'
import axios from 'axios'

export default function Register() {
  const [form, setForm] = useState({ email: '', username: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [step, setStep] = useState(1)
  const [particles, setParticles] = useState([])
  const navigate = useNavigate()

  useEffect(() => {
    setParticles(Array.from({ length: 15 }, (_, i) => ({
      id: i, x: Math.random() * 100, y: Math.random() * 100,
      size: Math.random() * 3 + 1, duration: Math.random() * 4 + 3, delay: Math.random() * 2
    })))
  }, [])

  const submit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      await axios.post('http://localhost:8000/api/auth/register', form)
      navigate('/login')
    } catch (err) {
      setError(err.response?.data?.detail || 'Registration failed')
    } finally { setLoading(false) }
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#050507', position: 'relative', overflow: 'hidden' }}>

      {/* Particles */}
      {particles.map(p => (
        <div key={p.id} style={{
          position: 'absolute', left: `${p.x}%`, top: `${p.y}%`,
          width: p.size, height: p.size, borderRadius: '50%',
          background: 'rgba(255,107,53,0.3)',
          animation: `float ${p.duration}s ease-in-out ${p.delay}s infinite`,
          pointerEvents: 'none'
        }} />
      ))}

      <div style={{ position: 'absolute', top: '-30%', right: '-10%', width: '60%', height: '60%', background: 'radial-gradient(circle, rgba(255,107,53,0.07) 0%, transparent 70%)', pointerEvents: 'none' }} />
      <div className="grid-dots" style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }} />

      <div style={{ width: '100%', maxWidth: 460, padding: '20px', position: 'relative', zIndex: 1 }}>

        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 40 }} className="fade-in">
          <div style={{
            width: 60, height: 60, borderRadius: 20,
            background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            margin: '0 auto 16px', boxShadow: '0 0 40px rgba(255,107,53,0.5)',
            animation: 'glow-pulse 3s ease-in-out infinite'
          }}>
            <Zap size={30} color="#fff" fill="#fff" />
          </div>
          <h1 style={{ fontSize: 32, fontWeight: 900, color: '#fff', marginBottom: 6 }}>
            Join <span className="gradient-text">Trustive AI</span>
          </h1>
          <p style={{ fontSize: 14, color: 'rgba(255,255,255,0.3)' }}>Create your free security account</p>
        </div>

        {/* Progress Steps */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginBottom: 32 }}>
          {[1, 2, 3].map(s => (
            <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                width: s < step ? 28 : s === step ? 28 : 28,
                height: 28, borderRadius: '50%',
                background: s <= step ? 'linear-gradient(135deg, #ff6b35, #ff3b3b)' : 'rgba(255,255,255,0.06)',
                border: s === step ? '2px solid #ff6b35' : 'none',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 12, fontWeight: 700, color: s <= step ? '#fff' : 'rgba(255,255,255,0.2)',
                boxShadow: s === step ? '0 0 20px rgba(255,107,53,0.4)' : 'none',
                transition: 'all 0.3s'
              }}>{s}</div>
              {s < 3 && <div style={{ width: 40, height: 2, background: s < step ? 'linear-gradient(90deg, #ff6b35, #ff3b3b)' : 'rgba(255,255,255,0.06)', borderRadius: 1, transition: 'all 0.3s' }} />}
            </div>
          ))}
        </div>

        {/* Card */}
        <div style={{
          background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: 28, padding: '40px', backdropFilter: 'blur(20px)',
          boxShadow: '0 40px 80px rgba(0,0,0,0.4)'
        }} className="fade-in">

          <h2 style={{ fontSize: 22, fontWeight: 900, color: '#fff', marginBottom: 4 }}>
            {step === 1 ? 'Your email' : step === 2 ? 'Choose username' : 'Set password'}
          </h2>
          <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.3)', marginBottom: 28 }}>
            {step === 1 ? 'We\'ll use this to identify you' : step === 2 ? 'Pick a unique display name' : 'Make it strong and secure'}
          </p>

          {error && (
            <div style={{ background: 'rgba(255,59,59,0.08)', border: '1px solid rgba(255,59,59,0.2)', color: '#ff6b6b', padding: '12px 16px', borderRadius: 12, marginBottom: 20, fontSize: 13 }}>
              ⚠️ {error}
            </div>
          )}

          <form onSubmit={step < 3 ? (e) => { e.preventDefault(); setStep(s => s + 1) } : submit}
            style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

            {step === 1 && (
              <div className="fade-in">
                <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Email Address</label>
                <div style={{ position: 'relative' }}>
                  <Mail size={15} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'rgba(255,255,255,0.2)' }} />
                  <input className="input" type="email" value={form.email}
                    onChange={e => setForm({ ...form, email: e.target.value })}
                    style={{ paddingLeft: 42 }} placeholder="you@company.com" required />
                </div>
              </div>
            )}

            {step === 2 && (
              <div className="fade-in">
                <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Username</label>
                <div style={{ position: 'relative' }}>
                  <User size={15} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'rgba(255,255,255,0.2)' }} />
                  <input className="input" value={form.username}
                    onChange={e => setForm({ ...form, username: e.target.value })}
                    style={{ paddingLeft: 42 }} placeholder="yourname" required />
                </div>
              </div>
            )}

            {step === 3 && (
              <div className="fade-in">
                <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Password</label>
                <div style={{ position: 'relative' }}>
                  <Lock size={15} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'rgba(255,255,255,0.2)' }} />
                  <input className="input" type="password" value={form.password}
                    onChange={e => setForm({ ...form, password: e.target.value })}
                    style={{ paddingLeft: 42 }} placeholder="••••••••" required />
                </div>
                {/* Password strength */}
                {form.password && (
                  <div style={{ marginTop: 10 }}>
                    <div style={{ display: 'flex', gap: 4, marginBottom: 4 }}>
                      {[1, 2, 3, 4].map(i => (
                        <div key={i} style={{
                          flex: 1, height: 3, borderRadius: 2,
                          background: form.password.length >= i * 2
                            ? i <= 1 ? '#ff3b3b' : i <= 2 ? '#fbbf24' : i <= 3 ? '#ff6b35' : '#00e5a0'
                            : 'rgba(255,255,255,0.08)',
                          transition: 'background 0.3s'
                        }} />
                      ))}
                    </div>
                    <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)' }}>
                      {form.password.length < 4 ? 'Too weak' : form.password.length < 6 ? 'Weak' : form.password.length < 8 ? 'Good' : 'Strong'}
                    </span>
                  </div>
                )}
              </div>
            )}

            <button className="btn btn-primary" type="submit" disabled={loading} style={{
              marginTop: 12, padding: '15px', fontSize: 15, fontWeight: 800,
              borderRadius: 14, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8
            }}>
              {loading ? (
                <><div style={{ width: 18, height: 18, border: '2px solid rgba(255,255,255,0.3)', borderTop: '2px solid #fff', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} /> Creating...</>
              ) : step < 3 ? (
                <>Continue →</>
              ) : (
                <><Zap size={17} /> Create Account</>
              )}
            </button>

            {step > 1 && (
              <button type="button" onClick={() => setStep(s => s - 1)} className="btn btn-secondary" style={{ padding: '12px' }}>
                ← Back
              </button>
            )}
          </form>

          <p style={{ textAlign: 'center', marginTop: 24, fontSize: 13, color: 'rgba(255,255,255,0.3)' }}>
            Have account?{' '}
            <Link to="/login" style={{ color: '#ff6b35', fontWeight: 700, textDecoration: 'none' }}>Sign In →</Link>
          </p>
        </div>
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}