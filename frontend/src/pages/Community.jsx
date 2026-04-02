import { useEffect, useState } from 'react'
import { Globe, Plus, CheckCircle, AlertTriangle, Shield, X, TrendingUp, Zap } from 'lucide-react'
import axios from 'axios'

const api = () => axios.create({
  baseURL: 'http://localhost:8000',
  headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
})

export default function Community() {
  const [feed, setFeed] = useState([])
  const [stats, setStats] = useState(null)
  const [form, setForm] = useState({ title: '', description: '', threat_type: 'phishing', severity: 'medium' })
  const [showForm, setShowForm] = useState(false)

  const load = () => {
    api().get('/api/community/feed').then(r => setFeed(r.data)).catch(() => {})
    api().get('/api/community/stats').then(r => setStats(r.data)).catch(() => {})
  }
  useEffect(() => { load() }, [])

  const submit = async (e) => {
    e.preventDefault()
    try {
      await api().post('/api/community/reports', form)
      setForm({ title: '', description: '', threat_type: 'phishing', severity: 'medium' })
      setShowForm(false)
      load()
    } catch (err) { alert(err.response?.data?.detail || 'Failed') }
  }

  const verify = async (id) => {
    try { await api().post(`/api/community/reports/${id}/verify`); load() }
    catch (err) { alert(err.response?.data?.detail || 'Cannot verify') }
  }

  const severityConfig = {
    high: { color: '#ff3b3b', bg: 'rgba(255,59,59,0.1)', border: 'rgba(255,59,59,0.2)', glow: '0 0 20px rgba(255,59,59,0.15)' },
    medium: { color: '#fbbf24', bg: 'rgba(251,191,36,0.1)', border: 'rgba(251,191,36,0.2)', glow: '0 0 20px rgba(251,191,36,0.1)' },
    low: { color: '#00e5a0', bg: 'rgba(0,229,160,0.1)', border: 'rgba(0,229,160,0.2)', glow: '0 0 20px rgba(0,229,160,0.1)' }
  }

  return (
    <div style={{ position: 'relative' }}>
      <div className="hero-bg" />
      <div className="grid-dots" style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0 }} />

      <div style={{ position: 'relative', zIndex: 1 }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 32 }} className="fade-in">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#3b82f6', animation: 'pulse 2s infinite' }} />
              <span style={{ fontSize: 12, color: '#3b82f6', fontWeight: 700, letterSpacing: 2, textTransform: 'uppercase' }}>Community Intelligence</span>
            </div>
            <h1 style={{ fontSize: 44, fontWeight: 900, color: '#fff', marginBottom: 8, lineHeight: 1.1 }}>
              Threat <span className="gradient-text">Feed</span>
            </h1>
            <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 15 }}>Shared threat intelligence from the security community</p>
          </div>
          <button onClick={() => setShowForm(!showForm)} className="btn btn-primary" style={{
            display: 'flex', alignItems: 'center', gap: 8, padding: '13px 22px',
            background: showForm ? 'rgba(255,255,255,0.06)' : 'linear-gradient(135deg, #ff6b35, #ff3b3b)',
            boxShadow: showForm ? 'none' : '0 8px 32px rgba(255,107,53,0.4)'
          }}>
            {showForm ? <X size={16} /> : <Plus size={16} />}
            {showForm ? 'Cancel' : 'Report Threat'}
          </button>
        </div>

        {/* Stats */}
        {stats && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 24 }}>
            {[
              { label: 'Total Reports', value: stats.total_reports, color: '#ff6b35', icon: <Globe size={22} /> },
              { label: 'Verified Threats', value: stats.verified_reports, color: '#00e5a0', icon: <CheckCircle size={22} /> },
              { label: 'Phishing Reports', value: stats.by_type?.phishing ?? 0, color: '#ff3b3b', icon: <AlertTriangle size={22} /> },
            ].map(({ label, value, color, icon }, i) => (
              <div key={label} style={{
                background: 'rgba(255,255,255,0.03)', border: `1px solid ${color}20`,
                borderRadius: 20, padding: '24px', position: 'relative', overflow: 'hidden',
                boxShadow: `0 0 30px ${color}10`, animation: `fadeInUp 0.4s ease ${i * 0.1}s both`
              }}>
                <div style={{ position: 'absolute', top: -30, right: -30, width: 100, height: 100, borderRadius: '50%', background: `${color}08` }} />
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                  <div style={{ color, background: `${color}15`, padding: 10, borderRadius: 12 }}>{icon}</div>
                </div>
                <div style={{ fontSize: 42, fontWeight: 900, color: '#fff', lineHeight: 1, marginBottom: 6 }}>{value}</div>
                <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.3)', fontWeight: 500 }}>{label}</div>
                <div style={{ marginTop: 14, height: 3, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                  <div style={{ height: '100%', width: `${Math.min(100, value * 5 + 10)}%`, background: `linear-gradient(90deg, ${color}88, ${color})`, borderRadius: 2 }} />
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Report Form */}
        {showForm && (
          <div style={{
            background: 'rgba(255,107,53,0.05)', border: '1px solid rgba(255,107,53,0.2)',
            borderRadius: 24, padding: '28px', marginBottom: 24,
            boxShadow: '0 0 40px rgba(255,107,53,0.1)', backdropFilter: 'blur(20px)'
          }} className="fade-in">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
              <Zap size={20} color="#ff6b35" />
              <h2 style={{ fontSize: 18, fontWeight: 800, color: '#fff' }}>Report New Threat</h2>
            </div>
            <form onSubmit={submit} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Title</label>
                <input className="input" value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} placeholder="Describe the threat briefly" required />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Threat Type</label>
                <select className="input" value={form.threat_type} onChange={e => setForm({ ...form, threat_type: e.target.value })}>
                  <option value="phishing">Phishing</option>
                  <option value="malware">Malware</option>
                  <option value="spam">Spam</option>
                  <option value="social_engineering">Social Engineering</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 10, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Severity</label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                  {['high', 'medium', 'low'].map(level => {
                    const cfg = severityConfig[level]
                    return (
                      <button key={level} type="button" onClick={() => setForm({ ...form, severity: level })} style={{
                        padding: '12px', borderRadius: 12, cursor: 'pointer', fontSize: 12, fontWeight: 700,
                        border: `1px solid ${form.severity === level ? cfg.color : 'rgba(255,255,255,0.06)'}`,
                        background: form.severity === level ? cfg.bg : 'rgba(255,255,255,0.03)',
                        color: form.severity === level ? cfg.color : 'rgba(255,255,255,0.25)',
                        textTransform: 'capitalize', transition: 'all 0.2s',
                        boxShadow: form.severity === level ? cfg.glow : 'none',
                        transform: form.severity === level ? 'translateY(-1px)' : 'none'
                      }}>
                        {level}
                      </button>
                    )
                  })}
                </div>
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Description</label>
                <textarea className="input" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Provide details about the threat..." rows={3} style={{ resize: 'vertical' }} />
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <button className="btn btn-primary" type="submit" style={{ padding: '14px 24px', borderRadius: 12, fontWeight: 800, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Shield size={16} /> Submit Report
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Feed */}
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 24, padding: '28px', backdropFilter: 'blur(20px)' }} className="fade-in-delay-2">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
            <Globe size={18} color="rgba(255,255,255,0.3)" />
            <h2 style={{ fontSize: 17, fontWeight: 800, color: '#fff' }}>Community Reports</h2>
            <div style={{ padding: '3px 10px', borderRadius: 20, background: 'rgba(255,107,53,0.1)', border: '1px solid rgba(255,107,53,0.2)', fontSize: 12, fontWeight: 700, color: '#ff6b35' }}>
              {feed.length}
            </div>
          </div>

          {feed.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '60px 0' }}>
              <div className="float" style={{ display: 'inline-block', marginBottom: 16 }}>
                <Globe size={52} style={{ color: 'rgba(255,255,255,0.05)' }} />
              </div>
              <p style={{ color: 'rgba(255,255,255,0.2)', fontWeight: 600, marginBottom: 4 }}>No reports yet</p>
              <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.12)' }}>Be the first to report a threat!</p>
            </div>
          ) : (
            feed.map((r, i) => {
              const cfg = severityConfig[r.severity] || severityConfig.medium
              return (
                <div key={r.id} style={{
                  padding: '18px', marginBottom: 10, borderRadius: 16,
                  background: 'rgba(255,255,255,0.02)',
                  border: `1px solid ${r.is_verified ? 'rgba(0,229,160,0.2)' : 'rgba(255,255,255,0.05)'}`,
                  transition: 'all 0.2s', animation: `fadeInUp 0.3s ease ${i * 0.07}s both`
                }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = r.is_verified ? 'rgba(0,229,160,0.3)' : 'rgba(255,107,53,0.15)'; e.currentTarget.style.background = 'rgba(255,255,255,0.03)' }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = r.is_verified ? 'rgba(0,229,160,0.2)' : 'rgba(255,255,255,0.05)'; e.currentTarget.style.background = 'rgba(255,255,255,0.02)' }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                        <div style={{ color: cfg.color, background: cfg.bg, padding: 7, borderRadius: 9, boxShadow: cfg.glow }}>
                          <AlertTriangle size={15} />
                        </div>
                        <span style={{ fontWeight: 800, fontSize: 15, color: '#fff' }}>{r.title}</span>
                        {r.is_verified && (
                          <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#00e5a0', background: 'rgba(0,229,160,0.1)', padding: '3px 10px', borderRadius: 20, border: '1px solid rgba(0,229,160,0.2)', fontWeight: 700 }}>
                            <CheckCircle size={10} /> Verified
                          </span>
                        )}
                      </div>
                      {r.description && (
                        <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.4)', marginBottom: 10, lineHeight: 1.6, paddingLeft: 40 }}>{r.description}</p>
                      )}
                      <div style={{ display: 'flex', gap: 8, paddingLeft: 40 }}>
                        <span style={{ fontSize: 11, padding: '4px 12px', borderRadius: 20, background: 'rgba(255,255,255,0.05)', color: 'rgba(255,255,255,0.35)', border: '1px solid rgba(255,255,255,0.07)', textTransform: 'capitalize', fontWeight: 600 }}>
                          {r.threat_type?.replace('_', ' ')}
                        </span>
                        <span style={{ fontSize: 11, fontWeight: 700, padding: '4px 12px', borderRadius: 20, background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}`, textTransform: 'uppercase', letterSpacing: 0.5, boxShadow: cfg.glow }}>
                          {r.severity}
                        </span>
                      </div>
                    </div>
                    {!r.is_verified && (
                      <button onClick={() => verify(r.id)} style={{
                        display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, padding: '9px 16px', marginLeft: 16,
                        background: 'rgba(0,229,160,0.08)', color: '#00e5a0',
                        border: '1px solid rgba(0,229,160,0.2)', borderRadius: 12, cursor: 'pointer', fontWeight: 700,
                        transition: 'all 0.2s'
                      }}
                        onMouseEnter={e => { e.currentTarget.style.background = 'rgba(0,229,160,0.15)'; e.currentTarget.style.boxShadow = '0 0 20px rgba(0,229,160,0.2)' }}
                        onMouseLeave={e => { e.currentTarget.style.background = 'rgba(0,229,160,0.08)'; e.currentTarget.style.boxShadow = 'none' }}
                      >
                        <CheckCircle size={13} /> Verify
                      </button>
                    )}
                  </div>
                </div>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}