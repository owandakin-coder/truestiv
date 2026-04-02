import { useEffect, useState } from 'react'
import { UserPlus, Trash2, Users, Search, Shield } from 'lucide-react'
import axios from 'axios'

const api = () => axios.create({
  baseURL: 'http://localhost:8000',
  headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
})

export default function Contacts() {
  const [contacts, setContacts] = useState([])
  const [form, setForm] = useState({ email: '', name: '', trust_level: 'medium' })
  const [loading, setLoading] = useState(false)
  const [search, setSearch] = useState('')

  const load = () => api().get('/api/trust/contacts').then(r => setContacts(r.data)).catch(() => {})
  useEffect(() => { load() }, [])

  const add = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      await api().post('/api/trust/contacts', form)
      setForm({ email: '', name: '', trust_level: 'medium' })
      load()
    } catch (err) { alert(err.response?.data?.detail || 'Failed') }
    finally { setLoading(false) }
  }

  const remove = async (id) => {
    if (!confirm('Delete?')) return
    await api().delete(`/api/trust/contacts/${id}`)
    load()
  }

  const trustConfig = {
    high: { color: '#00e5a0', bg: 'rgba(0,229,160,0.1)', border: 'rgba(0,229,160,0.2)', glow: '0 0 20px rgba(0,229,160,0.15)' },
    medium: { color: '#fbbf24', bg: 'rgba(251,191,36,0.1)', border: 'rgba(251,191,36,0.2)', glow: '0 0 20px rgba(251,191,36,0.1)' },
    low: { color: '#ff3b3b', bg: 'rgba(255,59,59,0.1)', border: 'rgba(255,59,59,0.2)', glow: '0 0 20px rgba(255,59,59,0.1)' }
  }

  const filtered = contacts.filter(c =>
    c.email.toLowerCase().includes(search.toLowerCase()) ||
    (c.name || '').toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div style={{ position: 'relative' }}>
      <div className="hero-bg" />
      <div className="grid-dots" style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0 }} />

      <div style={{ position: 'relative', zIndex: 1 }}>
        {/* Header */}
        <div className="fade-in" style={{ marginBottom: 32 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#00e5a0', animation: 'pulse 2s infinite' }} />
            <span style={{ fontSize: 12, color: '#00e5a0', fontWeight: 700, letterSpacing: 2, textTransform: 'uppercase' }}>Trust Management</span>
          </div>
          <h1 style={{ fontSize: 44, fontWeight: 900, color: '#fff', marginBottom: 8, lineHeight: 1.1 }}>
            Trusted <span className="gradient-text">Contacts</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 15 }}>Manage email trust levels for smarter threat filtering</p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 24 }}>

          {/* Add Form */}
          <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 24, padding: '28px', backdropFilter: 'blur(20px)', height: 'fit-content', boxShadow: '0 20px 60px rgba(0,0,0,0.3)' }} className="fade-in">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
              <div style={{ color: '#ff6b35', background: 'rgba(255,107,53,0.1)', padding: 8, borderRadius: 10 }}>
                <UserPlus size={18} />
              </div>
              <h2 style={{ fontSize: 17, fontWeight: 800, color: '#fff' }}>Add Contact</h2>
            </div>

            <form onSubmit={add} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
              <div>
                <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Email</label>
                <input className="input" type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} placeholder="contact@company.com" required />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Name</label>
                <input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Full name" />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 12, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Trust Level</label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                  {['high', 'medium', 'low'].map(level => {
                    const cfg = trustConfig[level]
                    return (
                      <button key={level} type="button" onClick={() => setForm({ ...form, trust_level: level })} style={{
                        padding: '12px 8px', borderRadius: 12, cursor: 'pointer', fontSize: 12, fontWeight: 700,
                        border: `1px solid ${form.trust_level === level ? cfg.color : 'rgba(255,255,255,0.06)'}`,
                        background: form.trust_level === level ? cfg.bg : 'rgba(255,255,255,0.03)',
                        color: form.trust_level === level ? cfg.color : 'rgba(255,255,255,0.25)',
                        textTransform: 'capitalize', transition: 'all 0.2s',
                        boxShadow: form.trust_level === level ? cfg.glow : 'none',
                        transform: form.trust_level === level ? 'translateY(-1px)' : 'none'
                      }}>
                        {level}
                      </button>
                    )
                  })}
                </div>
              </div>
              <button className="btn btn-primary" type="submit" disabled={loading} style={{ padding: '14px', borderRadius: 14, fontWeight: 800, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginTop: 4 }}>
                <UserPlus size={16} /> {loading ? 'Adding...' : 'Add Contact'}
              </button>
            </form>
          </div>

          {/* Contacts List */}
          <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 24, padding: '28px', backdropFilter: 'blur(20px)' }} className="fade-in-delay-1">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Users size={18} color="rgba(255,255,255,0.3)" />
                <h2 style={{ fontSize: 17, fontWeight: 800, color: '#fff' }}>Contacts</h2>
                <div style={{ padding: '3px 10px', borderRadius: 20, background: 'rgba(255,107,53,0.1)', border: '1px solid rgba(255,107,53,0.2)', fontSize: 12, fontWeight: 700, color: '#ff6b35' }}>
                  {contacts.length}
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12, padding: '8px 14px' }}>
                <Search size={14} color="rgba(255,255,255,0.2)" />
                <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search..." style={{ background: 'none', border: 'none', outline: 'none', color: '#fff', fontSize: 13, width: 160, fontFamily: 'Inter, sans-serif' }} />
              </div>
            </div>

            {filtered.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '60px 0' }}>
                <div className="float" style={{ display: 'inline-block', marginBottom: 16 }}>
                  <Users size={52} style={{ color: 'rgba(255,255,255,0.05)' }} />
                </div>
                <p style={{ color: 'rgba(255,255,255,0.2)', fontWeight: 600, marginBottom: 4 }}>
                  {contacts.length === 0 ? 'No contacts yet' : 'No results found'}
                </p>
                <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.12)' }}>
                  {contacts.length === 0 ? 'Add trusted contacts to improve filtering' : 'Try a different search term'}
                </p>
              </div>
            ) : (
              filtered.map((c, i) => {
                const cfg = trustConfig[c.trust_level] || trustConfig.medium
                return (
                  <div key={c.id} style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '14px 16px', marginBottom: 8, borderRadius: 14,
                    background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)',
                    transition: 'all 0.2s', cursor: 'default',
                    animation: `fadeInUp 0.3s ease ${i * 0.06}s both`
                  }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(255,107,53,0.15)'; e.currentTarget.style.background = 'rgba(255,107,53,0.04)' }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.05)'; e.currentTarget.style.background = 'rgba(255,255,255,0.02)' }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                      <div style={{
                        width: 44, height: 44, borderRadius: 14,
                        background: `linear-gradient(135deg, ${cfg.color}20, ${cfg.color}08)`,
                        border: `1px solid ${cfg.border}`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: 18, fontWeight: 900, color: cfg.color,
                        boxShadow: cfg.glow
                      }}>
                        {(c.name || c.email)[0].toUpperCase()}
                      </div>
                      <div>
                        <div style={{ fontWeight: 700, fontSize: 14, color: '#fff', marginBottom: 2 }}>{c.name || c.email}</div>
                        <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.25)' }}>{c.email}</div>
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontSize: 11, fontWeight: 700, padding: '5px 14px', borderRadius: 20, background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}`, textTransform: 'uppercase', letterSpacing: 0.5, boxShadow: cfg.glow }}>
                        {c.trust_level}
                      </span>
                      <button onClick={() => remove(c.id)} style={{ width: 36, height: 36, borderRadius: 10, border: '1px solid rgba(255,59,59,0.15)', background: 'rgba(255,59,59,0.06)', color: '#ff3b3b', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', transition: 'all 0.2s' }}
                        onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,59,59,0.15)'; e.currentTarget.style.borderColor = 'rgba(255,59,59,0.3)' }}
                        onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,59,59,0.06)'; e.currentTarget.style.borderColor = 'rgba(255,59,59,0.15)' }}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                )
              })
            )}
          </div>
        </div>
      </div>
    </div>
  )
}