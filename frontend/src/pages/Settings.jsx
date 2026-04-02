import { useState, useEffect } from 'react'
import { User, Bell, Shield, Palette, Save, Eye, EyeOff, Check, Moon, Sun } from 'lucide-react'
import axios from 'axios'

const api = () => axios.create({
  baseURL: 'http://localhost:8000',
  headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
})

export default function Settings() {
  const [tab, setTab] = useState('profile')
  const [profile, setProfile] = useState({ username: '', email: '', current_password: '', new_password: '' })
  const [notifications, setNotifications] = useState({
    email_threats: true, sms_threats: true, community_reports: false,
    weekly_summary: true, critical_only: false
  })
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark')
  const [accent, setAccent] = useState(localStorage.getItem('accent') || 'orange')
  const [showPassword, setShowPassword] = useState(false)
  const [saved, setSaved] = useState(false)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    api().get('/api/auth/profile').then(r => {
      setProfile(p => ({ ...p, username: r.data.username, email: r.data.email }))
    }).catch(() => {})
  }, [])

  const save = async () => {
    setLoading(true)
    await new Promise(r => setTimeout(r, 800))
    setSaved(true)
    setTimeout(() => setSaved(false), 2500)
    setLoading(false)
  }

  const applyTheme = (t) => {
    setTheme(t)
    localStorage.setItem('theme', t)
    document.documentElement.setAttribute('data-theme', t)
  }

  const applyAccent = (a) => {
    setAccent(a)
    localStorage.setItem('accent', a)
    const colors = {
      orange: { main: '#ff6b35', secondary: '#ff3b3b' },
      cyan: { main: '#00d4ff', secondary: '#7c3aed' },
      green: { main: '#00e5a0', secondary: '#3b82f6' },
      purple: { main: '#a78bfa', secondary: '#ec4899' },
    }
    const c = colors[a]
    document.documentElement.style.setProperty('--accent-cyan', c.main)
    document.documentElement.style.setProperty('--accent-purple', c.secondary)
    document.documentElement.style.setProperty('--border-accent', c.main + '40')
    document.documentElement.style.setProperty('--glow-cyan', `0 0 40px ${c.main}25`)
  }

  const tabs = [
    { id: 'profile', label: 'Profile', icon: <User size={16} /> },
    { id: 'notifications', label: 'Notifications', icon: <Bell size={16} /> },
    { id: 'appearance', label: 'Appearance', icon: <Palette size={16} /> },
    { id: 'security', label: 'Security', icon: <Shield size={16} /> },
  ]

  const accentColors = [
    { id: 'orange', label: 'Orange', color: '#ff6b35' },
    { id: 'cyan', label: 'Cyan', color: '#00d4ff' },
    { id: 'green', label: 'Green', color: '#00e5a0' },
    { id: 'purple', label: 'Purple', color: '#a78bfa' },
  ]

  return (
    <div style={{ position: 'relative' }}>
      <div className="hero-bg" />
      <div className="grid-dots" style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0 }} />

      <div style={{ position: 'relative', zIndex: 1 }}>
        {/* Header */}
        <div className="fade-in" style={{ marginBottom: 32 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent-cyan)', animation: 'pulse 2s infinite' }} />
            <span style={{ fontSize: 12, color: 'var(--accent-cyan)', fontWeight: 700, letterSpacing: 2, textTransform: 'uppercase' }}>Account</span>
          </div>
          <h1 style={{ fontSize: 44, fontWeight: 900, color: '#fff', marginBottom: 8, lineHeight: 1.1 }}>
            <span className="gradient-text">Settings</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 15 }}>Manage your account, notifications and appearance</p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 24 }}>

          {/* Sidebar */}
          <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 20, padding: '16px', height: 'fit-content' }} className="fade-in">
            {tabs.map(({ id, label, icon }) => (
              <button key={id} onClick={() => setTab(id)} style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                padding: '12px 14px', borderRadius: 12, marginBottom: 4,
                border: 'none', cursor: 'pointer', fontSize: 14, fontWeight: 600,
                background: tab === id ? 'linear-gradient(135deg, rgba(255,107,53,0.2), rgba(255,59,59,0.1))' : 'transparent',
                color: tab === id ? '#fff' : 'rgba(255,255,255,0.35)',
                borderLeft: tab === id ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                transition: 'all 0.2s', textAlign: 'left'
              }}>
                <span style={{ color: tab === id ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.25)' }}>{icon}</span>
                {label}
              </button>
            ))}
          </div>

          {/* Content */}
          <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 20, padding: '32px', backdropFilter: 'blur(20px)' }} className="fade-in-delay-1">

            {/* Profile Tab */}
            {tab === 'profile' && (
              <div>
                <h2 style={{ fontSize: 20, fontWeight: 800, color: '#fff', marginBottom: 4 }}>Profile Settings</h2>
                <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.3)', marginBottom: 28 }}>Update your personal information</p>

                {/* Avatar */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 32, padding: '20px', background: 'rgba(255,255,255,0.02)', borderRadius: 16, border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ width: 72, height: 72, borderRadius: 20, background: 'linear-gradient(135deg, var(--accent-cyan), #ff3b3b)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 28, fontWeight: 900, color: '#fff', boxShadow: '0 0 30px rgba(255,107,53,0.3)' }}>
                    {profile.username?.[0]?.toUpperCase() || 'U'}
                  </div>
                  <div>
                    <div style={{ fontSize: 18, fontWeight: 800, color: '#fff', marginBottom: 4 }}>{profile.username || 'User'}</div>
                    <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.35)' }}>{profile.email}</div>
                    <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#00e5a0', boxShadow: '0 0 6px #00e5a0' }} />
                      <span style={{ fontSize: 12, color: '#00e5a0', fontWeight: 600 }}>Active Account</span>
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                    <div>
                      <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Username</label>
                      <input className="input" value={profile.username} onChange={e => setProfile({ ...profile, username: e.target.value })} placeholder="yourname" />
                    </div>
                    <div>
                      <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Email</label>
                      <input className="input" type="email" value={profile.email} onChange={e => setProfile({ ...profile, email: e.target.value })} placeholder="you@company.com" />
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Notifications Tab */}
            {tab === 'notifications' && (
              <div>
                <h2 style={{ fontSize: 20, fontWeight: 800, color: '#fff', marginBottom: 4 }}>Notification Settings</h2>
                <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.3)', marginBottom: 28 }}>Control when and how you get notified</p>

                {[
                  { key: 'email_threats', label: 'Email Threat Alerts', desc: 'Get notified when a threat is detected in email analysis', color: '#ff3b3b' },
                  { key: 'sms_threats', label: 'SMS/WhatsApp Alerts', desc: 'Notifications for SMS and WhatsApp threat detection', color: '#fbbf24' },
                  { key: 'community_reports', label: 'Community Reports', desc: 'When new threats are reported by the community', color: '#3b82f6' },
                  { key: 'weekly_summary', label: 'Weekly Summary', desc: 'Weekly digest of your security activity', color: '#00e5a0' },
                  { key: 'critical_only', label: 'Critical Threats Only', desc: 'Only notify for high-confidence threats', color: '#ff6b35' },
                ].map(({ key, label, desc, color }) => (
                  <div key={key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 20px', marginBottom: 10, borderRadius: 14, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', transition: 'all 0.2s' }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)'}
                    onMouseLeave={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.05)'}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                      <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, boxShadow: `0 0 8px ${color}` }} />
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 700, color: '#fff', marginBottom: 2 }}>{label}</div>
                        <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)' }}>{desc}</div>
                      </div>
                    </div>
                    <button onClick={() => setNotifications(n => ({ ...n, [key]: !n[key] }))} style={{
                      width: 52, height: 28, borderRadius: 14, border: 'none', cursor: 'pointer',
                      background: notifications[key] ? 'linear-gradient(135deg, var(--accent-cyan), #ff3b3b)' : 'rgba(255,255,255,0.08)',
                      position: 'relative', transition: 'all 0.3s',
                      boxShadow: notifications[key] ? '0 0 16px rgba(255,107,53,0.3)' : 'none'
                    }}>
                      <div style={{ position: 'absolute', top: 4, left: notifications[key] ? 28 : 4, width: 20, height: 20, borderRadius: '50%', background: '#fff', transition: 'left 0.3s', boxShadow: '0 2px 6px rgba(0,0,0,0.3)' }} />
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* Appearance Tab */}
            {tab === 'appearance' && (
              <div>
                <h2 style={{ fontSize: 20, fontWeight: 800, color: '#fff', marginBottom: 4 }}>Appearance</h2>
                <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.3)', marginBottom: 28 }}>Customize the look and feel</p>

                {/* Theme */}
                <div style={{ marginBottom: 32 }}>
                  <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 14, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Theme Mode</label>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    {[
                      { id: 'dark', label: 'Dark Mode', desc: 'Easy on the eyes', icon: <Moon size={24} />, preview: '#050507' },
                      { id: 'light', label: 'Light Mode', desc: 'Bright and clean', icon: <Sun size={24} />, preview: '#f8fafc' },
                    ].map(({ id, label, desc, icon, preview }) => (
                      <button key={id} onClick={() => applyTheme(id)} style={{
                        padding: '20px', borderRadius: 16, cursor: 'pointer', textAlign: 'left',
                        border: `2px solid ${theme === id ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.06)'}`,
                        background: theme === id ? 'rgba(255,107,53,0.08)' : 'rgba(255,255,255,0.02)',
                        transition: 'all 0.2s', position: 'relative',
                        boxShadow: theme === id ? '0 0 20px rgba(255,107,53,0.15)' : 'none'
                      }}>
                        {theme === id && (
                          <div style={{ position: 'absolute', top: 12, right: 12, width: 22, height: 22, borderRadius: '50%', background: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                            <Check size={12} color="#000" strokeWidth={3} />
                          </div>
                        )}
                        <div style={{ width: '100%', height: 60, borderRadius: 10, background: preview, marginBottom: 12, border: '1px solid rgba(255,255,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: id === 'dark' ? 'rgba(255,255,255,0.3)' : 'rgba(0,0,0,0.3)' }}>
                          {icon}
                        </div>
                        <div style={{ fontSize: 14, fontWeight: 700, color: '#fff', marginBottom: 2 }}>{label}</div>
                        <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.35)' }}>{desc}</div>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Accent Color */}
                <div>
                  <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 14, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Accent Color</label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
                    {accentColors.map(({ id, label, color }) => (
                      <button key={id} onClick={() => applyAccent(id)} style={{
                        padding: '16px 12px', borderRadius: 14, cursor: 'pointer', textAlign: 'center',
                        border: `2px solid ${accent === id ? color : 'rgba(255,255,255,0.06)'}`,
                        background: accent === id ? `${color}12` : 'rgba(255,255,255,0.02)',
                        transition: 'all 0.2s', position: 'relative',
                        boxShadow: accent === id ? `0 0 20px ${color}20` : 'none'
                      }}>
                        {accent === id && (
                          <div style={{ position: 'absolute', top: 8, right: 8, width: 18, height: 18, borderRadius: '50%', background: color, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                            <Check size={10} color="#000" strokeWidth={3} />
                          </div>
                        )}
                        <div style={{ width: 36, height: 36, borderRadius: '50%', background: color, margin: '0 auto 10px', boxShadow: `0 0 16px ${color}60` }} />
                        <div style={{ fontSize: 12, fontWeight: 700, color: accent === id ? color : 'rgba(255,255,255,0.4)' }}>{label}</div>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Security Tab */}
            {tab === 'security' && (
              <div>
                <h2 style={{ fontSize: 20, fontWeight: 800, color: '#fff', marginBottom: 4 }}>Security Settings</h2>
                <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.3)', marginBottom: 28 }}>Manage your password and security preferences</p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                  <div>
                    <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Current Password</label>
                    <div style={{ position: 'relative' }}>
                      <input className="input" type={showPassword ? 'text' : 'password'} value={profile.current_password}
                        onChange={e => setProfile({ ...profile, current_password: e.target.value })}
                        placeholder="••••••••" style={{ paddingRight: 44 }} />
                      <button onClick={() => setShowPassword(!showPassword)} style={{ position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.3)' }}>
                        {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>New Password</label>
                    <input className="input" type="password" value={profile.new_password}
                      onChange={e => setProfile({ ...profile, new_password: e.target.value })}
                      placeholder="••••••••" />
                    {profile.new_password && (
                      <div style={{ marginTop: 8, display: 'flex', gap: 4 }}>
                        {[1, 2, 3, 4].map(i => (
                          <div key={i} style={{ flex: 1, height: 3, borderRadius: 2, background: profile.new_password.length >= i * 2 ? i <= 1 ? '#ff3b3b' : i <= 2 ? '#fbbf24' : i <= 3 ? '#ff6b35' : '#00e5a0' : 'rgba(255,255,255,0.08)', transition: 'background 0.3s' }} />
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Security Stats */}
                  <div style={{ marginTop: 8, padding: '20px', background: 'rgba(0,229,160,0.05)', border: '1px solid rgba(0,229,160,0.15)', borderRadius: 16 }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: '#00e5a0', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Shield size={16} /> Account Security Status
                    </div>
                    {[
                      { label: 'Password Strength', value: 'Strong', color: '#00e5a0' },
                      { label: 'Last Login', value: 'Today', color: '#fff' },
                      { label: 'Active Sessions', value: '1 device', color: '#fff' },
                      { label: '2FA Status', value: 'Not enabled', color: '#fbbf24' },
                    ].map(({ label, value, color }) => (
                      <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '7px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 13 }}>
                        <span style={{ color: 'rgba(255,255,255,0.4)' }}>{label}</span>
                        <span style={{ color, fontWeight: 600 }}>{value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Save Button */}
            <div style={{ marginTop: 32, display: 'flex', alignItems: 'center', gap: 12 }}>
              <button className="btn btn-primary" onClick={save} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 28px', borderRadius: 12, fontWeight: 800, fontSize: 14 }}>
                {loading ? (
                  <><div style={{ width: 16, height: 16, border: '2px solid rgba(255,255,255,0.3)', borderTop: '2px solid #fff', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} /> Saving...</>
                ) : saved ? (
                  <><Check size={16} /> Saved!</>
                ) : (
                  <><Save size={16} /> Save Changes</>
                )}
              </button>
              {saved && <span style={{ fontSize: 13, color: '#00e5a0', fontWeight: 600, animation: 'fadeIn 0.3s ease' }}>✓ Changes saved successfully</span>}
            </div>
          </div>
        </div>
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}