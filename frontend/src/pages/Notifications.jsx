import { useState, useEffect } from 'react'
import { Bell, AlertTriangle, CheckCircle, Shield, Globe, X, Filter, Check } from 'lucide-react'
import axios from 'axios'

const api = () => axios.create({
  baseURL: 'http://localhost:8000',
  headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
})

const mockNotifications = [
  { id: 1, type: 'threat', title: 'Phishing email detected', message: 'An email from security@paypa1.com was identified as phishing with 95% confidence.', time: '2 min ago', read: false, color: '#ff3b3b' },
  { id: 2, type: 'warning', title: 'Suspicious URL scanned', message: 'URL http://amazon-verify.xyz was flagged as suspicious.', time: '15 min ago', read: false, color: '#fbbf24' },
  { id: 3, type: 'community', title: 'New community threat report', message: 'A new phishing campaign targeting Israeli banks was reported.', time: '1 hour ago', read: true, color: '#3b82f6' },
  { id: 4, type: 'safe', title: 'Email analysis completed', message: 'Email from newsletter@github.com was verified as safe.', time: '2 hours ago', read: true, color: '#00e5a0' },
  { id: 5, type: 'threat', title: 'Malware attachment detected', message: 'File invoice_urgent.exe was blocked before download.', time: '3 hours ago', read: true, color: '#ff3b3b' },
  { id: 6, type: 'warning', title: 'Suspicious IP detected', message: 'Connection attempt from 185.220.101.42 was blocked.', time: '5 hours ago', read: true, color: '#fbbf24' },
  { id: 7, type: 'safe', title: 'Weekly security summary ready', message: 'Your weekly threat intelligence report is now available.', time: '1 day ago', read: true, color: '#00e5a0' },
  { id: 8, type: 'community', title: 'Threat verified by community', message: 'The phishing report you submitted was verified by 5 users.', time: '2 days ago', read: true, color: '#3b82f6' },
]

export default function Notifications() {
  const [notifications, setNotifications] = useState(mockNotifications)
  const [filter, setFilter] = useState('all')

  const unread = notifications.filter(n => !n.read).length

  const markRead = (id) => setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true } : n))
  const markAllRead = () => setNotifications(prev => prev.map(n => ({ ...n, read: true })))
  const remove = (id) => setNotifications(prev => prev.filter(n => n.id !== id))

  const filtered = notifications.filter(n => filter === 'all' ? true : filter === 'unread' ? !n.read : n.type === filter)

  const typeIcons = {
    threat: <AlertTriangle size={18} />,
    warning: <Shield size={18} />,
    community: <Globe size={18} />,
    safe: <CheckCircle size={18} />
  }

  const filters = [
    { id: 'all', label: 'All' },
    { id: 'unread', label: 'Unread' },
    { id: 'threat', label: 'Threats' },
    { id: 'warning', label: 'Warnings' },
    { id: 'community', label: 'Community' },
  ]

  return (
    <div style={{ position: 'relative' }}>
      <div className="hero-bg" />
      <div className="grid-dots" style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0 }} />

      <div style={{ position: 'relative', zIndex: 1 }}>
        {/* Header */}
        <div className="fade-in" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 32 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#fbbf24', animation: 'pulse 2s infinite' }} />
              <span style={{ fontSize: 12, color: '#fbbf24', fontWeight: 700, letterSpacing: 2, textTransform: 'uppercase' }}>Alert Center</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <h1 style={{ fontSize: 44, fontWeight: 900, color: '#fff', lineHeight: 1.1 }}>
                <span className="gradient-text">Notifications</span>
              </h1>
              {unread > 0 && (
                <div style={{ padding: '4px 14px', borderRadius: 20, background: 'rgba(255,107,53,0.15)', border: '1px solid rgba(255,107,53,0.3)', fontSize: 14, fontWeight: 800, color: 'var(--accent-cyan)', animation: 'pulse 2s infinite' }}>
                  {unread} new
                </div>
              )}
            </div>
            <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 15, marginTop: 8 }}>Stay up to date with your security alerts</p>
          </div>

          {unread > 0 && (
            <button onClick={markAllRead} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 20px', borderRadius: 12, background: 'rgba(0,229,160,0.08)', border: '1px solid rgba(0,229,160,0.2)', color: '#00e5a0', cursor: 'pointer', fontSize: 13, fontWeight: 700 }}>
              <Check size={15} /> Mark all read
            </button>
          )}
        </div>

        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
          {[
            { label: 'Total', value: notifications.length, color: 'var(--accent-cyan)' },
            { label: 'Unread', value: unread, color: '#fbbf24' },
            { label: 'Threats', value: notifications.filter(n => n.type === 'threat').length, color: '#ff3b3b' },
            { label: 'Resolved', value: notifications.filter(n => n.read).length, color: '#00e5a0' },
          ].map(({ label, value, color }, i) => (
            <div key={label} style={{ background: 'rgba(255,255,255,0.03)', border: `1px solid ${color}20`, borderRadius: 16, padding: '20px 24px', animation: `fadeInUp 0.4s ease ${i * 0.08}s both` }}>
              <div style={{ fontSize: 36, fontWeight: 900, color, lineHeight: 1, marginBottom: 6 }}>{value}</div>
              <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)', fontWeight: 500 }}>{label}</div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
          {filters.map(({ id, label }) => (
            <button key={id} onClick={() => setFilter(id)} style={{
              padding: '8px 16px', borderRadius: 10, border: 'none', cursor: 'pointer',
              fontSize: 13, fontWeight: 600, transition: 'all 0.2s',
              background: filter === id ? 'linear-gradient(135deg, rgba(255,107,53,0.2), rgba(255,59,59,0.1))' : 'rgba(255,255,255,0.04)',
              color: filter === id ? '#fff' : 'rgba(255,255,255,0.35)',
              border: filter === id ? '1px solid rgba(255,107,53,0.3)' : '1px solid rgba(255,255,255,0.06)'
            }}>
              {label}
            </button>
          ))}
        </div>

        {/* Notifications List */}
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 24, padding: '8px', backdropFilter: 'blur(20px)' }} className="fade-in-delay-1">
          {filtered.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '60px 0' }}>
              <div className="float" style={{ display: 'inline-block', marginBottom: 16 }}>
                <Bell size={52} style={{ color: 'rgba(255,255,255,0.05)' }} />
              </div>
              <p style={{ color: 'rgba(255,255,255,0.2)', fontWeight: 600 }}>No notifications</p>
            </div>
          ) : (
            filtered.map((n, i) => (
              <div key={n.id} onClick={() => markRead(n.id)} style={{
                display: 'flex', alignItems: 'flex-start', gap: 16, padding: '18px 20px',
                borderRadius: 16, marginBottom: 4, cursor: 'pointer',
                background: n.read ? 'transparent' : `${n.color}06`,
                border: `1px solid ${n.read ? 'transparent' : n.color + '15'}`,
                transition: 'all 0.2s', position: 'relative',
                animation: `fadeInUp 0.3s ease ${i * 0.05}s both`
              }}
                onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)' }}
                onMouseLeave={e => { e.currentTarget.style.background = n.read ? 'transparent' : `${n.color}06`; e.currentTarget.style.borderColor = n.read ? 'transparent' : n.color + '15' }}
              >
                {/* Unread dot */}
                {!n.read && (
                  <div style={{ position: 'absolute', top: 20, left: 8, width: 6, height: 6, borderRadius: '50%', background: n.color, boxShadow: `0 0 8px ${n.color}` }} />
                )}

                {/* Icon */}
                <div style={{ width: 44, height: 44, borderRadius: 12, background: `${n.color}15`, border: `1px solid ${n.color}25`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: n.color, flexShrink: 0 }}>
                  {typeIcons[n.type]}
                </div>

                {/* Content */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 4 }}>
                    <div style={{ fontSize: 14, fontWeight: n.read ? 600 : 800, color: '#fff' }}>{n.title}</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0, marginLeft: 12 }}>
                      <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.25)' }}>{n.time}</span>
                      <button onClick={(e) => { e.stopPropagation(); remove(n.id) }} style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.2)', cursor: 'pointer', padding: 2, display: 'flex', alignItems: 'center' }}>
                        <X size={13} />
                      </button>
                    </div>
                  </div>
                  <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.4)', lineHeight: 1.5 }}>{n.message}</p>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}