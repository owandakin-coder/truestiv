import { useState, useEffect, useRef } from 'react'
import { Search, Shield, ScanLine, Users, Globe, BarChart2, Map, Bell, Settings, ArrowRight, X, Activity } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

const pages = [
  { label: 'Dashboard', path: '/', icon: <BarChart2 size={16} />, desc: 'Security overview and stats', color: '#ff6b35' },
  { label: 'Analysis', path: '/analysis', icon: <Shield size={16} />, desc: 'Analyze emails and messages', color: '#ff3b3b' },
  { label: 'Scanner', path: '/scanner', icon: <ScanLine size={16} />, desc: 'URL, IP and file scanning', color: '#a78bfa' },
  { label: 'Threat Map', path: '/propagation', icon: <Map size={16} />, desc: 'Threat propagation visualization', color: '#3b82f6' },
  { label: 'Contacts', path: '/contacts', icon: <Users size={16} />, desc: 'Manage trusted contacts', color: '#00e5a0' },
  { label: 'Community', path: '/community', icon: <Globe size={16} />, desc: 'Community threat feed', color: '#fbbf24' },
  { label: 'Notifications', path: '/notifications', icon: <Bell size={16} />, desc: 'Alert center', color: '#ff6b35' },
  { label: 'Settings', path: '/settings', icon: <Settings size={16} />, desc: 'Account and preferences', color: '#64748b' },
  { label: 'Performance', path: '/performance', icon: <Activity size={16} />, desc: 'System metrics and AI performance', color: '#00e5a0' },
]

export default function SearchModal({ open, onClose }) {
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const inputRef = useRef()
  const navigate = useNavigate()

  useEffect(() => {
    if (open) { setQuery(''); setSelected(0); setTimeout(() => inputRef.current?.focus(), 100) }
  }, [open])

  useEffect(() => {
    const handler = (e) => {
      if (e.key === 'Escape') onClose()
      if (e.key === 'ArrowDown') setSelected(s => Math.min(s + 1, filtered.length - 1))
      if (e.key === 'ArrowUp') setSelected(s => Math.max(s - 1, 0))
      if (e.key === 'Enter') { go(filtered[selected]?.path); }
    }
    if (open) window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, selected, query])

  const filtered = pages.filter(p =>
    p.label.toLowerCase().includes(query.toLowerCase()) ||
    p.desc.toLowerCase().includes(query.toLowerCase())
  )

  const go = (path) => { if (path) { navigate(path); onClose() } }

  if (!open) return null

  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 9998, background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'flex-start', justifyContent: 'center', padding: '80px 20px' }}>
      <div onClick={e => e.stopPropagation()} style={{ width: '100%', maxWidth: 560, background: 'rgba(10,10,12,0.98)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 20, overflow: 'hidden', boxShadow: '0 40px 80px rgba(0,0,0,0.6)', animation: 'fadeInUp 0.2s ease' }}>

        {/* Input */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '16px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <Search size={18} color="rgba(255,255,255,0.3)" />
          <input ref={inputRef} value={query} onChange={e => { setQuery(e.target.value); setSelected(0) }}
            placeholder="Search pages, features..." style={{ flex: 1, background: 'none', border: 'none', outline: 'none', color: '#fff', fontSize: 16, fontFamily: 'Inter, sans-serif' }} />
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.3)', cursor: 'pointer' }}>
            <X size={16} />
          </button>
        </div>

        {/* Results */}
        <div style={{ padding: '8px', maxHeight: 400, overflowY: 'auto' }}>
          {filtered.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '32px 0', color: 'rgba(255,255,255,0.2)', fontSize: 14 }}>No results found</div>
          ) : (
            filtered.map((page, i) => (
              <div key={page.path} onClick={() => go(page.path)}
                onMouseEnter={() => setSelected(i)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 14, padding: '12px 14px', borderRadius: 12, cursor: 'pointer',
                  background: selected === i ? `${page.color}12` : 'transparent',
                  border: `1px solid ${selected === i ? page.color + '25' : 'transparent'}`,
                  transition: 'all 0.15s', marginBottom: 4
                }}>
                <div style={{ width: 38, height: 38, borderRadius: 10, background: `${page.color}15`, border: `1px solid ${page.color}25`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: page.color, flexShrink: 0 }}>
                  {page.icon}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 14, fontWeight: 700, color: '#fff', marginBottom: 2 }}>{page.label}</div>
                  <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)' }}>{page.desc}</div>
                </div>
                {selected === i && <ArrowRight size={14} color={page.color} />}
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: '10px 20px', borderTop: '1px solid rgba(255,255,255,0.04)', display: 'flex', gap: 16 }}>
          {[['↑↓', 'Navigate'], ['↵', 'Select'], ['Esc', 'Close']].map(([key, label]) => (
            <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'rgba(255,255,255,0.25)' }}>
              <span style={{ padding: '2px 6px', borderRadius: 6, background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.08)', fontFamily: 'monospace', fontSize: 10 }}>{key}</span>
              {label}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}