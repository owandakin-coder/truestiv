import { useState, useEffect } from 'react'
import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom'
import { BarChart2, Shield, Map, Users, Globe, LogOut, Zap, Bell, Search, Activity, ScanLine, Settings, Moon, Sun } from 'lucide-react'
import { useTheme } from './ThemeProvider'
import SearchModal from './SearchModal'
import KeyboardShortcuts from './KeyboardShortcuts'

export default function Layout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { theme, toggleTheme } = useTheme()
  const logout = () => { localStorage.removeItem('token'); navigate('/login') }
  const [searchOpen, setSearchOpen] = useState(false)

  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setSearchOpen(true)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  const navItems = [
    { to: '/', icon: <BarChart2 size={19} />, label: 'Dashboard' },
    { to: '/analysis', icon: <Shield size={19} />, label: 'Analysis' },
    { to: '/scanner', icon: <ScanLine size={19} />, label: 'Scanner' },
    { to: '/propagation', icon: <Map size={19} />, label: 'Threat Map' },
    { to: '/performance', icon: <Activity size={19} />, label: 'Performance' },
    { to: '/contacts', icon: <Users size={19} />, label: 'Contacts' },
    { to: '/community', icon: <Globe size={19} />, label: 'Community' },
    { to: '/notifications', icon: <Bell size={19} />, label: 'Notifications' },
    { to: '/settings', icon: <Settings size={19} />, label: 'Settings' },
  ]

  const pageTitle = navItems.find(n => n.to === location.pathname)?.label || 'Dashboard'
  const isLight = theme === 'light'

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: isLight ? '#f8fafc' : '#050507' }}>
      <div className="hero-bg" />

      {/* Sidebar */}
      <aside style={{
        width: 240,
        background: isLight ? 'rgba(255,255,255,0.95)' : 'rgba(10,10,12,0.95)',
        borderRight: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.05)'}`,
        display: 'flex', flexDirection: 'column',
        position: 'fixed', top: 0, left: 0, bottom: 0, zIndex: 100,
        backdropFilter: 'blur(20px)',
        boxShadow: isLight ? '4px 0 20px rgba(0,0,0,0.06)' : 'none'
      }}>

        {/* Logo */}
        <div style={{ padding: '28px 24px 24px', borderBottom: `1px solid ${isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.04)'}` }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              width: 42, height: 42, borderRadius: 14,
              background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 30px rgba(255,107,53,0.5)',
              animation: 'glow-pulse 3s ease-in-out infinite'
            }}>
              <Zap size={22} color="#fff" fill="#fff" />
            </div>
            <div>
              <div style={{ fontSize: 16, fontWeight: 900, color: isLight ? '#0f172a' : '#fff', letterSpacing: 0.3 }}>Trustive AI</div>
              <div style={{ fontSize: 10, color: isLight ? '#94a3b8' : 'rgba(255,255,255,0.25)', marginTop: 1, letterSpacing: 0.5 }}>SECURITY PLATFORM</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '20px 14px', overflowY: 'auto' }}>
          {navItems.map(({ to, icon, label }) => (
            <NavLink key={to} to={to} end={to === '/'} style={({ isActive }) => ({
              display: 'flex', alignItems: 'center', gap: 12,
              padding: '11px 14px', borderRadius: 12, marginBottom: 4,
              color: isActive ? '#fff' : isLight ? '#64748b' : 'rgba(255,255,255,0.3)',
              background: isActive ? 'linear-gradient(135deg, rgba(255,107,53,0.25), rgba(255,59,59,0.15))' : 'transparent',
              textDecoration: 'none', fontSize: 14, fontWeight: isActive ? 700 : 500,
              transition: 'all 0.2s',
              border: isActive ? '1px solid rgba(255,107,53,0.2)' : '1px solid transparent',
              boxShadow: isActive ? '0 4px 20px rgba(255,107,53,0.15)' : 'none'
            })}>
              {({ isActive }) => (
                <>
                  {isActive && <div style={{ position: 'absolute', left: 0, width: 3, height: '60%', background: 'linear-gradient(#ff6b35, #ff3b3b)', borderRadius: '0 2px 2px 0' }} />}
                  <span style={{ color: isActive ? '#ff6b35' : isLight ? '#94a3b8' : 'rgba(255,255,255,0.3)' }}>{icon}</span>
                  {label}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Bottom */}
        <div style={{ padding: '16px 14px', borderTop: `1px solid ${isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.04)'}` }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 14px', borderRadius: 12, marginBottom: 10, background: 'rgba(0,229,160,0.06)', border: '1px solid rgba(0,229,160,0.12)' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#00e5a0', boxShadow: '0 0 8px #00e5a0', animation: 'pulse 2s infinite' }} />
            <span style={{ fontSize: 12, color: '#00e5a0', fontWeight: 600 }}>System Online</span>
          </div>
          <button onClick={logout} style={{
            width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
            padding: '10px', borderRadius: 12,
            background: isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.03)',
            border: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.06)'}`,
            color: isLight ? '#64748b' : 'rgba(255,255,255,0.3)',
            cursor: 'pointer', fontSize: 13, fontWeight: 600, transition: 'all 0.2s'
          }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,59,59,0.08)'; e.currentTarget.style.color = '#ff3b3b' }}
            onMouseLeave={e => { e.currentTarget.style.background = isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.03)'; e.currentTarget.style.color = isLight ? '#64748b' : 'rgba(255,255,255,0.3)' }}
          >
            <LogOut size={15} /> Sign Out
          </button>
        </div>
      </aside>

      {/* Main */}
      <div style={{ flex: 1, marginLeft: 240, display: 'flex', flexDirection: 'column', minHeight: '100vh', position: 'relative', zIndex: 1 }}>

        {/* TopBar */}
        <header style={{
          height: 68,
          background: isLight ? 'rgba(248,250,252,0.9)' : 'rgba(5,5,7,0.8)',
          borderBottom: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.05)'}`,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0 32px', position: 'sticky', top: 0, zIndex: 50,
          backdropFilter: 'blur(20px)',
          boxShadow: isLight ? '0 2px 12px rgba(0,0,0,0.06)' : 'none'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <h2 style={{ fontSize: 18, fontWeight: 800, color: isLight ? '#0f172a' : '#fff' }}>{pageTitle}</h2>
            <div style={{ width: 1, height: 20, background: isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.1)' }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: isLight ? '#64748b' : 'rgba(255,255,255,0.3)' }}>
              <Activity size={13} color="#00e5a0" />
              <span style={{ color: '#00e5a0', fontWeight: 600 }}>Live</span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {/* Search - Clickable bar that opens modal */}
            <div onClick={() => setSearchOpen(true)} style={{
              display: 'flex', alignItems: 'center', gap: 8,
              background: isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.04)',
              border: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.06)'}`,
              borderRadius: 12, padding: '8px 14px', width: 220, cursor: 'pointer',
              transition: 'all 0.2s'
            }}
              onMouseEnter={e => e.currentTarget.style.borderColor = 'rgba(255,107,53,0.3)'}
              onMouseLeave={e => e.currentTarget.style.borderColor = isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.06)'}
            >
              <Search size={14} color={isLight ? '#94a3b8' : 'rgba(255,255,255,0.2)'} />
              <span style={{ fontSize: 13, color: isLight ? '#94a3b8' : 'rgba(255,255,255,0.25)', flex: 1 }}>Search...</span>
              <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.2)', background: 'rgba(255,255,255,0.06)', padding: '2px 6px', borderRadius: 6, fontFamily: 'monospace' }}>⌘K</span>
            </div>

            {/* Theme Toggle */}
            <button onClick={toggleTheme} style={{
              width: 40, height: 40, borderRadius: 12,
              background: isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.04)',
              border: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.06)'}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              cursor: 'pointer', transition: 'all 0.2s',
              color: isLight ? '#64748b' : 'rgba(255,255,255,0.4)'
            }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(255,107,53,0.3)'; e.currentTarget.style.color = '#ff6b35' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.06)'; e.currentTarget.style.color = isLight ? '#64748b' : 'rgba(255,255,255,0.4)' }}
            >
              {isLight ? <Moon size={16} /> : <Sun size={16} />}
            </button>

            {/* Bell */}
            <button onClick={() => navigate('/notifications')} style={{
              width: 40, height: 40, borderRadius: 12,
              background: isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.04)',
              border: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.06)'}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              cursor: 'pointer', position: 'relative', transition: 'all 0.2s'
            }}>
              <Bell size={16} color={isLight ? '#64748b' : 'rgba(255,255,255,0.4)'} />
              <div style={{ position: 'absolute', top: 8, right: 8, width: 7, height: 7, borderRadius: '50%', background: '#ff6b35', boxShadow: '0 0 8px #ff6b35' }} />
            </button>

            {/* User */}
            <div onClick={() => navigate('/settings')} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 14px 6px 6px', background: isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.04)', border: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.06)'}`, borderRadius: 12, cursor: 'pointer' }}>
              <div style={{ width: 32, height: 32, borderRadius: 10, background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 13, fontWeight: 900, color: '#fff', boxShadow: '0 0 16px rgba(255,107,53,0.4)' }}>T</div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: isLight ? '#0f172a' : '#fff', lineHeight: 1.2 }}>Admin</div>
                <div style={{ fontSize: 10, color: isLight ? '#94a3b8' : 'rgba(255,255,255,0.3)' }}>Security Team</div>
              </div>
            </div>
          </div>
        </header>

        {/* Page */}
        <main style={{ flex: 1, padding: '36px', overflowY: 'auto' }}>
          <Outlet />
        </main>
      </div>

      {/* Search Modal */}
      <SearchModal open={searchOpen} onClose={() => setSearchOpen(false)} />

      {/* Keyboard Shortcuts */}
      <KeyboardShortcuts onToggleTheme={toggleTheme} />
    </div>
  )
}