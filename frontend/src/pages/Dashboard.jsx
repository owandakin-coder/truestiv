import { useEffect, useState, useRef } from 'react'
import { Shield, AlertTriangle, CheckCircle, BarChart2, Zap, ArrowRight, TrendingUp, Activity } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import axios from 'axios'


const api = () => axios.create({
  baseURL: 'http://localhost:8000',
  headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
})

function AnimatedNumber({ value, duration = 1000 }) {
  const [display, setDisplay] = useState(0)
  useEffect(() => {
    let start = 0
    const step = value / (duration / 16)
    const timer = setInterval(() => {
      start += step
      if (start >= value) { setDisplay(value); clearInterval(timer) }
      else setDisplay(Math.floor(start))
    }, 16)
    return () => clearInterval(timer)
  }, [value, duration])
  return <span>{display}</span>
}

const areaData = [
  { day: 'Mon', threats: 4, safe: 28 },
  { day: 'Tue', threats: 8, safe: 45 },
  { day: 'Wed', threats: 12, safe: 38 },
  { day: 'Thu', threats: 6, safe: 52 },
  { day: 'Fri', threats: 18, safe: 41 },
  { day: 'Sat', threats: 9, safe: 34 },
  { day: 'Sun', threats: 14, safe: 48 },
]

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: '#111', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, padding: '10px 14px' }}>
      <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: 12, marginBottom: 6 }}>{label}</p>
      {payload.map(p => (
        <p key={p.name} style={{ color: p.color, fontSize: 13, fontWeight: 600 }}>{p.name}: {p.value}</p>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [history, setHistory] = useState([])
  const navigate = useNavigate()

  useEffect(() => {
    api().get('/api/analysis/stats').then(r => setStats(r.data)).catch(() => {})
    api().get('/api/analysis/history').then(r => setHistory(r.data.slice(0, 5))).catch(() => {})
  }, [])

  const threatRate = stats?.total_analyzed > 0
    ? Math.round((stats.threats_detected / stats.total_analyzed) * 100) : 0
  const circumference = 2 * Math.PI * 54

  const statCards = [
    { label: 'Total Analyzed', value: stats?.total_analyzed ?? 0, icon: <BarChart2 size={22} />, color: '#ff6b35', change: '+12%', delay: 'fade-in-delay-1' },
    { label: 'Threats Detected', value: stats?.threats_detected ?? 0, icon: <AlertTriangle size={22} />, color: '#ff3b3b', change: '+5%', delay: 'fade-in-delay-2' },
    { label: 'Hijack Attempts', value: stats?.hijack_attempts ?? 0, icon: <Shield size={22} />, color: '#fbbf24', change: '-3%', delay: 'fade-in-delay-3' },
    { label: 'Safe Messages', value: stats?.safe ?? 0, icon: <CheckCircle size={22} />, color: '#00e5a0', change: '+18%', delay: 'fade-in-delay-3' },
  ]

  return (
    <div style={{ position: 'relative' }}>
      <div className="hero-bg" />
      <div className="grid-dots" style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0 }} />

      <div style={{ position: 'relative', zIndex: 1 }}>

        {/* Header */}
        <div className="fade-in" style={{ marginBottom: 36 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#00e5a0', animation: 'pulse 2s infinite' }} />
            <span style={{ fontSize: 12, color: '#00e5a0', fontWeight: 600, letterSpacing: 2, textTransform: 'uppercase' }}>Live Monitoring</span>
          </div>
          <h1 style={{ fontSize: 48, fontWeight: 900, lineHeight: 1.05, marginBottom: 10 }}>
            Threat<br />
            <span className="gradient-text">Intelligence</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 15 }}>Real-time AI-powered security monitoring</p>
        </div>

        {/* Stat Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
          {statCards.map(({ label, value, icon, color, change, delay }) => (
            <div key={label} className={`card ${delay}`} style={{ cursor: 'default' }}>
              <div style={{ position: 'absolute', top: 0, right: 0, width: 120, height: 120, borderRadius: '0 20px 0 120px', background: `${color}08`, pointerEvents: 'none' }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
                <div style={{ color, background: `${color}15`, padding: 10, borderRadius: 12 }}>{icon}</div>
                <span style={{ fontSize: 12, fontWeight: 700, color: change.startsWith('+') ? '#00e5a0' : '#ff3b3b', background: change.startsWith('+') ? 'rgba(0,229,160,0.1)' : 'rgba(255,59,59,0.1)', padding: '3px 8px', borderRadius: 20 }}>{change}</span>
              </div>
              <div style={{ fontSize: 44, fontWeight: 900, color: '#fff', lineHeight: 1, marginBottom: 6 }} className="stat-number">
                <AnimatedNumber value={value} />
              </div>
              <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.35)', fontWeight: 500 }}>{label}</div>
              <div style={{ marginTop: 14, height: 3, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                <div style={{ height: '100%', width: `${Math.min(100, value * 10 + 20)}%`, background: `linear-gradient(90deg, ${color}, ${color}88)`, borderRadius: 2, transition: 'width 1s ease' }} />
              </div>
            </div>
          ))}
        </div>

        {/* Charts Row */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 20, marginBottom: 20 }}>

          {/* Area Chart */}
          <div className="card fade-in-delay-2">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
              <div>
                <h2 style={{ fontSize: 18, fontWeight: 800, color: '#fff', marginBottom: 4 }}>Weekly Overview</h2>
                <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.3)' }}>Threats vs safe messages</p>
              </div>
              <div style={{ display: 'flex', gap: 16 }}>
                {[{ label: 'Threats', color: '#ff6b35' }, { label: 'Safe', color: '#00e5a0' }].map(({ label, color }) => (
                  <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: color }} />
                    <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.4)', fontWeight: 500 }}>{label}</span>
                  </div>
                ))}
              </div>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={areaData}>
                <defs>
                  <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff6b35" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ff6b35" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="safeGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00e5a0" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00e5a0" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" axisLine={false} tickLine={false} tick={{ fill: 'rgba(255,255,255,0.25)', fontSize: 12 }} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: 'rgba(255,255,255,0.25)', fontSize: 12 }} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="threats" stroke="#ff6b35" strokeWidth={2.5} fill="url(#threatGrad)" />
                <Area type="monotone" dataKey="safe" stroke="#00e5a0" strokeWidth={2.5} fill="url(#safeGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Threat Rate */}
          <div className="card fade-in-delay-3" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <h2 style={{ fontSize: 16, fontWeight: 800, color: '#fff', marginBottom: 4, alignSelf: 'flex-start' }}>Threat Rate</h2>
            <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)', marginBottom: 24, alignSelf: 'flex-start' }}>Current period</p>

            <div style={{ position: 'relative', width: 160, height: 160, marginBottom: 24 }} className="float">
              <svg width="160" height="160" viewBox="0 0 160 160">
                <circle cx="80" cy="80" r="54" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="12" />
                <circle cx="80" cy="80" r="54" fill="none"
                  stroke={threatRate > 50 ? '#ff3b3b' : threatRate > 20 ? '#fbbf24' : '#00e5a0'}
                  strokeWidth="12" strokeLinecap="round"
                  strokeDasharray={circumference}
                  strokeDashoffset={circumference * (1 - threatRate / 100)}
                  transform="rotate(-90 80 80)"
                  style={{ transition: 'all 1.5s cubic-bezier(0.4, 0, 0.2, 1)', filter: 'drop-shadow(0 0 8px currentColor)' }}
                />
              </svg>
              <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', textAlign: 'center' }}>
                <div style={{ fontSize: 36, fontWeight: 900, color: '#fff' }}>{threatRate}%</div>
                <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>threats</div>
              </div>
            </div>

            {[
              { label: 'Threats', value: stats?.threats_detected ?? 0, color: '#ff3b3b' },
              { label: 'Safe', value: stats?.safe ?? 0, color: '#00e5a0' },
              { label: 'Quarantined', value: stats?.quarantined ?? 0, color: '#fbbf24' },
            ].map(({ label, value, color }) => (
              <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: color, boxShadow: `0 0 8px ${color}` }} />
                  <span style={{ fontSize: 13, color: 'rgba(255,255,255,0.4)' }}>{label}</span>
                </div>
                <span style={{ fontSize: 15, fontWeight: 800, color }}><AnimatedNumber value={value} /></span>
              </div>
            ))}
          </div>
        </div>

        {/* Bottom Row */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>

          {/* Recent */}
          <div className="card fade-in-delay-2">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h2 style={{ fontSize: 16, fontWeight: 800, color: '#fff' }}>Recent Threats</h2>
              <button onClick={() => navigate('/analysis')} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: '#ff6b35', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 700 }}>
                Analyze <ArrowRight size={13} />
              </button>
            </div>

            {history.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '40px 0' }}>
                <div className="float" style={{ display: 'inline-block', marginBottom: 16 }}>
                  <Shield size={48} style={{ color: 'rgba(255,255,255,0.06)' }} />
                </div>
                <p style={{ color: 'rgba(255,255,255,0.2)', marginBottom: 16 }}>No analysis yet</p>
                <button onClick={() => navigate('/analysis')} className="btn btn-primary" style={{ fontSize: 13 }}>
                  <Zap size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} /> Start Analyzing
                </button>
              </div>
            ) : (
              history.map((item, i) => {
                const color = item.threat_level === 'threat' ? '#ff3b3b' : item.threat_level === 'suspicious' ? '#fbbf24' : '#00e5a0'
                return (
                  <div key={item.id} style={{
                    display: 'flex', alignItems: 'center', gap: 12, padding: '12px 0',
                    borderBottom: i < history.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                    animation: `fadeInUp 0.3s ease ${i * 0.08}s both`
                  }}>
                    <div style={{ width: 38, height: 38, borderRadius: 10, background: `${color}12`, border: `1px solid ${color}25`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                      {item.threat_level === 'threat' ? <AlertTriangle size={16} color={color} /> : item.threat_level === 'suspicious' ? <Shield size={16} color={color} /> : <CheckCircle size={16} color={color} />}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: '#fff', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.subject || 'No subject'}</div>
                      <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.25)', marginTop: 2 }}>{item.sender}</div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <span className={`badge badge-${item.threat_level}`}>{item.threat_level}</span>
                      <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.2)', marginTop: 4 }}>{item.confidence}%</div>
                    </div>
                  </div>
                )
              })
            )}
          </div>

          {/* CTA */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="glow-card glow-pulse" style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <div style={{ fontSize: 13, color: '#ff6b35', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', marginBottom: 12 }}>⚡ Quick Scan</div>
              <h3 style={{ fontSize: 22, fontWeight: 900, color: '#fff', marginBottom: 8, lineHeight: 1.2 }}>Analyze a threat now</h3>
              <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.35)', marginBottom: 20, lineHeight: 1.6 }}>
                Email, SMS, or WhatsApp — our AI detects threats in seconds.
              </p>
              <button onClick={() => navigate('/analysis')} className="btn btn-primary" style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Zap size={16} /> Start Analysis
              </button>
            </div>

            <div className="card" style={{ background: 'rgba(0,229,160,0.04)', border: '1px solid rgba(0,229,160,0.15)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Activity size={18} color="#00e5a0" />
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: '#fff' }}>System Status</div>
                  <div style={{ fontSize: 12, color: '#00e5a0', marginTop: 2, fontWeight: 600 }}>● All systems operational</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}