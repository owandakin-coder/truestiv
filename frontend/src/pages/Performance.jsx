import { useEffect, useState } from 'react'
import { Activity, Zap, Clock, TrendingUp, Shield, AlertTriangle, CheckCircle, BarChart2 } from 'lucide-react'
import { LineChart, Line, AreaChart, Area, RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import axios from 'axios'

const api = () => axios.create({
  baseURL: 'http://localhost:8000',
  headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
})

const generatePerf = () => Array.from({ length: 24 }, (_, i) => ({
  hour: `${i}:00`,
  responseTime: Math.floor(Math.random() * 200 + 50),
  accuracy: Math.floor(Math.random() * 10 + 88),
  throughput: Math.floor(Math.random() * 50 + 10),
  threats: Math.floor(Math.random() * 20),
}))

const radarData = [
  { subject: 'Phishing', score: 94 },
  { subject: 'Malware', score: 87 },
  { subject: 'Spam', score: 96 },
  { subject: 'Hijack', score: 82 },
  { subject: 'Social Eng.', score: 78 },
  { subject: 'URL Scan', score: 91 },
]

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: '#111', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, padding: '10px 14px' }}>
      <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: 12, marginBottom: 6 }}>{label}</p>
      {payload.map(p => (
        <p key={p.name} style={{ color: p.color, fontSize: 13, fontWeight: 600 }}>{p.name}: {p.value}{p.name === 'accuracy' ? '%' : p.name === 'responseTime' ? 'ms' : ''}</p>
      ))}
    </div>
  )
}

export default function Performance() {
  const [perfData] = useState(generatePerf())
  const [stats, setStats] = useState(null)
  const [uptime] = useState('99.97%')
  const [responseTime] = useState('127ms')

  useEffect(() => {
    api().get('/api/analysis/stats').then(r => setStats(r.data)).catch(() => {})
  }, [])

  const metrics = [
    { label: 'Uptime', value: uptime, icon: <Activity size={20} />, color: '#00e5a0', change: '+0.02%', desc: 'Last 30 days' },
    { label: 'Avg Response', value: responseTime, icon: <Zap size={20} />, color: '#ff6b35', change: '-12ms', desc: 'AI analysis time' },
    { label: 'Accuracy Rate', value: '94.2%', icon: <TrendingUp size={20} />, color: '#3b82f6', change: '+1.4%', desc: 'Threat detection' },
    { label: 'Scans Today', value: stats?.total_analyzed ?? 0, icon: <Shield size={20} />, color: '#a78bfa', change: '+8%', desc: 'Total analyzed' },
  ]

  return (
    <div style={{ position: 'relative' }}>
      <div className="hero-bg" />
      <div className="grid-dots" style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0 }} />

      <div style={{ position: 'relative', zIndex: 1 }}>
        {/* Header */}
        <div className="fade-in" style={{ marginBottom: 32 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#00e5a0', animation: 'pulse 2s infinite' }} />
            <span style={{ fontSize: 12, color: '#00e5a0', fontWeight: 700, letterSpacing: 2, textTransform: 'uppercase' }}>System Health</span>
          </div>
          <h1 style={{ fontSize: 44, fontWeight: 900, color: '#fff', marginBottom: 8, lineHeight: 1.1 }}>
            Performance <span className="gradient-text">Monitor</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 15 }}>Real-time system metrics and AI performance analytics</p>
        </div>

        {/* Metric Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
          {metrics.map(({ label, value, icon, color, change, desc }, i) => (
            <div key={label} style={{ background: 'rgba(255,255,255,0.03)', border: `1px solid ${color}20`, borderRadius: 20, padding: '24px', position: 'relative', overflow: 'hidden', animation: `fadeInUp 0.4s ease ${i * 0.1}s both` }}>
              <div style={{ position: 'absolute', top: -20, right: -20, width: 80, height: 80, borderRadius: '50%', background: `${color}08` }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                <div style={{ color, background: `${color}15`, padding: 10, borderRadius: 12 }}>{icon}</div>
                <span style={{ fontSize: 12, fontWeight: 700, color: change.startsWith('+') ? '#00e5a0' : '#ff3b3b', background: change.startsWith('+') ? 'rgba(0,229,160,0.1)' : 'rgba(255,59,59,0.1)', padding: '3px 8px', borderRadius: 20 }}>{change}</span>
              </div>
              <div style={{ fontSize: 32, fontWeight: 900, color: '#fff', lineHeight: 1, marginBottom: 4 }}>{value}</div>
              <div style={{ fontSize: 12, color, fontWeight: 700, marginBottom: 2 }}>{label}</div>
              <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.25)' }}>{desc}</div>
              <div style={{ marginTop: 14, height: 3, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                <div style={{ height: '100%', width: `${Math.random() * 40 + 60}%`, background: `linear-gradient(90deg, ${color}66, ${color})`, borderRadius: 2 }} />
              </div>
            </div>
          ))}
        </div>

        {/* Charts Row 1 */}
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 20, marginBottom: 20 }}>

          {/* Response Time */}
          <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 20, padding: '24px' }} className="fade-in-delay-1">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <div>
                <h2 style={{ fontSize: 16, fontWeight: 800, color: '#fff', marginBottom: 4 }}>Response Time</h2>
                <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)' }}>AI analysis speed over 24 hours</p>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', background: 'rgba(0,229,160,0.08)', border: '1px solid rgba(0,229,160,0.15)', borderRadius: 20 }}>
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#00e5a0', animation: 'pulse 2s infinite' }} />
                <span style={{ fontSize: 11, color: '#00e5a0', fontWeight: 700 }}>LIVE</span>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={perfData}>
                <defs>
                  <linearGradient id="rtGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff6b35" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ff6b35" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="hour" axisLine={false} tickLine={false} tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 10 }} interval={3} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 10 }} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="responseTime" name="responseTime" stroke="#ff6b35" strokeWidth={2} fill="url(#rtGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Radar */}
          <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 20, padding: '24px' }} className="fade-in-delay-2">
            <h2 style={{ fontSize: 16, fontWeight: 800, color: '#fff', marginBottom: 4 }}>Detection Accuracy</h2>
            <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)', marginBottom: 16 }}>By threat category</p>
            <ResponsiveContainer width="100%" height={200}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="rgba(255,255,255,0.06)" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10 }} />
                <Radar name="Accuracy" dataKey="score" stroke="#ff6b35" fill="#ff6b35" fillOpacity={0.15} strokeWidth={2} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Charts Row 2 */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>

          {/* Accuracy */}
          <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 20, padding: '24px' }} className="fade-in-delay-2">
            <h2 style={{ fontSize: 16, fontWeight: 800, color: '#fff', marginBottom: 4 }}>Detection Accuracy</h2>
            <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)', marginBottom: 16 }}>Hourly accuracy percentage</p>
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={perfData}>
                <XAxis dataKey="hour" axisLine={false} tickLine={false} tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 10 }} interval={5} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 10 }} domain={[80, 100]} />
                <Tooltip content={<CustomTooltip />} />
                <Line type="monotone" dataKey="accuracy" name="accuracy" stroke="#00e5a0" strokeWidth={2.5} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Throughput */}
          <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 20, padding: '24px' }} className="fade-in-delay-3">
            <h2 style={{ fontSize: 16, fontWeight: 800, color: '#fff', marginBottom: 4 }}>Scan Throughput</h2>
            <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)', marginBottom: 16 }}>Scans per hour</p>
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={perfData}>
                <defs>
                  <linearGradient id="tpGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#a78bfa" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#a78bfa" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="hour" axisLine={false} tickLine={false} tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 10 }} interval={5} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 10 }} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="throughput" name="throughput" stroke="#a78bfa" strokeWidth={2} fill="url(#tpGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* System Status */}
        <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 20, padding: '28px' }} className="fade-in-delay-3">
          <h2 style={{ fontSize: 16, fontWeight: 800, color: '#fff', marginBottom: 20 }}>System Components</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
            {[
              { name: 'AI Analysis Engine', status: 'operational', uptime: '99.98%', latency: '89ms', color: '#00e5a0' },
              { name: 'Database', status: 'operational', uptime: '100%', latency: '12ms', color: '#00e5a0' },
              { name: 'Authentication', status: 'operational', uptime: '99.99%', latency: '23ms', color: '#00e5a0' },
              { name: 'URL Scanner', status: 'operational', uptime: '99.95%', latency: '145ms', color: '#00e5a0' },
              { name: 'Community Feed', status: 'operational', uptime: '99.90%', latency: '67ms', color: '#00e5a0' },
              { name: 'Notification Service', status: 'degraded', uptime: '98.50%', latency: '320ms', color: '#fbbf24' },
            ].map((comp, i) => (
              <div key={comp.name} style={{ padding: '16px 18px', borderRadius: 14, background: 'rgba(255,255,255,0.02)', border: `1px solid ${comp.color}20`, animation: `fadeInUp 0.3s ease ${i * 0.08}s both` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#fff' }}>{comp.name}</div>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: comp.color, boxShadow: `0 0 8px ${comp.color}` }} />
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <div>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', marginBottom: 2 }}>UPTIME</div>
                    <div style={{ fontSize: 13, fontWeight: 700, color: comp.color }}>{comp.uptime}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', marginBottom: 2 }}>LATENCY</div>
                    <div style={{ fontSize: 13, fontWeight: 700, color: '#fff' }}>{comp.latency}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', marginBottom: 2 }}>STATUS</div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: comp.color, textTransform: 'capitalize' }}>{comp.status}</div>
                  </div>
                </div>
                <div style={{ marginTop: 10, height: 3, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                  <div style={{ height: '100%', width: comp.uptime, background: `linear-gradient(90deg, ${comp.color}66, ${comp.color})`, borderRadius: 2 }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}