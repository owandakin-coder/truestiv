import { useEffect, useState } from 'react'
import { Map, AlertTriangle, Shield, Globe, Zap, TrendingUp } from 'lucide-react'
import axios from 'axios'

const api = () => axios.create({
  baseURL: 'http://localhost:8000',
  headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
})

export default function PropagationMap() {
  const [mapData, setMapData] = useState(null)
  const [clusters, setClusters] = useState([])
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      api().get('/api/analysis/propagation-map').catch(() => ({ data: { nodes: [], edges: [] } })),
      api().get('/api/analysis/threat-clusters').catch(() => ({ data: [] }))
    ]).then(([mapRes, clustersRes]) => {
      setMapData(mapRes.data)
      setClusters(Array.isArray(clustersRes.data) ? clustersRes.data : [])
      setLoading(false)
    })
  }, [])

  const typeConfig = {
    phishing: { color: '#ff3b3b', icon: <AlertTriangle size={14} /> },
    malware: { color: '#ff6b35', icon: <Shield size={14} /> },
    spam: { color: '#fbbf24', icon: <Globe size={14} /> },
    social_engineering: { color: '#a78bfa', icon: <TrendingUp size={14} /> },
    safe: { color: '#00e5a0', icon: <Shield size={14} /> },
    default: { color: '#3b82f6', icon: <Zap size={14} /> }
  }

  const nodes = mapData?.nodes || []
  const edges = mapData?.edges || []

  const getNodePos = (index, total) => {
    if (total === 0) return { x: 400, y: 300 }
    if (total === 1) return { x: 400, y: 300 }
    const angle = (index / total) * 2 * Math.PI - Math.PI / 2
    const radius = Math.min(220, 60 + total * 20)
    return {
      x: 400 + radius * Math.cos(angle),
      y: 300 + radius * Math.sin(angle)
    }
  }

  return (
    <div style={{ position: 'relative' }}>
      <div className="hero-bg" />
      <div className="grid-dots" style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0 }} />

      <div style={{ position: 'relative', zIndex: 1 }}>
        {/* Header */}
        <div className="fade-in" style={{ marginBottom: 32 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#a78bfa', animation: 'pulse 2s infinite' }} />
            <span style={{ fontSize: 12, color: '#a78bfa', fontWeight: 700, letterSpacing: 2, textTransform: 'uppercase' }}>Threat Propagation</span>
          </div>
          <h1 style={{ fontSize: 44, fontWeight: 900, color: '#fff', marginBottom: 8, lineHeight: 1.1 }}>
            Threat <span style={{ background: 'linear-gradient(135deg, #a78bfa, #3b82f6)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Map</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 15 }}>Visual threat propagation and cluster analysis</p>
        </div>

        {/* Stats Row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
          {[
            { label: 'Total Nodes', value: nodes.length, color: '#a78bfa' },
            { label: 'Connections', value: edges.length, color: '#3b82f6' },
            { label: 'Clusters', value: clusters.length, color: '#ff6b35' },
            { label: 'Threat Nodes', value: nodes.filter(n => n.threat_level === 'threat').length, color: '#ff3b3b' },
          ].map(({ label, value, color }, i) => (
            <div key={label} style={{
              background: 'rgba(255,255,255,0.03)', border: `1px solid ${color}20`,
              borderRadius: 18, padding: '20px 24px',
              boxShadow: `0 0 24px ${color}08`,
              animation: `fadeInUp 0.4s ease ${i * 0.1}s both`
            }}>
              <div style={{ fontSize: 36, fontWeight: 900, color, lineHeight: 1, marginBottom: 6 }}>{value}</div>
              <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)', fontWeight: 500 }}>{label}</div>
            </div>
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 20 }}>

          {/* Map Canvas */}
          <div style={{
            background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
            borderRadius: 24, overflow: 'hidden', position: 'relative', minHeight: 520
          }} className="fade-in">

            {/* Map header */}
            <div style={{ padding: '20px 24px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: 10 }}>
              <Map size={18} color="#a78bfa" />
              <span style={{ fontSize: 15, fontWeight: 800, color: '#fff' }}>Propagation Graph</span>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 12 }}>
                {Object.entries(typeConfig).slice(0, 4).map(([type, { color }]) => (
                  <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}` }} />
                    <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', textTransform: 'capitalize' }}>{type}</span>
                  </div>
                ))}
              </div>
            </div>

            {loading ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 440 }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ width: 40, height: 40, border: '3px solid rgba(167,139,250,0.2)', borderTop: '3px solid #a78bfa', borderRadius: '50%', animation: 'spin 1s linear infinite', margin: '0 auto 16px' }} />
                  <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 14 }}>Loading threat map...</p>
                </div>
              </div>
            ) : nodes.length === 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 440 }}>
                <div className="float" style={{ marginBottom: 20 }}>
                  <div style={{ width: 80, height: 80, borderRadius: '50%', background: 'rgba(167,139,250,0.1)', border: '2px solid rgba(167,139,250,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 30px rgba(167,139,250,0.15)' }}>
                    <Map size={36} color="#a78bfa" />
                  </div>
                </div>
                <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 15, fontWeight: 600, marginBottom: 8 }}>No threat data yet</p>
                <p style={{ color: 'rgba(255,255,255,0.15)', fontSize: 13 }}>Analyze some emails to see the propagation map</p>
              </div>
            ) : (
              <svg width="100%" height="460" viewBox="0 0 800 460" style={{ display: 'block' }}>
                <defs>
                  {Object.entries(typeConfig).map(([type, { color }]) => (
                    <radialGradient key={type} id={`grad-${type}`} cx="50%" cy="50%" r="50%">
                      <stop offset="0%" stopColor={color} stopOpacity="0.3" />
                      <stop offset="100%" stopColor={color} stopOpacity="0.05" />
                    </radialGradient>
                  ))}
                  <filter id="glow">
                    <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                    <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
                  </filter>
                </defs>

                {/* Grid lines */}
                {[...Array(8)].map((_, i) => (
                  <line key={`h${i}`} x1="0" y1={i * 60} x2="800" y2={i * 60} stroke="rgba(255,255,255,0.03)" strokeWidth="1" />
                ))}
                {[...Array(14)].map((_, i) => (
                  <line key={`v${i}`} x1={i * 60} y1="0" x2={i * 60} y2="460" stroke="rgba(255,255,255,0.03)" strokeWidth="1" />
                ))}

                {/* Edges */}
                {edges.map((edge, i) => {
                  const fromIdx = nodes.findIndex(n => n.id === edge.from)
                  const toIdx = nodes.findIndex(n => n.id === edge.to)
                  if (fromIdx === -1 || toIdx === -1) return null
                  const from = getNodePos(fromIdx, nodes.length)
                  const to = getNodePos(toIdx, nodes.length)
                  return (
                    <line key={i}
                      x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                      stroke="rgba(167,139,250,0.2)" strokeWidth="1.5"
                      strokeDasharray="4 4"
                    />
                  )
                })}

                {/* Nodes */}
                {nodes.map((node, i) => {
                  const pos = getNodePos(i, nodes.length)
                  const cfg = typeConfig[node.threat_type] || typeConfig.default
                  const isSelected = selected?.id === node.id
                  const radius = isSelected ? 22 : 16

                  return (
                    <g key={node.id} onClick={() => setSelected(isSelected ? null : node)} style={{ cursor: 'pointer' }}>
                      <circle cx={pos.x} cy={pos.y} r={radius + 12} fill={`url(#grad-${node.threat_type || 'default'})`} />
                      <circle cx={pos.x} cy={pos.y} r={radius}
                        fill={`${cfg.color}20`}
                        stroke={cfg.color}
                        strokeWidth={isSelected ? 2.5 : 1.5}
                        filter={isSelected ? 'url(#glow)' : ''}
                        style={{ transition: 'all 0.2s' }}
                      />
                      <text x={pos.x} y={pos.y + 4} textAnchor="middle" fontSize="10" fill={cfg.color} fontWeight="700">
                        {(node.threat_type || 'unknown').charAt(0).toUpperCase()}
                      </text>
                      {nodes.length <= 12 && (
                        <text x={pos.x} y={pos.y + radius + 14} textAnchor="middle" fontSize="10" fill="rgba(255,255,255,0.4)">
                          {node.sender?.split('@')[1]?.slice(0, 10) || 'unknown'}
                        </text>
                      )}
                    </g>
                  )
                })}
              </svg>
            )}
          </div>

          {/* Right Panel */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

            {/* Selected Node */}
            {selected && (
              <div style={{
                background: 'rgba(167,139,250,0.06)', border: '1px solid rgba(167,139,250,0.2)',
                borderRadius: 20, padding: '20px', boxShadow: '0 0 30px rgba(167,139,250,0.1)'
              }} className="fade-in">
                <div style={{ fontSize: 12, color: '#a78bfa', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', marginBottom: 14 }}>Selected Node</div>
                {[
                  { label: 'Sender', value: selected.sender },
                  { label: 'Threat Type', value: selected.threat_type },
                  { label: 'Threat Level', value: selected.threat_level },
                  { label: 'Confidence', value: `${selected.confidence}%` },
                ].map(({ label, value }) => (
                  <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 13 }}>
                    <span style={{ color: 'rgba(255,255,255,0.3)' }}>{label}</span>
                    <span style={{ color: '#fff', fontWeight: 600 }}>{value || 'N/A'}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Clusters */}
            <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 20, padding: '20px', flex: 1 }} className="fade-in-delay-1">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <Zap size={16} color="#ff6b35" />
                <span style={{ fontSize: 15, fontWeight: 800, color: '#fff' }}>Threat Clusters</span>
              </div>

              {clusters.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '30px 0' }}>
                  <p style={{ color: 'rgba(255,255,255,0.2)', fontSize: 13 }}>No clusters detected</p>
                </div>
              ) : (
                clusters.map((cluster, i) => {
                  const cfg = typeConfig[cluster.threat_type] || typeConfig.default
                  return (
                    <div key={i} style={{
                      padding: '14px', marginBottom: 8, borderRadius: 12,
                      background: `${cfg.color}08`, border: `1px solid ${cfg.color}20`,
                      animation: `fadeInUp 0.3s ease ${i * 0.08}s both`
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div style={{ color: cfg.color }}>{cfg.icon}</div>
                          <span style={{ fontSize: 13, fontWeight: 700, color: '#fff', textTransform: 'capitalize' }}>
                            {cluster.threat_type}
                          </span>
                        </div>
                        <span style={{ fontSize: 12, fontWeight: 700, color: cfg.color, background: `${cfg.color}15`, padding: '3px 10px', borderRadius: 20 }}>
                          {cluster.count} threats
                        </span>
                      </div>
                      <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                        <div style={{ height: '100%', width: `${Math.min(100, (cluster.count / Math.max(...clusters.map(c => c.count))) * 100)}%`, background: `linear-gradient(90deg, ${cfg.color}88, ${cfg.color})`, borderRadius: 2, boxShadow: `0 0 8px ${cfg.color}50` }} />
                      </div>
                    </div>
                  )
                })
              )}
            </div>

            {/* Legend */}
            <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 20, padding: '20px' }}>
              <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', marginBottom: 14 }}>Legend</div>
              {Object.entries(typeConfig).slice(0, 5).map(([type, { color, icon }]) => (
                <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 0' }}>
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, boxShadow: `0 0 8px ${color}`, flexShrink: 0 }} />
                  <span style={{ fontSize: 13, color: 'rgba(255,255,255,0.4)', textTransform: 'capitalize', fontWeight: 500 }}>{type.replace('_', ' ')}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}