import { useState, useEffect } from 'react'
import { Shield, AlertTriangle, CheckCircle, Zap, Mail, MessageSquare, Eye, Globe, Info, MapPin, Network, Building2 } from 'lucide-react'
import axios from 'axios'

const api = () => axios.create({
  baseURL: 'http://localhost:8000',
  headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
})

// Extract IP addresses from text
function extractIPs(text) {
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g
  return [...new Set(text.match(ipRegex) || [])]
}

// Component to display IP details
function IpDetails({ ipData, onClose }) {
  if (!ipData) return null

  const levelConfig = {
    threat: { color: '#ff3b3b', bg: 'rgba(255,59,59,0.08)', border: 'rgba(255,59,59,0.2)', label: 'THREAT', icon: <AlertTriangle size={20} /> },
    suspicious: { color: '#fbbf24', bg: 'rgba(251,191,36,0.08)', border: 'rgba(251,191,36,0.2)', label: 'SUSPICIOUS', icon: <Eye size={20} /> },
    safe: { color: '#00e5a0', bg: 'rgba(0,229,160,0.08)', border: 'rgba(0,229,160,0.2)', label: 'SAFE', icon: <CheckCircle size={20} /> }
  }
  const cfg = levelConfig[ipData.threat_level] || levelConfig.safe

  const getIsp = () => ipData.geo?.isp || ipData.sources?.find(s => s.isp)?.isp
  const getOrg = () => ipData.geo?.organization || ipData.sources?.find(s => s.org || s.as_owner)?.org || ipData.sources?.find(s => s.as_owner)?.as_owner
  const getAsn = () => ipData.geo?.asn || ipData.sources?.find(s => s.asn || s.as_owner)?.asn || ipData.sources?.find(s => s.as_owner)?.as_owner

  return (
    <div style={{
      background: cfg.bg, border: `1px solid ${cfg.border}`, borderRadius: 20, padding: '20px',
      marginTop: 16, position: 'relative'
    }}>
      <button onClick={onClose} style={{
        position: 'absolute', top: 12, right: 16, background: 'none', border: 'none',
        color: 'rgba(255,255,255,0.4)', cursor: 'pointer', fontSize: 18
      }}>✕</button>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <div style={{ color: cfg.color }}>{cfg.icon}</div>
        <div>
          <div style={{ fontWeight: 700 }}>IP: {ipData.ip}</div>
          <div style={{ fontSize: 12, color: cfg.color, textTransform: 'uppercase' }}>{cfg.label} (Score: {ipData.aggregated_score || 0}%)</div>
        </div>
      </div>

      {/* Geolocation */}
      {ipData.geo && (
        <div style={{ background: 'rgba(0,0,0,0.15)', padding: '12px', borderRadius: 12, marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
            <MapPin size={12} color="#00e5a0" />
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Location & Network</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: 6, fontSize: 12 }}>
            {ipData.geo.country && <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>Country:</span> {ipData.geo.country}</div>}
            {ipData.geo.city && <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>City:</span> {ipData.geo.city}</div>}
            {getIsp() && <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>ISP:</span> {getIsp()}</div>}
            {getOrg() && <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>Org:</span> {getOrg()}</div>}
            {getAsn() && <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>ASN:</span> {getAsn()}</div>}
          </div>
        </div>
      )}

      {/* Indicators */}
      {ipData.indicators?.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 6 }}>Indicators</div>
          {ipData.indicators.slice(0, 3).map((ind, i) => (
            <div key={i} style={{ fontSize: 12, padding: '4px 0', color: '#ff6b6b' }}>⚠️ {ind}</div>
          ))}
        </div>
      )}

      <div style={{ fontSize: 11, color: cfg.color, fontWeight: 600 }}>
        Recommendation: {ipData.recommendation?.toUpperCase()}
      </div>
    </div>
  )
}

export default function Analysis() {
  const [channel, setChannel] = useState('email')
  const [form, setForm] = useState({ subject: '', sender: '', content: '', phone_number: '' })
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [ipDetails, setIpDetails] = useState(null)
  const [ipLoading, setIpLoading] = useState(false)

  const analyze = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    setResult(null)
    setIpDetails(null)
    try {
      const res = await api().post('/api/analysis/analyze', { ...form, channel })
      setResult(res.data)

      // Extract IPs from text and fetch intelligence
      const textToScan = `${form.content} ${form.sender} ${form.subject} ${form.phone_number || ''}`
      const ips = extractIPs(textToScan)
      if (ips.length > 0) {
        setIpLoading(true)
        try {
          // Use the first IP for simplicity
          const ipRes = await api().post('/api/scanner/ip/enhanced', { ip: ips[0] })
          setIpDetails(ipRes.data)
        } catch (err) {
          console.error('Failed to fetch IP details', err)
        } finally {
          setIpLoading(false)
        }
      }
    } catch (err) {
      // Handle errors gracefully - extract meaningful message
      const detail = err.response?.data?.detail
      if (typeof detail === 'object' && detail.message) {
        setError(detail.message)
      } else if (typeof detail === 'string') {
        setError(detail)
      } else if (err.response?.status === 429) {
        setError('Scan limit exceeded. Please upgrade your plan or wait for next month.')
      } else {
        setError('Analysis failed. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  const levelConfig = {
    threat: { icon: <AlertTriangle size={48} />, color: '#ff3b3b', bg: 'rgba(255,59,59,0.08)', border: 'rgba(255,59,59,0.2)', label: 'THREAT DETECTED', glow: '0 0 40px rgba(255,59,59,0.2)' },
    suspicious: { icon: <Eye size={48} />, color: '#fbbf24', bg: 'rgba(251,191,36,0.08)', border: 'rgba(251,191,36,0.2)', label: 'SUSPICIOUS', glow: '0 0 40px rgba(251,191,36,0.15)' },
    safe: { icon: <CheckCircle size={48} />, color: '#00e5a0', bg: 'rgba(0,229,160,0.08)', border: 'rgba(0,229,160,0.2)', label: 'SAFE', glow: '0 0 40px rgba(0,229,160,0.15)' }
  }

  const channels = [
    { id: 'email', label: 'Email', icon: <Mail size={16} /> },
    { id: 'sms', label: 'SMS', icon: <MessageSquare size={16} /> },
    { id: 'whatsapp', label: 'WhatsApp', icon: <MessageSquare size={16} /> },
  ]

  return (
    <div style={{ position: 'relative' }}>
      <div className="hero-bg" />
      <div className="grid-dots" style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0 }} />

      <div style={{ position: 'relative', zIndex: 1 }}>
        {/* Header */}
        <div className="fade-in" style={{ marginBottom: 32 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#ff6b35', animation: 'pulse 2s infinite' }} />
            <span style={{ fontSize: 12, color: '#ff6b35', fontWeight: 700, letterSpacing: 2, textTransform: 'uppercase' }}>AI-Powered Detection</span>
          </div>
          <h1 style={{ fontSize: 44, fontWeight: 900, color: '#fff', marginBottom: 8, lineHeight: 1.1 }}>
            Threat <span className="gradient-text">Analysis</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 15 }}>Detect phishing, malware and social engineering in real-time</p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: result ? '1fr 1fr' : '1fr', gap: 24, maxWidth: result ? '100%' : 780 }}>

          {/* Form Card */}
          <div style={{
            background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
            borderRadius: 24, padding: '32px', backdropFilter: 'blur(20px)',
            boxShadow: '0 20px 60px rgba(0,0,0,0.3)'
          }} className="fade-in">

            {/* Channel Selector */}
            <div style={{ marginBottom: 24 }}>
              <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 12, display: 'block', fontWeight: 700, letterSpacing: 1.5, textTransform: 'uppercase' }}>Select Channel</label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
                {channels.map(({ id, label, icon }) => (
                  <button key={id} onClick={() => setChannel(id)} style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                    padding: '12px', borderRadius: 14, border: 'none', cursor: 'pointer',
                    fontSize: 13, fontWeight: 700, transition: 'all 0.2s',
                    background: channel === id
                      ? 'linear-gradient(135deg, rgba(255,107,53,0.25), rgba(255,59,59,0.15))'
                      : 'rgba(255,255,255,0.04)',
                    color: channel === id ? '#fff' : 'rgba(255,255,255,0.3)',
                    border: channel === id ? '1px solid rgba(255,107,53,0.3)' : '1px solid rgba(255,255,255,0.06)',
                    boxShadow: channel === id ? '0 4px 20px rgba(255,107,53,0.2)' : 'none',
                    transform: channel === id ? 'translateY(-1px)' : 'none'
                  }}>
                    <span style={{ color: channel === id ? '#ff6b35' : 'rgba(255,255,255,0.3)' }}>{icon}</span>
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {error && (
              <div style={{ background: 'rgba(255,59,59,0.08)', border: '1px solid rgba(255,59,59,0.2)', color: '#ff6b6b', padding: '12px 16px', borderRadius: 12, marginBottom: 20, fontSize: 13 }}>
                ⚠️ {error}
              </div>
            )}

            <form onSubmit={analyze} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
              {channel === 'email' && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                  <div>
                    <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Sender</label>
                    <input className="input" value={form.sender} onChange={e => setForm({ ...form, sender: e.target.value })} placeholder="sender@domain.com" required />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Subject</label>
                    <input className="input" value={form.subject} onChange={e => setForm({ ...form, subject: e.target.value })} placeholder="Email subject" required />
                  </div>
                </div>
              )}

              {(channel === 'sms' || channel === 'whatsapp') && (
                <div>
                  <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Phone Number</label>
                  <input className="input" value={form.phone_number} onChange={e => setForm({ ...form, phone_number: e.target.value })} placeholder="+972501234567" />
                </div>
              )}

              <div>
                <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>
                  {channel === 'email' ? 'Email Content' : 'Message Content'}
                </label>
                <textarea className="input" value={form.content} onChange={e => setForm({ ...form, content: e.target.value })}
                  placeholder={channel === 'email' ? 'Paste the full email content here...' : 'Paste message content here...'}
                  rows={9} required style={{ resize: 'vertical', lineHeight: 1.7 }} />
              </div>

              <button className="btn btn-primary" type="submit" disabled={loading} style={{
                padding: '16px', fontSize: 16, fontWeight: 800, borderRadius: 14,
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10
              }}>
                {loading ? (
                  <>
                    <div style={{ width: 20, height: 20, border: '2px solid rgba(255,255,255,0.3)', borderTop: '2px solid #fff', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
                    Analyzing with AI...
                  </>
                ) : (
                  <><Zap size={18} /> Analyze with AI</>
                )}
              </button>
            </form>
          </div>

          {/* Result Card */}
          {result && (() => {
            const cfg = levelConfig[result.threat_level] || levelConfig.safe
            return (
              <div style={{
                background: cfg.bg, border: `1px solid ${cfg.border}`,
                borderRadius: 24, padding: '32px', backdropFilter: 'blur(20px)',
                boxShadow: cfg.glow, display: 'flex', flexDirection: 'column', gap: 20
              }} className="fade-in">

                {/* Level */}
                <div style={{ textAlign: 'center', padding: '28px 20px', background: 'rgba(0,0,0,0.2)', borderRadius: 18, border: `1px solid ${cfg.color}15` }}>
                  <div style={{ color: cfg.color, marginBottom: 14, filter: `drop-shadow(0 0 12px ${cfg.color})` }}>{cfg.icon}</div>
                  <div style={{ fontSize: 26, fontWeight: 900, color: cfg.color, letterSpacing: 2, marginBottom: 16 }}>{cfg.label}</div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
                    <span style={{ fontSize: 13, color: 'rgba(255,255,255,0.4)' }}>Confidence</span>
                    <div style={{ flex: 1, maxWidth: 140, height: 8, background: 'rgba(255,255,255,0.08)', borderRadius: 4 }}>
                      <div style={{
                        width: `${result.confidence}%`, height: '100%',
                        background: `linear-gradient(90deg, ${cfg.color}88, ${cfg.color})`,
                        borderRadius: 4, transition: 'width 1.5s cubic-bezier(0.4,0,0.2,1)',
                        boxShadow: `0 0 10px ${cfg.color}50`
                      }} />
                    </div>
                    <span style={{ fontSize: 16, fontWeight: 900, color: cfg.color }}>{result.confidence}%</span>
                  </div>
                </div>

                {/* Badges */}
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 11, fontWeight: 700, padding: '5px 14px', borderRadius: 20, background: `${cfg.color}15`, color: cfg.color, border: `1px solid ${cfg.color}30`, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                    {result.threat_type}
                  </span>
                  {result.is_quarantined && (
                    <span style={{ fontSize: 11, fontWeight: 700, padding: '5px 14px', borderRadius: 20, background: 'rgba(251,191,36,0.1)', color: '#fbbf24', border: '1px solid rgba(251,191,36,0.2)', textTransform: 'uppercase' }}>
                      🔒 Quarantined
                    </span>
                  )}
                </div>

                {/* Summary */}
                <div style={{ background: 'rgba(0,0,0,0.2)', padding: '16px 18px', borderRadius: 14, border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', marginBottom: 8, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1 }}>Summary</div>
                  <p style={{ fontSize: 14, lineHeight: 1.7, color: 'rgba(255,255,255,0.75)' }}>{result.summary}</p>
                </div>

                {/* Indicators */}
                {result.indicators?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', marginBottom: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1 }}>Threat Indicators</div>
                    {result.indicators.map((ind, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 13, color: 'rgba(255,255,255,0.65)', animation: `fadeInUp 0.3s ease ${i * 0.08}s both` }}>
                        <div style={{ width: 6, height: 6, borderRadius: '50%', background: cfg.color, flexShrink: 0, boxShadow: `0 0 6px ${cfg.color}` }} />
                        {ind}
                      </div>
                    ))}
                  </div>
                )}

                {/* Recommendation */}
                <div style={{ background: `${cfg.color}10`, border: `1px solid ${cfg.color}25`, padding: '16px 18px', borderRadius: 14 }}>
                  <div style={{ fontSize: 10, color: cfg.color, marginBottom: 6, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 1 }}>
                    ⚡ {result.recommendation?.toUpperCase()}
                  </div>
                  <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.65)', lineHeight: 1.6 }}>{result.recommendation}</div>
                </div>

                {/* IP Details Section */}
                {ipLoading && (
                  <div style={{ textAlign: 'center', padding: 12 }}>
                    <div style={{ width: 20, height: 20, border: '2px solid rgba(255,255,255,0.2)', borderTop: '2px solid #00e5a0', borderRadius: '50%', animation: 'spin 0.8s linear infinite', margin: '0 auto' }} />
                    <div style={{ fontSize: 12, marginTop: 8, color: 'rgba(255,255,255,0.5)' }}>Fetching IP intelligence...</div>
                  </div>
                )}
                {ipDetails && <IpDetails ipData={ipDetails} onClose={() => setIpDetails(null)} />}
              </div>
            )
          })()}
        </div>
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}