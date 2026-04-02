import { useState } from 'react'
import { Link2, Globe, FileText, Key, AlertTriangle, CheckCircle, Eye, Shield, Copy, Plus, Zap, RefreshCw, Info, MapPin, Network, Building2 } from 'lucide-react'
import axios from 'axios'

const api = () => axios.create({
  baseURL: 'http://localhost:8000',
  headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
})

function ResultCard({ result, type }) {
  if (!result) return null

  const levelConfig = {
    threat: { color: '#ff3b3b', bg: 'rgba(255,59,59,0.08)', border: 'rgba(255,59,59,0.2)', label: 'THREAT', glow: '0 0 30px rgba(255,59,59,0.15)', icon: <AlertTriangle size={32} /> },
    suspicious: { color: '#fbbf24', bg: 'rgba(251,191,36,0.08)', border: 'rgba(251,191,36,0.2)', label: 'SUSPICIOUS', glow: '0 0 30px rgba(251,191,36,0.1)', icon: <Eye size={32} /> },
    safe: { color: '#00e5a0', bg: 'rgba(0,229,160,0.08)', border: 'rgba(0,229,160,0.2)', label: 'SAFE', glow: '0 0 30px rgba(0,229,160,0.1)', icon: <CheckCircle size={32} /> }
  }

  const cfg = levelConfig[result.threat_level] || levelConfig.safe
  const [showSources, setShowSources] = useState(false)

  // Helper to get ISP from geo or sources
  const getIsp = () => {
    if (result.geo?.isp) return result.geo.isp
    if (result.sources) {
      const ispFromSources = result.sources.find(s => s.isp)?.isp
      if (ispFromSources) return ispFromSources
    }
    return null
  }

  const getOrganization = () => {
    if (result.geo?.organization) return result.geo.organization
    if (result.sources) {
      const org = result.sources.find(s => s.org || s.as_owner)?.org || result.sources.find(s => s.as_owner)?.as_owner
      if (org) return org
    }
    return null
  }

  const getAsn = () => {
    if (result.geo?.asn) return result.geo.asn
    if (result.sources) {
      const asn = result.sources.find(s => s.asn || s.as_owner)?.asn || result.sources.find(s => s.as_owner)?.as_owner
      if (asn) return asn
    }
    return null
  }

  return (
    <div style={{ background: cfg.bg, border: `1px solid ${cfg.border}`, borderRadius: 20, padding: '24px', boxShadow: cfg.glow }} className="fade-in">
      {/* Threat level header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20, padding: '16px 20px', background: 'rgba(0,0,0,0.2)', borderRadius: 14 }}>
        <div style={{ color: cfg.color, filter: `drop-shadow(0 0 8px ${cfg.color})` }}>{cfg.icon}</div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 20, fontWeight: 900, color: cfg.color, letterSpacing: 1 }}>{cfg.label}</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
            <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 3 }}>
              <div style={{ width: `${result.risk_score || result.confidence || result.aggregated_score || 0}%`, height: '100%', background: `linear-gradient(90deg, ${cfg.color}66, ${cfg.color})`, borderRadius: 3, transition: 'width 1s ease' }} />
            </div>
            <span style={{ fontSize: 14, fontWeight: 800, color: cfg.color }}>
              {type === 'ip' ? `${result.aggregated_score || result.risk_score || 0}%` : `${result.risk_score || result.confidence || 0}%`}
            </span>
          </div>
        </div>
      </div>

      {/* Basic info (IP, URL, filename) */}
      <div style={{ background: 'rgba(0,0,0,0.15)', padding: '14px 16px', borderRadius: 12, marginBottom: 14, border: '1px solid rgba(255,255,255,0.05)' }}>
        <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
          {type === 'ip' ? 'IP Address' : type === 'url' ? 'URL' : 'Filename'}
        </div>
        <p style={{ fontSize: 14, color: '#fff', fontFamily: 'monospace', wordBreak: 'break-all' }}>{result.ip || result.url || result.filename}</p>
      </div>

      {/* Geolocation & Network Info (for IP) */}
      {type === 'ip' && result.geo && (
        <div style={{ background: 'rgba(0,0,0,0.15)', padding: '14px 16px', borderRadius: 12, marginBottom: 14, border: '1px solid rgba(255,255,255,0.05)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <MapPin size={14} color="#00e5a0" />
            <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.5)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1 }}>Location & Network</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 8 }}>
            <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>Country:</span> {result.geo.country || 'Unknown'}</div>
            {result.geo.city && <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>City:</span> {result.geo.city}</div>}
            {result.geo.region && <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>Region:</span> {result.geo.region}</div>}
            {getIsp() && <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>ISP:</span> {getIsp()}</div>}
            {getOrganization() && <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>Organization:</span> {getOrganization()}</div>}
            {getAsn() && <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>ASN:</span> {getAsn()}</div>}
            {result.geo.latitude && result.geo.longitude && (
              <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>Coordinates:</span> {result.geo.latitude}, {result.geo.longitude}</div>
            )}
          </div>
        </div>
      )}

      {/* Summary */}
      <div style={{ background: 'rgba(0,0,0,0.15)', padding: '14px 16px', borderRadius: 12, marginBottom: 14, border: '1px solid rgba(255,255,255,0.05)' }}>
        <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>Summary</div>
        <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.75)', lineHeight: 1.6 }}>{result.summary}</p>
      </div>

      {/* Indicators */}
      {result.indicators?.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Indicators</div>
          {result.indicators.map((ind, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '7px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 13, color: 'rgba(255,255,255,0.6)', animation: `fadeInUp 0.3s ease ${i * 0.06}s both` }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: cfg.color, flexShrink: 0, marginTop: 5, boxShadow: `0 0 6px ${cfg.color}` }} />
              {ind}
            </div>
          ))}
        </div>
      )}

      {/* Threat Intelligence Sources (for IP) */}
      {type === 'ip' && result.sources && result.sources.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <button
            onClick={() => setShowSources(!showSources)}
            style={{
              background: 'none',
              border: 'none',
              color: '#00e5a0',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 12,
              fontWeight: 600,
              padding: '8px 0',
              width: '100%',
              justifyContent: 'space-between',
              borderTop: '1px solid rgba(255,255,255,0.05)',
              marginTop: 4,
              paddingTop: 12
            }}
          >
            <span><Info size={14} style={{ marginRight: 6 }} /> Threat Intelligence Sources</span>
            <span>{showSources ? '▼' : '▶'}</span>
          </button>
          {showSources && (
            <div style={{ maxHeight: 400, overflowY: 'auto', background: 'rgba(0,0,0,0.2)', borderRadius: 12, padding: 12, marginTop: 8 }}>
              {result.sources.map((src, idx) => (
                <div key={idx} style={{ marginBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: 10 }}>
                  <div style={{ fontWeight: 700, marginBottom: 6, color: '#00e5a0', fontSize: 13 }}>{src.source}</div>
                  {src.error ? (
                    <div style={{ color: '#ff6b6b', fontSize: 12 }}>Error: {src.error}</div>
                  ) : (
                    <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.6)' }}>
                      {src.score !== undefined && <div>Score: {src.score}</div>}
                      {src.malicious_votes !== undefined && <div>Malicious votes: {src.malicious_votes}</div>}
                      {src.total_reports !== undefined && <div>Total reports: {src.total_reports}</div>}
                      {src.classification && <div>Classification: {src.classification}</div>}
                      {src.country && <div>Country: {src.country}</div>}
                      {src.isp && <div>ISP: {src.isp}</div>}
                      {src.as_owner && <div>AS Owner: {src.as_owner}</div>}
                      {src.organization && <div>Organization: {src.organization}</div>}
                      {src.categories && src.categories.length > 0 && (
                        <div>Categories: {src.categories.join(', ')}</div>
                      )}
                      {src.tags && src.tags.length > 0 && (
                        <div>Tags: {src.tags.join(', ')}</div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Recommendation */}
      <div style={{ marginTop: 14, background: `${cfg.color}10`, border: `1px solid ${cfg.color}25`, padding: '12px 16px', borderRadius: 12 }}>
        <div style={{ fontSize: 11, color: cfg.color, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 1 }}>
          ⚡ Recommendation: {result.recommendation?.toUpperCase()}
        </div>
      </div>
    </div>
  )
}

export default function Scanner() {
  const [tab, setTab] = useState('url')
  const [urlInput, setUrlInput] = useState('')
  const [ipInput, setIpInput] = useState('')
  const [fileData, setFileData] = useState({ filename: '', file_size: 0, file_hash: '' })
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [apiKeys, setApiKeys] = useState(null)
  const [apiLoading, setApiLoading] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [copied, setCopied] = useState(null)
  const [error, setError] = useState('')

  const scan = async () => {
    setLoading(true)
    setError('')
    setResult(null)
    try {
      let res
      if (tab === 'url') res = await api().post('/api/scanner/url', { url: urlInput })
      else if (tab === 'ip') res = await api().post('/api/scanner/ip/enhanced', { ip: ipInput })  // using enhanced endpoint
      else if (tab === 'file') res = await api().post('/api/scanner/file', fileData)
      setResult(res.data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Scan failed')
    } finally { setLoading(false) }
  }

  const loadApiKeys = async () => {
    setApiLoading(true)
    try {
      const res = await api().get('/api/scanner/apikeys')
      setApiKeys(res.data.keys)
    } catch { setError('Failed to load API keys') }
    finally { setApiLoading(false) }
  }

  const generateKey = async () => {
    if (!newKeyName.trim()) return
    try {
      const res = await api().post('/api/scanner/apikeys/generate', { name: newKeyName })
      setApiKeys(prev => [...(prev || []), res.data.key])
      setNewKeyName('')
    } catch { setError('Failed to generate key') }
  }

  const copyKey = (key, id) => {
    navigator.clipboard.writeText(key)
    setCopied(id)
    setTimeout(() => setCopied(null), 2000)
  }

  const tabs = [
    { id: 'url', label: 'URL Analysis', icon: <Link2 size={16} />, color: '#ff6b35' },
    { id: 'ip', label: 'IP Reputation', icon: <Globe size={16} />, color: '#3b82f6' },
    { id: 'file', label: 'File Scanner', icon: <FileText size={16} />, color: '#a78bfa' },
    { id: 'apikeys', label: 'API Keys', icon: <Key size={16} />, color: '#00e5a0' },
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
            <span style={{ fontSize: 12, color: '#ff6b35', fontWeight: 700, letterSpacing: 2, textTransform: 'uppercase' }}>Security Scanner</span>
          </div>
          <h1 style={{ fontSize: 44, fontWeight: 900, color: '#fff', marginBottom: 8, lineHeight: 1.1 }}>
            Advanced <span className="gradient-text">Scanner</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 15 }}>URL analysis, IP reputation, file scanning and API key management</p>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 28, background: 'rgba(255,255,255,0.03)', padding: 6, borderRadius: 16, border: '1px solid rgba(255,255,255,0.06)', width: 'fit-content' }}>
          {tabs.map(({ id, label, icon, color }) => (
            <button key={id} onClick={() => { setTab(id); setResult(null); setError(''); if (id === 'apikeys') loadApiKeys() }}
              style={{
                display: 'flex', alignItems: 'center', gap: 8, padding: '10px 18px', borderRadius: 12,
                border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 700, transition: 'all 0.2s',
                background: tab === id ? `linear-gradient(135deg, ${color}25, ${color}10)` : 'transparent',
                color: tab === id ? color : 'rgba(255,255,255,0.3)',
                borderBottom: tab === id ? `2px solid ${color}` : '2px solid transparent',
                boxShadow: tab === id ? `0 4px 20px ${color}15` : 'none'
              }}>
              {icon} {label}
            </button>
          ))}
        </div>

        {tab !== 'apikeys' && (
          <div style={{ display: 'grid', gridTemplateColumns: result ? '1fr 1fr' : '1fr', gap: 24, maxWidth: result ? '100%' : 720 }}>

            {/* Input Card */}
            <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 24, padding: '28px', backdropFilter: 'blur(20px)' }} className="fade-in">

              {error && (
                <div style={{ background: 'rgba(255,59,59,0.08)', border: '1px solid rgba(255,59,59,0.2)', color: '#ff6b6b', padding: '12px 16px', borderRadius: 12, marginBottom: 20, fontSize: 13 }}>
                  ⚠️ {error}
                </div>
              )}

              {tab === 'url' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                    <div style={{ color: '#ff6b35', background: 'rgba(255,107,53,0.1)', padding: 8, borderRadius: 10 }}>
                      <Link2 size={18} />
                    </div>
                    <div>
                      <h2 style={{ fontSize: 18, fontWeight: 800, color: '#fff' }}>URL Analysis</h2>
                      <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)' }}>Check if a URL is malicious or phishing</p>
                    </div>
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>URL to Analyze</label>
                    <input className="input" value={urlInput} onChange={e => setUrlInput(e.target.value)}
                      placeholder="https://suspicious-site.xyz/login" style={{ fontSize: 14 }} />
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                    {['https://paypa1.com/verify', 'http://amazon-login-secure.xyz', 'https://google.com', 'bit.ly/3xAm9Kz'].map(ex => (
                      <button key={ex} onClick={() => setUrlInput(ex)} style={{
                        padding: '8px 12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)',
                        background: 'rgba(255,255,255,0.03)', color: 'rgba(255,255,255,0.35)',
                        fontSize: 11, cursor: 'pointer', textAlign: 'left', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                      }}>
                        {ex}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {tab === 'ip' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                    <div style={{ color: '#3b82f6', background: 'rgba(59,130,246,0.1)', padding: 8, borderRadius: 10 }}>
                      <Globe size={18} />
                    </div>
                    <div>
                      <h2 style={{ fontSize: 18, fontWeight: 800, color: '#fff' }}>IP Reputation</h2>
                      <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)' }}>Check if an IP is malicious or suspicious (with geolocation & threat intel)</p>
                    </div>
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>IP Address</label>
                    <input className="input" value={ipInput} onChange={e => setIpInput(e.target.value)} placeholder="185.220.101.42" />
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                    {['185.220.101.42', '198.199.100.1', '192.168.1.1', '8.8.8.8'].map(ex => (
                      <button key={ex} onClick={() => setIpInput(ex)} style={{
                        padding: '8px 12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)',
                        background: 'rgba(255,255,255,0.03)', color: 'rgba(255,255,255,0.35)',
                        fontSize: 12, cursor: 'pointer', fontFamily: 'monospace'
                      }}>
                        {ex}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {tab === 'file' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                    <div style={{ color: '#a78bfa', background: 'rgba(167,139,250,0.1)', padding: 8, borderRadius: 10 }}>
                      <FileText size={18} />
                    </div>
                    <div>
                      <h2 style={{ fontSize: 18, fontWeight: 800, color: '#fff' }}>File Scanner</h2>
                      <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)' }}>Check filename, extension and hash</p>
                    </div>
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>Filename</label>
                    <input className="input" value={fileData.filename} onChange={e => setFileData({ ...fileData, filename: e.target.value })} placeholder="invoice_urgent.exe" />
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    <div>
                      <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>File Size (bytes)</label>
                      <input className="input" type="number" value={fileData.file_size} onChange={e => setFileData({ ...fileData, file_size: parseInt(e.target.value) || 0 })} placeholder="1024" />
                    </div>
                    <div>
                      <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, display: 'block', fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>MD5 Hash (optional)</label>
                      <input className="input" value={fileData.file_hash} onChange={e => setFileData({ ...fileData, file_hash: e.target.value })} placeholder="abc123..." />
                    </div>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                    {['invoice_payment.exe', 'document.pdf.bat', 'report.docm', 'photo.jpg'].map(ex => (
                      <button key={ex} onClick={() => setFileData({ ...fileData, filename: ex })} style={{
                        padding: '8px 12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)',
                        background: 'rgba(255,255,255,0.03)', color: 'rgba(255,255,255,0.35)',
                        fontSize: 12, cursor: 'pointer', fontFamily: 'monospace'
                      }}>
                        {ex}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <button className="btn btn-primary" onClick={scan} disabled={loading} style={{
                width: '100%', marginTop: 20, padding: '15px', fontSize: 15, fontWeight: 800,
                borderRadius: 14, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10
              }}>
                {loading ? (
                  <><div style={{ width: 20, height: 20, border: '2px solid rgba(255,255,255,0.3)', borderTop: '2px solid #fff', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} /> Scanning...</>
                ) : (
                  <><Shield size={18} /> Scan Now</>
                )}
              </button>
            </div>

            {/* Result */}
            {result && <ResultCard result={result} type={tab} />}
          </div>
        )}

        {/* API Keys Tab */}
        {tab === 'apikeys' && (
          <div style={{ maxWidth: 720 }} className="fade-in">
            <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 24, padding: '28px', backdropFilter: 'blur(20px)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
                <div style={{ color: '#00e5a0', background: 'rgba(0,229,160,0.1)', padding: 8, borderRadius: 10 }}>
                  <Key size={18} />
                </div>
                <div>
                  <h2 style={{ fontSize: 18, fontWeight: 800, color: '#fff' }}>API Keys</h2>
                  <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)' }}>Manage your API keys for integration</p>
                </div>
              </div>

              {/* Generate new key */}
              <div style={{ display: 'flex', gap: 10, marginBottom: 24 }}>
                <input className="input" value={newKeyName} onChange={e => setNewKeyName(e.target.value)}
                  placeholder="Key name (e.g. Production App)" style={{ flex: 1 }} />
                <button className="btn btn-primary" onClick={generateKey} style={{ display: 'flex', alignItems: 'center', gap: 8, whiteSpace: 'nowrap', padding: '12px 20px', borderRadius: 12 }}>
                  <Plus size={16} /> Generate
                </button>
              </div>

              {apiLoading ? (
                <div style={{ textAlign: 'center', padding: '40px 0' }}>
                  <div style={{ width: 32, height: 32, border: '2px solid rgba(0,229,160,0.2)', borderTop: '2px solid #00e5a0', borderRadius: '50%', animation: 'spin 1s linear infinite', margin: '0 auto 12px' }} />
                  <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 13 }}>Loading keys...</p>
                </div>
              ) : (
                (apiKeys || []).map((k, i) => (
                  <div key={k.id} style={{
                    padding: '18px', marginBottom: 12, borderRadius: 16,
                    background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)',
                    animation: `fadeInUp 0.3s ease ${i * 0.08}s both`
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                      <div>
                        <div style={{ fontWeight: 700, fontSize: 15, color: '#fff', marginBottom: 4 }}>{k.name}</div>
                        <div style={{ display: 'flex', gap: 8 }}>
                          <span style={{ fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 20, background: k.type === 'live' ? 'rgba(0,229,160,0.1)' : 'rgba(251,191,36,0.1)', color: k.type === 'live' ? '#00e5a0' : '#fbbf24', border: `1px solid ${k.type === 'live' ? 'rgba(0,229,160,0.2)' : 'rgba(251,191,36,0.2)'}`, textTransform: 'uppercase' }}>
                            {k.type}
                          </span>
                          <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.25)', padding: '3px 10px' }}>Last used: {k.last_used}</span>
                        </div>
                      </div>
                      <button onClick={() => copyKey(k.key, k.id)} style={{
                        display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', borderRadius: 10,
                        background: copied === k.id ? 'rgba(0,229,160,0.1)' : 'rgba(255,255,255,0.05)',
                        border: `1px solid ${copied === k.id ? 'rgba(0,229,160,0.2)' : 'rgba(255,255,255,0.08)'}`,
                        color: copied === k.id ? '#00e5a0' : 'rgba(255,255,255,0.4)',
                        cursor: 'pointer', fontSize: 12, fontWeight: 600, transition: 'all 0.2s'
                      }}>
                        <Copy size={13} /> {copied === k.id ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                    <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px 14px', borderRadius: 10, fontFamily: 'monospace', fontSize: 12, color: 'rgba(255,255,255,0.4)', letterSpacing: 0.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', border: '1px solid rgba(255,255,255,0.05)' }}>
                      {k.key.slice(0, 20)}{'•'.repeat(20)}{k.key.slice(-8)}
                    </div>
                  </div>
                ))
              )}

              {/* Usage example */}
              <div style={{ marginTop: 20, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 14, padding: '16px 20px' }}>
                <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Usage Example</div>
                <pre style={{ fontFamily: 'monospace', fontSize: 12, color: '#00e5a0', lineHeight: 1.7, overflow: 'auto' }}>
{`curl -X POST https://api.trustive.ai/v1/analyze \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"content": "email content", "channel": "email"}'`}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}