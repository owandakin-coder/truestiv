import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Zap, Shield, Globe, Search, ArrowRight, CheckCircle, Star, Menu, X, Activity, Lock, Eye } from 'lucide-react'

export default function Landing() {
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)
  const [particles, setParticles] = useState([])

  useEffect(() => {
    setParticles(Array.from({ length: 30 }, (_, i) => ({
      id: i, x: Math.random() * 100, y: Math.random() * 100,
      size: Math.random() * 3 + 1, duration: Math.random() * 6 + 4,
      delay: Math.random() * 4, color: ['#ff6b35', '#ff3b3b', '#00e5a0', '#3b82f6', '#a78bfa'][Math.floor(Math.random() * 5)]
    })))

    const handler = () => setScrolled(window.scrollY > 50)
    window.addEventListener('scroll', handler)
    return () => window.removeEventListener('scroll', handler)
  }, [])

  const features = [
    { icon: <Shield size={28} />, title: 'Phishing Detection', desc: 'AI detects phishing attempts with 99.9% accuracy across email, SMS and WhatsApp.', color: '#ff3b3b' },
    { icon: <Search size={28} />, title: 'URL & IP Scanner', desc: 'Scan suspicious URLs, IP addresses and files before they cause damage.', color: '#a78bfa' },
    { icon: <Globe size={28} />, title: 'Community Intelligence', desc: 'Benefit from shared threat intelligence across thousands of organizations.', color: '#3b82f6' },
    { icon: <Activity size={28} />, title: 'Real-time Monitoring', desc: 'Live threat monitoring with instant alerts and automated countermeasures.', color: '#00e5a0' },
    { icon: <Lock size={28} />, title: 'Zero Trust Security', desc: 'Every message is treated as potentially malicious until proven otherwise.', color: '#fbbf24' },
    { icon: <Eye size={28} />, title: 'Hijack Detection', desc: 'Identify conversation hijacking attempts and impersonation attacks instantly.', color: '#ff6b35' },
  ]

  const stats = [
    { value: '99.9%', label: 'Detection Accuracy' },
    { value: '<1s', label: 'Analysis Speed' },
    { value: '10M+', label: 'Threats Blocked' },
    { value: '500+', label: 'Enterprise Clients' },
  ]

  const testimonials = [
    { name: 'Sarah Chen', role: 'CISO at TechCorp', text: 'Trustive AI reduced our phishing incidents by 94%. The AI explanations in Hebrew are incredibly useful for our team.', rating: 5 },
    { name: 'David Levy', role: 'Security Manager at FinBank', text: 'The community threat feed has been invaluable. We are now aware of new attack vectors before they hit us.', rating: 5 },
    { name: 'Michal Ronen', role: 'IT Director at MedCenter', text: 'Easy deployment, powerful results. Our team detected 3x more threats in the first month.', rating: 5 },
  ]

  return (
    <div style={{ background: '#050507', color: '#f1f5f9', minHeight: '100vh', overflowX: 'hidden', position: 'relative' }}>

      {/* Particles */}
      {particles.map(p => (
        <div key={p.id} style={{ position: 'fixed', left: `${p.x}%`, top: `${p.y}%`, width: p.size, height: p.size, borderRadius: '50%', background: p.color, opacity: 0.15, animation: `float ${p.duration}s ease-in-out ${p.delay}s infinite`, pointerEvents: 'none', zIndex: 0 }} />
      ))}

      {/* Grid */}
      <div className="grid-dots" style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0 }} />

      {/* Glow blobs */}
      <div style={{ position: 'fixed', top: '-20%', left: '-10%', width: '60%', height: '60%', background: 'radial-gradient(circle, rgba(255,107,53,0.08) 0%, transparent 70%)', pointerEvents: 'none', zIndex: 0 }} />
      <div style={{ position: 'fixed', bottom: '-20%', right: '-10%', width: '50%', height: '50%', background: 'radial-gradient(circle, rgba(59,130,246,0.06) 0%, transparent 70%)', pointerEvents: 'none', zIndex: 0 }} />

      {/* Navbar */}
      <nav style={{
        position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
        padding: '0 40px', height: 68,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        background: scrolled ? 'rgba(5,5,7,0.95)' : 'transparent',
        borderBottom: scrolled ? '1px solid rgba(255,255,255,0.06)' : 'none',
        backdropFilter: scrolled ? 'blur(20px)' : 'none',
        transition: 'all 0.3s'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 36, height: 36, borderRadius: 10, background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 20px rgba(255,107,53,0.4)' }}>
            <Zap size={18} color="#fff" fill="#fff" />
          </div>
          <span style={{ fontSize: 18, fontWeight: 900, color: '#fff' }}>Trustive AI</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 32 }}>
          {['Features', 'Security', 'Pricing', 'About'].map(item => (
            <a key={item} href={`#${item.toLowerCase()}`} style={{ fontSize: 14, color: 'rgba(255,255,255,0.5)', textDecoration: 'none', fontWeight: 500, transition: 'color 0.2s' }}
              onMouseEnter={e => e.target.style.color = '#fff'}
              onMouseLeave={e => e.target.style.color = 'rgba(255,255,255,0.5)'}
            >{item}</a>
          ))}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button onClick={() => navigate('/login')} style={{ padding: '9px 20px', borderRadius: 10, background: 'transparent', border: '1px solid rgba(255,255,255,0.15)', color: 'rgba(255,255,255,0.7)', cursor: 'pointer', fontSize: 14, fontWeight: 600, transition: 'all 0.2s' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(255,107,53,0.4)'; e.currentTarget.style.color = '#fff' }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.15)'; e.currentTarget.style.color = 'rgba(255,255,255,0.7)' }}
          >Sign In</button>
          <button onClick={() => navigate('/register')} style={{ padding: '9px 20px', borderRadius: 10, background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)', border: 'none', color: '#fff', cursor: 'pointer', fontSize: 14, fontWeight: 700, boxShadow: '0 4px 20px rgba(255,107,53,0.35)', transition: 'all 0.2s' }}
            onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-1px)'; e.currentTarget.style.boxShadow = '0 8px 28px rgba(255,107,53,0.5)' }}
            onMouseLeave={e => { e.currentTarget.style.transform = 'none'; e.currentTarget.style.boxShadow = '0 4px 20px rgba(255,107,53,0.35)' }}
          >Get Started Free</button>
        </div>
      </nav>

      {/* Hero */}
      <section style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '120px 40px 80px', position: 'relative', zIndex: 1 }}>
        <div style={{ maxWidth: 900, textAlign: 'center' }}>

          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '8px 16px', borderRadius: 20, background: 'rgba(255,107,53,0.1)', border: '1px solid rgba(255,107,53,0.2)', marginBottom: 32, animation: 'fadeInUp 0.4s ease' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#00e5a0', animation: 'pulse 2s infinite' }} />
            <span style={{ fontSize: 13, color: '#ff6b35', fontWeight: 700 }}>Trusted by 500+ Enterprise Teams</span>
          </div>

          <h1 style={{ fontSize: 72, fontWeight: 900, lineHeight: 1.05, marginBottom: 24, animation: 'fadeInUp 0.4s ease 0.1s both' }}>
            AI Security That<br />
            <span className="gradient-text">Actually Works</span>
          </h1>

          <p style={{ fontSize: 20, color: 'rgba(255,255,255,0.5)', lineHeight: 1.7, maxWidth: 620, margin: '0 auto 48px', animation: 'fadeInUp 0.4s ease 0.2s both' }}>
            Protect your organization from phishing, malware and social engineering with enterprise-grade AI that detects threats in under a second.
          </p>

          <div style={{ display: 'flex', gap: 16, justifyContent: 'center', flexWrap: 'wrap', marginBottom: 64, animation: 'fadeInUp 0.4s ease 0.3s both' }}>
            <button onClick={() => navigate('/register')} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '16px 32px', borderRadius: 14, background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)', border: 'none', color: '#fff', cursor: 'pointer', fontSize: 16, fontWeight: 800, boxShadow: '0 8px 32px rgba(255,107,53,0.4)', transition: 'all 0.2s' }}
              onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = '0 16px 48px rgba(255,107,53,0.5)' }}
              onMouseLeave={e => { e.currentTarget.style.transform = 'none'; e.currentTarget.style.boxShadow = '0 8px 32px rgba(255,107,53,0.4)' }}
            >
              <Zap size={20} /> Start Free Trial <ArrowRight size={18} />
            </button>
            <button onClick={() => navigate('/login')} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '16px 32px', borderRadius: 14, background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.12)', color: '#fff', cursor: 'pointer', fontSize: 16, fontWeight: 700, transition: 'all 0.2s' }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.1)' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.06)' }}
            >
              View Demo
            </button>
          </div>

          {/* Stats */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 24, animation: 'fadeInUp 0.4s ease 0.4s both' }}>
            {stats.map(({ value, label }) => (
              <div key={label} style={{ textAlign: 'center', padding: '20px', background: 'rgba(255,255,255,0.03)', borderRadius: 16, border: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{ fontSize: 36, fontWeight: 900, color: '#ff6b35', marginBottom: 4 }}>{value}</div>
                <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.4)', fontWeight: 500 }}>{label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" style={{ padding: '100px 40px', position: 'relative', zIndex: 1, maxWidth: 1200, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 64 }}>
          <div style={{ fontSize: 12, color: '#ff6b35', fontWeight: 700, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 12 }}>Features</div>
          <h2 style={{ fontSize: 48, fontWeight: 900, color: '#fff', marginBottom: 16 }}>
            Everything you need to<br /><span className="gradient-text">stay secure</span>
          </h2>
          <p style={{ fontSize: 16, color: 'rgba(255,255,255,0.4)', maxWidth: 500, margin: '0 auto' }}>
            A complete security platform built for modern enterprise teams.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20 }}>
          {features.map(({ icon, title, desc, color }, i) => (
            <div key={title} style={{ background: 'rgba(255,255,255,0.03)', border: `1px solid rgba(255,255,255,0.06)`, borderRadius: 20, padding: '28px', transition: 'all 0.3s', animation: `fadeInUp 0.4s ease ${i * 0.08}s both`, cursor: 'default' }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = `${color}30`; e.currentTarget.style.transform = 'translateY(-4px)'; e.currentTarget.style.boxShadow = `0 20px 60px rgba(0,0,0,0.3), 0 0 30px ${color}10` }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'; e.currentTarget.style.transform = 'none'; e.currentTarget.style.boxShadow = 'none' }}
            >
              <div style={{ color, background: `${color}15`, width: 56, height: 56, borderRadius: 16, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 20, boxShadow: `0 0 20px ${color}20` }}>
                {icon}
              </div>
              <h3 style={{ fontSize: 18, fontWeight: 800, color: '#fff', marginBottom: 10 }}>{title}</h3>
              <p style={{ fontSize: 14, color: 'rgba(255,255,255,0.4)', lineHeight: 1.7 }}>{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Testimonials */}
      <section style={{ padding: '100px 40px', position: 'relative', zIndex: 1, maxWidth: 1200, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 64 }}>
          <div style={{ fontSize: 12, color: '#00e5a0', fontWeight: 700, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 12 }}>Testimonials</div>
          <h2 style={{ fontSize: 48, fontWeight: 900, color: '#fff' }}>
            Trusted by security <span className="gradient-text">professionals</span>
          </h2>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20 }}>
          {testimonials.map(({ name, role, text, rating }, i) => (
            <div key={name} style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 20, padding: '28px', animation: `fadeInUp 0.4s ease ${i * 0.1}s both` }}>
              <div style={{ display: 'flex', gap: 4, marginBottom: 16 }}>
                {Array.from({ length: rating }).map((_, i) => (
                  <Star key={i} size={16} color="#fbbf24" fill="#fbbf24" />
                ))}
              </div>
              <p style={{ fontSize: 14, color: 'rgba(255,255,255,0.6)', lineHeight: 1.7, marginBottom: 20 }}>"{text}"</p>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{ width: 40, height: 40, borderRadius: 12, background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16, fontWeight: 900, color: '#fff' }}>
                  {name[0]}
                </div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: '#fff' }}>{name}</div>
                  <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)' }}>{role}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section style={{ padding: '100px 40px', position: 'relative', zIndex: 1, maxWidth: 900, margin: '0 auto', textAlign: 'center' }}>
        <div style={{ background: 'linear-gradient(135deg, rgba(255,107,53,0.12), rgba(255,59,59,0.08))', border: '1px solid rgba(255,107,53,0.2)', borderRadius: 28, padding: '64px 48px', boxShadow: '0 0 60px rgba(255,107,53,0.1)' }}>
          <h2 style={{ fontSize: 52, fontWeight: 900, color: '#fff', marginBottom: 16, lineHeight: 1.1 }}>
            Ready to protect your<br /><span className="gradient-text">organization?</span>
          </h2>
          <p style={{ fontSize: 16, color: 'rgba(255,255,255,0.4)', marginBottom: 40, maxWidth: 480, margin: '0 auto 40px' }}>
            Join hundreds of enterprise teams using Trustive AI to stay ahead of cyber threats.
          </p>
          <div style={{ display: 'flex', gap: 16, justifyContent: 'center' }}>
            <button onClick={() => navigate('/register')} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '16px 36px', borderRadius: 14, background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)', border: 'none', color: '#fff', cursor: 'pointer', fontSize: 16, fontWeight: 800, boxShadow: '0 8px 32px rgba(255,107,53,0.4)', transition: 'all 0.2s' }}>
              <Zap size={20} /> Start Free — No Credit Card
            </button>
          </div>
          <div style={{ display: 'flex', gap: 24, justifyContent: 'center', marginTop: 28 }}>
            {['Free 14-day trial', 'No setup fees', 'Cancel anytime'].map(item => (
              <div key={item} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <CheckCircle size={14} color="#00e5a0" />
                <span style={{ fontSize: 13, color: 'rgba(255,255,255,0.4)' }}>{item}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer style={{ padding: '40px', borderTop: '1px solid rgba(255,255,255,0.06)', position: 'relative', zIndex: 1 }}>
        <div style={{ maxWidth: 1200, margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 28, height: 28, borderRadius: 8, background: 'linear-gradient(135deg, #ff6b35, #ff3b3b)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Zap size={14} color="#fff" fill="#fff" />
            </div>
            <span style={{ fontSize: 15, fontWeight: 800, color: '#fff' }}>Trustive AI</span>
          </div>
          <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.25)' }}>© 2026 Trustive AI. All rights reserved.</div>
          <div style={{ display: 'flex', gap: 20 }}>
            {['Privacy', 'Terms', 'Security'].map(item => (
              <a key={item} href="#" style={{ fontSize: 13, color: 'rgba(255,255,255,0.3)', textDecoration: 'none', transition: 'color 0.2s' }}
                onMouseEnter={e => e.target.style.color = '#ff6b35'}
                onMouseLeave={e => e.target.style.color = 'rgba(255,255,255,0.3)'}
              >{item}</a>
            ))}
          </div>
        </div>
      </footer>
    </div>
  )
}