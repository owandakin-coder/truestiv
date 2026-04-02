import { useState, useEffect } from 'react'
import { Zap, Shield, Globe, Search, ArrowRight, Check, X } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

const steps = [
  {
    id: 1,
    icon: <Zap size={40} />,
    color: '#ff6b35',
    title: 'Welcome to Trustive AI',
    subtitle: 'Your AI-powered security platform',
    description: 'Protect your organization from phishing, malware, and social engineering attacks in real-time.',
    action: null
  },
  {
    id: 2,
    icon: <Shield size={40} />,
    color: '#ff3b3b',
    title: 'Analyze Threats',
    subtitle: 'AI detects threats instantly',
    description: 'Paste any email, SMS or WhatsApp message and our AI will analyze it for threats in under a second.',
    action: { label: 'Try Analysis', path: '/analysis' }
  },
  {
    id: 3,
    icon: <Search size={40} />,
    color: '#a78bfa',
    title: 'Scan URLs & Files',
    subtitle: 'Advanced scanner tools',
    description: 'Check suspicious URLs, IP addresses and files before they cause damage to your organization.',
    action: { label: 'Open Scanner', path: '/scanner' }
  },
  {
    id: 4,
    icon: <Globe size={40} />,
    color: '#3b82f6',
    title: 'Community Intelligence',
    subtitle: 'Shared threat data',
    description: 'Share and receive threat intelligence from the security community to stay ahead of new attacks.',
    action: { label: 'View Feed', path: '/community' }
  },
  {
    id: 5,
    icon: <Check size={40} />,
    color: '#00e5a0',
    title: "You're all set!",
    subtitle: 'Start protecting your organization',
    description: 'Your dashboard is ready. Start by analyzing your first email or scanning a suspicious URL.',
    action: { label: 'Go to Dashboard', path: '/' }
  }
]

export default function Onboarding({ onComplete }) {
  const [step, setStep] = useState(0)
  const [animating, setAnimating] = useState(false)
  const navigate = useNavigate()
  const current = steps[step]

  const next = () => {
    if (animating) return
    if (step === steps.length - 1) {
      localStorage.setItem('onboarding_done', 'true')
      onComplete()
      return
    }
    setAnimating(true)
    setTimeout(() => { setStep(s => s + 1); setAnimating(false) }, 300)
  }

  const skip = () => {
    localStorage.setItem('onboarding_done', 'true')
    onComplete()
  }

  const goTo = (path) => {
    localStorage.setItem('onboarding_done', 'true')
    onComplete()
    navigate(path)
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(20px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 20
    }}>
      {/* Particles */}
      {[...Array(12)].map((_, i) => (
        <div key={i} style={{
          position: 'absolute',
          left: `${Math.random() * 100}%`,
          top: `${Math.random() * 100}%`,
          width: Math.random() * 4 + 1,
          height: Math.random() * 4 + 1,
          borderRadius: '50%',
          background: current.color,
          opacity: 0.3,
          animation: `float ${Math.random() * 4 + 3}s ease-in-out ${Math.random() * 2}s infinite`,
          pointerEvents: 'none'
        }} />
      ))}

      <div style={{
        width: '100%', maxWidth: 520,
        background: 'rgba(10,10,12,0.98)',
        border: `1px solid ${current.color}30`,
        borderRadius: 28, overflow: 'hidden',
        boxShadow: `0 40px 80px rgba(0,0,0,0.6), 0 0 60px ${current.color}15`,
        animation: animating ? 'fadeIn 0.3s ease' : 'fadeInUp 0.4s ease'
      }}>

        {/* Progress bar */}
        <div style={{ height: 3, background: 'rgba(255,255,255,0.06)' }}>
          <div style={{
            height: '100%',
            width: `${((step + 1) / steps.length) * 100}%`,
            background: `linear-gradient(90deg, ${current.color}, ${current.color}88)`,
            transition: 'width 0.4s cubic-bezier(0.4,0,0.2,1)',
            boxShadow: `0 0 10px ${current.color}60`
          }} />
        </div>

        {/* Content */}
        <div style={{ padding: '48px 44px' }}>

          {/* Icon */}
          <div style={{
            width: 80, height: 80, borderRadius: 24,
            background: `${current.color}15`,
            border: `1px solid ${current.color}30`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: current.color, marginBottom: 28,
            boxShadow: `0 0 30px ${current.color}20`,
            filter: `drop-shadow(0 0 12px ${current.color}60)`
          }}>
            {current.icon}
          </div>

          {/* Step indicator */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 20 }}>
            {steps.map((_, i) => (
              <div key={i} style={{
                height: 4, borderRadius: 2,
                flex: i === step ? 2 : 1,
                background: i <= step ? current.color : 'rgba(255,255,255,0.08)',
                transition: 'all 0.4s ease',
                boxShadow: i === step ? `0 0 8px ${current.color}60` : 'none'
              }} />
            ))}
          </div>

          <div style={{ fontSize: 12, color: current.color, fontWeight: 700, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 10 }}>
            Step {step + 1} of {steps.length}
          </div>

          <h2 style={{ fontSize: 32, fontWeight: 900, color: '#fff', marginBottom: 8, lineHeight: 1.1 }}>
            {current.title}
          </h2>
          <div style={{ fontSize: 15, color: current.color, fontWeight: 600, marginBottom: 16 }}>
            {current.subtitle}
          </div>
          <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.5)', lineHeight: 1.7, marginBottom: 36 }}>
            {current.description}
          </p>

          {/* Actions */}
          <div style={{ display: 'flex', gap: 12 }}>
            <button onClick={next} style={{
              flex: 1, padding: '14px', borderRadius: 14, border: 'none', cursor: 'pointer',
              background: `linear-gradient(135deg, ${current.color}, ${current.color}88)`,
              color: '#fff', fontSize: 15, fontWeight: 800,
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              boxShadow: `0 8px 24px ${current.color}30`, transition: 'all 0.2s'
            }}>
              {step === steps.length - 1 ? 'Get Started!' : 'Continue'}
              <ArrowRight size={18} />
            </button>

            {current.action && (
              <button onClick={() => goTo(current.action.path)} style={{
                padding: '14px 20px', borderRadius: 14, cursor: 'pointer',
                background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)',
                color: 'rgba(255,255,255,0.7)', fontSize: 14, fontWeight: 700, transition: 'all 0.2s'
              }}>
                {current.action.label}
              </button>
            )}
          </div>
        </div>

        {/* Footer */}
        <div style={{ padding: '16px 44px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid rgba(255,255,255,0.04)' }}>
          <button onClick={skip} style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.25)', cursor: 'pointer', fontSize: 13, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
            <X size={13} /> Skip tour
          </button>
          <div style={{ display: 'flex', gap: 6 }}>
            {steps.map((_, i) => (
              <div key={i} onClick={() => setStep(i)} style={{
                width: i === step ? 20 : 6, height: 6, borderRadius: 3,
                background: i === step ? current.color : i < step ? `${current.color}50` : 'rgba(255,255,255,0.1)',
                transition: 'all 0.3s', cursor: 'pointer',
                boxShadow: i === step ? `0 0 8px ${current.color}` : 'none'
              }} />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}