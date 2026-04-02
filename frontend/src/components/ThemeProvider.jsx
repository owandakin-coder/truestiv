import { createContext, useContext, useEffect, useState } from 'react'

const ThemeContext = createContext()

export function useTheme() {
  return useContext(ThemeContext)
}

export default function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark')
  const [accent, setAccent] = useState(localStorage.getItem('accent') || 'orange')

  const accentMap = {
    orange: { main: '#ff6b35', secondary: '#ff3b3b' },
    cyan: { main: '#00d4ff', secondary: '#7c3aed' },
    green: { main: '#00e5a0', secondary: '#3b82f6' },
    purple: { main: '#a78bfa', secondary: '#ec4899' },
  }

useEffect(() => {
  document.documentElement.setAttribute('data-theme', theme)
  if (theme === 'light') {
    document.body.style.background = '#f8fafc'
    document.body.style.color = '#0f172a'
  } else {
    document.body.style.background = '#050507'
    document.body.style.color = '#f1f5f9'
  }
}, [theme])

  useEffect(() => {
    const c = accentMap[accent] || accentMap.orange
    document.documentElement.style.setProperty('--accent-cyan', c.main)
    document.documentElement.style.setProperty('--accent-purple', c.secondary)
    document.documentElement.style.setProperty('--border-accent', c.main + '40')
    document.documentElement.style.setProperty('--glow-cyan', `0 0 40px ${c.main}25`)
    document.documentElement.style.setProperty('--orange', c.main)
  }, [accent])

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    localStorage.setItem('theme', next)
  }

  const changeAccent = (a) => {
    setAccent(a)
    localStorage.setItem('accent', a)
  }

  return (
    <ThemeContext.Provider value={{ theme, accent, toggleTheme, changeAccent }}>
      {children}
    </ThemeContext.Provider>
  )
}