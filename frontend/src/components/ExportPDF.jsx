import { useState } from 'react'
import { FileText, Download, Loader } from 'lucide-react'

export default function ExportPDF({ data, title = 'Trustive AI Report' }) {
  const [loading, setLoading] = useState(false)

  const generate = async () => {
    setLoading(true)
    try {
      const { jsPDF } = await import('jspdf')
      const doc = new jsPDF()

      // Header
      doc.setFillColor(5, 5, 7)
      doc.rect(0, 0, 210, 297, 'F')

      // Orange accent bar
      doc.setFillColor(255, 107, 53)
      doc.rect(0, 0, 210, 4, 'F')

      // Title
      doc.setTextColor(255, 255, 255)
      doc.setFontSize(24)
      doc.setFont('helvetica', 'bold')
      doc.text('Trustive AI', 20, 28)

      doc.setFontSize(12)
      doc.setFont('helvetica', 'normal')
      doc.setTextColor(150, 150, 150)
      doc.text('Security Intelligence Report', 20, 38)

      // Date
      doc.setFontSize(10)
      doc.text(`Generated: ${new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}`, 20, 48)

      // Divider
      doc.setDrawColor(255, 107, 53)
      doc.setLineWidth(0.5)
      doc.line(20, 54, 190, 54)

      // Stats Section
      doc.setTextColor(255, 107, 53)
      doc.setFontSize(14)
      doc.setFont('helvetica', 'bold')
      doc.text('Security Overview', 20, 68)

      const stats = [
        { label: 'Total Analyzed', value: data?.total_analyzed ?? 0 },
        { label: 'Threats Detected', value: data?.threats_detected ?? 0 },
        { label: 'Quarantined', value: data?.quarantined ?? 0 },
        { label: 'Safe Messages', value: data?.safe ?? 0 },
      ]

      let y = 80
      stats.forEach((stat, i) => {
        const x = i % 2 === 0 ? 20 : 110
        if (i % 2 === 0 && i > 0) y += 30

        doc.setFillColor(20, 20, 25)
        doc.roundedRect(x, y - 6, 80, 22, 3, 3, 'F')
        doc.setDrawColor(50, 50, 60)
        doc.setLineWidth(0.3)
        doc.roundedRect(x, y - 6, 80, 22, 3, 3, 'S')

        doc.setTextColor(255, 107, 53)
        doc.setFontSize(16)
        doc.setFont('helvetica', 'bold')
        doc.text(String(stat.value), x + 6, y + 6)

        doc.setTextColor(120, 120, 130)
        doc.setFontSize(8)
        doc.setFont('helvetica', 'normal')
        doc.text(stat.label, x + 6, y + 13)
      })

      y += 50

      // History Section
      if (data?.history?.length > 0) {
        doc.setDrawColor(255, 107, 53)
        doc.line(20, y, 190, y)
        y += 12

        doc.setTextColor(255, 107, 53)
        doc.setFontSize(14)
        doc.setFont('helvetica', 'bold')
        doc.text('Recent Analysis', 20, y)
        y += 12

        // Table header
        doc.setFillColor(30, 30, 40)
        doc.rect(20, y - 5, 170, 10, 'F')
        doc.setTextColor(150, 150, 160)
        doc.setFontSize(8)
        doc.setFont('helvetica', 'bold')
        doc.text('SENDER', 22, y + 2)
        doc.text('SUBJECT', 72, y + 2)
        doc.text('LEVEL', 142, y + 2)
        doc.text('CONFIDENCE', 162, y + 2)
        y += 12

        data.history.slice(0, 10).forEach((item, i) => {
          if (i % 2 === 0) {
            doc.setFillColor(15, 15, 20)
            doc.rect(20, y - 5, 170, 9, 'F')
          }

          const colors = {
            threat: [255, 59, 59],
            suspicious: [251, 191, 36],
            safe: [0, 229, 160]
          }
          const c = colors[item.threat_level] || [150, 150, 150]

          doc.setTextColor(200, 200, 210)
          doc.setFontSize(8)
          doc.setFont('helvetica', 'normal')
          doc.text((item.sender || '').slice(0, 22), 22, y + 1)
          doc.text((item.subject || '').slice(0, 30), 72, y + 1)

          doc.setTextColor(...c)
          doc.setFont('helvetica', 'bold')
          doc.text((item.threat_level || '').toUpperCase(), 142, y + 1)

          doc.setTextColor(200, 200, 210)
          doc.setFont('helvetica', 'normal')
          doc.text(`${item.confidence || 0}%`, 168, y + 1)

          y += 9
        })
      }

      // Footer
      doc.setFillColor(255, 107, 53)
      doc.rect(0, 290, 210, 7, 'F')
      doc.setTextColor(255, 255, 255)
      doc.setFontSize(8)
      doc.setFont('helvetica', 'normal')
      doc.text('Trustive AI — Confidential Security Report', 20, 295)
      doc.text(`Page 1 of 1`, 175, 295)

      doc.save(`trustive-report-${new Date().toISOString().split('T')[0]}.pdf`)
    } catch (err) {
      console.error('PDF error:', err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <button onClick={generate} disabled={loading} style={{
      display: 'flex', alignItems: 'center', gap: 8, padding: '10px 18px',
      borderRadius: 12, border: '1px solid rgba(255,107,53,0.3)',
      background: 'rgba(255,107,53,0.08)', color: '#ff6b35',
      cursor: loading ? 'not-allowed' : 'pointer', fontSize: 13, fontWeight: 700,
      transition: 'all 0.2s', opacity: loading ? 0.7 : 1
    }}
      onMouseEnter={e => { if (!loading) { e.currentTarget.style.background = 'rgba(255,107,53,0.15)'; e.currentTarget.style.boxShadow = '0 0 20px rgba(255,107,53,0.2)' } }}
      onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,107,53,0.08)'; e.currentTarget.style.boxShadow = 'none' }}
    >
      {loading ? <Loader size={15} style={{ animation: 'spin 1s linear infinite' }} /> : <Download size={15} />}
      {loading ? 'Generating...' : 'Export PDF'}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </button>
  )
}