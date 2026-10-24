import React from 'react'

export default function StatsCards({ stats }) {
  const cards = [
    { label: 'Total Devices', value: stats.total_devices },
    { label: 'Vulnerabilities', value: stats.total_vulnerabilities },
    { label: 'Critical CVEs', value: stats.severity_distribution.critical || 0 },
    { label: 'Countries', value: Object.keys(stats.devices_by_country).length },
  ]

  return (
    <div className="stat-cards">
      {cards.map(c => (
        <div key={c.label} className="stat-card">
          <div className="label">{c.label}</div>
          <div className="value">{c.value.toLocaleString()}</div>
        </div>
      ))}
    </div>
  )
}
