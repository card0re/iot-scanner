import React from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

const COLORS = ['#3b82f6', '#ef4444', '#f97316', '#eab308', '#22c55e', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16']

export default function Charts({ stats }) {
  const typeData = Object.entries(stats.devices_by_type).map(([name, value]) => ({ name, value }))
  const severityData = Object.entries(stats.severity_distribution).map(([name, value]) => ({ name, value }))
  const cveData = (stats.top_cves || []).slice(0, 10)

  return (
    <div className="charts">
      <div className="chart-card">
        <h3>Devices by Type</h3>
        <ResponsiveContainer width="100%" height={250}>
          <PieChart>
            <Pie data={typeData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
              {typeData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
            </Pie>
            <Tooltip contentStyle={{ background: '#1a1d27', border: '1px solid #2a2d3a', color: '#e4e4e7' }} />
          </PieChart>
        </ResponsiveContainer>
      </div>

      <div className="chart-card">
        <h3>Severity Distribution</h3>
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={severityData}>
            <XAxis dataKey="name" tick={{ fill: '#8b8d98', fontSize: 12 }} />
            <YAxis tick={{ fill: '#8b8d98', fontSize: 12 }} />
            <Tooltip contentStyle={{ background: '#1a1d27', border: '1px solid #2a2d3a', color: '#e4e4e7' }} />
            <Bar dataKey="value" radius={[4, 4, 0, 0]}>
              {severityData.map((entry, i) => {
                const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#8b8d98' }
                return <Cell key={i} fill={colors[entry.name] || '#3b82f6'} />
              })}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {cveData.length > 0 && (
        <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
          <h3>Top CVEs by Frequency</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={cveData} layout="vertical">
              <XAxis type="number" tick={{ fill: '#8b8d98', fontSize: 12 }} />
              <YAxis dataKey="cve_id" type="category" tick={{ fill: '#8b8d98', fontSize: 11 }} width={140} />
              <Tooltip contentStyle={{ background: '#1a1d27', border: '1px solid #2a2d3a', color: '#e4e4e7' }} />
              <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}
