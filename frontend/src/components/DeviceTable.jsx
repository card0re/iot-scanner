import React from 'react'

function scoreClass(score) {
  if (score >= 50) return 'severity-critical'
  if (score >= 30) return 'severity-high'
  if (score >= 10) return 'severity-medium'
  return 'severity-low'
}

export default function DeviceTable({ devices, page, onPageChange, loading }) {
  if (loading) return <div className="loading">Loading...</div>

  const totalPages = Math.ceil(devices.total / 50)

  return (
    <>
      <table className="device-table">
        <thead>
          <tr>
            <th>IP</th>
            <th>Port</th>
            <th>Type</th>
            <th>Manufacturer</th>
            <th>Country</th>
            <th>Vuln Score</th>
            <th>CVEs</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          {devices.items.map(d => (
            <tr key={d.id}>
              <td style={{ fontFamily: 'monospace' }}>{d.ip}</td>
              <td>{d.port}</td>
              <td>{d.device_type}</td>
              <td>{d.manufacturer || '—'}</td>
              <td>{d.country_code}</td>
              <td>
                <span className={`severity-badge ${scoreClass(d.vulnerability_score || 0)}`}>
                  {d.vulnerability_score?.toFixed(1) || '0'}
                </span>
              </td>
              <td>{d.vulnerabilities?.length || 0}</td>
              <td>{d.source}</td>
            </tr>
          ))}
          {devices.items.length === 0 && (
            <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: '#8b8d98' }}>No devices found</td></tr>
          )}
        </tbody>
      </table>

      {totalPages > 1 && (
        <div className="pagination">
          <button disabled={page <= 1} onClick={() => onPageChange(page - 1)}>Previous</button>
          <span style={{ padding: '8px 16px', color: '#8b8d98' }}>{page} / {totalPages}</span>
          <button disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>Next</button>
        </div>
      )}
    </>
  )
}
