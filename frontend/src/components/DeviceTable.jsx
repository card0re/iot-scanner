import React, { useState } from 'react'
import DeviceDetail from './DeviceDetail'

function scoreClass(score) {
  if (score >= 50) return 'severity-critical'
  if (score >= 30) return 'severity-high'
  if (score >= 10) return 'severity-medium'
  return 'severity-low'
}

const WEB_PORTS = new Set([80, 443, 8080, 8443, 8888, 8000, 8081, 9090, 3000, 4443])

function getWebUrl(ip, port) {
  if (!WEB_PORTS.has(port)) return null
  const proto = [443, 8443, 4443].includes(port) ? 'https' : 'http'
  const portPart = (proto === 'http' && port === 80) || (proto === 'https' && port === 443) ? '' : `:${port}`
  return `${proto}://${ip}${portPart}`
}

function getAliveWebUrl(d) {
  const alivePorts = d.alive_ports || []
  for (const p of alivePorts) {
    if (WEB_PORTS.has(p)) return getWebUrl(d.ip, p)
  }
  return getWebUrl(d.ip, d.port)
}

export default function DeviceTable({ devices, page, perPage, onPageChange, onPerPageChange, search, onSearchChange, loading }) {
  const [selected, setSelected] = useState(null)

  const totalPages = Math.ceil(devices.total / (perPage || 50))

  return (
    <>
      <div className="device-toolbar">
        <div className="device-toolbar-left">
          <span className="device-total-badge">{devices.total} devices</span>
          <input
            type="text"
            className="device-search"
            placeholder="Search IP, manufacturer, org..."
            value={search || ''}
            onChange={e => onSearchChange?.(e.target.value)}
          />
        </div>
        <div className="device-toolbar-right">
          <label className="device-per-page">
            <select value={perPage || 50} onChange={e => onPerPageChange?.(Number(e.target.value))}>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
            <span>/ page</span>
          </label>
        </div>
      </div>

      {loading && <div className="loading">Loading...</div>}

      <table className="device-table" style={{ display: loading ? 'none' : undefined }}>
        <thead>
          <tr>
            <th>Status</th>
            <th>IP</th>
            <th>Ports</th>
            <th>Type</th>
            <th>Title</th>
            <th>Country</th>
            <th>Score</th>
            <th>CVEs</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {devices.items.map(d => {
            const alive = d.is_alive
            const webUrl = getAliveWebUrl(d)
            const alivePorts = d.alive_ports || []
            return (
              <tr key={d.id} className={`${selected?.id === d.id ? 'row-selected' : ''} ${!alive ? 'row-dead' : ''}`}>
                <td>
                  <span className={`status-dot ${alive ? 'status-alive' : 'status-dead'}`} title={alive ? 'Alive' : 'Unreachable'} />
                </td>
                <td style={{ fontFamily: 'monospace' }}>{d.ip}</td>
                <td>
                  <span className="port-compact">
                    {alivePorts.length > 0
                      ? alivePorts.slice(0, 5).join(', ') + (alivePorts.length > 5 ? '...' : '')
                      : <span style={{ color: '#555' }}>{d.port}</span>
                    }
                  </span>
                </td>
                <td><span className="type-badge">{d.device_type}</span></td>
                <td className="title-cell">{d.http_title || '—'}</td>
                <td>{d.country_code}</td>
                <td>
                  <span className={`severity-badge ${scoreClass(d.vulnerability_score || 0)}`}>
                    {d.vulnerability_score?.toFixed(1) || '0'}
                  </span>
                </td>
                <td>{d.vulnerabilities?.length || 0}</td>
                <td className="actions-cell">
                  {alive && webUrl && (
                    <a href={webUrl} target="_blank" rel="noopener noreferrer" className="btn-action btn-open" title="Open web interface">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                      </svg>
                      Open
                    </a>
                  )}
                  <button className="btn-action btn-details" onClick={() => setSelected(selected?.id === d.id ? null : d)} title="View details">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
                    </svg>
                    Info
                  </button>
                  {alive && alivePorts.some(p => WEB_PORTS.has(p)) && (
                    <button
                      className="btn-action btn-ports"
                      onClick={() => {
                        alivePorts
                          .filter(p => WEB_PORTS.has(p))
                          .map(p => getWebUrl(d.ip, p))
                          .forEach(u => window.open(u, '_blank'))
                      }}
                      title="Open all live web ports"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
                      </svg>
                      Browse
                    </button>
                  )}
                </td>
              </tr>
            )
          })}
          {devices.items.length === 0 && (
            <tr><td colSpan={9} style={{ textAlign: 'center', padding: 40, color: '#8b8d98' }}>No devices found</td></tr>
          )}
        </tbody>
      </table>

      {selected && <DeviceDetail device={selected} onClose={() => setSelected(null)} />}

      {totalPages > 1 && (
        <div className="pagination">
          <button disabled={page <= 1} onClick={() => onPageChange(1)} title="First">&laquo;</button>
          <button disabled={page <= 1} onClick={() => onPageChange(page - 1)}>&lsaquo; Prev</button>
          {(() => {
            const pages = []
            let start = Math.max(1, page - 2)
            let end = Math.min(totalPages, page + 2)
            if (start > 1) pages.push(<span key="ds" className="page-dots">...</span>)
            for (let i = start; i <= end; i++) {
              pages.push(
                <button key={i} className={i === page ? 'page-active' : ''} onClick={() => onPageChange(i)}>{i}</button>
              )
            }
            if (end < totalPages) pages.push(<span key="de" className="page-dots">...</span>)
            return pages
          })()}
          <button disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>Next &rsaquo;</button>
          <button disabled={page >= totalPages} onClick={() => onPageChange(totalPages)} title="Last">&raquo;</button>
        </div>
      )}
    </>
  )
}
