import React, { useState } from 'react'
import DeviceDetail from './DeviceDetail'
import DeviceConsole from './DeviceConsole'

function scoreClass(score) {
  if (score >= 50) return 'severity-critical'
  if (score >= 30) return 'severity-high'
  if (score >= 10) return 'severity-medium'
  return 'severity-low'
}

const WEB_PORTS = new Set([80, 443, 8080, 8443, 8888, 8000, 8081, 9090, 3000, 4443])

function getProxyUrl(ip, port) {
  if (!WEB_PORTS.has(port)) return null
  const scheme = [443, 8443, 4443].includes(port) ? 'https' : 'http'
  return `/api/proxy/${scheme}/${ip}/${port}/`
}

function getAliveWebUrl(d) {
  const alivePorts = d.alive_ports || []
  for (const p of alivePorts) {
    const url = getProxyUrl(d.ip, p)
    if (url) return url
  }
  return getProxyUrl(d.ip, d.port)
}

function getAllWebUrls(d) {
  const alivePorts = d.alive_ports || []
  return alivePorts
    .filter(p => WEB_PORTS.has(p))
    .map(p => getProxyUrl(d.ip, p))
    .filter(Boolean)
}

export default function DeviceTable({ devices, page, perPage, onPageChange, onPerPageChange, search, onSearchChange, loading, exploitedIps = {} }) {
  const [selected, setSelected] = useState(null)
  const [consoleIp, setConsoleIp] = useState(null)
  const [exploiting, setExploiting] = useState({})
  const [exploitMsg, setExploitMsg] = useState(null)

  async function autoExploit(deviceId) {
    setExploiting(prev => ({ ...prev, [deviceId]: true }))
    setExploitMsg(null)
    try {
      const r = await fetch('/api/exploited/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: deviceId }),
      })
      const data = await r.json()
      if (data.status === 'success') {
        setExploitMsg({ ok: true, text: `${data.ip}:${data.port} — ${data.access_level} via ${data.protocol} (${data.username}:${data.password})` })
      } else {
        setExploitMsg({ ok: false, text: `${data.ip} — no valid credentials found` })
      }
    } catch (e) {
      setExploitMsg({ ok: false, text: e.message })
    }
    setExploiting(prev => ({ ...prev, [deviceId]: false }))
  }

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

      {exploitMsg && (
        <div className={`exploit-toast ${exploitMsg.ok ? 'exploit-toast-ok' : 'exploit-toast-fail'}`}>
          {exploitMsg.ok ? 'ACCESS GAINED' : 'FAILED'}: {exploitMsg.text}
          <button className="exploit-toast-close" onClick={() => setExploitMsg(null)}>&times;</button>
        </div>
      )}

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
            const exploit = exploitedIps[d.ip]
            return (
              <tr key={d.id} className={`${selected?.id === d.id ? 'row-selected' : ''} ${!alive ? 'row-dead' : ''} ${exploit ? 'row-exploited' : ''}`}>
                <td>
                  <div className="status-cell">
                    <span className={`status-dot ${alive ? 'status-alive' : 'status-dead'}`} title={alive ? 'Alive' : 'Unreachable'} />
                    {exploit && (
                      <span
                        className={`exploit-badge exploit-badge-${exploit.access_level}`}
                        title={`${exploit.protocol.toUpperCase()} ${exploit.username}:${exploit.password || '(empty)'} — ${exploit.access_level}`}
                      >
                        {exploit.access_level === 'root' ? 'ROOT' : exploit.access_level === 'user' ? 'USER' : 'ACC'}
                      </span>
                    )}
                  </div>
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
                  <button className="btn-action btn-console" onClick={() => setConsoleIp(d.ip)} title="Open console">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
                    </svg>
                    Console
                  </button>
                  {webUrl && (
                    <a href={webUrl} target="_blank" rel="noopener noreferrer" className="btn-action btn-open" title="Open web UI">
                      Open
                    </a>
                  )}
                  <button className="btn-action btn-details" onClick={() => setSelected(selected?.id === d.id ? null : d)} title="View details">
                    Info
                  </button>
                  {exploit ? (
                    <span className="btn-action btn-owned" title={`${exploit.protocol.toUpperCase()} ${exploit.username}:${exploit.password || '(empty)'}`}>
                      Owned
                    </span>
                  ) : alive && alivePorts.some(p => [22, 23, 2222, 2323].includes(p)) && (
                    <button
                      className="btn-action btn-exploit"
                      onClick={() => autoExploit(d.id)}
                      disabled={exploiting[d.id]}
                      title="Try default credentials via SSH/Telnet"
                    >
                      {exploiting[d.id] ? '...' : 'Exploit'}
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
      {consoleIp && <DeviceConsole ip={consoleIp} onClose={() => setConsoleIp(null)} />}

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
