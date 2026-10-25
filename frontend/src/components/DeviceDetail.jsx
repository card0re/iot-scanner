import React, { useState } from 'react'

const WEB_PORTS = new Set([80, 443, 8080, 8443, 8888, 8000, 8081, 9090, 3000, 4443])
const SERVICE_PORTS = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  80: 'HTTP', 110: 'POP3', 143: 'IMAP', 161: 'SNMP', 443: 'HTTPS',
  502: 'Modbus', 554: 'RTSP', 631: 'IPP', 1883: 'MQTT', 3306: 'MySQL',
  3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt', 8554: 'RTSP-Alt', 9100: 'JetDirect',
}

function sevColor(sev) {
  const m = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#8b8d98' }
  return m[sev] || '#8b8d98'
}

export default function DeviceDetail({ device, onClose }) {
  const [checking, setChecking] = useState(false)
  const [checkResult, setCheckResult] = useState(null)
  const d = device
  const allPorts = d.open_ports || [d.port]

  function proxyUrl(ip, port) {
    const scheme = [443, 8443, 4443].includes(port) ? 'https' : 'http'
    return `/api/proxy/${scheme}/${ip}/${port}/`
  }

  async function quickCheck() {
    setChecking(true)
    setCheckResult(null)
    const results = []
    for (const port of allPorts.slice(0, 10)) {
      const url = proxyUrl(d.ip, port)
      try {
        const ctrl = new AbortController()
        const tid = setTimeout(() => ctrl.abort(), 12000)
        const r = await fetch(url, { signal: ctrl.signal })
        clearTimeout(tid)
        results.push({ port, status: r.ok ? 'reachable' : 'error', service: SERVICE_PORTS[port] || '?' })
      } catch {
        results.push({ port, status: 'timeout', service: SERVICE_PORTS[port] || '?' })
      }
    }
    setCheckResult(results)
    setChecking(false)
  }

  return (
    <div className="detail-overlay" onClick={onClose}>
      <div className="detail-panel" onClick={e => e.stopPropagation()}>
        <div className="detail-header">
          <h2>{d.ip}</h2>
          <button className="detail-close" onClick={onClose}>&times;</button>
        </div>

        <div className="detail-grid">
          <div className="detail-field">
            <span className="detail-label">Type</span>
            <span className="detail-value">{d.device_type} {d.device_type_confidence ? `(${(d.device_type_confidence * 100).toFixed(0)}%)` : ''}</span>
          </div>
          <div className="detail-field">
            <span className="detail-label">Country</span>
            <span className="detail-value">{d.country_code}</span>
          </div>
          <div className="detail-field">
            <span className="detail-label">Manufacturer</span>
            <span className="detail-value">{d.manufacturer || 'Unknown'}</span>
          </div>
          <div className="detail-field">
            <span className="detail-label">Firmware</span>
            <span className="detail-value">{d.firmware_version || 'Unknown'}</span>
          </div>
          <div className="detail-field">
            <span className="detail-label">ASN / Org</span>
            <span className="detail-value">{d.asn || '—'} / {d.org || '—'}</span>
          </div>
          <div className="detail-field">
            <span className="detail-label">Source</span>
            <span className="detail-value">{d.source}</span>
          </div>
          <div className="detail-field">
            <span className="detail-label">Vuln Score</span>
            <span className="detail-value" style={{ fontSize: '1.25rem', fontWeight: 700 }}>
              {d.vulnerability_score?.toFixed(1) || '0'}
            </span>
          </div>
          <div className="detail-field">
            <span className="detail-label">First Seen</span>
            <span className="detail-value">{new Date(d.first_seen).toLocaleDateString()}</span>
          </div>
        </div>

        <div className="detail-section">
          <h3>Open Ports</h3>
          <div className="port-list">
            {allPorts.map(p => {
              const isWeb = WEB_PORTS.has(p)
              return (
                <div key={p} className="port-chip">
                  <span className="port-num">{p}</span>
                  <span className="port-svc">{SERVICE_PORTS[p] || '?'}</span>
                  {isWeb && (
                    <a href={proxyUrl(d.ip, p)} target="_blank" rel="noopener noreferrer" className="port-link" title={`Open via proxy :${p}`}>
                      &rarr;
                    </a>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        <div className="detail-section">
          <h3>Quick Check</h3>
          <button className="btn-action btn-check" onClick={quickCheck} disabled={checking}>
            {checking ? 'Checking...' : 'Check reachability'}
          </button>
          {checkResult && (
            <div className="check-results">
              {checkResult.map(r => (
                <div key={r.port} className={`check-row check-${r.status}`}>
                  <span>{r.port} ({r.service})</span>
                  <span className="check-status">{r.status === 'reachable' ? 'LIVE' : 'N/A'}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {d.vulnerabilities?.length > 0 && (
          <div className="detail-section">
            <h3>Vulnerabilities ({d.vulnerabilities.length})</h3>
            <div className="vuln-list">
              {d.vulnerabilities.map(v => (
                <div key={v.id} className="vuln-row">
                  <div className="vuln-header">
                    <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noopener noreferrer" className="vuln-cve">
                      {v.cve_id}
                    </a>
                    <span className="vuln-sev" style={{ color: sevColor(v.severity) }}>
                      {v.severity?.toUpperCase()} {v.cvss_score ? `(${v.cvss_score})` : ''}
                    </span>
                  </div>
                  {v.description && <p className="vuln-desc">{v.description}</p>}
                </div>
              ))}
            </div>
          </div>
        )}

        {d.banner && (
          <div className="detail-section">
            <h3>Banner</h3>
            <pre className="banner-pre">{d.banner}</pre>
          </div>
        )}
      </div>
    </div>
  )
}
