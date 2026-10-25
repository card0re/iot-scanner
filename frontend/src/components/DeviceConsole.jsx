import React, { useState, useEffect, useRef } from 'react'

const SEV_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#8b8d98' }

export default function DeviceConsole({ ip, onClose }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [httpDetail, setHttpDetail] = useState(null)
  const [httpLoading, setHttpLoading] = useState(false)
  const [customUrl, setCustomUrl] = useState('')
  const [customResult, setCustomResult] = useState(null)
  const [customLoading, setCustomLoading] = useState(false)
  const logRef = useRef(null)

  useEffect(() => {
    loadProbe()
  }, [ip])

  async function loadProbe() {
    setLoading(true)
    setError(null)
    try {
      const r = await fetch(`/api/probe/${ip}`)
      if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
      setData(await r.json())
    } catch (e) {
      setError(e.message)
    }
    setLoading(false)
  }

  async function probeHttp(port) {
    setHttpLoading(true)
    setHttpDetail(null)
    try {
      const r = await fetch(`/api/probe/${ip}/http/${port}`)
      setHttpDetail(await r.json())
    } catch (e) {
      setHttpDetail({ error: e.message })
    }
    setHttpLoading(false)
  }

  async function sendCustom() {
    if (!customUrl.trim()) return
    setCustomLoading(true)
    setCustomResult(null)
    let url = customUrl.trim()
    if (!url.startsWith('http')) url = `http://${ip}${url.startsWith('/') ? '' : ':'}${url}`
    try {
      const port = new URL(url).port || (url.startsWith('https') ? 443 : 80)
      const r = await fetch(`/api/probe/${ip}/http/${port}`)
      setCustomResult(await r.json())
    } catch (e) {
      setCustomResult({ error: e.message })
    }
    setCustomLoading(false)
  }

  const dev = data?.device
  const scoreColor = (s) => s >= 50 ? '#ef4444' : s >= 30 ? '#f97316' : s >= 10 ? '#eab308' : '#22c55e'

  return (
    <div className="console-overlay" onClick={onClose}>
      <div className="console-panel" onClick={e => e.stopPropagation()}>
        <div className="console-header">
          <div className="console-title">
            <span className="console-prompt">$</span>
            <span className="console-ip">{ip}</span>
            {dev && (
              <>
                <span className="console-tag">{dev.type}</span>
                <span className="console-tag">{dev.country}</span>
                <span className="console-score" style={{ color: scoreColor(dev.score) }}>
                  [{dev.score.toFixed(1)}]
                </span>
              </>
            )}
          </div>
          <div className="console-actions">
            <button className="console-btn" onClick={loadProbe} title="Refresh">refresh</button>
            <button className="console-btn console-close" onClick={onClose}>&times;</button>
          </div>
        </div>

        <div className="console-body" ref={logRef}>
          {loading && <div className="console-line console-info">Probing {ip}...</div>}
          {error && <div className="console-line console-error">ERROR: {error}</div>}

          {data && (
            <>
              {/* Device info */}
              {dev && (
                <div className="console-section">
                  <div className="console-line console-info">--- Device Info ---</div>
                  <div className="console-line">IP:           {dev.ip}</div>
                  <div className="console-line">Type:         {dev.type} ({dev.manufacturer} / {dev.model})</div>
                  <div className="console-line">Firmware:     {dev.firmware}</div>
                  <div className="console-line">Location:     {dev.country} | {dev.org} | ASN {dev.asn}</div>
                  <div className="console-line">HTTP Title:   {dev.http_title || '—'}</div>
                  <div className="console-line">First Seen:   {dev.first_seen || '—'}</div>
                  <div className="console-line">Last Seen:    {dev.last_seen || '—'}</div>
                  {dev.banner && (
                    <>
                      <div className="console-line console-info">--- Stored Banner ---</div>
                      <pre className="console-pre">{dev.banner}</pre>
                    </>
                  )}
                </div>
              )}

              {/* Alive ports */}
              <div className="console-section">
                <div className="console-line console-info">--- Port Scan ({data.alive_ports.length} alive) ---</div>
                {data.alive_ports.length === 0 && (
                  <div className="console-line console-dim">No alive ports detected</div>
                )}
                {data.alive_ports.map(p => (
                  <div key={p} className="console-line">
                    <span className="console-port-num">{String(p).padStart(5)}/tcp</span>
                    <span className="console-port-svc">{data.port_services[String(p)] || 'unknown'}</span>
                    {data.management_ports.some(m => m.port === p) && (
                      <span className="console-mgmt-tag">MGMT</span>
                    )}
                    {data.banners[String(p)] && (
                      <span className="console-banner-inline" title={data.banners[String(p)]}>
                        {data.banners[String(p)].slice(0, 60)}
                      </span>
                    )}
                    {[80, 443, 8080, 8443, 8888, 8000, 8081].includes(p) && (
                      <button className="console-btn-sm" onClick={() => probeHttp(p)}>
                        HTTP &rarr;
                      </button>
                    )}
                  </div>
                ))}
              </div>

              {/* Management ports */}
              {data.management_ports.length > 0 && (
                <div className="console-section">
                  <div className="console-line console-warn">--- Management Ports ---</div>
                  {data.management_ports.map(m => (
                    <div key={m.port} className="console-line">
                      <span className="console-port-num">{String(m.port).padStart(5)}/tcp</span>
                      <span className="console-mgmt-tag">{m.service}</span>
                      {data.banners[String(m.port)] && (
                        <pre className="console-pre">{data.banners[String(m.port)]}</pre>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Banners */}
              {Object.keys(data.banners).length > 0 && (
                <div className="console-section">
                  <div className="console-line console-info">--- Service Banners ---</div>
                  {Object.entries(data.banners).map(([port, banner]) => (
                    <div key={port}>
                      <div className="console-line console-dim">Port {port}:</div>
                      <pre className="console-pre">{banner}</pre>
                    </div>
                  ))}
                </div>
              )}

              {/* HTTP probes */}
              {data.http_probes.length > 0 && (
                <div className="console-section">
                  <div className="console-line console-info">--- HTTP Probes ---</div>
                  {data.http_probes.map((h, i) => (
                    <div key={i} className="console-http-block">
                      <div className="console-line">
                        <span className={`console-status ${h.status >= 200 && h.status < 400 ? 'console-ok' : 'console-error'}`}>
                          {h.status || 'ERR'}
                        </span>
                        <span>{h.url}</span>
                        {h.server && <span className="console-dim"> ({h.server})</span>}
                        <button className="console-btn-sm" onClick={() => probeHttp(h.port)}>
                          Full &rarr;
                        </button>
                      </div>
                      {h.error && <div className="console-line console-error">{h.error}</div>}
                    </div>
                  ))}
                </div>
              )}

              {/* Vulnerabilities */}
              {dev && dev.vulns && dev.vulns.length > 0 && (
                <div className="console-section">
                  <div className="console-line console-warn">--- Vulnerabilities ({dev.vulns.length}) ---</div>
                  {dev.vulns.map((v, i) => (
                    <div key={i} className="console-line">
                      <span style={{ color: SEV_COLORS[v.severity] || '#8b8d98' }}>
                        [{v.severity.toUpperCase()}]
                      </span>
                      <a href={`https://nvd.nist.gov/vuln/detail/${v.cve}`} target="_blank" rel="noopener noreferrer"
                        className="console-cve">{v.cve}</a>
                      {v.cvss && <span className="console-dim"> CVSS:{v.cvss}</span>}
                      {v.rce && <span className="console-rce-tag">RCE</span>}
                      {v.desc && <span className="console-dim"> {v.desc.slice(0, 80)}</span>}
                    </div>
                  ))}
                </div>
              )}

              {/* RCE vulns highlight */}
              {data.rce_vulns.length > 0 && (
                <div className="console-section">
                  <div className="console-line console-error">--- RCE Vulnerabilities ({data.rce_vulns.length}) ---</div>
                  {data.rce_vulns.map((v, i) => (
                    <div key={i} className="console-line">
                      <span className="console-rce-tag">RCE</span>
                      <a href={`https://nvd.nist.gov/vuln/detail/${v.cve}`} target="_blank" rel="noopener noreferrer"
                        className="console-cve">{v.cve}</a>
                      <span className="console-dim"> {v.desc}</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}

          {/* HTTP detail viewer */}
          {httpLoading && <div className="console-line console-info">Fetching HTTP response...</div>}
          {httpDetail && (
            <div className="console-section">
              <div className="console-line console-info">--- HTTP Response (:{httpDetail.port}) ---</div>
              {httpDetail.error ? (
                <div className="console-line console-error">{httpDetail.error}</div>
              ) : (
                <>
                  <div className="console-line">
                    <span className={`console-status ${httpDetail.status >= 200 && httpDetail.status < 400 ? 'console-ok' : 'console-error'}`}>
                      HTTP {httpDetail.status}
                    </span>
                    <span className="console-dim">{httpDetail.content_type}</span>
                  </div>
                  {httpDetail.headers && (
                    <pre className="console-pre console-headers">
                      {Object.entries(httpDetail.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}
                    </pre>
                  )}
                  {httpDetail.body_preview && (
                    <>
                      <div className="console-line console-dim">--- Body ---</div>
                      <pre className="console-pre console-body-preview">{httpDetail.body_preview}</pre>
                    </>
                  )}
                </>
              )}
            </div>
          )}

          {/* Custom HTTP probe */}
          {customResult && (
            <div className="console-section">
              <div className="console-line console-info">--- Custom Probe Result ---</div>
              {customResult.error ? (
                <div className="console-line console-error">{customResult.error}</div>
              ) : (
                <>
                  <div className="console-line">
                    <span className={`console-status ${customResult.status >= 200 && customResult.status < 400 ? 'console-ok' : 'console-error'}`}>
                      HTTP {customResult.status}
                    </span>
                  </div>
                  {customResult.headers && (
                    <pre className="console-pre console-headers">
                      {Object.entries(customResult.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}
                    </pre>
                  )}
                  {customResult.body_preview && (
                    <pre className="console-pre console-body-preview">{customResult.body_preview}</pre>
                  )}
                </>
              )}
            </div>
          )}
        </div>

        {/* Custom request input */}
        <div className="console-input-bar">
          <span className="console-prompt">$</span>
          <span className="console-dim">curl&nbsp;</span>
          <input
            className="console-input"
            placeholder={`http://${ip}/path or just :port`}
            value={customUrl}
            onChange={e => setCustomUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && sendCustom()}
          />
          <button className="console-btn" onClick={sendCustom} disabled={customLoading}>
            {customLoading ? '...' : 'Send'}
          </button>
        </div>
      </div>
    </div>
  )
}
