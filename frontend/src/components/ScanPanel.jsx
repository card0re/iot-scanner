import React, { useState, useEffect, useRef } from 'react'

export default function ScanPanel({ onScanComplete }) {
  const [active, setActive] = useState(false)
  const [status, setStatus] = useState(null)
  const [logs, setLogs] = useState([])
  const [elapsed, setElapsed] = useState(0)
  const logEndRef = useRef(null)
  const timerRef = useRef(null)
  const pollRef = useRef(null)

  const [proxyUrl, setProxyUrl] = useState('')
  const [proxyStatus, setProxyStatus] = useState(null)
  const [proxyTesting, setProxyTesting] = useState(false)
  const [proxySaving, setProxySaving] = useState(false)
  const [showProxy, setShowProxy] = useState(false)

  useEffect(() => {
    fetch('/api/scans/proxy').then(r => r.json()).then(data => {
      setProxyUrl(data.proxy_url || '')
      if (data.configured) setProxyStatus({ status: 'ok', message: 'Configured' })
    }).catch(() => {})
    return () => {
      clearInterval(timerRef.current)
      clearInterval(pollRef.current)
    }
  }, [])

  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs])

  async function startScan() {
    setActive(true)
    setLogs([])
    setElapsed(0)
    setStatus(null)

    try {
      const res = await fetch('/api/scans/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      })
      const data = await res.json()
      if (data.status === 'already_running') {
        setLogs([{ time: new Date().toISOString(), message: 'Scan already in progress...', level: 'warn' }])
      }
    } catch (e) {
      setLogs([{ time: new Date().toISOString(), message: `Failed to trigger: ${e.message}`, level: 'error' }])
      setActive(false)
      return
    }

    timerRef.current = setInterval(() => setElapsed(e => e + 1), 1000)

    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch('/api/scans/status')
        const data = await res.json()
        setStatus(data)
        setLogs(data.log || [])
        if (!data.active) {
          clearInterval(timerRef.current)
          clearInterval(pollRef.current)
          setActive(false)
          onScanComplete?.()
        }
      } catch {}
    }, 1500)
  }

  async function saveProxy() {
    setProxySaving(true)
    try {
      const res = await fetch('/api/scans/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxy_url: proxyUrl }),
      })
      const data = await res.json()
      if (data.status === 'ok') {
        setProxyStatus({ status: 'ok', message: proxyUrl ? 'Saved' : 'Proxy removed' })
      }
    } catch (e) {
      setProxyStatus({ status: 'error', message: e.message })
    }
    setProxySaving(false)
  }

  async function testProxy() {
    setProxyTesting(true)
    setProxyStatus(null)
    try {
      const res = await fetch('/api/scans/proxy/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxy_url: proxyUrl }),
      })
      const data = await res.json()
      setProxyStatus(data)
    } catch (e) {
      setProxyStatus({ status: 'error', message: e.message })
    }
    setProxyTesting(false)
  }

  function formatTime(s) {
    const m = Math.floor(s / 60)
    const sec = s % 60
    return `${m}:${sec.toString().padStart(2, '0')}`
  }

  return (
    <div className="scan-panel">
      <div className="scan-header">
        <div className="scan-title-row">
          {active && <div className="pulse-dot" />}
          <h2>{active ? 'Scan in Progress' : 'Scanner'}</h2>
          {active && <span className="scan-timer">{formatTime(elapsed)}</span>}
        </div>
        <div className="scan-header-actions">
          <button className="btn-proxy-toggle" onClick={() => setShowProxy(p => !p)}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
            {proxyUrl ? <span className="proxy-dot proxy-dot-on" /> : null}
          </button>
          <button className="btn-scan" onClick={startScan} disabled={active}>
            {active ? (
              <span className="btn-scan-active">
                <span className="spinner" />
                Scanning...
              </span>
            ) : 'Run Scan'}
          </button>
        </div>
      </div>

      {showProxy && (
        <div className="proxy-settings">
          <div className="proxy-row">
            <input
              type="text"
              className="proxy-input"
              placeholder="socks5://user:pass@host:port  or  http://host:port"
              value={proxyUrl}
              onChange={e => setProxyUrl(e.target.value)}
              spellCheck={false}
            />
            <button className="btn-action btn-proxy-save" onClick={saveProxy} disabled={proxySaving}>
              {proxySaving ? '...' : 'Save'}
            </button>
            <button className="btn-action btn-proxy-test" onClick={testProxy} disabled={proxyTesting || !proxyUrl}>
              {proxyTesting ? 'Testing...' : 'Test'}
            </button>
          </div>
          {proxyStatus && (
            <div className={`proxy-result proxy-result-${proxyStatus.status}`}>
              {proxyStatus.status === 'ok' ? '✓' : '✗'} {proxyStatus.message}
            </div>
          )}
        </div>
      )}

      {active && status && (
        <div className="scan-counters">
          <div className="scan-counter">
            <span className="scan-counter-value animate-count">{status.total_devices}</span>
            <span className="scan-counter-label">Devices</span>
          </div>
          <div className="scan-counter">
            <span className="scan-counter-value animate-count">{status.total_vulns}</span>
            <span className="scan-counter-label">CVEs</span>
          </div>
          <div className="scan-counter">
            <span className="scan-counter-value">{status.running_jobs}</span>
            <span className="scan-counter-label">Active Jobs</span>
          </div>
        </div>
      )}

      {(active || logs.length > 0) && (
        <div className="scan-log">
          {logs.map((l, i) => (
            <div key={i} className={`log-line log-${l.level} ${i === logs.length - 1 ? 'log-latest' : ''}`}>
              <span className="log-time">{new Date(l.time).toLocaleTimeString()}</span>
              <span className="log-msg">{l.message}</span>
            </div>
          ))}
          {active && (
            <div className="log-line log-cursor">
              <span className="log-time">&nbsp;</span>
              <span className="blink-cursor">_</span>
            </div>
          )}
          <div ref={logEndRef} />
        </div>
      )}

      {!active && status?.latest_job?.status === 'completed' && (
        <div className="scan-done-banner">
          Scan complete — {status.total_devices} devices, {status.total_vulns} vulnerabilities found
        </div>
      )}
    </div>
  )
}
