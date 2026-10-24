import React, { useState, useEffect, useRef } from 'react'

export default function ScanPanel({ onScanComplete }) {
  const [active, setActive] = useState(false)
  const [status, setStatus] = useState(null)
  const [logs, setLogs] = useState([])
  const [elapsed, setElapsed] = useState(0)
  const logEndRef = useRef(null)
  const timerRef = useRef(null)
  const pollRef = useRef(null)

  useEffect(() => {
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
        <button className="btn-scan" onClick={startScan} disabled={active}>
          {active ? (
            <span className="btn-scan-active">
              <span className="spinner" />
              Scanning...
            </span>
          ) : 'Run Scan'}
        </button>
      </div>

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
