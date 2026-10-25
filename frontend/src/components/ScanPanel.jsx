import React, { useState, useEffect, useRef } from 'react'

export default function ScanPanel({ onScanComplete }) {
  const [active, setActive] = useState(false)
  const [status, setStatus] = useState(null)
  const [logs, setLogs] = useState([])
  const [elapsed, setElapsed] = useState(0)
  const timerRef = useRef(null)
  const pollRef = useRef(null)

  const [showProxy, setShowProxy] = useState(false)
  const [proxies, setProxies] = useState([])
  const [strategy, setStrategy] = useState('round-robin')
  const [pasteText, setPasteText] = useState('')
  const [proxyMsg, setProxyMsg] = useState(null)
  const [testing, setTesting] = useState(false)
  const fileRef = useRef(null)

  const [sampleSize, setSampleSize] = useState(500)

  const [scraper, setScraper] = useState({ running: false, interval: 600, last_run: {} })
  const [scraperInterval, setScraperInterval] = useState('10')
  const [progress, setProgress] = useState(null)
  const scraperPollRef = useRef(null)

  useEffect(() => {
    loadProxies()
    loadScraper()
    return () => {
      clearInterval(timerRef.current)
      clearInterval(pollRef.current)
      clearInterval(scraperPollRef.current)
    }
  }, [])

  const logContainerRef = useRef(null)

  useEffect(() => {
    const container = logContainerRef.current
    if (container) container.scrollTop = container.scrollHeight
  }, [logs])

  async function loadProxies() {
    try {
      const r = await fetch('/api/scans/proxy')
      const data = await r.json()
      setProxies(data.proxies || [])
      setStrategy(data.strategy || 'round-robin')
    } catch {}
  }

  async function loadScraper() {
    try {
      const r = await fetch('/api/scans/proxy/scraper')
      const data = await r.json()
      setScraper(data)
      setScraperInterval(String(Math.round((data.interval || 600) / 60)))
      if (data.progress) setProgress(data.progress)
      if (data.progress?.active && !scraperPollRef.current) {
        startScraperPoll()
      }
    } catch {}
  }

  function startScraperPoll() {
    clearInterval(scraperPollRef.current)
    scraperPollRef.current = setInterval(async () => {
      try {
        const r = await fetch('/api/scans/proxy/scraper')
        const data = await r.json()
        setScraper(data)
        const prog = data.progress || {}
        setProgress(prog)
        if (prog.active) {
          loadProxies()
        } else {
          clearInterval(scraperPollRef.current)
          scraperPollRef.current = null
          loadProxies()
        }
      } catch {}
    }, 1200)
  }

  async function startScan() {
    setActive(true); setLogs([]); setElapsed(0); setStatus(null)
    try {
      const res = await fetch('/api/scans/trigger', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sample_size: sampleSize }),
      })
      const data = await res.json()
      if (data.status === 'already_running')
        setLogs([{ time: new Date().toISOString(), message: 'Scan already in progress...', level: 'warn' }])
    } catch (e) {
      setLogs([{ time: new Date().toISOString(), message: `Failed to trigger: ${e.message}`, level: 'error' }])
      setActive(false); return
    }
    timerRef.current = setInterval(() => setElapsed(e => e + 1), 1000)
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch('/api/scans/status')
        const data = await res.json()
        setStatus(data); setLogs(data.log || [])
        if (!data.active) {
          clearInterval(timerRef.current); clearInterval(pollRef.current)
          setActive(false); onScanComplete?.()
        }
      } catch {}
    }, 1500)
  }

  async function addFromPaste() {
    const lines = pasteText.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
    if (!lines.length) return
    const res = await fetch('/api/scans/proxy', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxies: lines, strategy }),
    })
    const data = await res.json()
    setProxyMsg({ ok: true, text: `+${data.added} proxies (${data.total} total)` })
    setPasteText('')
    loadProxies()
  }

  async function uploadFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const form = new FormData()
    form.append('file', file)
    const res = await fetch('/api/scans/proxy/file', { method: 'POST', body: form })
    const data = await res.json()
    setProxyMsg({ ok: true, text: `+${data.added} from file (${data.total} total)` })
    fileRef.current.value = ''
    loadProxies()
  }

  async function removeProxy(url) {
    await fetch('/api/scans/proxy', {
      method: 'DELETE', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
    loadProxies()
  }

  async function clearAll() {
    await fetch('/api/scans/proxy/all', { method: 'DELETE' })
    setProxies([])
    setProxyMsg({ ok: true, text: 'All proxies removed' })
  }

  async function testAll() {
    setTesting(true); setProxyMsg(null)
    const res = await fetch('/api/scans/proxy/test-all', { method: 'POST' })
    const data = await res.json()
    setProxyMsg({ ok: true, text: `Tested: ${data.alive}/${data.total} alive` })
    setTesting(false)
    loadProxies()
  }

  async function testOne(url) {
    const res = await fetch('/api/scans/proxy/test', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
    const data = await res.json()
    setProxyMsg({ ok: data.status === 'ok', text: `${url} — ${data.message}` })
    loadProxies()
  }

  async function changeStrategy(s) {
    setStrategy(s)
    await fetch('/api/scans/proxy', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxies: [], strategy: s }),
    })
  }

  async function toggleScraper() {
    const action = scraper.running ? 'stop' : 'start'
    const interval = Math.max(1, parseInt(scraperInterval) || 10) * 60
    await fetch('/api/scans/proxy/scraper', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, interval }),
    })
    loadScraper()
  }

  async function runScraperOnce() {
    setProxyMsg(null)
    await fetch('/api/scans/proxy/scraper', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'run_once', interval: 600 }),
    })
    startScraperPoll()
    loadScraper()
  }

  function formatTime(s) {
    const m = Math.floor(s / 60), sec = s % 60
    return `${m}:${sec.toString().padStart(2, '0')}`
  }

  function formatAgo(ts) {
    if (!ts) return 'never'
    const sec = Math.floor(Date.now() / 1000 - ts)
    if (sec < 60) return `${sec}s ago`
    if (sec < 3600) return `${Math.floor(sec / 60)}m ago`
    return `${Math.floor(sec / 3600)}h ago`
  }

  const lastRun = scraper.last_run || {}
  const isScraperActive = progress?.active

  // progress bar percentage
  let progressPct = 0
  let progressLabel = ''
  if (progress?.active) {
    if (progress.phase === 'scraping') {
      progressPct = progress.sources_total ? (progress.sources_done / progress.sources_total) * 50 : 0
      progressLabel = `Scraping: ${progress.current_source} (${progress.sources_done}/${progress.sources_total})`
    } else if (progress.phase === 'verifying') {
      progressPct = 50 + (progress.verify_total ? (progress.verify_current / progress.verify_total) * 45 : 0)
      progressLabel = `Verifying: ${progress.verify_current}/${progress.verify_total} — ${progress.verified_alive} alive`
    } else if (progress.phase === 'purging') {
      progressPct = 95
      progressLabel = 'Purging dead proxies...'
    }
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
          <button className="btn-proxy-toggle" onClick={() => setShowProxy(p => !p)} title="Proxy settings">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
            {proxies.length > 0 && <span className="proxy-badge">{proxies.length}</span>}
          </button>
          <div className="sample-size-group">
            <input
              type="number"
              className="sample-size-input"
              value={sampleSize}
              onChange={e => setSampleSize(Math.max(1, parseInt(e.target.value) || 1))}
              min={1}
              max={10000}
              disabled={active}
              title="Number of new devices to scan"
            />
            <span className="sample-size-label">devices</span>
          </div>
          <button className="btn-scan" onClick={startScan} disabled={active}>
            {active ? (
              <span className="btn-scan-active"><span className="spinner" /> Scanning...</span>
            ) : 'Run Scan'}
          </button>
        </div>
      </div>

      {showProxy && (
        <div className="proxy-settings">
          {/* --- Auto-scraper --- */}
          <div className="scraper-section">
            <div className="scraper-header">
              <div className="scraper-title">
                {isScraperActive
                  ? <span className="scraper-radar" />
                  : <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/>
                      <polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/>
                      <line x1="4" y1="4" x2="9" y2="9"/>
                    </svg>
                }
                <span>Auto-Scraper</span>
                {scraper.running && <span className="scraper-live-badge">AUTO</span>}
              </div>
              <div className="scraper-controls">
                <div className="scraper-interval-group">
                  <input
                    type="number"
                    className="scraper-interval-input"
                    value={scraperInterval}
                    onChange={e => setScraperInterval(e.target.value)}
                    min={1} max={120}
                    disabled={scraper.running}
                  />
                  <span className="scraper-interval-label">min</span>
                </div>
                <button className={`btn-action ${scraper.running ? 'btn-scraper-stop' : 'btn-scraper-start'}`} onClick={toggleScraper}>
                  {scraper.running ? 'Stop' : 'Start'}
                </button>
                <button className="btn-action btn-scraper-once" onClick={runScraperOnce} disabled={isScraperActive}>
                  {isScraperActive ? 'Working...' : 'Run Once'}
                </button>
              </div>
            </div>

            {/* Progress bar */}
            {isScraperActive && (
              <div className="scraper-progress">
                <div className="scraper-progress-bar">
                  <div className="scraper-progress-fill" style={{ width: `${progressPct}%` }}>
                    <div className="scraper-progress-glow" />
                  </div>
                </div>
                <div className="scraper-progress-label">{progressLabel}</div>
                <div className="scraper-live-stats">
                  <span>Candidates: <b>{progress.candidates_found}</b></span>
                  <span className="scraper-stat-sep">|</span>
                  <span style={{color:'var(--success)'}}>Alive: <b>{progress.verified_alive}</b></span>
                  <span className="scraper-stat-sep">|</span>
                  <span style={{color:'var(--critical)'}}>Failed: <b>{progress.verified_failed}</b></span>
                  <span className="scraper-stat-sep">|</span>
                  <span>Pool: <b>{progress.pool_size}</b></span>
                </div>
              </div>
            )}

            {/* Recently found */}
            {isScraperActive && progress.recent_adds?.length > 0 && (
              <div className="scraper-recent">
                <span className="scraper-recent-title">Just found:</span>
                <div className="scraper-recent-list">
                  {progress.recent_adds.slice(-8).reverse().map((url, i) => (
                    <span key={url} className="scraper-recent-item" style={{ animationDelay: `${i * 0.05}s` }}>
                      {url.replace(/^socks[45]?:\/\/|^https?:\/\//, '')}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Last run stats (when not active) */}
            {!isScraperActive && lastRun.timestamp && (
              <div className="scraper-stats">
                <span>Last: {formatAgo(lastRun.timestamp)}</span>
                <span className="scraper-stat-sep">|</span>
                <span>Found: {lastRun.scraped_total || 0}</span>
                <span className="scraper-stat-sep">|</span>
                <span style={{ color: 'var(--success)' }}>+{lastRun.verified_alive || 0} alive</span>
                <span className="scraper-stat-sep">|</span>
                <span style={{ color: 'var(--critical)' }}>-{lastRun.purged_dead || 0} dead</span>
              </div>
            )}
          </div>

          <div className="proxy-divider" />

          {/* --- Manual add --- */}
          <div className="proxy-top-row">
            <h3>Proxy Pool <span className="proxy-pool-count">{proxies.length}</span></h3>
            <div className="proxy-strategy">
              <label className={strategy === 'round-robin' ? 'active' : ''}>
                <input type="radio" name="strat" checked={strategy === 'round-robin'} onChange={() => changeStrategy('round-robin')} />
                Round-Robin
              </label>
              <label className={strategy === 'random' ? 'active' : ''}>
                <input type="radio" name="strat" checked={strategy === 'random'} onChange={() => changeStrategy('random')} />
                Random
              </label>
            </div>
          </div>

          <div className="proxy-add-section">
            <textarea
              className="proxy-textarea"
              rows={3}
              placeholder={"Paste proxies — one per line:\nsocks5://user:pass@host:port\nhttp://host:port\nhost:port  (defaults to socks5)"}
              value={pasteText}
              onChange={e => setPasteText(e.target.value)}
              spellCheck={false}
            />
            <div className="proxy-add-actions">
              <button className="btn-action btn-proxy-add" onClick={addFromPaste} disabled={!pasteText.trim()}>Add</button>
              <button className="btn-action btn-proxy-file" onClick={() => fileRef.current?.click()}>Upload File</button>
              <input ref={fileRef} type="file" accept=".txt,.csv,.list" style={{ display: 'none' }} onChange={uploadFile} />
              {proxies.length > 0 && (
                <>
                  <button className="btn-action btn-proxy-testall" onClick={testAll} disabled={testing}>{testing ? 'Testing...' : 'Test All'}</button>
                  <button className="btn-action btn-proxy-clear" onClick={clearAll}>Clear All</button>
                </>
              )}
            </div>
          </div>

          {proxyMsg && (
            <div className={`proxy-result proxy-result-${proxyMsg.ok ? 'ok' : 'error'}`}>
              {proxyMsg.ok ? '✓' : '✗'} {proxyMsg.text}
            </div>
          )}

          {proxies.length > 0 && (
            <div className="proxy-list">
              {proxies.map((p) => (
                <div key={p.url} className={`proxy-item ${p.alive === true && isScraperActive ? 'proxy-item-new' : ''}`}>
                  <span className={`proxy-status-dot ${p.alive === true ? 'dot-alive' : p.alive === false ? 'dot-dead' : 'dot-unknown'}`} />
                  <span className="proxy-url">{p.url}</span>
                  {p.fail_count > 0 && <span className="proxy-fails">{p.fail_count}x fail</span>}
                  <div className="proxy-item-actions">
                    <button className="proxy-btn-test" onClick={() => testOne(p.url)} title="Test">Test</button>
                    <button className="proxy-btn-del" onClick={() => removeProxy(p.url)} title="Remove">&times;</button>
                  </div>
                </div>
              ))}
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
        <div className="scan-log" ref={logContainerRef}>
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
