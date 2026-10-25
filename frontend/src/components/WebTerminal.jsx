import React, { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import '@xterm/xterm/css/xterm.css'

export default function WebTerminal({ ip, port, protocol, onClose }) {
  const termRef = useRef(null)
  const termInstance = useRef(null)
  const wsRef = useRef(null)
  const fitRef = useRef(null)
  const [connected, setConnected] = useState(false)
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [connecting, setConnecting] = useState(false)
  const [defaults, setDefaults] = useState([])
  const [showLogin, setShowLogin] = useState(true)

  useEffect(() => {
    fetch(`/api/terminal/defaults/unknown`)
      .then(r => r.json())
      .then(d => setDefaults(d.credentials || []))
      .catch(() => {})
  }, [])

  useEffect(() => {
    return () => {
      wsRef.current?.close()
      termInstance.current?.dispose()
    }
  }, [])

  function initTerminal() {
    if (termInstance.current) termInstance.current.dispose()

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      theme: {
        background: '#0a0c10',
        foreground: '#c9d1d9',
        cursor: '#58a6ff',
        selectionBackground: '#264f78',
        black: '#0d1117', red: '#f85149', green: '#3fb950', yellow: '#e3b341',
        blue: '#58a6ff', magenta: '#bc8cff', cyan: '#39d353', white: '#c9d1d9',
        brightBlack: '#484f58', brightRed: '#ff7b72', brightGreen: '#56d364',
        brightYellow: '#e3b341', brightBlue: '#79c0ff', brightMagenta: '#d2a8ff',
        brightCyan: '#56d364', brightWhite: '#f0f6fc',
      },
      allowProposedApi: true,
    })

    const fit = new FitAddon()
    fitRef.current = fit
    term.loadAddon(fit)
    term.loadAddon(new WebLinksAddon())
    term.open(termRef.current)
    fit.fit()
    termInstance.current = term

    const ro = new ResizeObserver(() => {
      try { fit.fit() } catch {}
    })
    ro.observe(termRef.current)

    return term
  }

  function connect() {
    setConnecting(true)
    const term = initTerminal()
    setShowLogin(false)

    const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${wsProto}//${location.host}/api/terminal/${protocol}/${ip}/${port}`

    term.writeln(`\x1b[36mConnecting ${protocol.toUpperCase()} to ${ip}:${port}...\x1b[0m`)

    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      if (protocol === 'ssh') {
        ws.send(JSON.stringify({ username, password }))
      }
    }

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)
      switch (msg.type) {
        case 'output':
          term.write(msg.data)
          break
        case 'connected':
          setConnected(true)
          setConnecting(false)
          term.writeln(`\x1b[32m${msg.data}\x1b[0m`)
          term.focus()
          break
        case 'status':
          term.writeln(`\x1b[33m${msg.data}\x1b[0m`)
          break
        case 'error':
          term.writeln(`\x1b[31m${msg.data}\x1b[0m`)
          setConnecting(false)
          setShowLogin(true)
          break
        case 'disconnected':
          term.writeln(`\x1b[31m${msg.data}\x1b[0m`)
          setConnected(false)
          setConnecting(false)
          break
      }
    }

    ws.onclose = () => {
      setConnected(false)
      setConnecting(false)
      term.writeln('\x1b[31mConnection closed\x1b[0m')
    }

    ws.onerror = () => {
      term.writeln('\x1b[31mWebSocket error\x1b[0m')
      setConnecting(false)
    }

    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data }))
      }
    })

    term.onResize(({ cols, rows }) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols, rows }))
      }
    })
  }

  function disconnect() {
    wsRef.current?.close()
    setConnected(false)
    setShowLogin(true)
  }

  function fillCred(u, p) {
    setUsername(u)
    setPassword(p)
  }

  return (
    <div className="webterminal">
      <div className="webterminal-bar">
        <span className="webterminal-title">
          {protocol.toUpperCase()} — {ip}:{port}
        </span>
        <span className={`webterminal-status ${connected ? 'wt-connected' : ''}`}>
          {connected ? 'CONNECTED' : connecting ? 'CONNECTING...' : 'DISCONNECTED'}
        </span>
        {connected && (
          <button className="console-btn" onClick={disconnect}>Disconnect</button>
        )}
        <button className="console-btn console-close" onClick={onClose}>&times;</button>
      </div>

      {showLogin && protocol === 'ssh' && (
        <div className="webterminal-login">
          <input
            placeholder="Username"
            value={username}
            onChange={e => setUsername(e.target.value)}
            className="wt-input"
          />
          <input
            placeholder="Password"
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            className="wt-input"
            onKeyDown={e => e.key === 'Enter' && connect()}
          />
          <button className="wt-connect-btn" onClick={connect} disabled={connecting}>
            {connecting ? 'Connecting...' : 'Connect'}
          </button>
          {defaults.length > 0 && (
            <div className="wt-defaults">
              <span className="console-dim">Known defaults:</span>
              {defaults.map((c, i) => (
                <button key={i} className="wt-default-btn" onClick={() => fillCred(c.username, c.password)}>
                  {c.username}:{c.password || '(empty)'}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {showLogin && protocol === 'telnet' && (
        <div className="webterminal-login">
          <button className="wt-connect-btn" onClick={connect} disabled={connecting}>
            {connecting ? 'Connecting...' : 'Connect Telnet'}
          </button>
        </div>
      )}

      <div className="webterminal-container" ref={termRef} />
    </div>
  )
}
