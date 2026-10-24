import React, { useState, useEffect } from 'react'
import { fetchStats, fetchDevices } from './api/client'
import ScanPanel from './components/ScanPanel'
import StatsCards from './components/StatsCards'
import Charts from './components/Charts'
import DeviceTable from './components/DeviceTable'
import './App.css'

export default function App() {
  const [stats, setStats] = useState(null)
  const [devices, setDevices] = useState({ items: [], total: 0 })
  const [filters, setFilters] = useState({ page: 1, country_code: '', device_type: '', min_score: '' })
  const [loading, setLoading] = useState(true)

  useEffect(() => { loadData() }, [filters])

  async function loadData() {
    setLoading(true)
    const params = { ...filters }
    Object.keys(params).forEach(k => { if (!params[k]) delete params[k] })
    const [statsRes, devicesRes] = await Promise.allSettled([
      fetchStats(),
      fetchDevices(params),
    ])
    if (statsRes.status === 'fulfilled') setStats(statsRes.value)
    if (devicesRes.status === 'fulfilled') setDevices(devicesRes.value)
    setLoading(false)
  }

  return (
    <div className="app">
      <header className="header">
        <h1>IoT Vulnerability Scanner</h1>
      </header>

      <ScanPanel onScanComplete={loadData} />

      {stats && <StatsCards stats={stats} />}
      {stats && <Charts stats={stats} />}

      <section className="filters">
        <select value={filters.country_code} onChange={e => setFilters(f => ({ ...f, country_code: e.target.value, page: 1 }))}>
          <option value="">All countries</option>
          <option value="IR">Iran</option>
          <option value="RU">Russia</option>
        </select>
        <select value={filters.device_type} onChange={e => setFilters(f => ({ ...f, device_type: e.target.value, page: 1 }))}>
          <option value="">All types</option>
          <option value="camera">Camera</option>
          <option value="router">Router</option>
          <option value="nas">NAS</option>
          <option value="dvr">DVR</option>
          <option value="scada">SCADA</option>
          <option value="printer">Printer</option>
          <option value="smart_home">Smart Home</option>
          <option value="industrial">Industrial</option>
          <option value="unknown">Unknown</option>
        </select>
        <input
          type="number" placeholder="Min vuln score" value={filters.min_score}
          onChange={e => setFilters(f => ({ ...f, min_score: e.target.value, page: 1 }))}
        />
        <label className="filter-toggle">
          <input
            type="checkbox"
            checked={filters.alive_only || false}
            onChange={e => setFilters(f => ({ ...f, alive_only: e.target.checked, page: 1 }))}
          />
          <span>Alive only</span>
        </label>
      </section>

      <DeviceTable
        devices={devices}
        page={filters.page}
        onPageChange={p => setFilters(f => ({ ...f, page: p }))}
        loading={loading}
      />
    </div>
  )
}
