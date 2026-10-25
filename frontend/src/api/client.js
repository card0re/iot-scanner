import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  timeout: 10000,
})

export async function fetchStats() {
  const { data } = await api.get('/api/stats')
  return data
}

export async function fetchDevices(params) {
  const clean = { ...params }
  if (clean.alive_only) clean.alive_only = 'true'
  else delete clean.alive_only
  if (clean.exploited_only) clean.exploited_only = 'true'
  else delete clean.exploited_only
  Object.keys(clean).forEach(k => { if (!clean[k] && clean[k] !== 0) delete clean[k] })
  const { data } = await api.get('/api/devices', { params: clean })
  return data
}

export async function fetchExploitedIps() {
  const { data } = await api.get('/api/exploited/ips')
  return data
}

export async function fetchDevice(id) {
  const { data } = await api.get(`/api/devices/${id}`)
  return data
}

export async function triggerScan(body) {
  const { data } = await api.post('/api/scans/trigger', body)
  return data
}

export async function fetchScans() {
  const { data } = await api.get('/api/scans')
  return data
}
