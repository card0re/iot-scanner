import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
})

export async function fetchStats() {
  const { data } = await api.get('/api/stats')
  return data
}

export async function fetchDevices(params) {
  const { data } = await api.get('/api/devices', { params })
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
