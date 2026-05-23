import axios from 'axios'
const api = axios.create({ baseURL: '/api/v1', timeout: 120000 })

export const deviceApi = {
  list:        ()       => api.get('/devices'),
  scan:        (opts)   => api.post('/devices/scan', opts),
  getScan:     (id)     => api.get(`/devices/scan/${id}`),
  details:     (port)   => api.get(`/devices/${encodeURIComponent(port)}/details`),
  networkScan: (subnet) => api.get('/devices/network/scan', { params: { subnet } }),
}

export const firmwareApi = {
  upload:      (file)   => {
    const fd = new FormData(); fd.append('file', file)
    return api.post('/firmware/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
  },
  analyze:     (path)   => api.post('/firmware/analyze', { path }),
  extract:     (path)   => api.post('/firmware/extract', { path }),
  extractDevice: (deviceOpts) => api.post('/firmware/extract-device', deviceOpts),
  getJob:      (id)     => api.get(`/firmware/extract/${id}`),
  getTree:     (id)     => api.get(`/firmware/extract/${id}/tree`),
  deleteJob:   (id)     => api.delete(`/firmware/extract/${id}`),
  listJobs:    ()       => api.get('/firmware/jobs'),
}

export const systemApi = { info: () => api.get('/system/info') }
export default api
