import axios from 'axios'
const api = axios.create({ baseURL: '/api/v1', timeout: 60000 })
export const deviceApi = {
  list:        ()       => api.get('/devices'),
  scan:        (opts)   => api.post('/devices/scan', opts),
  getScan:     (id)     => api.get(`/devices/scan/${id}`),
  details:     (port)   => api.get(`/devices/${encodeURIComponent(port)}/details`),
  networkScan: (subnet) => api.get('/devices/network/scan', { params: { subnet } }),
}
export const systemApi = { info: () => api.get('/system/info') }
export default api
