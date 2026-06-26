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
  upload: (file) => {
    const fd = new FormData(); fd.append('file', file)
    return api.post('/firmware/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
  },
  analyze:       (path)  => api.post('/firmware/analyze', { path }),
  extract:       (path)  => api.post('/firmware/extract', { path }),
  extractDevice: (opts)  => api.post('/firmware/extract-device', opts),
  getJob:        (id)    => api.get(`/firmware/extract/${id}`),
  getTree:       (id)    => api.get(`/firmware/extract/${id}/tree`),
  deleteJob:     (id)    => api.delete(`/firmware/extract/${id}`),
  listJobs:      ()      => api.get('/firmware/jobs'),
}

export const sbomApi = {
  generate:      (opts)  => api.post('/sbom/generate', opts),
  getJob:        (id)    => api.get(`/sbom/${id}`),
  getStatus:     (id)    => api.get(`/sbom/${id}/status`),
  getFullSBOM:   (id)    => api.get(`/sbom/${id}`),
  getHBOM:       (id)    => api.get(`/sbom/${id}/hbom`),
  getCBOM:       (id)    => api.get(`/sbom/${id}/cbom`),
  getComponents: (id, p) => api.get(`/sbom/${id}/components`, { params: p }),
  download:      (id, f) => api.get(`/sbom/${id}/download`, { params: { format: f }, responseType: 'blob' }),
}

export const cveApi = {
  startScan:   (opts)  => api.post('/cve/scan', opts),
  listJobs:    ()      => api.get('/cve/jobs/list'),
  getResult:   (id)    => api.get(`/cve/${id}`),
  getSummary:  (id)    => api.get(`/cve/${id}/summary`),
  getFindings: (id, p) => api.get(`/cve/${id}/findings`, { params: p }),
  getCritical: (id)    => api.get(`/cve/${id}/critical`),
  getKev:      (id)    => api.get(`/cve/${id}/kev`),
  deleteJob:   (id)    => api.delete(`/cve/${id}`),
}

export const vexApi = {
  analyze:        (opts)  => api.post('/vex/analyze', opts),
  listJobs:       ()      => api.get('/vex/jobs/list'),
  getJob:         (id)    => api.get(`/vex/${id}`),
  getStatus:      (id)    => api.get(`/vex/${id}/status`),
  getSummary:     (id)    => api.get(`/vex/${id}/summary`),
  getTriage:      (id, p) => api.get(`/vex/${id}/triage`, { params: p }),
  getRemediation: (id)    => api.get(`/vex/${id}/remediation`),
  download:       (id)    => api.get(`/vex/${id}/download`, { responseType: 'blob' }),
  deleteJob:      (id)    => api.delete(`/vex/${id}`),
}

export const complianceApi = {
  generate:     (opts) => api.post('/compliance/generate', opts),
  listJobs:     ()     => api.get('/compliance/jobs/list'),
  getJob:       (id)   => api.get(`/compliance/${id}`),
  getStatus:    (id)   => api.get(`/compliance/${id}/status`),
  getSummary:   (id)   => api.get(`/compliance/${id}/summary`),
  getControls:  (id,p) => api.get(`/compliance/${id}/controls`, { params: p }),
  downloadPdf:  (id)   => api.get(`/compliance/${id}/download/pdf`,  { responseType: 'blob' }),
  downloadJson: (id)   => api.get(`/compliance/${id}/download/json`, { responseType: 'blob' }),
  deleteJob:    (id)   => api.delete(`/compliance/${id}`),
}

export const systemApi = { info: () => api.get('/system/info') }

// ── AI API ─────────────────────────────────────────────────────────────────
import { buildAIHeaders, loadAIConfig } from '../hooks/useAI'

const aiAxios = axios.create({ baseURL: '/api/v1/ai', timeout: 90000 })

function aiPost(endpoint, body) {
  const cfg = loadAIConfig()
  return aiAxios.post(endpoint, body, { headers: buildAIHeaders(cfg) })
}

export const aiApi = {
  listProviders:        ()       => aiAxios.get('/providers'),
  test:                 ()       => aiAxios.post('/test', {}, { headers: buildAIHeaders(loadAIConfig()) }),
  explainCve:           (body)   => aiPost('/explain-cve',            body),
  vexJustification:     (body)   => aiPost('/vex-justification',       body),
  complianceWriteup:    (body)   => aiPost('/compliance-writeup',      body),
  complianceExecSummary:(body)   => aiPost('/compliance-exec-summary', body),
  explainFinding:       (body)   => aiPost('/explain-finding',         body),
  chat:                 (body)   => aiPost('/chat',                    body),
}

export default api
