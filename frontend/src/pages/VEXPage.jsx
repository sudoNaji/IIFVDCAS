import { useState, useEffect, useCallback, useRef } from 'react'
import {
  ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2,
  Search, RefreshCw, Download, Zap, ChevronDown, ChevronRight,
  Activity, Clock, Info, Copy, Check
} from 'lucide-react'
import { vexApi, cveApi } from '../utils/api'
import { useWebSocket } from '../hooks/useWebSocket'
import { useAI } from '../hooks/useAI'

// ─── VEX status config ────────────────────────────────────────────────────────
const VEX_CONFIG = {
  affected: {
    label: 'Affected',
    color: 'text-red-400',
    bg: 'bg-red-950 border border-red-800',
    icon: ShieldAlert,
    row: 'bg-red-950/10',
  },
  not_affected: {
    label: 'Not Affected',
    color: 'text-green-400',
    bg: 'bg-green-950 border border-green-800',
    icon: ShieldCheck,
    row: '',
  },
  fixed: {
    label: 'Fixed',
    color: 'text-blue-400',
    bg: 'bg-blue-950 border border-blue-800',
    icon: CheckCircle2,
    row: 'bg-blue-950/10',
  },
  under_investigation: {
    label: 'Under Investigation',
    color: 'text-amber-400',
    bg: 'bg-amber-950 border border-amber-800',
    icon: Clock,
    row: 'bg-amber-950/10',
  },
}

const EXPLOITABILITY_COLOR = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-amber-400',
  low:      'text-blue-400',
  none:     'text-gray-600',
  unknown:  'text-gray-500',
}

// ─── Risk gauge ───────────────────────────────────────────────────────────────
function RiskGauge({ score, label }) {
  const color =
    score >= 90 ? '#ef4444' :
    score >= 70 ? '#f97316' :
    score >= 40 ? '#f59e0b' :
    score >= 10 ? '#3b82f6' : '#22c55e'

  const angle = (score / 100) * 180
  const r = 70
  const cx = 90, cy = 90
  const toRad = (a) => ((a - 90) * Math.PI) / 180
  const x1 = cx + r * Math.cos(toRad(-90))
  const y1 = cy + r * Math.sin(toRad(-90))
  const x2 = cx + r * Math.cos(toRad(-90 + angle))
  const y2 = cy + r * Math.sin(toRad(-90 + angle))
  const large = angle > 180 ? 1 : 0

  return (
    <div className="flex flex-col items-center">
      <svg width="180" height="100" viewBox="0 0 180 100">
        {/* Background arc */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none" stroke="#1f2937" strokeWidth="14" strokeLinecap="round"
        />
        {/* Score arc */}
        {score > 0 && (
          <path
            d={`M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`}
            fill="none" stroke={color} strokeWidth="14" strokeLinecap="round"
          />
        )}
        {/* Score text */}
        <text x={cx} y={cy - 6} textAnchor="middle"
          fill={color} fontSize="26" fontWeight="700" fontFamily="monospace">
          {score.toFixed(0)}
        </text>
        <text x={cx} y={cy + 12} textAnchor="middle"
          fill={color} fontSize="11" fontWeight="600">
          {label}
        </text>
      </svg>
      <p className="text-xs text-gray-500 -mt-1">Firmware Risk Score</p>
    </div>
  )
}

// ─── Stat card ────────────────────────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, color = 'text-white' }) {
  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-1">
        <Icon size={13} className="text-gray-500" />
        <span className="text-xs text-gray-500">{label}</span>
      </div>
      <div className={`text-2xl font-bold ${color}`}>{value ?? 0}</div>
    </div>
  )
}

// ─── Progress bar ─────────────────────────────────────────────────────────────
function ProgressBar({ progress, step }) {
  return (
    <div className="card mb-4">
      <div className="flex justify-between text-xs mb-2">
        <span className="text-gray-400">{step || 'Running VEX analysis…'}</span>
        <span className="text-indigo-400 font-medium">{Math.round(progress)}%</span>
      </div>
      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
        <div
          className="h-full bg-indigo-600 rounded-full transition-all duration-500"
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  )
}

// ─── VEX status badge ─────────────────────────────────────────────────────────
function VEXBadge({ status }) {
  const cfg = VEX_CONFIG[status] || VEX_CONFIG.under_investigation
  const Icon = cfg.icon
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full ${cfg.bg} ${cfg.color}`}>
      <Icon size={10} />
      {cfg.label}
    </span>
  )
}

// ─── Triage Detail Row (localized state for AI generation) ───────────────────
function TriageDetailRow({ finding }) {
  const { callAI } = useAI()
  const [aiJust, setAiJust] = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')

  // Reset state when target finding changes
  useEffect(() => {
    setAiJust('')
    setError('')
    setCopied(false)
  }, [finding.cve_id])

  const handleGenerate = async () => {
    setLoading(true)
    setError('')
    try {
      const resp = await callAI('vex-justification', {
        triage_finding: {
          cve_id: finding.cve_id,
          component: finding.component,
          version: finding.version,
          vex_status: finding.vex_status,
          justification: finding.justification,
          exploitability: finding.exploitability,
          notes: finding.notes
        }
      })
      setAiJust(resp.justification)
    } catch (err) {
      setError(err.message || 'Failed to generate justification')
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = () => {
    const textToCopy = aiJust || finding.justification || ''
    navigator.clipboard.writeText(textToCopy)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="space-y-3 p-3 bg-gray-950/40 rounded-lg border border-gray-800">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Main Details */}
        <div className="space-y-2">
          <div>
            <span className="text-[10px] text-gray-500 uppercase tracking-wider block">Rule Engine Recommendation</span>
            <p className="text-xs text-gray-200 leading-relaxed mt-0.5">
              {finding.justification || 'No recommendation justification provided by matching engine.'}
            </p>
          </div>
          {finding.notes?.length > 0 && (
            <div>
              <span className="text-[10px] text-gray-500 uppercase tracking-wider block mb-1">Scan Notes</span>
              <ul className="list-disc list-inside text-xs text-gray-400 space-y-0.5">
                {finding.notes.map((n, ni) => <li key={ni}>{n}</li>)}
              </ul>
            </div>
          )}
          {finding.remediation && (
            <div>
              <span className="text-[10px] text-gray-500 uppercase tracking-wider block">Remediation Step</span>
              <p className="text-xs text-amber-400 font-medium mt-0.5">
                {finding.remediation}
              </p>
            </div>
          )}
        </div>

        {/* AI Compliance Section */}
        <div className="border-t md:border-t-0 md:border-l border-gray-850 md:pl-4 space-y-2 flex flex-col justify-between">
          <div className="space-y-2">
            <span className="text-[10px] text-indigo-400 uppercase tracking-wider font-semibold block flex items-center gap-1">
              <Zap size={11} className="fill-indigo-400" />
              CycloneDX VEX Compliance Statement
            </span>
            {aiJust ? (
              <div className="bg-indigo-950/20 border border-indigo-900/35 rounded p-2.5 text-xs text-gray-300 leading-relaxed italic relative group">
                <p className="pr-6">{aiJust}</p>
                <button
                  onClick={handleCopy}
                  title="Copy justification"
                  className="absolute right-2 top-2 p-1 rounded bg-gray-900 hover:bg-gray-800 text-gray-400 hover:text-white transition-colors"
                >
                  {copied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                </button>
              </div>
            ) : (
              <p className="text-xs text-gray-500 italic">
                Generate a formal justification statement for CycloneDX 1.5 VEX compliance reports.
              </p>
            )}
            {error && (
              <p className="text-[11px] text-red-400 bg-red-950/10 border border-red-900/30 p-2 rounded">
                {error}
              </p>
            )}
          </div>
          
          <div className="flex gap-2 justify-end pt-2">
            {(finding.justification || aiJust) && (
              <button
                onClick={handleCopy}
                className="btn-secondary text-[11px] flex items-center gap-1.5 py-1.5 px-3 border border-gray-700 bg-gray-900 hover:bg-gray-800 text-white rounded-md"
              >
                {copied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            )}
            <button
              onClick={handleGenerate}
              disabled={loading}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-semibold transition-all border ${
                loading
                  ? 'bg-indigo-950 text-indigo-400 border-indigo-900 cursor-not-allowed'
                  : 'bg-indigo-600 text-white border-indigo-500 hover:bg-indigo-500 shadow-md shadow-indigo-600/10'
              }`}
            >
              <Zap size={11} className={loading ? 'animate-spin' : ''} />
              {loading ? 'Generating...' : '⚡ Generate Formal VEX Justification'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Triage table ─────────────────────────────────────────────────────────────
function TriageTable({ findings, statusFilter, onStatusFilter }) {
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState(null)

  const filtered = findings.filter(f => {
    const matchStatus = !statusFilter || f.vex_status === statusFilter
    const matchSearch = !search ||
      f.cve_id?.toLowerCase().includes(search.toLowerCase()) ||
      f.component?.toLowerCase().includes(search.toLowerCase())
    return matchStatus && matchSearch
  })

  return (
    <div className="space-y-3">
      <div className="flex gap-2 flex-wrap items-center">
        <div className="flex items-center gap-1.5 flex-1 min-w-48">
          <Search size={13} className="text-gray-600" />
          <input
            type="text"
            placeholder="Search CVE ID or component…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="flex-1 bg-gray-950 border border-gray-800 rounded px-2 py-1 text-xs text-gray-300 placeholder-gray-700"
          />
        </div>
        <div className="flex gap-1.5 flex-wrap">
          {['', 'affected', 'not_affected', 'fixed', 'under_investigation'].map(s => (
            <button
              key={s}
              onClick={() => onStatusFilter(s)}
              className={`text-[10px] px-2 py-0.5 rounded-full border transition-colors ${
                statusFilter === s
                  ? 'bg-indigo-900 border-indigo-600 text-indigo-300'
                  : 'bg-gray-900 border-gray-700 text-gray-500 hover:text-gray-300'
              }`}
            >
              {s ? VEX_CONFIG[s]?.label : 'All'}
            </button>
          ))}
        </div>
      </div>

      <div className="card p-0 overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-gray-500 border-b border-gray-800">
              <th className="text-left py-2 px-3 font-medium w-6"></th>
              {['CVE ID','Component','Version','VEX Status','Exploitability','Confidence'].map(h => (
                <th key={h} className="text-left py-2 px-3 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 150).map((f, i) => {
              const cfg = VEX_CONFIG[f.vex_status] || {}
              const isOpen = expanded === f.cve_id
              return (
                <>
                  <tr
                    key={f.cve_id + i}
                    onClick={() => setExpanded(isOpen ? null : f.cve_id)}
                    className={`border-b border-gray-900 cursor-pointer hover:bg-gray-800/40 transition-colors ${cfg.row || ''}`}
                  >
                    <td className="py-2 px-3">
                      {isOpen ? <ChevronDown size={12} className="text-gray-500"/> : <ChevronRight size={12} className="text-gray-600"/>}
                    </td>
                    <td className="py-2 px-3 font-mono text-indigo-400 whitespace-nowrap">{f.cve_id}</td>
                    <td className="py-2 px-3 text-gray-200 max-w-28 truncate">{f.component}</td>
                    <td className="py-2 px-3 text-gray-400 font-mono">{f.version || '—'}</td>
                    <td className="py-2 px-3"><VEXBadge status={f.vex_status} /></td>
                    <td className={`py-2 px-3 font-medium capitalize ${EXPLOITABILITY_COLOR[f.exploitability] || 'text-gray-400'}`}>
                      {f.exploitability || '—'}
                    </td>
                    <td className="py-2 px-3 text-gray-400">
                      {f.confidence ? `${(f.confidence * 100).toFixed(0)}%` : '—'}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr key={f.cve_id + '_detail'} className={cfg.row || ''}>
                      <td colSpan={7} className="px-4 py-3 border-b border-gray-800">
                        <TriageDetailRow finding={f} />
                      </td>
                    </tr>
                  )}
                </>
              )
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="px-6 py-8 text-center text-gray-500">
                  No findings match the current filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {filtered.length > 150 && (
          <p className="text-xs text-gray-600 px-3 py-2">
            Showing 150 of {filtered.length} findings
          </p>
        )}
      </div>
    </div>
  )
}

// ─── Remediation plan ─────────────────────────────────────────────────────────
function RemediationPlan({ plan }) {
  const priorityColor = {
    CRITICAL: 'text-red-400 border-red-900 bg-red-950/20',
    HIGH:     'text-orange-400 border-orange-900 bg-orange-950/20',
    MEDIUM:   'text-amber-400 border-amber-900 bg-amber-950/20',
    LOW:      'text-blue-400 border-blue-900 bg-blue-950/20',
  }

  if (!plan?.length) return (
    <div className="card text-center py-8 text-gray-500 text-sm">
      No remediation actions required.
    </div>
  )

  return (
    <div className="space-y-3">
      {plan.map((item, i) => (
        <div key={i} className={`card border ${priorityColor[item.priority] || 'text-gray-400 border-gray-800'}`}>
          <div className="flex items-start justify-between mb-2">
            <div>
              <span className="text-sm font-bold text-white">{item.component}</span>
              <span className="text-xs text-gray-500 ml-2 font-mono">
                {item.versions?.join(', ')}
              </span>
            </div>
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${priorityColor[item.priority]}`}>
              {item.priority}
            </span>
          </div>
          <p className="text-xs text-gray-300 mb-2">{item.action}</p>
          <div className="flex items-center gap-3 text-xs text-gray-600">
            <span>{item.affected_cves} CVE{item.affected_cves !== 1 ? 's' : ''}</span>
            <span>Confidence: {item.confidence ? `${(item.confidence * 100).toFixed(0)}%` : '—'}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Component summary ────────────────────────────────────────────────────────
function ComponentSummary({ summary }) {
  if (!summary?.length) return null
  return (
    <div className="card p-0 overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-gray-500 border-b border-gray-800">
            {['Component','Version','Total CVEs','Affected','Not Affected','Fixed','Worst'].map(h => (
              <th key={h} className="text-left py-2 px-3 font-medium">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {summary.map((c, i) => (
            <tr key={i} className="border-b border-gray-900 hover:bg-gray-800/30">
              <td className="py-2 px-3 text-gray-200 font-medium">{c.component}</td>
              <td className="py-2 px-3 text-gray-400 font-mono">{c.version || '—'}</td>
              <td className="py-2 px-3 text-gray-300">{c.total}</td>
              <td className="py-2 px-3 text-red-400 font-medium">{c.affected}</td>
              <td className="py-2 px-3 text-green-400">{c.not_affected}</td>
              <td className="py-2 px-3 text-blue-400">{c.fixed}</td>
              <td className={`py-2 px-3 font-medium capitalize ${EXPLOITABILITY_COLOR[c.worst_cvss] || 'text-gray-500'}`}>
                {c.worst_cvss || '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function VEXPage() {
  const [cveJobs,  setCveJobs]  = useState([])
  const [pastJobs, setPastJobs] = useState([])

  const [selectedCveJobId,  setSelectedCveJobId]  = useState('')
  const [selectedSbomJobId, setSelectedSbomJobId] = useState('')

  const [running,      setRunning]      = useState(false)
  const [progress,     setProgress]     = useState(0)
  const [progressStep, setProgressStep] = useState('')
  const [vexJobId,     setVexJobId]     = useState(null)
  const [error,        setError]        = useState('')

  const [result,       setResult]       = useState(null)
  const [triage,       setTriage]       = useState([])
  const [remediation,  setRemediation]  = useState([])
  const [compSummary,  setCompSummary]  = useState([])

  const [activeTab,    setActiveTab]    = useState('triage')
  const [statusFilter, setStatusFilter] = useState('')

  const pollRef = useRef(null)
  const { subscribe } = useWebSocket('ws://localhost:8000/ws')

  // Load CVE jobs + past VEX jobs
  useEffect(() => {
    cveApi.listJobs()
      .then(r => setCveJobs(r.data.jobs || []))
      .catch(() => {})
    vexApi.listJobs()
      .then(r => setPastJobs(r.data.jobs || []))
      .catch(() => {})
  }, [])

  // Auto-fill sbom_job_id when cve job changes
  useEffect(() => {
    if (!selectedCveJobId) return
    const job = cveJobs.find(j => j.job_id === selectedCveJobId)
    if (job?.sbom_job_id) setSelectedSbomJobId(job.sbom_job_id)
  }, [selectedCveJobId, cveJobs])

  // WS live progress
  useEffect(() => {
    return subscribe(ev => {
      if (ev.phase !== 'phase6') return
      if (ev.event === 'progress') {
        setProgress(ev.percent ?? 0)
        setProgressStep(ev.step ?? '')
      }
      if (ev.event === 'vex_complete') {
        setRunning(false)
        setProgress(100)
        setProgressStep('VEX analysis complete!')
        if (ev.job_id) loadResults(ev.job_id)
      }
    })
  }, [subscribe])

  // Polling fallback
  useEffect(() => {
    if (!running || !vexJobId) return
    pollRef.current = setInterval(async () => {
      try {
        const r = await vexApi.getStatus(vexJobId)
        const { status, progress: pct } = r.data
        setProgress(p => Math.max(p, pct ?? 0))
        if (status === 'success' || status === 'failed') {
          clearInterval(pollRef.current)
          setRunning(false)
          if (status === 'failed') setError(r.data.error || 'VEX analysis failed')
          else await loadResults(vexJobId)
        }
      } catch (_) {}
    }, 1500)
    return () => clearInterval(pollRef.current)
  }, [running, vexJobId])

  const loadResults = useCallback(async (jobId) => {
    try {
      const [sumR, trR, remR] = await Promise.all([
        vexApi.getSummary(jobId),
        vexApi.getTriage(jobId, { limit: 500 }),
        vexApi.getRemediation(jobId),
      ])
      setResult(sumR.data)
      setTriage(trR.data.findings || [])
      setRemediation(remR.data.remediation_plan || [])
      setCompSummary(remR.data.component_summary || [])
      vexApi.listJobs().then(r => setPastJobs(r.data.jobs || [])).catch(() => {})
    } catch (e) {
      setError('Failed to load VEX results: ' + e.message)
    }
  }, [])

  const handleStart = useCallback(async () => {
    if (!selectedCveJobId) {
      setError('Select a CVE mapping job first')
      return
    }
    setRunning(true); setError('')
    setResult(null); setTriage([]); setRemediation([])
    setProgress(1); setProgressStep('Submitting…')
    try {
      const r = await vexApi.analyze({
        cve_job_id:  selectedCveJobId,
        sbom_job_id: selectedSbomJobId || undefined,
      })
      setVexJobId(r.data.job_id)
    } catch (err) {
      setRunning(false); setProgress(0)
      setError(err.response?.data?.detail || err.message)
    }
  }, [selectedCveJobId, selectedSbomJobId])

  const handleLoadPast = useCallback(async (jobId) => {
    setVexJobId(jobId); setResult(null); setError('')
    await loadResults(jobId)
  }, [loadResults])

  const handleReset = () => {
    clearInterval(pollRef.current)
    setRunning(false); setProgress(0); setProgressStep('')
    setError(''); setVexJobId(null)
    setResult(null); setTriage([]); setRemediation([])
    setSelectedCveJobId(''); setSelectedSbomJobId('')
    setStatusFilter('')
  }

  const handleDownload = async () => {
    if (!vexJobId) return
    try {
      const r = await vexApi.download(vexJobId)
      const url = URL.createObjectURL(new Blob([r.data]))
      const a   = document.createElement('a')
      a.href = url; a.download = `vex_${vexJobId?.substring(0,8)}.json`
      a.click(); URL.revokeObjectURL(url)
    } catch (e) {
      alert('Download failed: ' + e.message)
    }
  }

  const isDone = !!result

  // Counts from triage list
  const affectedCount   = triage.filter(f => f.vex_status === 'affected').length
  const notAffectedCount = triage.filter(f => f.vex_status === 'not_affected').length
  const fixedCount      = triage.filter(f => f.vex_status === 'fixed').length
  const underInvCount   = triage.filter(f => f.vex_status === 'under_investigation').length

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="badge badge-blue text-[10px]">Phase 6</span>
            <span className="text-gray-600 text-xs font-mono">
              OpenVEX · CycloneDX 1.5 · EPSS · KEV
            </span>
          </div>
          <h1 className="text-2xl font-bold text-white">VEX Risk Analysis</h1>
          <p className="text-gray-400 text-sm mt-1">
            Vulnerability Exploitability eXchange — triage CVEs against your firmware context
          </p>
        </div>
        {isDone && (
          <div className="flex gap-2">
            <button onClick={handleDownload} className="btn-secondary text-sm">
              <Download size={14} /> CycloneDX VEX
            </button>
            <button onClick={handleReset} className="btn-secondary text-sm">
              <RefreshCw size={14} /> Reset
            </button>
          </div>
        )}
      </div>

      {/* Input form */}
      {!running && !isDone && (
        <div className="card mb-6">
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1.5 font-medium">
                CVE Mapping Job <span className="text-red-500">*</span>
              </label>
              <select
                value={selectedCveJobId}
                onChange={e => setSelectedCveJobId(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-sm text-gray-300 font-mono"
              >
                <option value="">— Select Phase 5 CVE job —</option>
                {cveJobs.map(j => (
                  <option key={j.job_id} value={j.job_id}>
                    {j.job_id.substring(0,14)}… — {j.total_cves ?? 0} CVEs / {j.status}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1.5 font-medium">
                SBOM Job <span className="text-gray-600">(auto-filled)</span>
              </label>
              <input
                type="text"
                value={selectedSbomJobId}
                onChange={e => setSelectedSbomJobId(e.target.value)}
                placeholder="Phase 4 SBOM job ID"
                className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-sm text-gray-300 font-mono placeholder-gray-700"
              />
            </div>
          </div>

          {pastJobs.length > 0 && (
            <div className="mb-4">
              <label className="block text-xs text-gray-400 mb-1.5 font-medium">
                Or load a past VEX analysis
              </label>
              <select
                onChange={e => e.target.value && handleLoadPast(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-sm text-gray-300 font-mono"
              >
                <option value="">— Past VEX jobs —</option>
                {pastJobs.map(j => (
                  <option key={j.job_id} value={j.job_id}>
                    {j.job_id.substring(0,12)} — score {j.risk_score ?? '?'} {j.risk_label} / {j.status}
                  </option>
                ))}
              </select>
            </div>
          )}

          {error && (
            <div className="bg-red-950 border border-red-800 rounded-lg p-3 mb-4 flex gap-2">
              <AlertTriangle size={14} className="text-red-400 flex-shrink-0 mt-0.5" />
              <span className="text-xs text-red-300">{error}</span>
            </div>
          )}

          <button onClick={handleStart} className="btn-primary">
            <Zap size={14} /> Run VEX Analysis
          </button>
        </div>
      )}

      {/* Progress */}
      {running && <ProgressBar progress={progress} step={progressStep} />}

      {/* Error state */}
      {!running && error && !isDone && (
        <div className="card bg-red-950/30 border border-red-900 mb-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle size={14} className="text-red-400" />
            <span className="text-sm font-medium text-red-300">Analysis Failed</span>
          </div>
          <p className="text-xs text-red-400">{error}</p>
          <button onClick={handleReset} className="btn-secondary text-xs mt-3">
            <RefreshCw size={12} /> Try Again
          </button>
        </div>
      )}

      {/* Results */}
      {isDone && (
        <>
          {/* Risk gauge + stat cards */}
          <div className="grid grid-cols-5 gap-4 mb-6">
            <div className="card flex items-center justify-center col-span-1">
              <RiskGauge score={result.risk_score || 0} label={result.risk_label || 'MINIMAL'} />
            </div>
            <div className="col-span-4 grid grid-cols-4 gap-3">
              <StatCard icon={ShieldAlert}  label="Affected"           value={affectedCount}    color="text-red-400" />
              <StatCard icon={ShieldCheck}  label="Not Affected"       value={notAffectedCount} color="text-green-400" />
              <StatCard icon={CheckCircle2} label="Fixed"              value={fixedCount}       color="text-blue-400" />
              <StatCard icon={Clock}        label="Under Investigation" value={underInvCount}    color="text-amber-400" />
            </div>
          </div>

          {/* Firmware context */}
          {result.firmware_context && (
            <div className="card mb-4 flex flex-wrap gap-4 text-xs">
              <span className="text-gray-500 font-medium">Firmware context:</span>
              <span className="text-gray-300">
                Arch: <span className="text-indigo-400">{result.firmware_context.architecture || '?'}</span>
              </span>
              <span className="text-gray-300">
                Bare-metal: <span className={result.firmware_context.is_bare_metal ? 'text-green-400' : 'text-amber-400'}>
                  {result.firmware_context.is_bare_metal ? 'Yes' : 'No'}
                </span>
              </span>
              <span className="text-gray-300">
                Network stack: <span className={result.firmware_context.has_network_stack ? 'text-amber-400' : 'text-green-400'}>
                  {result.firmware_context.has_network_stack ? 'Present' : 'None'}
                </span>
              </span>
              <span className="text-gray-300">
                CBOM algos: <span className="text-indigo-400">
                  {result.firmware_context.cbom_algorithms?.length ?? 0}
                </span>
              </span>
            </div>
          )}

          {/* Top risks */}
          {result.top_risks?.length > 0 && (
            <div className="card mb-6">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <Activity size={14} className="text-red-400" />
                Top 5 Critical Risks
              </h3>
              <div className="space-y-2">
                {result.top_risks.map((r, i) => (
                  <div key={i} className="flex items-start gap-3 text-xs border-b border-gray-800 pb-2 last:border-0 last:pb-0">
                    <span className="text-gray-600 font-mono w-4 flex-shrink-0">{i+1}.</span>
                    <span className="text-indigo-400 font-mono flex-shrink-0 w-36">{r.cve_id}</span>
                    <span className="text-gray-300 flex-shrink-0 w-24">{r.component}</span>
                    <span className={`capitalize font-medium flex-shrink-0 w-16 ${EXPLOITABILITY_COLOR[r.exploitability]}`}>
                      {r.exploitability}
                    </span>
                    <span className="text-gray-500 flex-1">{r.remediation}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tabs */}
          <div className="flex gap-1 mb-4 border-b border-gray-800">
            {[
              { id: 'triage',      label: 'CVE Triage',         icon: ShieldAlert },
              { id: 'remediation', label: 'Remediation Plan',   icon: Zap },
              { id: 'components',  label: 'Component Summary',  icon: Activity },
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
                  activeTab === tab.id
                    ? 'text-indigo-400 border-indigo-600'
                    : 'text-gray-500 border-transparent hover:text-gray-300'
                }`}
              >
                <tab.icon size={14} /> {tab.label}
              </button>
            ))}
          </div>

          {activeTab === 'triage' && (
            <TriageTable
              findings={triage}
              statusFilter={statusFilter}
              onStatusFilter={setStatusFilter}
            />
          )}
          {activeTab === 'remediation' && (
            <RemediationPlan plan={remediation} />
          )}
          {activeTab === 'components' && (
            <ComponentSummary summary={compSummary} />
          )}
        </>
      )}
    </div>
  )
}
