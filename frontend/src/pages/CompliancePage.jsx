import { useState, useEffect, useCallback, useRef } from 'react'
import {
  FileText, Download, RefreshCw, Zap, AlertTriangle,
  CheckCircle2, XCircle, Clock, Shield, Activity,
  ChevronDown, ChevronRight, Award
} from 'lucide-react'
import { complianceApi, vexApi, aiApi } from '../utils/api'
import { useWebSocket } from '../hooks/useWebSocket'

// ─── Colour helpers ───────────────────────────────────────────────────────────
const STATUS_CFG = {
  pass:    { label: 'PASS',    color: 'text-green-400',  bg: 'bg-green-950 border-green-800',  icon: CheckCircle2 },
  fail:    { label: 'FAIL',    color: 'text-red-400',    bg: 'bg-red-950 border-red-800',      icon: XCircle      },
  partial: { label: 'PARTIAL', color: 'text-amber-400',  bg: 'bg-amber-950 border-amber-800',  icon: AlertTriangle},
  unknown: { label: 'UNKNOWN', color: 'text-gray-500',   bg: 'bg-gray-800 border-gray-700',    icon: Clock        },
  na:      { label: 'N/A',     color: 'text-gray-600',   bg: 'bg-gray-900 border-gray-800',    icon: Clock        },
}

const GRADE_CFG = {
  A: { color: 'text-green-400',  desc: 'Excellent — strong security posture'  },
  B: { color: 'text-blue-400',   desc: 'Good — minor gaps to address'         },
  C: { color: 'text-amber-400',  desc: 'Fair — significant improvements needed'},
  D: { color: 'text-orange-400', desc: 'Poor — critical issues present'       },
  F: { color: 'text-red-400',    desc: 'Critical — immediate action required' },
}

const RISK_COLOR = {
  CRITICAL: 'text-red-400',
  HIGH:     'text-orange-400',
  MEDIUM:   'text-amber-400',
  LOW:      'text-blue-400',
  MINIMAL:  'text-green-400',
}

function StatusBadge({ status }) {
  const cfg = STATUS_CFG[status] || STATUS_CFG.unknown
  const Icon = cfg.icon
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.color}`}>
      <Icon size={10} />{cfg.label}
    </span>
  )
}

function ProgressBar({ progress, step }) {
  return (
    <div className="card mb-4">
      <div className="flex justify-between text-xs mb-2">
        <span className="text-gray-400">{step || 'Generating compliance report…'}</span>
        <span className="text-indigo-400 font-medium">{Math.round(progress)}%</span>
      </div>
      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
        <div className="h-full bg-indigo-600 rounded-full transition-all duration-500"
             style={{ width: `${progress}%` }}/>
      </div>
    </div>
  )
}

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

// ─── Compliance scorecard ─────────────────────────────────────────────────────
import { useAI } from '../hooks/useAI'
import { Copy, Check, Sparkles } from 'lucide-react'

// ─── Compliance scorecard ─────────────────────────────────────────────────────
function Scorecard({ summary }) {
  const grade     = summary.compliance_grade || 'F'
  const gradeCfg  = GRADE_CFG[grade] || GRADE_CFG.F
  const riskColor = RISK_COLOR[summary.risk_label] || 'text-gray-400'
  const score     = summary.compliance_score || 0
  const total     = summary.controls_total   || 1

  return (
    <div className="grid grid-cols-3 gap-4 mb-6">
      {/* Grade */}
      <div className="card flex flex-col items-center justify-center py-6">
        <div className={`text-7xl font-black ${gradeCfg.color}`}>{grade}</div>
        <div className="text-xs text-gray-500 mt-1 text-center">{gradeCfg.desc}</div>
        <div className="text-2xl font-bold text-white mt-3">{score.toFixed(1)}%</div>
        <div className="text-xs text-gray-500">Compliance score</div>
      </div>

      {/* Controls breakdown */}
      <div className="card">
        <p className="text-xs text-gray-500 mb-3 font-medium">Controls ({total} total)</p>
        {[
          ['pass',    summary.controls_pass,    'text-green-400'],
          ['fail',    summary.controls_fail,    'text-red-400'],
          ['partial', summary.controls_partial, 'text-amber-400'],
          ['unknown', summary.controls_unknown, 'text-gray-500'],
        ].map(([lbl, val, clr]) => (
          <div key={lbl} className="flex items-center gap-2 mb-1.5">
            <div className="flex-1">
              <div className="flex justify-between text-xs mb-0.5">
                <span className="text-gray-400 capitalize">{lbl}</span>
                <span className={`font-bold ${clr}`}>{val || 0}</span>
              </div>
              <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                <div className={`h-full rounded-full ${
                  lbl==='pass'?'bg-green-600':lbl==='fail'?'bg-red-600':
                  lbl==='partial'?'bg-amber-600':'bg-gray-600'
                }`} style={{ width: `${total ? ((val||0)/total)*100 : 0}%` }}/>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Risk + device */}
      <div className="card space-y-3">
        <div>
          <p className="text-xs text-gray-500 mb-0.5">Firmware risk</p>
          <span className={`text-3xl font-bold ${riskColor}`}>{summary.risk_score?.toFixed(0) ?? 0}</span>
          <span className="text-gray-500 text-sm">/100</span>
          <span className={`ml-2 text-sm font-semibold ${riskColor}`}>{summary.risk_label}</span>
        </div>
        <hr className="border-gray-800"/>
        <div className="space-y-1 text-xs">
          {[
            ['Device',      summary.device_name      || '—'],
            ['Firmware',    summary.firmware_version  || '—'],
            ['Arch',        summary.architecture      || '—'],
            ['Scan date',   summary.scan_date         || '—'],
            ['Total CVEs',  summary.total_cves        ?? 0],
            ['Critical',    summary.critical_cves     ?? 0],
            ['Affected',    summary.affected_count    ?? 0],
          ].map(([k,v]) => (
            <div key={k} className="flex justify-between">
              <span className="text-gray-500">{k}</span>
              <span className="text-gray-200 font-medium">{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Control Detail Row (local state for AI non-conformance generation) ──────
function ControlDetailRow({ control }) {
  const { callAI } = useAI()
  const [writeup, setWriteup] = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    setWriteup('')
    setError('')
    setCopied(false)
  }, [control.control_id, control.standard])

  const handleGenerate = async () => {
    setLoading(true)
    setError('')
    try {
      const resp = await callAI('compliance-writeup', {
        control: {
          control_id: control.control_id,
          standard: control.standard,
          title: control.title,
          status: control.status,
          severity: control.severity,
          gaps: control.gaps,
          evidence: control.evidence,
          remediation: control.remediation
        }
      })
      setWriteup(resp.writeup)
    } catch (err) {
      setError(err.message || 'Failed to generate audit write-up')
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(writeup)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const showAiBtn = control.status === 'fail' || control.status === 'partial'

  return (
    <div className="space-y-3 p-3 bg-gray-950/40 rounded-lg border border-gray-800 text-xs">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Basic scan info */}
        <div className="space-y-2">
          {control.evidence?.length > 0 && (
            <div>
              <span className="text-gray-500 font-semibold uppercase tracking-wider text-[10px] block">Evidence found</span>
              <p className="text-gray-300 mt-0.5 leading-relaxed">{control.evidence[0]}</p>
            </div>
          )}
          {control.gaps?.length > 0 && (
            <div>
              <span className="text-red-400 font-semibold uppercase tracking-wider text-[10px] block mb-1">Identified Compliance Gaps</span>
              <ul className="list-disc list-inside text-gray-400 space-y-0.5">
                {control.gaps.map((g, gi) => <li key={gi}>{g}</li>)}
              </ul>
            </div>
          )}
          {control.remediation && (
            <div>
              <span className="text-amber-400 font-semibold uppercase tracking-wider text-[10px] block">Corrective Action</span>
              <p className="text-gray-300 mt-0.5 leading-relaxed">{control.remediation}</p>
            </div>
          )}
        </div>

        {/* AI Compliance statement */}
        <div className="border-t md:border-t-0 md:border-l border-gray-850 md:pl-4 space-y-2 flex flex-col justify-between">
          <div className="space-y-2">
            <span className="text-[10px] text-indigo-400 uppercase tracking-wider font-semibold block flex items-center gap-1">
              <Zap size={11} className="fill-indigo-400" />
              Formal Non-Conformance Write-Up
            </span>
            {writeup ? (
              <div className="bg-indigo-950/20 border border-indigo-900/35 rounded p-2.5 text-xs text-gray-300 leading-relaxed relative group whitespace-pre-wrap">
                <p className="pr-6">{writeup}</p>
                <button
                  onClick={handleCopy}
                  title="Copy write-up"
                  className="absolute right-2 top-2 p-1 rounded bg-gray-900 hover:bg-gray-800 text-gray-400 hover:text-white transition-colors"
                >
                  {copied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                </button>
              </div>
            ) : (
              <p className="text-xs text-gray-500 italic">
                Generate a formal non-conformance statement containing regulatory language, evidence citations, and timeline urgency suitable for final certification audit reports.
              </p>
            )}
            {error && (
              <p className="text-[11px] text-red-400 bg-red-950/10 border border-red-900/30 p-2 rounded">
                {error}
              </p>
            )}
          </div>

          {showAiBtn && (
            <div className="flex gap-2 justify-end pt-2">
              {writeup && (
                <button
                  onClick={handleCopy}
                  className="btn-secondary text-[11px] flex items-center gap-1.5 py-1.5 px-3 border border-gray-700 bg-gray-900 hover:bg-gray-800 text-white rounded-md"
                >
                  {copied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                  {copied ? 'Copied' : 'Copy Write-up'}
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
                {loading ? 'Generating...' : '⚡ Generate Audit Write-Up'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Controls table ───────────────────────────────────────────────────────────
function ControlsTable({ controls, stdFilter, onStdFilter }) {
  const [expanded, setExpanded] = useState(null)
  const standards = [...new Set(controls.map(c => c.standard))]
  const filtered  = stdFilter ? controls.filter(c => c.standard === stdFilter) : controls

  const SEV_COLOR = {
    critical:'text-red-400', high:'text-orange-400',
    medium:'text-amber-400', low:'text-blue-400', info:'text-gray-500',
  }

  return (
    <div className="space-y-3">
      {/* Standard filter tabs */}
      <div className="flex gap-1.5 flex-wrap">
        <button
          onClick={() => onStdFilter('')}
          className={`text-[10px] px-2.5 py-1 rounded-full border transition-colors ${
            !stdFilter ? 'bg-indigo-900 border-indigo-600 text-indigo-300'
                       : 'bg-gray-900 border-gray-700 text-gray-500 hover:text-gray-300'
          }`}
        >All standards</button>
        {standards.map(s => (
          <button
            key={s}
            onClick={() => onStdFilter(s)}
            className={`text-[10px] px-2.5 py-1 rounded-full border transition-colors ${
              stdFilter === s ? 'bg-indigo-900 border-indigo-600 text-indigo-300'
                              : 'bg-gray-900 border-gray-700 text-gray-500 hover:text-gray-300'
            }`}
          >{s}</button>
        ))}
      </div>

      <div className="card p-0">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-gray-500 border-b border-gray-800">
              <th className="w-6 py-2 px-3"></th>
              {['Control','Standard','Title','Status','Severity'].map(h => (
                <th key={h} className="text-left py-2 px-3 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((c, i) => {
              const isOpen = expanded === `${c.standard}-${c.control_id}`
              return (
                <>
                  <tr
                    key={i}
                    onClick={() => setExpanded(isOpen ? null : `${c.standard}-${c.control_id}`)}
                    className={`border-b border-gray-900 cursor-pointer hover:bg-gray-800/40 transition-colors ${
                      c.status === 'fail' ? 'bg-red-950/10' :
                      c.status === 'partial' ? 'bg-amber-950/10' : ''
                    }`}
                  >
                    <td className="py-2 px-3">
                      {isOpen
                        ? <ChevronDown size={11} className="text-gray-500"/>
                        : <ChevronRight size={11} className="text-gray-600"/>
                      }
                    </td>
                    <td className="py-2 px-3 font-mono text-indigo-400 whitespace-nowrap">{c.control_id}</td>
                    <td className="py-2 px-3 text-gray-500 text-[10px] max-w-28 truncate">{c.standard}</td>
                    <td className="py-2 px-3 text-gray-200 max-w-48 truncate" title={c.title}>{c.title}</td>
                    <td className="py-2 px-3"><StatusBadge status={c.status} /></td>
                    <td className={`py-2 px-3 capitalize font-medium text-[10px] ${SEV_COLOR[c.severity] || 'text-gray-500'}`}>
                      {c.severity}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr key={`${i}_detail`}>
                      <td colSpan={6} className="px-4 py-3 border-b border-gray-800 bg-gray-900/50">
                        <ControlDetailRow control={c} />
                      </td>
                    </tr>
                  )}
                </>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function CompliancePage() {
  const [vexJobs,  setVexJobs]  = useState([])
  const [pastJobs, setPastJobs] = useState([])

  const [selVexJobId, setSelVexJobId] = useState('')
  const [deviceName,  setDeviceName]  = useState('')

  const [running,      setRunning]      = useState(false)
  const [progress,     setProgress]     = useState(0)
  const [progressStep, setProgressStep] = useState('')
  const [jobId,        setJobId]        = useState(null)
  const [error,        setError]        = useState('')

  const [summary,   setSummary]   = useState(null)
  const [controls,  setControls]  = useState([])
  const [stdFilter, setStdFilter] = useState('')

  // AI Executive Summary State
  const [execSummary, setExecSummary] = useState('')
  const [summaryLoading, setSummaryLoading] = useState(false)
  const [summaryError, setSummaryError] = useState('')

  const pollRef = useRef(null)
  const { subscribe } = useWebSocket('ws://localhost:8000/ws')

  // Load VEX jobs + past compliance jobs
  useEffect(() => {
    vexApi.listJobs()
      .then(r => setVexJobs(r.data.jobs || []))
      .catch(() => {})
    complianceApi.listJobs()
      .then(r => setPastJobs(r.data.jobs || []))
      .catch(() => {})
  }, [])

  // Auto-fill device name from VEX job
  useEffect(() => {
    if (!selVexJobId) return
    const job = vexJobs.find(j => j.job_id === selVexJobId)
    if (job?.device_name) setDeviceName(job.device_name)
  }, [selVexJobId, vexJobs])

  // WS live progress
  useEffect(() => {
    return subscribe(ev => {
      if (ev.phase !== 'phase7') return
      if (ev.event === 'progress') {
        setProgress(ev.percent ?? 0)
        setProgressStep(ev.step ?? '')
      }
      if (ev.event === 'compliance_complete') {
        setRunning(false)
        setProgress(100)
        setProgressStep('Report complete!')
        if (ev.job_id) loadResults(ev.job_id)
      }
    })
  }, [subscribe])

  // Polling fallback
  useEffect(() => {
    if (!running || !jobId) return
    pollRef.current = setInterval(async () => {
      try {
        const r = await complianceApi.getStatus(jobId)
        const { status, progress: pct } = r.data
        setProgress(p => Math.max(p, pct ?? 0))
        if (status === 'success' || status === 'failed') {
          clearInterval(pollRef.current)
          setRunning(false)
          if (status === 'failed') setError(r.data.error || 'Report generation failed')
          else await loadResults(jobId)
        }
      } catch (_) {}
    }, 1500)
    return () => clearInterval(pollRef.current)
  }, [running, jobId])

  const loadResults = useCallback(async (jid) => {
    try {
      const [sumR, ctrlR] = await Promise.all([
        complianceApi.getSummary(jid),
        complianceApi.getControls(jid),
      ])
      setSummary(sumR.data)
      setControls(ctrlR.data.controls || [])
      setExecSummary('')
      setSummaryError('')
      complianceApi.listJobs().then(r => setPastJobs(r.data.jobs || [])).catch(() => {})
    } catch (e) {
      setError('Failed to load results: ' + e.message)
    }
  }, [])

  const handleStart = useCallback(async () => {
    if (!selVexJobId) { setError('Select a VEX analysis job first'); return }
    setRunning(true); setError('')
    setSummary(null); setControls([])
    setExecSummary(''); setSummaryError('')
    setProgress(1); setProgressStep('Submitting…')
    try {
      const r = await complianceApi.generate({
        vex_job_id:  selVexJobId,
        device_info: deviceName ? { name: deviceName } : undefined,
      })
      setJobId(r.data.job_id)
    } catch (err) {
      setRunning(false); setProgress(0)
      setError(err.response?.data?.detail || err.message)
    }
  }, [selVexJobId, deviceName])

  const handleLoadPast = useCallback(async (jid) => {
    setJobId(jid); setSummary(null); setControls([]); setError('')
    setExecSummary(''); setSummaryError('')
    await loadResults(jid)
  }, [loadResults])

  const handleDownload = useCallback(async (fmt) => {
    if (!jobId) return
    try {
      const r = fmt === 'pdf'
        ? await complianceApi.downloadPdf(jobId)
        : await complianceApi.downloadJson(jobId)
      const url = URL.createObjectURL(new Blob([r.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = `IIFVDCAS_Report_${jobId.substring(0,8)}.${fmt}`
      a.click(); URL.revokeObjectURL(url)
    } catch (e) { alert('Download failed: ' + e.message) }
  }, [jobId])

  const handleReset = () => {
    clearInterval(pollRef.current)
    setRunning(false); setProgress(0); setProgressStep('')
    setError(''); setJobId(null)
    setSummary(null); setControls([])
    setSelVexJobId(''); setDeviceName('')
    setExecSummary(''); setSummaryError('')
  }

  const handleGenerateSummary = async () => {
    setSummaryLoading(true)
    setSummaryError('')
    try {
      const resp = await aiApi.complianceExecSummary({
        summary: summary,
        failed_controls: controls.filter(c => c.status === 'fail'),
        firmware_context: {
          device_name: summary.device_name || deviceName,
          firmware_version: summary.firmware_version,
          architecture: summary.architecture
        }
      })
      setExecSummary(resp.executive_summary)
    } catch (err) {
      setSummaryError(err.message || 'Failed to generate Executive Summary')
    } finally {
      setSummaryLoading(false)
    }
  }

  const isDone = !!summary

  // Per-standard fail counts for mini summary
  const failsByStd = controls.reduce((acc, c) => {
    if (c.status === 'fail') acc[c.standard] = (acc[c.standard] || 0) + 1
    return acc
  }, {})

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="badge badge-blue text-[10px]">Phase 7</span>
            <span className="text-gray-600 text-xs font-mono">
              ETSI EN 303 645 · EU CRA 2024 · OWASP IoT · IEC 62443
            </span>
          </div>
          <h1 className="text-2xl font-bold text-white">Compliance Report</h1>
          <p className="text-gray-400 text-sm mt-1">
            Security gap analysis + PDF audit report across all phases
          </p>
        </div>
        {isDone && (
          <div className="flex gap-2">
            <button onClick={() => handleDownload('pdf')}
              className="btn-primary text-sm">
              <Download size={14}/> Download PDF
            </button>
            <button onClick={() => handleDownload('json')}
              className="btn-secondary text-sm">
              <Download size={14}/> JSON
            </button>
            <button onClick={handleReset} className="btn-secondary text-sm">
              <RefreshCw size={14}/> Reset
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
                VEX Analysis Job <span className="text-red-500">*</span>
              </label>
              <select
                value={selVexJobId}
                onChange={e => setSelVexJobId(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-sm text-gray-300 font-mono"
              >
                <option value="">— Select Phase 6 VEX job —</option>
                {vexJobs.map(j => (
                  <option key={j.job_id} value={j.job_id}>
                    {j.job_id.substring(0,14)}… — score {j.risk_score?.toFixed(0) ?? '?'} {j.risk_label} / {j.status}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1.5 font-medium">
                Device name <span className="text-gray-600">(optional)</span>
              </label>
              <input
                type="text"
                value={deviceName}
                onChange={e => setDeviceName(e.target.value)}
                placeholder="e.g. SmartHome-IoT v2.1"
                className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-sm text-gray-300 placeholder-gray-700"
              />
            </div>
          </div>

          {pastJobs.length > 0 && (
            <div className="mb-4">
              <label className="block text-xs text-gray-400 mb-1.5 font-medium">
                Or load a past report
              </label>
              <select
                onChange={e => e.target.value && handleLoadPast(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-sm text-gray-300 font-mono"
              >
                <option value="">— Past compliance reports —</option>
                {pastJobs.map(j => (
                  <option key={j.job_id} value={j.job_id}>
                    {j.job_id.substring(0,10)} — {j.device_name || 'unknown'} — grade {j.compliance_grade || '?'} / {j.status}
                  </option>
                ))}
              </select>
            </div>
          )}

          {error && (
            <div className="bg-red-950 border border-red-800 rounded-lg p-3 mb-4 flex gap-2">
              <AlertTriangle size={14} className="text-red-400 flex-shrink-0 mt-0.5"/>
              <span className="text-xs text-red-300">{error}</span>
            </div>
          )}

          <button onClick={handleStart} className="btn-primary">
            <Zap size={14}/> Generate Compliance Report
          </button>
        </div>
      )}

      {/* Progress */}
      {running && <ProgressBar progress={progress} step={progressStep}/>}

      {/* Error state */}
      {!running && error && !isDone && (
        <div className="card bg-red-950/30 border border-red-900 mb-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle size={14} className="text-red-400"/>
            <span className="text-sm font-medium text-red-300">Generation Failed</span>
          </div>
          <p className="text-xs text-red-400">{error}</p>
          <button onClick={handleReset} className="btn-secondary text-xs mt-3">
            <RefreshCw size={12}/> Try Again
          </button>
        </div>
      )}

      {/* Results */}
      {isDone && (
        <>
          <Scorecard summary={summary}/>

          {/* AI Executive Summary Card */}
          <div className="card mb-6 border border-gray-800">
            <div className="flex items-center justify-between border-b border-gray-850 pb-3 mb-3">
              <div className="flex items-center gap-2">
                <Sparkles size={14} className="text-indigo-400" />
                <h3 className="text-xs font-semibold text-white uppercase tracking-wider">AI Executive Summary</h3>
              </div>
              <button
                onClick={handleGenerateSummary}
                disabled={summaryLoading}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all border ${
                  summaryLoading
                    ? 'bg-indigo-950 text-indigo-400 border-indigo-900 cursor-not-allowed'
                    : 'bg-indigo-600 text-white border-indigo-500 hover:bg-indigo-500 shadow-md shadow-indigo-600/10'
                }`}
              >
                <Zap size={11} className={summaryLoading ? 'animate-spin' : ''} />
                {summaryLoading ? 'Generating Summary...' : execSummary ? '⚡ Regenerate Summary' : '⚡ Generate Summary'}
              </button>
            </div>

            {execSummary ? (
              <div className="text-xs text-gray-300 leading-relaxed whitespace-pre-wrap font-serif italic bg-indigo-950/10 p-4 border border-indigo-900/30 rounded-lg">
                {execSummary}
              </div>
            ) : summaryLoading ? (
              <div className="text-xs text-gray-500 animate-pulse py-2">
                Drafting compliance assessment cover-page briefing using NVD mappings and VEX matrices...
              </div>
            ) : (
              <p className="text-xs text-gray-500">
                Draft a high-level compliance assessment briefing suitable as the introduction cover-page paragraph for regulatory audit dossiers.
              </p>
            )}

            {summaryError && (
              <div className="mt-3 p-3 bg-red-950/20 border border-red-900/30 rounded-lg text-red-400 text-xs flex items-center gap-2">
                <AlertTriangle size={14} className="flex-shrink-0" />
                <span>{summaryError}</span>
              </div>
            )}
          </div>

          {/* Per-standard quick summary */}
          {Object.keys(failsByStd).length > 0 && (
            <div className="card mb-6">
              <p className="text-xs text-gray-500 font-medium mb-3">Failed controls by standard</p>
              <div className="flex gap-4 flex-wrap">
                {Object.entries(failsByStd).map(([std, cnt]) => (
                  <div key={std} className="text-xs">
                    <span className="text-gray-400">{std}</span>
                    <span className="text-red-400 font-bold ml-1.5">{cnt} failed</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Quick stats row */}
          <div className="grid grid-cols-4 gap-3 mb-6">
            <StatCard icon={Shield}    label="SBOM components"   value={summary.sbom_count}      color="text-indigo-400"/>
            <StatCard icon={Activity}  label="Crypto assets"     value={summary.cbom_count}      color="text-amber-400"/>
            <StatCard icon={AlertTriangle} label="Insecure crypto" value={summary.insecure_crypto} color="text-red-400"/>
            <StatCard icon={Award}     label="Controls assessed"  value={summary.controls_total}  color="text-white"/>
          </div>

          {/* Controls table */}
          <h2 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
            <FileText size={14} className="text-indigo-400"/>
            Compliance Controls ({controls.length})
          </h2>
          <ControlsTable
            controls={controls}
            stdFilter={stdFilter}
            onStdFilter={setStdFilter}
          />
        </>
      )}
    </div>
  )
}
