import { useState, useEffect, useCallback, useRef } from 'react'
import { useLocation } from 'react-router-dom'
import {
  Shield, Play, RefreshCw, CheckCircle2, AlertCircle, AlertTriangle,
  Lock, Key, FileText, Terminal, ChevronDown, ChevronRight,
  BarChart3, Activity, Cpu, FileSearch, Info, Zap
} from 'lucide-react'
import { useWebSocket } from '../hooks/useWebSocket'
import axios from 'axios'

const api = axios.create({ baseURL: '/api/v1', timeout: 300000 })

// ─── Severity badge ───────────────────────────────────────────────────────────
const SEV_BADGE = {
  critical: 'bg-red-950 text-red-400 border border-red-800',
  high:     'bg-orange-950 text-orange-400 border border-orange-800',
  medium:   'bg-amber-950 text-amber-400 border border-amber-800',
  low:      'bg-blue-950 text-blue-400 border border-blue-800',
  info:     'bg-gray-800 text-gray-400 border border-gray-700',
}

const RISK_COLOR = {
  critical: '#ef4444', high: '#f97316', medium: '#f59e0b',
  low: '#22c55e', minimal: '#22c55e', unknown: '#6b7280'
}

function SeverityBadge({ sev }) {
  return <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${SEV_BADGE[sev] || SEV_BADGE.info}`}>{sev}</span>
}

// ─── Risk score gauge ─────────────────────────────────────────────────────────
function RiskGauge({ score, label }) {
  const color = RISK_COLOR[label] || '#6b7280'
  const pct = score
  return (
    <div className="flex flex-col items-center">
      <div className="relative w-24 h-24">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r="40" fill="none" stroke="#1f2937" strokeWidth="10" />
          <circle cx="50" cy="50" r="40" fill="none" stroke={color} strokeWidth="10"
            strokeDasharray={`${pct * 2.51327} ${251.327 - pct * 2.51327}`}
            strokeLinecap="round" style={{ transition: 'stroke-dasharray 0.8s ease' }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold" style={{ color }}>{score}</span>
          <span className="text-[10px] text-gray-500">/100</span>
        </div>
      </div>
      <span className="text-xs font-medium mt-1 capitalize" style={{ color }}>{label || 'unknown'}</span>
    </div>
  )
}

// ─── Stat card ────────────────────────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, sub, color = 'text-white' }) {
  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-1">
        <Icon size={13} className="text-gray-500" />
        <span className="text-xs text-gray-500">{label}</span>
      </div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      {sub && <div className="text-xs text-gray-600 mt-0.5">{sub}</div>}
    </div>
  )
}

// ─── Collapsible section ──────────────────────────────────────────────────────
function Section({ title, icon: Icon, badge, badgeColor = 'badge-gray', count, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="card">
      <div className="flex items-center gap-2 cursor-pointer select-none" onClick={() => setOpen(!open)}>
        <Icon size={14} className="text-indigo-400" />
        <span className="text-sm font-semibold text-white flex-1">{title}</span>
        {count !== undefined && (
          <span className={`badge text-[10px] ${badgeColor}`}>{count} findings</span>
        )}
        {open ? <ChevronDown size={13} className="text-gray-500" />
               : <ChevronRight size={13} className="text-gray-500" />}
      </div>
      {open && <div className="mt-3 border-t border-gray-800 pt-3">{children}</div>}
    </div>
  )
}

// ─── Binary protection table ──────────────────────────────────────────────────
function BinaryTable({ binaries }) {
  if (!binaries?.length) return <p className="text-xs text-gray-500">No binaries found.</p>

  const FLAG = (v, good) => {
    const isGood = good ? v.includes(good) : v !== 'No'
    return <span className={`text-xs font-mono ${isGood ? 'text-green-400' : 'text-red-400'}`}>{v || '—'}</span>
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-gray-500 border-b border-gray-800">
            {['Binary', 'RELRO', 'Canary', 'NX', 'PIE', 'RPATH', 'Arch', 'Risk'].map(h => (
              <th key={h} className="text-left py-1.5 pr-3 font-medium">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {binaries.slice(0, 100).map((b, i) => (
            <tr key={i} className="border-b border-gray-900 hover:bg-gray-800/40">
              <td className="py-1.5 pr-3 mono text-gray-300 max-w-[180px] truncate" title={b.path}>{b.path?.split('/').pop()}</td>
              <td className="pr-3">{FLAG(b.relro || 'No', 'Full')}</td>
              <td className="pr-3">{FLAG(b.canary || 'No', 'Yes')}</td>
              <td className="pr-3">{FLAG(b.nx || 'No', 'Yes')}</td>
              <td className="pr-3">{FLAG(b.pie || 'No', 'PIE')}</td>
              <td className="pr-3">{FLAG(b.rpath === 'Yes' ? 'Yes' : 'No', null)}</td>
              <td className="pr-3 text-gray-400">{b.architecture || '—'}</td>
              <td>
                <div className="flex items-center gap-1">
                  <div className="h-1.5 w-16 bg-gray-800 rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{
                      width: `${(b.risk_score || 0) * 10}%`,
                      background: b.risk_score >= 7 ? '#ef4444' : b.risk_score >= 4 ? '#f59e0b' : '#22c55e'
                    }} />
                  </div>
                  <span className="text-gray-500">{b.risk_score}/10</span>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {binaries.length > 100 && (
        <p className="text-xs text-gray-600 mt-2">Showing 100 of {binaries.length} binaries</p>
      )}
    </div>
  )
}

import { useAI } from '../hooks/useAI'

// ─── Finding Row (local state for AI explanation) ───────────────────────────
function FindingRow({ item, fields }) {
  const { callAI } = useAI()
  const [explanation, setExplanation] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    setExplanation('')
    setError('')
  }, [item])

  const handleExplain = async () => {
    setLoading(true)
    setError('')
    try {
      const resp = await callAI('explain-finding', {
        finding: item,
        firmware_context: {}
      })
      setExplanation(resp.explanation)
    } catch (err) {
      setError(err.message || 'Failed to explain finding')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-gray-950 rounded-lg p-3 border border-gray-800 space-y-2">
      <div className="flex items-start justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge sev={item.severity || 'info'} />
          {fields.title && <span className="text-xs font-semibold text-white">{item[fields.title]}</span>}
        </div>
        <button
          onClick={handleExplain}
          disabled={loading}
          className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border transition-all ${
            loading
              ? 'bg-indigo-950 text-indigo-400 border-indigo-900 cursor-not-allowed'
              : 'bg-indigo-950/20 text-indigo-400 border-indigo-800/40 hover:bg-indigo-950/50'
          }`}
        >
          <Zap size={10} className={loading ? 'animate-spin' : ''} />
          {loading ? 'Analyzing...' : '⚡ Explain'}
        </button>
      </div>

      <div className="space-y-0.5">
        {fields.detail?.map(([label, key]) => item[key] ? (
          <div key={key} className="flex gap-2 text-xs">
            <span className="text-gray-600 w-24 flex-shrink-0">{label}</span>
            <span className="text-gray-300 mono break-all">{String(item[key]).substring(0, 120)}</span>
          </div>
        ) : null)}
      </div>

      {explanation && (
        <div className="p-2 bg-indigo-950/10 border border-indigo-900/30 rounded text-[11px] text-gray-350 leading-relaxed whitespace-pre-wrap">
          {explanation}
        </div>
      )}

      {error && (
        <div className="p-2 bg-red-950/10 border border-red-900/30 rounded text-[11px] text-red-400">
          {error}
        </div>
      )}
    </div>
  )
}

// ─── Findings list ────────────────────────────────────────────────────────────
function FindingsList({ items, fields }) {
  if (!items?.length) return <p className="text-xs text-gray-500">No findings.</p>
  return (
    <div className="space-y-2">
      {items.slice(0, 50).map((item, i) => (
        <FindingRow key={i} item={item} fields={fields} />
      ))}
      {items.length > 50 && (
        <p className="text-xs text-gray-600">Showing 50 of {items.length} findings</p>
      )}
    </div>
  )
}

// ─── Log panel ────────────────────────────────────────────────────────────────
function LogPanel({ logs }) {
  const ref = useRef(null)
  useEffect(() => { ref.current?.scrollTo(0, ref.current.scrollHeight) }, [logs])
  if (!logs.length) return null
  return (
    <div className="card mt-4">
      <div className="flex items-center gap-2 mb-2">
        <Terminal size={12} className="text-gray-500" />
        <span className="text-xs text-gray-500 font-medium">Analysis Log</span>
      </div>
      <div ref={ref} className="max-h-48 overflow-y-auto space-y-0.5">
        {logs.map((e, i) => (
          <div key={i} className="text-[11px] mono flex gap-2">
            <span className="text-gray-600 flex-shrink-0">{e.ts?.substring(11, 19)}</span>
            <span className={
              e.msg?.includes('[S12]') ? 'text-blue-400' :
              e.msg?.includes('[S13]') ? 'text-purple-400' :
              e.msg?.includes('[S20]') ? 'text-cyan-400' :
              e.msg?.includes('[S45]') || e.msg?.includes('[S107]') ? 'text-red-400' :
              e.msg?.includes('[S60]') ? 'text-amber-400' :
              e.msg?.includes('[S85]') ? 'text-orange-400' :
              e.msg?.includes('[DONE]') ? 'text-green-400' :
              e.msg?.includes('[ERROR]') ? 'text-red-500' :
              'text-gray-400'
            }>{e.msg}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Progress bar ─────────────────────────────────────────────────────────────
function ProgressBar({ progress, step }) {
  return (
    <div className="card">
      <div className="flex justify-between text-xs mb-2">
        <span className="text-gray-400">{step || 'Analyzing...'}</span>
        <span className="text-indigo-400 font-medium">{progress}%</span>
      </div>
      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
        <div className="h-full bg-indigo-600 rounded-full transition-all duration-300"
             style={{ width: `${progress}%` }} />
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function StaticAnalysis() {
  const [targetDir, setTargetDir] = useState('')
  const [extractionJobId, setExtractionJobId] = useState('')
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [progressStep, setProgressStep] = useState('')
  const [logs, setLogs] = useState([])
  const [result, setResult] = useState(null)
  const [jobId, setJobId] = useState(null)
  const [error, setError] = useState('')
  const [extractionJobs, setExtractionJobs] = useState([])


  const { subscribe } = useWebSocket('ws://localhost:8000/ws')

  // Fetch extraction jobs and auto-select saved job
  useEffect(() => {
    api.get('/firmware/jobs')
      .then(r => {
        const jobs = r.data.jobs || []
        setExtractionJobs(jobs)
        const savedJobId = sessionStorage.getItem('fw_extraction_job_id')
        if (savedJobId && jobs.find(j => j.job_id === savedJobId)) {
          setExtractionJobId(savedJobId)
        } else if (savedJobId) {
          // job not in list yet, set anyway
          setExtractionJobId(savedJobId)
        }
      })
      .catch(() => {})
  }, [])

  // Subscribe to WS events
  useEffect(() => {
    return subscribe((event) => {
      if (event.phase !== 'phase3') return
      if (event.event === 'log') {
        setLogs(prev => [...prev, { ts: new Date().toISOString(), msg: event.message }])
      }
      if (event.event === 'progress') {
        setProgress(event.percent || 0)
        setProgressStep(event.step || '')
      }
      if (event.event === 'analysis_complete') {
        setRunning(false)
        setProgress(100)
        setResult(event.result || {})
        setLogs(prev => [...prev, {
          ts: new Date().toISOString(),
          msg: `[DONE] ${event.status} — Risk: ${event.risk_score}/100 (${event.risk_label})`
        }])
      }
      if (event.event === 'analysis_started') {
        setLogs([{ ts: new Date().toISOString(), msg: '[S12] Static analysis started...' }])
        setProgress(0)
        setResult(null)
      }
    })
  }, [subscribe])

  const handleStart = useCallback(async () => {
    const body = extractionJobId
      ? { extraction_job_id: extractionJobId }
      : { target_dir: targetDir }

    setRunning(true); setError(''); setResult(null)
    setLogs([{ ts: new Date().toISOString(), msg: '[P3] Starting static analysis...' }])
    setProgress(2)

    try {
      const r = await api.post('/analysis/start', body)
      const analysisJobId = r.data.job_id
      setJobId(analysisJobId)
      const poll = setInterval(async () => {
        try {
          const res = await api.get('/analysis/' + analysisJobId)
          if (res.data.status === 'success' || res.data.status === 'failed') {
            clearInterval(poll)
            setRunning(false)
            setProgress(100)
            setResult(res.data)
            setLogs(prev => [...prev, { ts: new Date().toISOString(), msg: '[DONE] ' + res.data.status + ' — Risk: ' + res.data.risk_score + '/100 (' + res.data.risk_label + ')' }])
          }
        } catch (_) {}
      }, 1000)
    } catch (err) {
      setRunning(false)
      setError(err.response?.data?.detail || err.message)
    }
  }, [targetDir, extractionJobId])

  const handleReset = () => {
    setResult(null); setLogs([]); setProgress(0); setError('')
    setRunning(false); setJobId(null)
  }

  const riskColor = result ? (RISK_COLOR[result.risk_label] || '#6b7280') : '#6b7280'

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="badge badge-purple text-[10px]">Phase 3</span>
            <span className="text-gray-600 text-xs mono">EMBA: S12·S13·S20·S45·S60·S85·S107</span>
          </div>
          <h1 className="text-2xl font-bold text-white">Static Analysis</h1>
          <p className="text-gray-400 text-sm mt-1">
            Binary protections · Weak functions · Credentials · Certificates · SSH
          </p>
        </div>
        {result && (
          <button onClick={handleReset} className="btn-secondary text-sm">
            <RefreshCw size={14} /> Reset
          </button>
        )}
      </div>

      {/* Input + launch */}
      {!result && (
        <div className="card mb-6 max-w-2xl">
          <div className="text-sm font-medium text-white mb-3">Target — extracted firmware directory</div>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Extraction Job ID (from Phase 2)</label>
              <select
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm mono text-gray-200 focus:border-indigo-600 outline-none"
                value={extractionJobId}
                onChange={e => { setExtractionJobId(e.target.value); setTargetDir('') }}
              >
                <option value="">-- Select an extracted job --</option>
                {extractionJobs.map(job => (
                  <option key={job.job_id} value={job.job_id}>
                    {job.job_id} — {job.device_port || job.fw_path?.split('/').pop()}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2 text-xs text-gray-600">
              <div className="flex-1 h-px bg-gray-800" /> or <div className="flex-1 h-px bg-gray-800" />
            </div>
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Direct path to extracted directory</label>
              <input
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm mono text-gray-200 focus:border-indigo-600 outline-none"
                placeholder="/tmp/iifvdcas_extractions/abc123/"
                value={targetDir}
                onChange={e => { setTargetDir(e.target.value); setExtractionJobId('') }}
              />
            </div>
          </div>
          {error && (
            <div className="mt-3 flex items-center gap-2 text-xs text-red-400 bg-red-950 border border-red-800 rounded-lg px-3 py-2">
              <AlertCircle size={12} /> {error}
            </div>
          )}
          <button
            onClick={handleStart}
            disabled={running || (!targetDir && !extractionJobId)}
            className="btn-primary text-sm mt-4 w-full justify-center"
          >
            <Play size={14} className={running ? 'animate-pulse' : ''} />
            {running ? 'Running Analysis...' : 'Run Static Analysis'}
          </button>
        </div>
      )}

      {/* Progress */}
      {running && (
        <div className="max-w-2xl mb-4">
          <ProgressBar progress={progress} step={progressStep} />
          <LogPanel logs={logs} />
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Summary row */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="card flex items-center gap-4 col-span-2 lg:col-span-1 row-span-2">
              <RiskGauge score={result.risk_score || 0} label={result.risk_label} />
              <div>
                <div className="text-xs text-gray-500 mb-1">Overall Risk</div>
                <div className="text-sm font-medium text-white capitalize">{result.risk_label}</div>
                <div className="text-xs text-gray-600 mt-1">Based on all S-modules</div>
              </div>
            </div>
            <StatCard icon={Cpu} label="Binaries Checked" value={result.total_binaries || 0}
              sub={`${result.binaries_no_nx || 0} no NX · ${result.binaries_no_pie || 0} no PIE`}
              color={result.binaries_no_nx > 5 ? 'text-red-400' : 'text-white'} />
            <StatCard icon={AlertTriangle} label="Weak Functions" value={result.total_weak_funcs || 0}
              sub="strcpy, gets, system..."
              color={result.total_weak_funcs > 10 ? 'text-red-400' : result.total_weak_funcs > 0 ? 'text-amber-400' : 'text-green-400'} />
            <StatCard icon={Key} label="Credentials Found" value={result.total_passwords || 0}
              sub="hashes · keys · passwords"
              color={result.total_passwords > 0 ? 'text-red-400' : 'text-green-400'} />
            <StatCard icon={FileText} label="Cert Issues" value={result.total_expired_certs || 0}
              sub="expired certificates"
              color={result.total_expired_certs > 0 ? 'text-amber-400' : 'text-green-400'} />
            <StatCard icon={Lock} label="SSH Issues" value={result.total_ssh_issues || 0}
              sub="keys · weak config"
              color={result.total_ssh_issues > 0 ? 'text-red-400' : 'text-green-400'} />
            <StatCard icon={FileSearch} label="Script Issues" value={result.total_script_issues || 0}
              sub="shellcheck · bandit"
              color={result.total_script_issues > 0 ? 'text-amber-400' : 'text-green-400'} />
            <StatCard icon={AlertTriangle} label="Embedded Findings" value={result.total_embedded_findings || 0}
              sub={String(result.total_embedded_critical || 0) + ' critical — creds · backdoors'}
              color={result.total_embedded_critical > 0 ? 'text-red-400' : result.total_embedded_findings > 0 ? 'text-amber-400' : 'text-green-400'} />
            <StatCard icon={Cpu} label="AVR/MCU Findings" value={result.total_avr_findings || 0}
              sub={String(result.total_avr_critical || 0) + ' critical — disasm · symbols'}
              color={result.total_avr_critical > 0 ? 'text-red-400' : result.total_avr_findings > 0 ? 'text-amber-400' : 'text-green-400'} />
          </div>

          {/* S12: Binary Protections */}
          <Section title="S12 — Binary Protection Mechanisms"
            icon={Shield} count={result.total_binaries}
            badgeColor={result.binaries_no_nx > 0 ? 'badge-red' : 'badge-green'}
            defaultOpen={true}>
            <div className="text-xs text-gray-500 mb-3 flex gap-4">
              <span>No NX: <span className="text-red-400">{result.binaries_no_nx}</span></span>
              <span>No PIE: <span className="text-red-400">{result.binaries_no_pie}</span></span>
              <span>No Canary: <span className="text-red-400">{result.binaries_no_canary}</span></span>
            </div>
            <BinaryTable binaries={result.binary_protections} />
          </Section>

          {/* S13: Weak Functions */}
          <Section title="S13 — Weak / Dangerous Functions"
            icon={AlertTriangle} count={result.total_weak_funcs}
            badgeColor={result.total_weak_funcs > 0 ? 'badge-red' : 'badge-green'}>
            <FindingsList items={result.weak_functions} fields={{
              title: 'function',
              detail: [['Binary', 'binary'], ['Count', 'count']]
            }} />
          </Section>

          {/* S45/S107: Passwords */}
          <Section title="S45/S107 — Passwords & Credentials"
            icon={Key} count={result.total_passwords}
            badgeColor={result.total_passwords > 0 ? 'badge-red' : 'badge-green'}>
            <FindingsList items={result.password_findings} fields={{
              title: 'finding_type',
              detail: [['File', 'file_path'], ['Hash Type', 'hash_type'], ['Value', 'value'], ['Line', 'line_number']]
            }} />
          </Section>

          {/* S60: Certificates */}
          <Section title="S60 — SSL/TLS Certificate Check"
            icon={FileText} count={result.cert_findings?.length || 0}
            badgeColor={result.total_expired_certs > 0 ? 'badge-amber' : 'badge-green'}>
            <FindingsList items={result.cert_findings} fields={{
              title: 'file_path',
              detail: [['Subject', 'subject'], ['Expires', 'not_after'],
                       ['Days left', 'days_until_expiry'], ['Expired', 'is_expired']]
            }} />
          </Section>

          {/* S85: SSH */}
          <Section title="S85 — SSH Keys & Configuration"
            icon={Lock} count={result.total_ssh_issues}
            badgeColor={result.total_ssh_issues > 0 ? 'badge-red' : 'badge-green'}>
            <FindingsList items={result.ssh_findings} fields={{
              title: 'finding_type',
              detail: [['File', 'file_path'], ['Detail', 'detail']]
            }} />
          </Section>

          {/* S20: Scripts */}
          <Section title="S20 — Shell / Python Script Analysis"
            icon={FileSearch} count={result.total_script_issues}
            badgeColor={result.total_script_issues > 0 ? 'badge-amber' : 'badge-green'}>
            <FindingsList items={result.script_findings} fields={{
              title: 'issue_code',
              detail: [['File', 'file_path'], ['Tool', 'tool'], ['Message', 'message'], ['Line', 'line']]
            }} />
          </Section>

          {/* AVR: Disassembly + Security Analysis */}
          {(result.avr_disassembly || result.total_avr_findings > 0) && (
            <Section title="AVR Analysis — avr-objdump · avr-strings · r2pipe"
              icon={Cpu} count={result.total_avr_findings}
              badgeColor={result.total_avr_critical > 0 ? 'badge-red' : 'badge-green'}
              defaultOpen={result.total_avr_findings > 0}>

              {/* Disassembly metadata */}
              {result.avr_disassembly && (
                <div className="mb-4 grid grid-cols-2 lg:grid-cols-4 gap-3">
                  {[
                    ['Device', result.avr_disassembly.device_hint],
                    ['Flash Size', result.avr_disassembly.flash_size_bytes ? Math.round(result.avr_disassembly.flash_size_bytes/1024) + ' KB' : '—'],
                    ['Entry Point', result.avr_disassembly.entry_point || '—'],
                    ['Instructions', result.avr_disassembly.total_instructions?.toLocaleString() || '0'],
                    ['IVT Entries', result.avr_disassembly.interrupt_vectors?.length || 0],
                    ['Symbols', result.avr_disassembly.functions?.length || 0],
                    ['Strings Found', result.strings_extracted || '—'],
                    ['Architecture', result.avr_disassembly.architecture || 'AVR'],
                  ].map(([label, val]) => (
                    <div key={label} className="bg-gray-950 border border-gray-800 rounded-lg p-2">
                      <div className="text-[10px] text-gray-600 mb-0.5">{label}</div>
                      <div className="text-xs font-medium text-gray-200 mono">{val}</div>
                    </div>
                  ))}
                </div>
              )}

              {/* Interrupt Vector Table */}
              {result.avr_disassembly?.interrupt_vectors?.length > 0 && (
                <details className="mb-4">
                  <summary className="text-xs text-gray-500 cursor-pointer mb-2">
                    Interrupt Vector Table ({result.avr_disassembly.interrupt_vectors.length} entries)
                  </summary>
                  <div className="bg-gray-950 rounded-lg border border-gray-800 overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-gray-600 border-b border-gray-800">
                          <th className="text-left px-3 py-1.5">#</th>
                          <th className="text-left px-3 py-1.5">Name</th>
                          <th className="text-left px-3 py-1.5">Address</th>
                          <th className="text-left px-3 py-1.5">Target</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.avr_disassembly.interrupt_vectors.slice(0,10).map((v,i) => (
                          <tr key={i} className="border-b border-gray-900">
                            <td className="px-3 py-1 text-gray-600">{v.index}</td>
                            <td className="px-3 py-1 text-indigo-300 font-medium">{v.name}</td>
                            <td className="px-3 py-1 mono text-gray-300">{v.address}</td>
                            <td className="px-3 py-1 mono text-amber-300">{v.target}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </details>
              )}

              {/* Security Findings */}
              <div className="space-y-2">
                {(result.avr_findings || []).map((f, i) => (
                  <div key={i} className="bg-gray-950 rounded-lg p-3 border border-gray-800">
                    <div className="flex items-center gap-2 flex-wrap mb-2">
                      <SeverityBadge sev={f.severity} />
                      <span className="text-xs font-medium text-white">{f.finding_type?.replace(/_/g,' ')}</span>
                      <span className="badge badge-gray text-[10px] ml-auto">{f.category}</span>
                      {f.address && <span className="mono text-[10px] text-gray-600">{f.address}</span>}
                    </div>
                    <div className="space-y-0.5">
                      <div className="flex gap-2 text-xs">
                        <span className="text-gray-600 w-16 flex-shrink-0">Detail</span>
                        <span className="text-red-300 mono font-medium">{f.detail}</span>
                      </div>
                      {f.context && (
                        <div className="flex gap-2 text-xs">
                          <span className="text-gray-600 w-16 flex-shrink-0">Context</span>
                          <span className="text-gray-500 mono">{f.context.substring(0,120)}</span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
                {!result.avr_findings?.length && <p className="text-xs text-gray-500">No AVR security issues found.</p>}
              </div>

              {/* Raw disassembly excerpt */}
              {result.avr_disassembly?.raw_disasm_excerpt && (
                <details className="mt-3">
                  <summary className="text-xs text-gray-500 cursor-pointer">
                    Raw disassembly (first 100 instructions)
                  </summary>
                  <pre className="text-[10px] mono text-green-400 bg-gray-950 border border-gray-800 rounded-lg p-3 mt-1 overflow-x-auto max-h-64">
                    {result.avr_disassembly.raw_disasm_excerpt}
                  </pre>
                </details>
              )}
            </Section>
          )}

          {/* S108: Embedded Binary String Analysis */}
          <Section title="S108 — Embedded Binary String Analysis (IoT/MCU/AVR)"
            icon={Zap} count={result.total_embedded_findings}
            badgeColor={result.total_embedded_critical > 0 ? 'badge-red' : result.total_embedded_findings > 0 ? 'badge-amber' : 'badge-green'}
            defaultOpen={result.total_embedded_findings > 0}>
            {result.total_embedded_findings > 0 && (
              <div className="mb-3 grid grid-cols-3 gap-2 text-xs">
                {[
                  ['Credentials', result.embedded_string_findings?.filter(e => e.category === 'credential').length || 0, 'text-red-400'],
                  ['Backdoors',   result.embedded_string_findings?.filter(e => e.category === 'backdoor').length || 0,   'text-orange-400'],
                  ['Insecure Protocols', result.embedded_string_findings?.filter(e => e.category === 'insecure_protocol').length || 0, 'text-amber-400'],
                ].map(([label, count, color]) => (
                  <div key={label} className="bg-gray-950 rounded-lg p-2 border border-gray-800 text-center">
                    <div className={String(color) + " text-xl font-bold"}>{count}</div>
                    <div className="text-gray-500">{label}</div>
                  </div>
                ))}
              </div>
            )}
            <div className="space-y-2">
              {(result.embedded_string_findings || []).map((f, i) => (
                <div key={i} className="bg-gray-950 rounded-lg p-3 border border-gray-800">
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <SeverityBadge sev={f.severity} />
                    <span className="text-xs font-medium text-white">{f.finding_type?.replace(/_/g, ' ')}</span>
                    <span className="badge badge-gray text-[10px] ml-auto">{f.category}</span>
                  </div>
                  <div className="space-y-1">
                    <div className="flex gap-2 text-xs">
                      <span className="text-gray-600 w-20 flex-shrink-0">File</span>
                      <span className="text-gray-400 mono">{f.file_path}</span>
                    </div>
                    <div className="flex gap-2 text-xs">
                      <span className="text-gray-600 w-20 flex-shrink-0">Match</span>
                      <span className="text-red-300 mono font-medium">{f.pattern_match}</span>
                    </div>
                    {f.context && (
                      <div className="flex gap-2 text-xs">
                        <span className="text-gray-600 w-20 flex-shrink-0">Context</span>
                        <span className="text-gray-500 mono">{f.context.substring(0, 120)}</span>
                      </div>
                    )}
                  </div>
                </div>
              ))}
              {!result.embedded_string_findings?.length && (
                <p className="text-xs text-gray-500">No embedded credentials or backdoors found.</p>
              )}
            </div>
          </Section>

          {/* Log */}
          <LogPanel logs={result.log || []} />
        </div>
      )}
    </div>
  )
}
