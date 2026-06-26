import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Package, Play, RefreshCw, CheckCircle2, AlertTriangle,
  Download, ChevronDown, ChevronRight, FileJson, Zap,
  Shield, Activity, Search, Info
} from 'lucide-react'
import api, { sbomApi } from '../utils/api'
import { useWebSocket } from '../hooks/useWebSocket'

// ─── Severity badge ───────────────────────────────────────────────────────────
function StrengthBadge({ strength }) {
  const colors = {
    strong:     'bg-green-950 text-green-400 border border-green-800',
    acceptable: 'bg-blue-950 text-blue-400 border border-blue-800',
    weak:       'bg-amber-950 text-amber-400 border border-amber-800',
    insecure:   'bg-red-950 text-red-400 border border-red-800',
  }
  return (
    <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${colors[strength] || colors.acceptable}`}>
      {strength || 'unknown'}
    </span>
  )
}

// ─── Progress bar ─────────────────────────────────────────────────────────────
function ProgressBar({ progress, step }) {
  return (
    <div className="card mb-4">
      <div className="flex justify-between text-xs mb-2">
        <span className="text-gray-400">{step || 'Generating SBOM…'}</span>
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

// ─── Stat card ────────────────────────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, color = 'text-white' }) {
  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-1">
        <Icon size={13} className="text-gray-500" />
        <span className="text-xs text-gray-500">{label}</span>
      </div>
      <div className={`text-2xl font-bold ${color}`}>{value ?? '—'}</div>
    </div>
  )
}

// ─── JSON Viewer ──────────────────────────────────────────────────────────────
function JSONViewer({ data, title }) {
  const [collapsed, setCollapsed] = useState(false)
  if (!data) return (
    <div className="card text-center py-8 text-gray-500 text-sm">No data available</div>
  )
  return (
    <div className="card">
      <div
        className="flex items-center gap-2 cursor-pointer select-none mb-2"
        onClick={() => setCollapsed(v => !v)}
      >
        {collapsed ? <ChevronRight size={14} /> : <ChevronDown size={14} />}
        <FileJson size={14} className="text-indigo-400" />
        <span className="text-sm font-semibold text-white flex-1">{title}</span>
      </div>
      {!collapsed && (
        <pre className="bg-gray-950 rounded p-3 text-[11px] font-mono text-gray-400 overflow-x-auto max-h-96 overflow-y-auto border border-gray-800">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  )
}

// ─── Component table ──────────────────────────────────────────────────────────
function ComponentTable({ components }) {
  const [search, setSearch] = useState('')
  const [filterType, setFilterType] = useState('')
  const filtered = components.filter(c => {
    const matchSearch = !search || c.name?.toLowerCase().includes(search.toLowerCase())
    const matchType   = !filterType || c.type === filterType || c.component_type === filterType
    return matchSearch && matchType
  })

  if (!components.length) return (
    <div className="card text-center py-8 text-gray-500 text-sm">No components found</div>
  )

  return (
    <div className="space-y-3">
      <div className="flex gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 flex-1 min-w-48">
          <Search size={14} className="text-gray-600" />
          <input
            type="text"
            placeholder="Search components…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="flex-1 bg-gray-950 border border-gray-800 rounded px-2 py-1 text-xs text-gray-300 placeholder-gray-700"
          />
        </div>
        <select
          value={filterType}
          onChange={e => setFilterType(e.target.value)}
          className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-xs text-gray-300"
        >
          <option value="">All types</option>
          <option value="library">Library</option>
          <option value="application">Application</option>
          <option value="firmware">Firmware</option>
        </select>
      </div>
      <div className="card overflow-x-auto p-0">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-gray-500 border-b border-gray-800">
              {['Name','Version','Type','PURL / CPE','License','Source'].map(h => (
                <th key={h} className="text-left py-2 px-3 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 200).map((c, i) => (
              <tr key={i} className="border-b border-gray-900 hover:bg-gray-800/40">
                <td className="py-2 px-3 text-gray-200 max-w-40 truncate" title={c.name}>{c.name}</td>
                <td className="py-2 px-3 text-gray-400 font-mono text-[11px]">{c.version || '—'}</td>
                <td className="py-2 px-3">
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-300">
                    {c.type || c.component_type || '—'}
                  </span>
                </td>
                <td className="py-2 px-3 text-gray-500 text-[10px] font-mono max-w-36 truncate"
                    title={c.purl || c.cpe}>
                  {(c.purl || c.cpe || '—').substring(0, 40)}
                </td>
                <td className="py-2 px-3 text-gray-400 text-[10px] max-w-24 truncate">
                  {c.license || '—'}
                </td>
                <td className="py-2 px-3 text-gray-500 text-[10px] max-w-32 truncate"
                    title={c.source_path || c.source}>
                  {c.source_path || c.source || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length > 200 && (
          <p className="text-xs text-gray-600 px-3 py-2">Showing 200 of {filtered.length} components</p>
        )}
      </div>
    </div>
  )
}

// ─── CBOM table ───────────────────────────────────────────────────────────────
function CBOMTable({ components }) {
  if (!components?.length) return (
    <div className="card text-center py-8 text-gray-500 text-sm">No cryptographic assets found</div>
  )
  return (
    <div className="card overflow-x-auto p-0">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-gray-500 border-b border-gray-800">
            {['Algorithm','Category','Strength','Source','Context'].map(h => (
              <th key={h} className="text-left py-2 px-3 font-medium">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {components.map((c, i) => (
            <tr key={i} className="border-b border-gray-900 hover:bg-gray-800/40">
              <td className="py-2 px-3 text-gray-200 font-mono">{c.algorithm}</td>
              <td className="py-2 px-3 text-gray-400">{c.category}</td>
              <td className="py-2 px-3"><StrengthBadge strength={c.strength} /></td>
              <td className="py-2 px-3 text-gray-500 text-[10px] max-w-32 truncate">{c.source_file || '—'}</td>
              <td className="py-2 px-3 text-gray-600 text-[10px] max-w-40 truncate">{c.context || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── HBOM table ───────────────────────────────────────────────────────────────
function HBOMTable({ components }) {
  if (!components?.length) return (
    <div className="card text-center py-8 text-gray-500 text-sm">No hardware components found</div>
  )
  return (
    <div className="card overflow-x-auto p-0">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-gray-500 border-b border-gray-800">
            {['Component','Type','Manufacturer','Source','Description'].map(h => (
              <th key={h} className="text-left py-2 px-3 font-medium">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {components.map((c, i) => (
            <tr key={i} className="border-b border-gray-900 hover:bg-gray-800/40">
              <td className="py-2 px-3 text-gray-200 font-medium">{c.name}</td>
              <td className="py-2 px-3">
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-300">
                  {c.component_type || '—'}
                </span>
              </td>
              <td className="py-2 px-3 text-gray-400">{c.manufacturer || '—'}</td>
              <td className="py-2 px-3 text-gray-500 text-[10px]">{c.source || '—'}</td>
              <td className="py-2 px-3 text-gray-600 text-[10px] max-w-48 truncate">{c.description || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function SBOM() {
  const [extractionJobId, setExtractionJobId] = useState('')
  const [analysisJobId,   setAnalysisJobId]   = useState('')
  const [deviceInfo,      setDeviceInfo]       = useState('')
  const [outputDir,       setOutputDir]        = useState('')

  const [running,       setRunning]       = useState(false)
  const [progress,      setProgress]      = useState(0)
  const [progressStep,  setProgressStep]  = useState('')
  const [jobId,         setJobId]         = useState(null)
  const [error,         setError]         = useState('')

  // Full result data
  const [sbomData, setSbomData] = useState(null)   // full /sbom/{id} response
  const [hbomData, setHbomData] = useState(null)
  const [cbomData, setCbomData] = useState(null)

  const [activeTab,       setActiveTab]       = useState('sbom')
  const [extractionJobs,  setExtractionJobs]  = useState([])

  const pollRef = useRef(null)
  const { subscribe } = useWebSocket('ws://localhost:8000/ws')

  // Load existing extraction jobs for dropdown
  useEffect(() => {
    api.get('/firmware/jobs')
      .then(r => setExtractionJobs(r.data.jobs || []))
      .catch(() => {})
  }, [])

  // ── WebSocket: receive live progress ────────────────────────────────────────
  useEffect(() => {
    return subscribe(ev => {
      if (ev.phase !== 'phase4') return

      if (ev.event === 'sbom_started') {
        setProgressStep('Starting SBOM generation…')
        setProgress(2)
      }
      if (ev.event === 'progress') {
        setProgress(ev.percent ?? 0)
        setProgressStep(ev.step ?? '')
      }
      if (ev.event === 'log') {
        // visible in browser console
        console.log('[SBOM WS]', ev.message)
      }
      if (ev.event === 'sbom_complete') {
        setRunning(false)
        setProgress(100)
        setProgressStep('Generation complete!')
        // Load full data now
        if (ev.job_id) loadFullData(ev.job_id)
      }
    })
  }, [subscribe])

  // ── Polling fallback (every 1.5 s while running) ──────────────────────────
  // Used when WS drops or events are delayed
  useEffect(() => {
    if (!running || !jobId) return

    pollRef.current = setInterval(async () => {
      try {
        const r = await sbomApi.getStatus(jobId)
        const { status, progress: pct, progress_step } = r.data
        setProgress(p => Math.max(p, pct ?? 0))
        if (progress_step) setProgressStep(progress_step)

        if (status === 'success' || status === 'failed') {
          clearInterval(pollRef.current)
          setRunning(false)
          setProgress(100)
          if (status === 'failed') {
            setError(r.data.error || 'SBOM generation failed')
          } else {
            await loadFullData(jobId)
          }
        }
      } catch (_) {}
    }, 1500)

    return () => clearInterval(pollRef.current)
  }, [running, jobId])

  const loadFullData = useCallback(async (id) => {
    try {
      const [sbom, hbom, cbom] = await Promise.all([
        sbomApi.getFullSBOM(id),
        sbomApi.getHBOM(id),
        sbomApi.getCBOM(id),
      ])
      setSbomData(sbom.data)
      setHbomData(hbom.data)
      setCbomData(cbom.data)
    } catch (e) {
      console.error('Failed to load SBOM data', e)
    }
  }, [])

  const handleStart = useCallback(async () => {
    if (!extractionJobId && !analysisJobId && !deviceInfo && !outputDir) {
      setError('Provide at least an extraction job ID or output directory')
      return
    }

    const body = {
      extraction_job_id: extractionJobId || null,
      analysis_job_id:   analysisJobId   || null,
      device_info:       deviceInfo ? { name: deviceInfo } : null,
      output_dir:        outputDir  || null,
    }

    setRunning(true)
    setError('')
    setSbomData(null)
    setHbomData(null)
    setCbomData(null)
    setProgress(1)
    setProgressStep('Submitting job…')

    try {
      const r = await sbomApi.generate(body)
      setJobId(r.data.job_id)
    } catch (err) {
      setRunning(false)
      setProgress(0)
      setError(err.response?.data?.detail || err.message)
    }
  }, [extractionJobId, analysisJobId, deviceInfo, outputDir])

  const handleDownload = useCallback(async (format) => {
    if (!jobId) return
    try {
      const r = await sbomApi.download(jobId, format)
      const url = URL.createObjectURL(new Blob([r.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = `sbom_${jobId.substring(0,8)}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      alert('Download failed: ' + (err.response?.data?.detail || err.message))
    }
  }, [jobId])

  const handleReset = () => {
    clearInterval(pollRef.current)
    setRunning(false); setProgress(0); setProgressStep('')
    setError(''); setJobId(null)
    setSbomData(null); setHbomData(null); setCbomData(null)
    setExtractionJobId(''); setAnalysisJobId('')
    setDeviceInfo(''); setOutputDir('')
  }

  const isDone = !!sbomData

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="badge badge-blue text-[10px]">Phase 4</span>
            <span className="text-gray-600 text-xs font-mono">F02 · F10 · F15 · CycloneDX 1.5</span>
          </div>
          <h1 className="text-2xl font-bold text-white">SBOM / HBOM / CBOM</h1>
          <p className="text-gray-400 text-sm mt-1">Software, Hardware &amp; Cryptographic Bills of Materials</p>
        </div>
        {isDone && (
          <button onClick={handleReset} className="btn-secondary text-sm">
            <RefreshCw size={14} /> Reset
          </button>
        )}
      </div>

      {/* Input form — shown when not running and no result yet */}
      {!running && !isDone && (
        <div className="card mb-6">
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1.5 font-medium">
                Extraction Job ID
              </label>
              <select
                value={extractionJobId}
                onChange={e => setExtractionJobId(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-sm text-gray-300 font-mono"
              >
                <option value="">— Select extracted job —</option>
                {extractionJobs.map(j => (
                  <option key={j.job_id} value={j.job_id}>
                    {j.job_id.substring(0,8)} — {j.device_port || j.fw_path?.split('/').pop() || 'unknown'}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1.5 font-medium">
                Output / Target Directory <span className="text-gray-600">(optional)</span>
              </label>
              <input
                type="text"
                value={outputDir}
                onChange={e => setOutputDir(e.target.value)}
                placeholder="/tmp/iifvdcas_extractions/..."
                className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-sm text-gray-300 font-mono placeholder-gray-700"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1.5 font-medium">
                Analysis Job ID <span className="text-gray-600">(optional)</span>
              </label>
              <input
                type="text"
                value={analysisJobId}
                onChange={e => setAnalysisJobId(e.target.value)}
                placeholder="Phase 3 job ID"
                className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-sm text-gray-300 font-mono placeholder-gray-700"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1.5 font-medium">
                Device Info <span className="text-gray-600">(optional)</span>
              </label>
              <input
                type="text"
                value={deviceInfo}
                onChange={e => setDeviceInfo(e.target.value)}
                placeholder="e.g. Arduino Uno R3"
                className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-sm text-gray-300 placeholder-gray-700"
              />
            </div>
          </div>

          {error && (
            <div className="bg-red-950 border border-red-800 rounded-lg p-3 mb-4 flex gap-2 items-start">
              <AlertTriangle size={14} className="text-red-400 flex-shrink-0 mt-0.5" />
              <span className="text-xs text-red-300">{error}</span>
            </div>
          )}

          <button onClick={handleStart} className="btn-primary">
            <Zap size={14} /> Generate SBOM
          </button>
        </div>
      )}

      {/* Live progress — shown while running */}
      {running && (
        <ProgressBar progress={progress} step={progressStep} />
      )}

      {/* Error state (when done but failed) */}
      {!running && error && !isDone && (
        <div className="card bg-red-950/30 border border-red-900 mb-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle size={14} className="text-red-400" />
            <span className="text-sm font-medium text-red-300">Generation Failed</span>
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
          {/* Summary cards */}
          <div className="grid grid-cols-4 gap-4 mb-6">
            <StatCard
              icon={Package}
              label="SW Components"
              value={sbomData?.total_components ?? sbomData?.components?.length ?? 0}
              color="text-indigo-400"
            />
            <StatCard
              icon={Shield}
              label="HW Components"
              value={hbomData?.total_hw_components ?? hbomData?.hardware_components?.length ?? 0}
              color="text-blue-400"
            />
            <StatCard
              icon={Activity}
              label="Crypto Assets"
              value={cbomData?.summary?.total ?? 0}
              color="text-amber-400"
            />
            <StatCard
              icon={AlertTriangle}
              label="Insecure Crypto"
              value={cbomData?.summary?.insecure ?? 0}
              color={cbomData?.summary?.insecure > 0 ? 'text-red-400' : 'text-green-400'}
            />
          </div>

          {/* CBOM strength breakdown */}
          {cbomData?.summary && (
            <div className="card mb-4 flex gap-4 flex-wrap items-center">
              <span className="text-xs text-gray-400 font-medium">Crypto strength:</span>
              {[
                { k: 'strong',     color: 'text-green-400' },
                { k: 'acceptable', color: 'text-blue-400'  },
                { k: 'weak',       color: 'text-amber-400' },
                { k: 'insecure',   color: 'text-red-400'   },
              ].map(({ k, color }) => (
                <span key={k} className="flex items-center gap-1.5">
                  <span className={`text-sm font-bold ${color}`}>{cbomData.summary[k] ?? 0}</span>
                  <span className="text-xs text-gray-500">{k}</span>
                </span>
              ))}
            </div>
          )}

          {/* Download */}
          <div className="flex gap-2 mb-6 flex-wrap">
            <button onClick={() => handleDownload('cyclonedx')} className="btn-primary text-sm">
              <Download size={14} /> Download CycloneDX
            </button>
            {jobId && (
              <span className="flex items-center text-xs text-gray-600 font-mono px-2">
                job: {jobId.substring(0, 16)}…
              </span>
            )}
          </div>

          {/* Tabs */}
          <div className="flex gap-1 mb-4 border-b border-gray-800">
            {[
              { id: 'sbom',       label: 'Software (SBOM)',  icon: Package       },
              { id: 'hbom',       label: 'Hardware (HBOM)',  icon: Shield        },
              { id: 'cbom',       label: 'Crypto (CBOM)',    icon: Activity      },
              { id: 'components', label: 'Components Table', icon: Search        },
              { id: 'raw',        label: 'Raw JSON',         icon: FileJson      },
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
                <tab.icon size={14} />
                {tab.label}
              </button>
            ))}
          </div>

          {activeTab === 'sbom'       && <ComponentTable components={sbomData?.components || []} />}
          {activeTab === 'hbom'       && <HBOMTable  components={hbomData?.hardware_components || []} />}
          {activeTab === 'cbom'       && <CBOMTable  components={cbomData?.crypto_components   || []} />}
          {activeTab === 'components' && <ComponentTable components={sbomData?.components || []} />}
          {activeTab === 'raw'        && (
            <div className="space-y-4">
              <JSONViewer data={sbomData} title="SBOM (CycloneDX 1.5)" />
              <JSONViewer data={hbomData} title="HBOM (Hardware)" />
              <JSONViewer data={cbomData} title="CBOM (Cryptography)" />
            </div>
          )}
        </>
      )}
    </div>
  )
}
