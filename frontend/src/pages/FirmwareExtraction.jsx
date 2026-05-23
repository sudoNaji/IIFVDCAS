import { useState, useEffect, useCallback, useRef } from 'react'
import {
  HardDrive, Upload, Cpu, Scan, CheckCircle2, AlertCircle,
  FolderOpen, File, ChevronRight, ChevronDown, Terminal,
  Zap, Shield, Package, RefreshCw, Trash2, Search,
  Lock, AlertTriangle, Info
} from 'lucide-react'
import { firmwareApi, deviceApi } from '../utils/api'
import { useWebSocket } from '../hooks/useWebSocket'

// ─── Firmware type badge colours ─────────────────────────────────────────────
const TYPE_BADGE = {
  squashfs:'badge-blue', cramfs:'badge-blue', jffs2:'badge-blue',
  ubi_image:'badge-amber', ext2_filesystem:'badge-purple',
  ext3_filesystem:'badge-purple', ext4_filesystem:'badge-purple',
  elf_binary:'badge-green', archive_zip_tar_gz:'badge-gray',
  debian_package:'badge-red', rpm_package:'badge-red',
  uefi_bios:'badge-amber', raw_binary:'badge-red',
  linux_filesystem:'badge-green', unknown:'badge-gray',
}

// ─── Entropy bar ──────────────────────────────────────────────────────────────
function EntropyBar({ entropy, label }) {
  const pct = Math.min((entropy / 8) * 100, 100)
  const color = entropy > 7.5 ? '#ef4444' : entropy > 7.0 ? '#f59e0b' : '#22c55e'
  return (
    <div>
      <div className="flex justify-between text-xs mb-1">
        <span className="text-gray-400">Entropy</span>
        <span style={{ color }}>{entropy.toFixed(3)} — {label?.replace(/_/g,' ')}</span>
      </div>
      <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  )
}

// ─── File tree node ───────────────────────────────────────────────────────────
function TreeNode({ node, depth = 0 }) {
  const [open, setOpen] = useState(depth < 1)
  const isDir = node.type === 'dir'
  const indent = depth * 14

  return (
    <div>
      <div
        className="flex items-center gap-1.5 py-0.5 px-2 rounded hover:bg-gray-800 cursor-pointer text-xs"
        style={{ paddingLeft: `${8 + indent}px` }}
        onClick={() => isDir && setOpen(!open)}
      >
        {isDir
          ? (open ? <ChevronDown size={11} className="text-gray-500 flex-shrink-0" />
                  : <ChevronRight size={11} className="text-gray-500 flex-shrink-0" />)
          : <span className="w-3" />
        }
        {isDir
          ? <FolderOpen size={12} className="text-amber-400 flex-shrink-0" />
          : <File size={12} className="text-gray-500 flex-shrink-0" />
        }
        <span className={isDir ? 'text-amber-300' : 'text-gray-300'}>{node.name}</span>
        {!isDir && node.size_human && (
          <span className="ml-auto text-gray-600 text-[10px]">{node.size_human}</span>
        )}
      </div>
      {isDir && open && node.children?.map((child, i) => (
        <TreeNode key={i} node={child} depth={depth + 1} />
      ))}
    </div>
  )
}

// ─── Analysis card (P02 results) ─────────────────────────────────────────────
function FirmwareInfoCard({ info }) {
  if (!info) return null
  const badge = TYPE_BADGE[info.firmware_type] || 'badge-gray'
  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-3">
        <Shield size={14} className="text-indigo-400" />
        <span className="text-sm font-semibold text-white">Firmware Analysis (P02)</span>
        <span className={`badge ${badge} text-[10px] ml-auto`}>
          {info.firmware_type?.replace(/_/g, ' ')}
        </span>
      </div>
      <EntropyBar entropy={info.entropy || 0} label={info.entropy_label} />
      <div className="mt-3 space-y-1">
        {[
          ['Size',         info.size_human],
          ['File Type',    info.file_type?.substring(0, 60)],
          ['Architecture', info.architecture_hint || '—'],
          ['Endianness',   info.endianness || '—'],
          ['MD5',          info.md5?.substring(0, 20) + '...'],
          ['Encrypted',    info.is_encrypted ? '⚠️ Possibly encrypted' : '✅ No'],
          ['Compressed',   info.is_compressed ? 'Yes' : 'No'],
        ].filter(([,v]) => v).map(([k, v]) => (
          <div key={k} className="flex gap-2 text-xs">
            <span className="text-gray-500 w-28 flex-shrink-0">{k}</span>
            <span className="text-gray-300 mono break-all">{v}</span>
          </div>
        ))}
      </div>
      {info.raw_binwalk_scan && (
        <details className="mt-3">
          <summary className="text-xs text-gray-500 cursor-pointer">binwalk scan output</summary>
          <pre className="text-[10px] mono text-gray-500 bg-gray-950 rounded p-2 mt-1 overflow-x-auto max-h-32">
            {info.raw_binwalk_scan.substring(0, 800)}
          </pre>
        </details>
      )}
    </div>
  )
}

// ─── Extraction result card ───────────────────────────────────────────────────
function ExtractionResultCard({ result }) {
  if (!result || result.status === 'pending' || result.status === 'running') return null
  const ok = result.status === 'success' || result.status === 'partial'
  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-3">
        {ok ? <CheckCircle2 size={14} className="text-green-400" />
            : <AlertCircle size={14} className="text-red-400" />}
        <span className="text-sm font-semibold text-white">Extraction Result</span>
        <span className={`badge ml-auto text-[10px] ${ok ? 'badge-green' : 'badge-red'}`}>
          {result.status}
        </span>
      </div>
      <div className="space-y-1 mb-3">
        {[
          ['Extractor', result.extractor_used],
          ['Files extracted', result.total_files?.toLocaleString()],
          ['Directories', result.total_dirs?.toLocaleString()],
          ['Linux FS found', result.linux_found ? '✅ Yes' : '❌ No'],
          ['Output dir', result.output_dir],
        ].filter(([,v]) => v !== undefined && v !== '').map(([k, v]) => (
          <div key={k} className="flex gap-2 text-xs">
            <span className="text-gray-500 w-28 flex-shrink-0">{k}</span>
            <span className="text-gray-300 mono break-all">{String(v)}</span>
          </div>
        ))}
      </div>
      {result.linux_paths?.length > 0 && (
        <div className="bg-green-950 border border-green-800 rounded-lg p-2 mb-3">
          <div className="text-xs text-green-400 font-medium mb-1">Linux FS paths found:</div>
          {result.linux_paths.slice(0,5).map((p,i) => (
            <div key={i} className="text-xs mono text-green-300">{p}</div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Log panel ───────────────────────────────────────────────────────────────
function LogPanel({ logs }) {
  const ref = useRef(null)
  useEffect(() => { ref.current?.scrollTo(0, ref.current.scrollHeight) }, [logs])
  if (!logs.length) return null
  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-2">
        <Terminal size={12} className="text-gray-500" />
        <span className="text-xs text-gray-500 font-medium">Extraction Log</span>
      </div>
      <div ref={ref} className="max-h-48 overflow-y-auto space-y-0.5">
        {logs.map((entry, i) => (
          <div key={i} className="text-[11px] mono flex gap-2">
            <span className="text-gray-600 flex-shrink-0">{entry.ts?.substring(11,19)}</span>
            <span className={`
              ${entry.msg?.includes('✅') || entry.msg?.includes('[DONE]') ? 'text-green-400' : ''}
              ${entry.msg?.includes('[ERROR]') ? 'text-red-400' : ''}
              ${entry.msg?.includes('[P02]') ? 'text-blue-400' : ''}
              ${entry.msg?.includes('[P50]') || entry.msg?.includes('[P55]') || entry.msg?.includes('[P60]') ? 'text-amber-400' : ''}
              ${!entry.msg?.match(/✅|ERROR|P0[2-9]|P[56]/) ? 'text-gray-400' : ''}
            `}>{entry.msg}</span>
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
        <span className="text-gray-400">{step || 'Processing...'}</span>
        <span className="text-indigo-400 font-medium">{progress}%</span>
      </div>
      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
        <div
          className="h-full bg-indigo-600 rounded-full transition-all duration-300"
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function FirmwareExtraction() {
  const [devices, setDevices] = useState([])
  const [selectedDevice, setSelectedDevice] = useState(null)
  const [uploadedFile, setUploadedFile] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [extracting, setExtracting] = useState(false)
  const [firmwareInfo, setFirmwareInfo] = useState(null)
  const [jobId, setJobId] = useState(null)
  const [extractionResult, setExtractionResult] = useState(null)
  const [logs, setLogs] = useState([])
  const [progress, setProgress] = useState(0)
  const [progressStep, setProgressStep] = useState('')
  const [fileTree, setFileTree] = useState([])
  const [activeTab, setActiveTab] = useState('upload') // upload | device
  const [dragOver, setDragOver] = useState(false)
  const fileInputRef = useRef(null)
  const { subscribe } = useWebSocket('ws://localhost:8000/ws')

  // Load connected devices
  useEffect(() => {
    deviceApi.list()
      .then(r => setDevices(r.data.devices))
      .catch(() => {})
  }, [])

  // Subscribe to WebSocket events
  useEffect(() => {
    return subscribe((event) => {
      if (event.phase !== 'phase2') return

      if (event.event === 'log') {
        setLogs(prev => [...prev, { ts: new Date().toISOString(), msg: event.message }])
      }
      if (event.event === 'progress') {
        setProgress(event.percent || 0)
        setProgressStep(event.step || '')
      }
      if (event.event === 'extraction_complete') {
        setExtracting(false)
        setProgress(100)
        const result = event.result || {}
        setExtractionResult(result)
        if (result.firmware_info) setFirmwareInfo(result.firmware_info)
        if (result.file_tree) setFileTree(result.file_tree)
        setLogs(prev => [...prev, { ts: new Date().toISOString(), msg: `[DONE] ${event.status} — ${event.total_files} files extracted` }])
      }
      if (event.event === 'extraction_started') {
        setLogs([{ ts: new Date().toISOString(), msg: '[P02] Extraction started...' }])
        setProgress(0)
      }
    })
  }, [subscribe])

  const handleFileSelect = useCallback(async (file) => {
    if (!file) return
    setUploadedFile(null); setFirmwareInfo(null); setExtractionResult(null)
    setLogs([]); setFileTree([]); setProgress(0)
    try {
      const r = await firmwareApi.upload(file)
      setUploadedFile(r.data)
    } catch (err) {
      alert('Upload failed: ' + (err.response?.data?.detail || err.message))
    }
  }, [])

  const handleAnalyze = useCallback(async () => {
    const path = activeTab === 'upload' ? uploadedFile?.path : selectedDevice?.port
    if (!path) return
    setAnalyzing(true); setFirmwareInfo(null)
    try {
      const r = await firmwareApi.analyze(path)
      setFirmwareInfo(r.data)
    } catch (err) {
      alert('Analysis failed: ' + (err.response?.data?.detail || err.message))
    }
    setAnalyzing(false)
  }, [activeTab, uploadedFile, selectedDevice])

  const handleExtract = useCallback(async () => {
    if (activeTab === 'upload') {
      const path = uploadedFile?.path
      if (!path) return
      setExtracting(true); setExtractionResult(null); setFileTree([])
      setLogs([{ ts: new Date().toISOString(), msg: `[P02] Starting extraction: ${path}` }])
      setProgress(2)
      try {
        const r = await firmwareApi.extract(path)
        setJobId(r.data.job_id)
      } catch (err) {
        setExtracting(false)
        alert('Extraction failed: ' + (err.response?.data?.detail || err.message))
      }
    } else if (activeTab === 'device') {
      const deviceOpts = {
        device_port: selectedDevice?.port,
        baudrate: 115200,
        mcu: 'm328p',
        include_eeprom: false
      }
      if (!deviceOpts.device_port) return
      setExtracting(true); setExtractionResult(null); setFileTree([])
      setLogs([{ ts: new Date().toISOString(), msg: `[FLASH] Starting flash read from ${deviceOpts.device_port}` }])
      setProgress(2)
      try {
        const r = await firmwareApi.extractDevice(deviceOpts)
        setJobId(r.data.job_id)
      } catch (err) {
        setExtracting(false)
        alert('Extraction failed: ' + (err.response?.data?.detail || err.message))
      }
    }
  }, [activeTab, uploadedFile, selectedDevice])

  const handleReset = () => {
    setUploadedFile(null); setSelectedDevice(null); setFirmwareInfo(null)
    setExtractionResult(null); setLogs([]); setFileTree([])
    setProgress(0); setJobId(null); setExtracting(false); setAnalyzing(false)
  }

  const hasSource = activeTab === 'upload' ? !!uploadedFile : !!selectedDevice
  const sourcePath = activeTab === 'upload' ? uploadedFile?.path : selectedDevice?.port

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="badge badge-blue text-[10px]">Phase 2</span>
            <span className="text-gray-600 text-xs mono">EMBA: P02 · P50 · P55 · P60 · binwalk · unblob</span>
          </div>
          <h1 className="text-2xl font-bold text-white">Firmware Extraction</h1>
          <p className="text-gray-400 text-sm mt-1">
            Extract and analyze firmware from uploaded files or connected IoT devices.
          </p>
        </div>
        <div className="flex gap-2">
          {(uploadedFile || selectedDevice) && (
            <button onClick={handleReset} className="btn-secondary text-sm">
              <RefreshCw size={14} /> Reset
            </button>
          )}
        </div>
      </div>

      {/* Source tabs */}
      <div className="flex gap-1 mb-4 bg-gray-900 rounded-lg p-1 w-fit border border-gray-800">
        {[
          { id: 'upload', icon: Upload, label: 'Upload Firmware File' },
          { id: 'device', icon: Cpu, label: `Connected Devices (${devices.length})` },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => { setActiveTab(tab.id); handleReset() }}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-indigo-600 text-white'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <tab.icon size={14} /> {tab.label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Left: Source + Actions */}
        <div className="space-y-4">

          {/* Upload tab */}
          {activeTab === 'upload' && (
            <div
              onDragOver={e => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={e => { e.preventDefault(); setDragOver(false); handleFileSelect(e.dataTransfer.files[0]) }}
              onClick={() => !uploadedFile && fileInputRef.current?.click()}
              className={`card border-2 border-dashed transition-all cursor-pointer ${
                dragOver ? 'border-indigo-500 bg-indigo-600/5' : 'border-gray-700 hover:border-gray-600'
              } ${uploadedFile ? 'cursor-default' : ''}`}
            >
              <input
                ref={fileInputRef} type="file" className="hidden"
                onChange={e => handleFileSelect(e.target.files[0])}
                accept=".bin,.img,.zip,.gz,.tar,.tgz,.xz,.bz2,.deb,.rpm,.ubi,.cramfs,.squashfs,.jffs2,.vmdk,.fw,.rom"
              />
              {uploadedFile ? (
                <div className="flex items-start gap-3">
                  <HardDrive size={24} className="text-indigo-400 flex-shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-white text-sm truncate">{uploadedFile.filename}</div>
                    <div className="text-xs text-gray-400 mt-0.5">{uploadedFile.size_human}</div>
                    <div className="text-xs mono text-gray-600 mt-0.5 truncate">{uploadedFile.path}</div>
                  </div>
                  <span className="badge badge-green text-[10px]">Uploaded</span>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-center">
                  <Upload size={28} className="text-gray-600 mb-2" />
                  <p className="text-gray-400 text-sm">Drop firmware file here or click to browse</p>
                  <p className="text-gray-600 text-xs mt-1">.bin .img .zip .tar.gz .ubi .squashfs .vmdk ...</p>
                </div>
              )}
            </div>
          )}

          {/* Device tab */}
          {activeTab === 'device' && (
            <div className="card">
              <div className="flex items-center gap-2 mb-3">
                <Cpu size={14} className="text-indigo-400" />
                <span className="text-sm font-semibold text-white">Connected IoT Devices</span>
                <button
                  onClick={() => deviceApi.list().then(r => setDevices(r.data.devices)).catch(()=>{})}
                  className="ml-auto text-xs text-gray-500 hover:text-gray-300 flex items-center gap-1"
                >
                  <RefreshCw size={10} /> Refresh
                </button>
              </div>
              {devices.length === 0 ? (
                <div className="text-center py-6 text-gray-600 text-sm">
                  No devices detected. Go to Phase 1 to scan.
                </div>
              ) : (
                <div className="space-y-2">
                  {devices.map(d => (
                    <div
                      key={d.id}
                      onClick={() => setSelectedDevice(d)}
                      className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                        selectedDevice?.id === d.id
                          ? 'border-indigo-600 bg-indigo-600/10'
                          : 'border-gray-800 hover:border-gray-700'
                      }`}
                    >
                      <Cpu size={16} className="text-indigo-400 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-white">{d.device_class}</div>
                        <div className="text-xs text-gray-500 mono">{d.port} · {d.chipset}</div>
                      </div>
                      {selectedDevice?.id === d.id && (
                        <CheckCircle2 size={14} className="text-indigo-400" />
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Action buttons */}
          {hasSource && (
            <div className="flex gap-2">
              <button
                onClick={handleAnalyze}
                disabled={analyzing || extracting}
                className="btn-secondary text-sm flex-1"
              >
                <Search size={14} className={analyzing ? 'animate-spin' : ''} />
                {analyzing ? 'Analyzing...' : 'Analyze (P02)'}
              </button>
              <button
                onClick={handleExtract}
                disabled={extracting || analyzing}
                className="btn-primary text-sm flex-1"
              >
                <Zap size={14} className={extracting ? 'animate-pulse' : ''} />
                {extracting ? 'Extracting...' : 'Extract Firmware'}
              </button>
            </div>
          )}

          {/* Info cards */}
          <FirmwareInfoCard info={firmwareInfo} />
          {extracting && progress > 0 && <ProgressBar progress={progress} step={progressStep} />}
          <ExtractionResultCard result={extractionResult} />
          <LogPanel logs={logs} />
        </div>

        {/* Right: File tree */}
        <div>
          {fileTree.length > 0 ? (
            <div className="card h-full">
              <div className="flex items-center gap-2 mb-3">
                <FolderOpen size={14} className="text-amber-400" />
                <span className="text-sm font-semibold text-white">Extracted File Tree</span>
                <span className="badge badge-green text-[10px] ml-auto">
                  {extractionResult?.total_files?.toLocaleString()} files
                </span>
              </div>
              {extractionResult?.linux_found && (
                <div className="mb-3 flex items-center gap-2 bg-green-950 border border-green-800 rounded-lg px-3 py-2">
                  <CheckCircle2 size={12} className="text-green-400" />
                  <span className="text-xs text-green-300">Linux filesystem structure detected</span>
                </div>
              )}
              <div className="bg-gray-950 rounded-lg border border-gray-800 max-h-[500px] overflow-y-auto py-1">
                {fileTree.map((node, i) => (
                  <TreeNode key={i} node={node} depth={0} />
                ))}
              </div>
            </div>
          ) : (
            <div className="card flex flex-col items-center justify-center py-16 text-center border-dashed h-full">
              {extracting ? (
                <>
                  <HardDrive size={32} className="text-indigo-500 mb-3 animate-pulse" />
                  <p className="text-gray-400 text-sm">Extraction in progress...</p>
                  <p className="text-gray-600 text-xs mt-1 mono">
                    {progressStep || 'Waiting for extractor...'}
                  </p>
                </>
              ) : (
                <>
                  <FolderOpen size={32} className="text-gray-700 mb-3" />
                  <p className="text-gray-500 text-sm">File tree will appear here</p>
                  <p className="text-gray-600 text-xs mt-1">
                    Upload a file and click Extract Firmware
                  </p>
                  <div className="mt-4 text-xs text-gray-700 space-y-0.5">
                    {['squashfs', 'cramfs', 'jffs2', 'ubi', 'ext2/3/4', 'vmdk', 'tar/gz/zip', 'deb/rpm'].map(t => (
                      <div key={t} className="mono">· {t}</div>
                    ))}
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
