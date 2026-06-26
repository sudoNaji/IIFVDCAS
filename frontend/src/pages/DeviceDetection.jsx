import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Cpu, Scan, Usb, RefreshCw, ChevronRight, Terminal,
  CheckCircle2, AlertCircle, Network, Info, Wifi,
  Zap, HardDrive, Shield
} from 'lucide-react'
import { deviceApi, systemApi } from '../utils/api'
import { useWebSocket } from '../hooks/useWebSocket'

// ─── Architecture badge colour ────────────────────────────────────────────────
const ARCH_BADGE = {
  'AVR':             'badge-blue',
  'ARM':             'badge-purple',
  'ARM Cortex-M0+':  'badge-purple',
  'ARM Cortex-M3':   'badge-purple',
  'ARM Cortex-M4':   'badge-purple',
  'Xtensa':          'badge-amber',
  'Xtensa LX6':      'badge-amber',
  'MIPS':            'badge-red',
}

// ─── Device card ──────────────────────────────────────────────────────────────
function DeviceCard({ device, onSelect, selected }) {
  const isSelected = selected?.id === device.id
  const archBadge = ARCH_BADGE[device.architecture] || 'badge-gray'

  return (
    <div
      onClick={() => onSelect(device)}
      className={`card cursor-pointer transition-all hover:border-indigo-600/50 ${
        isSelected ? 'border-indigo-600 bg-indigo-600/5' : ''
      }`}
    >
      <div className="flex items-start gap-3">
        <div className="w-10 h-10 rounded-lg bg-gray-800 flex items-center justify-center flex-shrink-0">
          {device.connection_type === 'network'
            ? <Network size={20} className="text-indigo-400" />
            : <Usb size={20} className="text-indigo-400" />
          }
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-sm font-semibold text-white">
              {device.device_class || 'Unknown Device'}
            </span>
            <span className="badge badge-green">✅ Detected</span>
            {device.architecture && (
              <span className={`badge ${archBadge}`}>{device.architecture}</span>
            )}
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs text-gray-400">
            {device.port        && <span className="mono text-gray-200">{device.port}</span>}
            {device.chipset     && <span className="text-gray-300">{device.chipset}</span>}
            {device.vendor_name && <span className="truncate">{device.vendor_name}</span>}
            {device.vendor_id && device.product_id && (
              <span className="mono text-gray-500">{device.vendor_id}:{device.product_id}</span>
            )}
            {device.firmware_version && (
              <span className="text-green-400">FW: v{device.firmware_version}</span>
            )}
            {device.serial_number && (
              <span className="mono text-gray-500 truncate col-span-2">
                S/N: {device.serial_number}
              </span>
            )}
          </div>
        </div>
        <ChevronRight
          size={14}
          className={`text-gray-600 flex-shrink-0 mt-1 transition-transform ${
            isSelected ? 'rotate-90 text-indigo-400' : ''
          }`}
        />
      </div>
    </div>
  )
}

// ─── Device detail panel ──────────────────────────────────────────────────────
function DeviceDetail({ device, onClose, onExtract }) {
  const [details, setDetails] = useState(null)
  const [loadingDetails, setLoadingDetails] = useState(false)

  useEffect(() => {
    if (!device?.port) return
    setLoadingDetails(true)
    deviceApi.details(device.port)
      .then(r => setDetails(r.data.details))
      .catch(() => {})
      .finally(() => setLoadingDetails(false))
  }, [device])

  if (!device) return null

  const rows = [
    ['Device Class',   device.device_class],
    ['Port',           device.port],
    ['Chipset',        device.chipset],
    ['Architecture',   device.architecture],
    ['Vendor',         device.vendor_name],
    ['VID:PID',        device.vendor_id && device.product_id
                         ? `${device.vendor_id}:${device.product_id}` : null],
    ['Serial Number',  device.serial_number],
    ['Firmware Ver.',  device.firmware_version],
    ['Connection',     device.connection_type],
    ['Detected At',    device.detected_at?.replace('T',' ').substring(0,19)],
  ].filter(([, v]) => v)

  return (
    <div className="card h-full overflow-y-auto flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Cpu size={14} className="text-indigo-400" />
          <span className="font-semibold text-white text-sm">Device Details</span>
        </div>
        <button onClick={onClose} className="text-xs text-gray-600 hover:text-gray-300">✕ Close</button>
      </div>

      {/* Core info */}
      <div className="space-y-1.5">
        {rows.map(([label, value]) => (
          <div key={label} className="flex gap-3 text-xs">
            <span className="text-gray-500 w-28 flex-shrink-0">{label}</span>
            <span className="text-gray-200 mono break-all">{value}</span>
          </div>
        ))}
      </div>

      {/* Action buttons */}
      <div className="flex gap-2 flex-wrap">
        <button
          onClick={() => onExtract && onExtract(device)}
          className="btn-primary text-xs flex-1 justify-center"
        >
          <HardDrive size={12} /> Extract Firmware
        </button>
        <button
          onClick={() => window.location.href = '/analysis'}
          className="btn-secondary text-xs flex-1 justify-center"
        >
          <Shield size={12} /> Analyse
        </button>
      </div>

      {/* udevadm raw info */}
      {loadingDetails && (
        <div className="text-xs text-gray-500 flex items-center gap-2">
          <RefreshCw size={10} className="animate-spin" /> Loading udevadm info...
        </div>
      )}
      {details && Object.keys(details).filter(k => k !== 'stat' && k !== 'stty').length > 0 && (
        <div>
          <div className="text-xs text-gray-500 font-medium mb-1.5 flex items-center gap-1">
            <Terminal size={10} /> udevadm raw info
          </div>
          <div className="bg-gray-950 rounded-lg p-3 text-[11px] mono text-gray-400 max-h-44 overflow-y-auto border border-gray-800">
            {Object.entries(details)
              .filter(([k]) => k !== 'stat' && k !== 'stty')
              .map(([k, v]) => (
                <div key={k} className="flex gap-2">
                  <span className="text-blue-400 w-40 flex-shrink-0">{k}</span>
                  <span className="break-all">{v}</span>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Probe responses */}
      {device.raw_info?.probe_responses?.length > 0 && (
        <div>
          <div className="text-xs text-gray-500 font-medium mb-1.5 flex items-center gap-1">
            <Zap size={10} /> Serial probe
          </div>
          <div className="bg-gray-950 rounded-lg p-3 text-[11px] mono text-green-400 border border-gray-800">
            {device.raw_info.probe_responses.join('\n')}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function DeviceDetection() {
  const [devices, setDevices]         = useState([])
  const [selected, setSelected]       = useState(null)
  const [scanning, setScanning]       = useState(false)
  const [loading, setLoading]         = useState(false)   // quick list loading
  const [includeNetwork, setIncludeNetwork] = useState(false)
  const [scanEvents, setScanEvents]   = useState([])
  const [tools, setTools]             = useState({})
  const [error, setError]             = useState('')
  const { subscribe, connected }      = useWebSocket('ws://localhost:8000/ws')
  const hasMounted = useRef(false)

  // ── Auto-load devices on mount ─────────────────────────────────────────────
  useEffect(() => {
    if (hasMounted.current) return
    hasMounted.current = true
    quickList()
    systemApi.info().then(r => setTools(r.data.tools)).catch(() => {})
  }, [])

  const quickList = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const r = await deviceApi.list()
      setDevices(r.data.devices || [])
    } catch (err) {
      setError(`API error: ${err.message} — is the backend running?`)
    } finally {
      setLoading(false)
    }
  }, [])

  // ── WebSocket scan events ──────────────────────────────────────────────────
  useEffect(() => {
    return subscribe((event) => {
      if (!['scan_started', 'scan_progress', 'scan_complete'].includes(event.event)) return
      setScanEvents(prev => [...prev.slice(-49), event])
      if (event.event === 'scan_complete') {
        setScanning(false)
        if (event.result?.devices) setDevices(event.result.devices)
      }
    })
  }, [subscribe])

  const handleFullScan = useCallback(async () => {
    setScanning(true)
    setScanEvents([])
    setDevices([])
    setSelected(null)
    setError('')
    try {
      await deviceApi.scan({ include_network: includeNetwork })
    } catch (err) {
      setScanning(false)
      setError(`Scan failed: ${err.message}`)
    }
  }, [includeNetwork])

  const handleExtract = useCallback((device) => {
    // Navigate to firmware extraction page with device pre-selected
    sessionStorage.setItem('extract_device_port', device.port)
    sessionStorage.setItem('extract_device_name', device.device_class)
    window.location.href = '/firmware'
  }, [])

  const usbDevices = devices.filter(d => d.connection_type === 'usb')
  const netDevices = devices.filter(d => d.connection_type === 'network')

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="badge badge-green text-[10px]">Phase 1 — Active</span>
            <span className="text-gray-600 text-xs mono">EMBA: P02 · S06 · udevadm · lsusb</span>
            <div className={`w-2 h-2 rounded-full ml-2 ${connected ? 'bg-green-400' : 'bg-gray-600'}`} />
            <span className={`text-xs ${connected ? 'text-green-400' : 'text-gray-600'}`}>
              {connected ? 'WS live' : 'WS offline'}
            </span>
          </div>
          <h1 className="text-2xl font-bold text-white">IoT Device Detection</h1>
          <p className="text-gray-400 text-sm mt-1">
            Detect and identify connected IoT devices via USB, Serial, and Network.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={quickList}
            disabled={loading || scanning}
            className="btn-secondary text-sm"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            {loading ? 'Loading...' : 'Refresh'}
          </button>
          <button
            onClick={handleFullScan}
            disabled={scanning || loading}
            className="btn-primary text-sm"
          >
            <Scan size={14} className={scanning ? 'animate-spin' : ''} />
            {scanning ? 'Scanning...' : 'Full Scan'}
          </button>
        </div>
      </div>

      {/* Tool status bar */}
      <div className="flex gap-4 mb-5 flex-wrap items-center">
        {[
          { key: 'udevadm', label: 'udevadm' },
          { key: 'nmap',    label: 'nmap' },
          { key: 'avrdude', label: 'avrdude' },
        ].map(({ key, label }) => (
          <div key={key} className="flex items-center gap-1.5 text-xs">
            {tools[key]
              ? <CheckCircle2 size={12} className="text-green-400" />
              : <AlertCircle  size={12} className="text-red-400" />
            }
            <span className={tools[key] ? 'text-gray-300' : 'text-gray-600'}>{label}</span>
          </div>
        ))}

        {/* Network scan toggle */}
        <label className="flex items-center gap-2 ml-auto text-xs text-gray-400 cursor-pointer">
          <span>Include network scan</span>
          <div
            onClick={() => setIncludeNetwork(v => !v)}
            className={`w-8 h-4 rounded-full transition-colors cursor-pointer relative ${
              includeNetwork ? 'bg-indigo-600' : 'bg-gray-700'
            }`}
          >
            <div className={`absolute top-0.5 w-3 h-3 bg-white rounded-full transition-transform ${
              includeNetwork ? 'translate-x-4' : 'translate-x-0.5'
            }`} />
          </div>
        </label>
      </div>

      {/* Error banner */}
      {error && (
        <div className="mb-4 flex items-center gap-2 bg-red-950 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-300">
          <AlertCircle size={14} className="flex-shrink-0" />
          {error}
          <button onClick={() => setError('')} className="ml-auto text-red-500 hover:text-red-300 text-xs">✕</button>
        </div>
      )}

      {/* Main grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* ── Left: device list ─────────────────────────────────────────── */}
        <div className="space-y-3">

          {/* Loading state */}
          {(loading || scanning) && devices.length === 0 && (
            <div className="card flex flex-col items-center justify-center py-14 text-center border-dashed">
              <Scan size={30} className="text-indigo-500 mb-3 animate-pulse" />
              <p className="text-gray-400 text-sm">
                {scanning ? 'Running full scan...' : 'Loading devices...'}
              </p>
              <p className="text-gray-600 text-xs mt-1 mono">
                {scanning
                  ? (includeNetwork ? 'USB + Network (nmap)' : 'USB / Serial only')
                  : 'Calling /api/v1/devices'}
              </p>
            </div>
          )}

          {/* Empty state — not loading */}
          {!loading && !scanning && devices.length === 0 && !error && (
            <div className="card flex flex-col items-center justify-center py-14 text-center border-dashed">
              <Usb size={30} className="text-gray-700 mb-3" />
              <p className="text-gray-500 text-sm font-medium">No IoT devices detected</p>
              <p className="text-gray-600 text-xs mt-1">
                Make sure your Arduino is connected via USB, then click Refresh.
              </p>
              <button onClick={quickList} className="btn-primary text-xs mt-4">
                <RefreshCw size={12} /> Try Again
              </button>
            </div>
          )}

          {/* Device cards */}
          {devices.map(d => (
            <DeviceCard
              key={d.id}
              device={d}
              onSelect={setSelected}
              selected={selected}
            />
          ))}

          {/* Stats */}
          {devices.length > 0 && (
            <div className="flex gap-3">
              {[
                { label: 'Total',      value: devices.length,  color: 'text-white' },
                { label: 'USB/Serial', value: usbDevices.length, color: 'text-blue-400' },
                { label: 'Network',    value: netDevices.length, color: 'text-green-400' },
              ].map(s => (
                <div key={s.label} className="card flex-1 text-center py-3">
                  <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                  <div className="text-xs text-gray-500">{s.label}</div>
                </div>
              ))}
            </div>
          )}

          {/* Scan log */}
          {scanEvents.length > 0 && (
            <div className="card">
              <div className="text-xs text-gray-500 font-medium mb-2 flex items-center gap-1">
                <Terminal size={10} /> Scan log
              </div>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {scanEvents.map((e, i) => (
                  <div key={i} className="text-xs mono flex items-start gap-2">
                    <span className={`
                      ${e.event === 'scan_complete' ? 'text-green-400' : ''}
                      ${e.event === 'scan_started'  ? 'text-blue-400'  : ''}
                      ${e.event === 'error'         ? 'text-red-400'   : ''}
                      ${!['scan_complete','scan_started','error'].includes(e.event) ? 'text-amber-400' : ''}
                    `}>
                      [{e.event}]{' '}
                      {e.message || (e.total_found !== undefined
                        ? `Found ${e.total_found} devices in ${e.duration_ms}ms`
                        : '')}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── Right: detail panel ───────────────────────────────────────── */}
        <div>
          {selected ? (
            <DeviceDetail
              device={selected}
              onClose={() => setSelected(null)}
              onExtract={handleExtract}
            />
          ) : (
            <div className="card flex flex-col items-center justify-center py-14 text-center border-dashed h-full min-h-[200px]">
              <Info size={24} className="text-gray-700 mb-3" />
              <p className="text-gray-500 text-sm">Select a device to view details</p>
              <p className="text-gray-600 text-xs mt-1">
                Click any device card on the left
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
