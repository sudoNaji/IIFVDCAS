import { useState, useEffect, useCallback } from 'react'
import { Cpu, Scan, Usb, RefreshCw, ChevronRight, Terminal, CheckCircle2, AlertCircle, Network, Info } from 'lucide-react'
import { deviceApi, systemApi } from '../utils/api'
import { useWebSocket } from '../hooks/useWebSocket'

const archColor = { 'AVR':'badge-blue','ARM':'badge-purple','ARM Cortex-M0+':'badge-purple','ARM Cortex-M3':'badge-purple','ARM Cortex-M4':'badge-purple','Xtensa':'badge-amber','MIPS':'badge-red' }

function DeviceCard({ device, onSelect, selected }) {
  const isSelected = selected?.id === device.id
  return (
    <div onClick={() => onSelect(device)} className={`card cursor-pointer transition-all hover:border-indigo-600/50 ${isSelected?'border-indigo-600 bg-indigo-600/5':''}`}>
      <div className="flex items-start gap-4">
        <div className="w-10 h-10 rounded-lg bg-gray-800 flex items-center justify-center flex-shrink-0 mt-0.5">
          {device.connection_type==='network' ? <Network size={20} className="text-indigo-400" /> : <Usb size={20} className="text-indigo-400" />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-white">{device.device_class || 'Unknown Device'}</span>
            <span className="badge badge-green">Detected</span>
            {device.architecture && <span className={`badge ${archColor[device.architecture]||'badge-gray'}`}>{device.architecture}</span>}
          </div>
          <div className="mt-1 grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs text-gray-400">
            {device.port && <span className="mono text-gray-300">{device.port}</span>}
            {device.chipset && <span>{device.chipset}</span>}
            {device.vendor_name && <span className="truncate">{device.vendor_name}</span>}
            {device.vendor_id && device.product_id && <span className="mono text-gray-500">{device.vendor_id}:{device.product_id}</span>}
            {device.firmware_version && <span className="text-green-400">FW: v{device.firmware_version}</span>}
            {device.serial_number && <span className="mono text-gray-500 truncate">S/N: {device.serial_number.substring(0,20)}</span>}
          </div>
        </div>
        <ChevronRight size={14} className={`text-gray-600 flex-shrink-0 mt-1 transition-transform ${isSelected?'rotate-90 text-indigo-400':''}`} />
      </div>
    </div>
  )
}

function DeviceDetail({ device, onClose }) {
  const [details, setDetails] = useState(null)
  useEffect(() => {
    if (!device?.port) return
    deviceApi.details(device.port).then(r => setDetails(r.data.details)).catch(()=>{})
  }, [device])
  if (!device) return null
  return (
    <div className="card h-full overflow-y-auto">
      <div className="flex items-center justify-between mb-4">
        <span className="font-semibold text-white text-sm flex items-center gap-2"><Cpu size={14} className="text-indigo-400"/>Device Details</span>
        <button onClick={onClose} className="text-gray-600 hover:text-gray-400 text-xs">✕</button>
      </div>
      <div className="space-y-1 mb-4">
        {[['Device Class',device.device_class],['Port',device.port],['Chipset',device.chipset],['Architecture',device.architecture],['Vendor',device.vendor_name],['VID:PID',device.vendor_id&&device.product_id?`${device.vendor_id}:${device.product_id}`:null],['Serial Number',device.serial_number],['Firmware',device.firmware_version],['Connection',device.connection_type],['Detected',device.detected_at]].filter(([,v])=>v).map(([l,v])=>(
          <div key={l} className="flex gap-3 text-xs"><span className="text-gray-500 w-28 flex-shrink-0">{l}</span><span className="text-gray-200 mono break-all">{v}</span></div>
        ))}
      </div>
      {details && Object.keys(details).filter(k=>k!=='stat'&&k!=='stty').length > 0 && (
        <div>
          <div className="text-xs text-gray-500 font-medium mb-2 flex items-center gap-1"><Terminal size={10}/>udevadm info</div>
          <div className="bg-gray-950 rounded-lg p-3 text-xs mono text-gray-400 max-h-48 overflow-y-auto border border-gray-800">
            {Object.entries(details).filter(([k])=>k!=='stat'&&k!=='stty').map(([k,v])=>(
              <div key={k} className="flex gap-2"><span className="text-blue-400 w-40 flex-shrink-0">{k}</span><span className="break-all">{v}</span></div>
            ))}
          </div>
        </div>
      )}
      {device.raw_info?.probe_responses?.length > 0 && (
        <div className="mt-3">
          <div className="text-xs text-gray-500 font-medium mb-2">Serial probe</div>
          <div className="bg-gray-950 rounded-lg p-3 text-xs mono text-green-400 border border-gray-800">{device.raw_info.probe_responses.join('\n')}</div>
        </div>
      )}
    </div>
  )
}

export default function DeviceDetection() {
  const [devices, setDevices] = useState([])
  const [selected, setSelected] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [includeNetwork, setIncludeNetwork] = useState(false)
  const [scanEvents, setScanEvents] = useState([])
  const [tools, setTools] = useState({})
  const { subscribe } = useWebSocket('ws://localhost:8000/ws')

  useEffect(() => { systemApi.info().then(r=>setTools(r.data.tools)).catch(()=>{}) }, [])

  useEffect(() => {
    return subscribe((event) => {
      if (['scan_started','scan_progress','scan_complete'].includes(event.event)) {
        setScanEvents(prev => [...prev.slice(-49), event])
        if (event.event === 'scan_complete') {
          setScanning(false)
          if (event.result?.devices) setDevices(event.result.devices)
        }
      }
    })
  }, [subscribe])

  const handleScan = useCallback(async () => {
    setScanning(true); setScanEvents([]); setDevices([]); setSelected(null)
    try { await deviceApi.scan({ include_network: includeNetwork }) }
    catch (err) { setScanEvents([{event:'error',message:err.message}]); setScanning(false) }
  }, [includeNetwork])

  const handleQuickList = useCallback(async () => {
    setScanning(true)
    try { const r = await deviceApi.list(); setDevices(r.data.devices) } catch {}
    setScanning(false)
  }, [])

  return (
    <div className="p-6">
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="badge badge-green text-[10px]">Phase 1 — Active</span>
            <span className="text-gray-600 text-xs mono">EMBA: P02 · S06 · udevadm · lsusb</span>
          </div>
          <h1 className="text-2xl font-bold text-white">IoT Device Detection</h1>
          <p className="text-gray-400 text-sm mt-1">Detect and identify connected IoT devices via USB, Serial, and Network.</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={handleQuickList} disabled={scanning} className="btn-secondary text-sm">
            <RefreshCw size={14} className={scanning?'animate-spin':''} />Quick Refresh
          </button>
          <button onClick={handleScan} disabled={scanning} className="btn-primary text-sm">
            <Scan size={14} className={scanning?'animate-spin':''} />{scanning?'Scanning...':'Full Scan'}
          </button>
        </div>
      </div>

      <div className="flex gap-4 mb-6 flex-wrap items-center">
        {[{key:'udevadm',label:'udevadm'},{key:'nmap',label:'nmap'},{key:'avrdude',label:'avrdude'}].map(({key,label})=>(
          <div key={key} className="flex items-center gap-1.5 text-xs">
            {tools[key] ? <CheckCircle2 size={12} className="text-green-400"/> : <AlertCircle size={12} className="text-red-400"/>}
            <span className={tools[key]?'text-gray-300':'text-gray-600'}>{label}</span>
          </div>
        ))}
        <label className="flex items-center gap-2 ml-auto text-xs text-gray-400 cursor-pointer">
          <span>Network scan</span>
          <div onClick={()=>setIncludeNetwork(!includeNetwork)} className={`w-8 h-4 rounded-full transition-colors cursor-pointer relative ${includeNetwork?'bg-indigo-600':'bg-gray-700'}`}>
            <div className={`absolute top-0.5 w-3 h-3 bg-white rounded-full transition-transform ${includeNetwork?'translate-x-4':'translate-x-0.5'}`}/>
          </div>
        </label>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div>
          {devices.length===0 && !scanning && (
            <div className="card flex flex-col items-center justify-center py-16 text-center">
              <Usb size={32} className="text-gray-700 mb-3"/>
              <p className="text-gray-500 text-sm">No devices detected yet.</p>
              <p className="text-gray-600 text-xs mt-1">Connect an IoT device and click Full Scan.</p>
            </div>
          )}
          {scanning && devices.length===0 && (
            <div className="card flex flex-col items-center justify-center py-16 text-center">
              <Scan size={32} className="text-indigo-500 mb-3 animate-pulse"/>
              <p className="text-gray-400 text-sm">Scanning for devices...</p>
              <p className="text-gray-600 text-xs mt-1">{includeNetwork?'USB + Network (nmap)':'USB / Serial only'}</p>
            </div>
          )}
          <div className="space-y-3">
            {devices.map(d => <DeviceCard key={d.id} device={d} onSelect={setSelected} selected={selected}/>)}
          </div>
          {devices.length > 0 && (
            <div className="mt-4 flex gap-4">
              {[{label:'Total',value:devices.length,color:'text-white'},{label:'USB/Serial',value:devices.filter(d=>d.connection_type==='usb').length,color:'text-blue-400'},{label:'Network',value:devices.filter(d=>d.connection_type==='network').length,color:'text-green-400'}].map(s=>(
                <div key={s.label} className="card flex-1 text-center py-3">
                  <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                  <div className="text-xs text-gray-500">{s.label}</div>
                </div>
              ))}
            </div>
          )}
          {scanEvents.length > 0 && (
            <div className="card mt-4">
              <div className="text-xs text-gray-500 font-medium mb-2 flex items-center gap-1"><Terminal size={10}/>Scan log</div>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {scanEvents.map((e,i)=>(
                  <div key={i} className="text-xs mono flex items-start gap-2">
                    <span className={`${e.event==='scan_complete'?'text-green-400':e.event==='scan_started'?'text-blue-400':e.event==='error'?'text-red-400':'text-amber-400'}`}>
                      [{e.event}] {e.message||(e.total_found!==undefined?`Found ${e.total_found} devices in ${e.duration_ms}ms`:'')}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
        <div>
          {selected ? (
            <DeviceDetail device={selected} onClose={()=>setSelected(null)}/>
          ) : (
            <div className="card flex flex-col items-center justify-center py-16 text-center border-dashed">
              <Info size={24} className="text-gray-700 mb-3"/>
              <p className="text-gray-500 text-sm">Select a device to view details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
