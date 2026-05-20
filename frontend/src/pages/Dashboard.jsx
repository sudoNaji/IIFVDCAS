import { useState, useEffect } from 'react'
import { Shield, Cpu, HardDrive, AlertTriangle, FileCheck, BarChart3, Package, CheckCircle2, AlertCircle, ArrowRight, Activity, Zap } from 'lucide-react'
import { systemApi } from '../utils/api'
import { useNavigate } from 'react-router-dom'

const phases = [
  { num:1, label:'Device Detection',    path:'/devices',    icon:Cpu,           status:'active',  emba:'P02 · S06 · udevadm' },
  { num:2, label:'Firmware Extraction', path:'/firmware',   icon:HardDrive,     status:'planned', emba:'P50 · P55 · binwalk · unblob' },
  { num:3, label:'Static Analysis',     path:'/analysis',   icon:Shield,        status:'planned', emba:'S12 · S13 · S45 · S60 · checksec' },
  { num:4, label:'SBOM / HBOM / CBOM',  path:'/sbom',       icon:Package,       status:'planned', emba:'S08 · F15 · CycloneDX' },
  { num:5, label:'CVE Mapping',         path:'/cve',        icon:AlertTriangle, status:'planned', emba:'F50 · NVD REST v2 · EPSS' },
  { num:6, label:'VEX Risk Analysis',   path:'/vex',        icon:BarChart3,     status:'planned', emba:'KEV · VEX engine' },
  { num:7, label:'Compliance',          path:'/compliance', icon:FileCheck,     status:'planned', emba:'ETSI EN 303 645 · EU CRA' },
]
const toolList = [
  {key:'udevadm',label:'udevadm',phase:1},{key:'nmap',label:'nmap',phase:1},{key:'avrdude',label:'avrdude',phase:1},
  {key:'binwalk',label:'binwalk',phase:2},{key:'unblob',label:'unblob',phase:2},
  {key:'checksec',label:'checksec',phase:3},{key:'john',label:'john (JtR)',phase:3},{key:'openssl',label:'openssl',phase:3},{key:'shellcheck',label:'shellcheck',phase:3},
  {key:'qemu-arm-static',label:'qemu',phase:8},
]

export default function Dashboard() {
  const [tools, setTools] = useState({})
  const navigate = useNavigate()
  useEffect(() => { systemApi.info().then(r => setTools(r.data.tools)).catch(()=>{}) }, [])
  const ready = toolList.filter(t => tools[t.key]).length
  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">IIFVDCAS Dashboard</h1>
        <p className="text-gray-400 text-sm mt-1">Intelligent IoT Firmware Vulnerability Detection & Compliance Assessment System</p>
        <p className="text-gray-600 text-xs mt-0.5">Powered by EMBA v2.0.1 · UMT Lahore</p>
      </div>
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          {label:'Total Phases',value:7,color:'text-white',icon:Activity},
          {label:'Active Phase',value:'1 of 7',color:'text-green-400',icon:Zap},
          {label:'Tools Ready',value:`${ready}/${toolList.length}`,color:ready===toolList.length?'text-green-400':'text-amber-400',icon:CheckCircle2},
          {label:'Platform',value:'Web → Win → Linux',color:'text-indigo-400',icon:Shield},
        ].map(s => (
          <div key={s.label} className="card">
            <div className="flex items-center gap-2 mb-2"><s.icon size={14} className="text-gray-500" /><span className="text-xs text-gray-500">{s.label}</span></div>
            <div className={`text-xl font-bold ${s.color}`}>{s.value}</div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2">
          <div className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-3">Analysis Pipeline</div>
          <div className="space-y-2">
            {phases.map(p => (
              <div key={p.num} onClick={() => navigate(p.path)} className="card flex items-center gap-4 cursor-pointer hover:border-gray-700 transition-colors">
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${p.status==='active'?'bg-indigo-600':'bg-gray-800'}`}>
                  <p.icon size={15} className={p.status==='active'?'text-white':'text-gray-500'} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-white">Phase {p.num}: {p.label}</span>
                    <span className={`badge text-[10px] ${p.status==='active'?'badge-green':'badge-gray'}`}>{p.status==='active'?'Active':'Planned'}</span>
                  </div>
                  <div className="text-xs text-gray-600 mono mt-0.5">{p.emba}</div>
                </div>
                <ArrowRight size={14} className="text-gray-700 flex-shrink-0" />
              </div>
            ))}
          </div>
        </div>
        <div>
          <div className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-3">Tool Availability</div>
          <div className="card">
            <div className="mb-4">
              <div className="flex justify-between text-xs text-gray-500 mb-1"><span>Tools ready</span><span>{ready}/{toolList.length}</span></div>
              <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                <div className="h-full bg-indigo-600 rounded-full transition-all" style={{width:`${(ready/toolList.length)*100}%`}} />
              </div>
            </div>
            <div className="space-y-1.5">
              {toolList.map(t => (
                <div key={t.key} className="flex items-center gap-2 text-xs">
                  {tools[t.key] ? <CheckCircle2 size={11} className="text-green-400 flex-shrink-0" /> : <AlertCircle size={11} className="text-gray-600 flex-shrink-0" />}
                  <span className={`flex-1 ${tools[t.key]?'text-gray-300':'text-gray-600'}`}>{t.label}</span>
                  <span className="text-gray-700 text-[10px]">P{t.phase}</span>
                </div>
              ))}
            </div>
            {ready < toolList.length && (
              <div className="mt-4 pt-3 border-t border-gray-800">
                <p className="text-xs text-amber-400 mb-1">Install missing tools:</p>
                <code className="text-xs text-gray-500">./scripts/install.sh</code>
              </div>
            )}
          </div>
          <div className="card mt-4">
            <div className="text-xs text-gray-500 font-medium mb-2">EMBA Engine</div>
            <div className="space-y-1 text-xs">
              {[['Version','2.0.1'],['Location','~/emba'],['Modules','93 total'],['P-modules','20 (extraction)'],['S-modules','51 (static)'],['L-modules','9 (dynamic)'],['F-modules','7 (reporting)']].map(([k,v]) => (
                <div key={k} className="flex gap-2"><span className="text-gray-600 w-20">{k}</span><span className="text-gray-300 mono">{v}</span></div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
