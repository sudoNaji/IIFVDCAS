import { useState, useEffect } from 'react'
import { Shield, Cpu, HardDrive, AlertTriangle, FileCheck, BarChart3, Package, CheckCircle2, AlertCircle, ArrowRight, Activity, Zap } from 'lucide-react'
import { systemApi } from '../utils/api'
import { useNavigate } from 'react-router-dom'

const phases = [
  { num:1, label:'Device Detection',    path:'/devices',    icon:Cpu,           status:'active',  emba:'P02 · S06 · udevadm' },
  { num:2, label:'Firmware Extraction', path:'/firmware',   icon:HardDrive,     status:'planned', emba:'P50 · P55 · binwalk · unblob' },
  { num:3, label:'Static Analysis',     path:'/analysis',   icon:Shield,        status:'planned', emba:'S12 · S13 · S45 · S60 · checksec' },
  { num:4, label:'SBOM / HBOM / CBOM',  path:'/sbom',       icon:Package,       status:'active',  emba:'S08 · F15 · CycloneDX' },
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

  const stats = [
    { label:'Total Phases', value:7, icon:Activity, accent:'#0084d5' },
    { label:'Active Phase', value:'1 of 7', icon:Zap, accent:'#00c154' },
    { label:'Tools Ready', value:`${ready}/${toolList.length}`, icon:CheckCircle2, accent: ready === toolList.length ? '#00c154' : '#eb9d00' },
    { label:'Platform', value:'Web → WSL → Linux', icon:Shield, accent:'#8457d5' },
  ]

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">IIFVDCAS Dashboard</h1>
        <p className="text-sm mt-1" style={{color:'#6c757d'}}>Intelligent IoT Firmware Vulnerability Detection & Compliance Assessment System</p>
        <p className="text-xs mt-0.5" style={{color:'#434a54'}}>Powered by EMBA v2.0.1 · UMT Lahore</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {stats.map(s => (
          <div key={s.label} className="card">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{backgroundColor: s.accent + '22'}}>
                <s.icon size={16} style={{color: s.accent}} />
              </div>
              <span className="text-xs" style={{color:'#6c757d'}}>{s.label}</span>
            </div>
            <div className="text-xl font-bold" style={{color: s.accent}}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-3 gap-4">
        {/* Pipeline */}
        <div className="col-span-2">
          <div className="text-xs font-semibold uppercase tracking-widest mb-3" style={{color:'#6c757d'}}>
            Analysis Pipeline
          </div>
          <div className="space-y-2">
            {phases.map(p => (
              <div
                key={p.num}
                onClick={() => navigate(p.path)}
                className="card flex items-center gap-4 cursor-pointer transition-all hover:border-gray-600"
                style={{borderColor:'#2c2e33'}}
              >
                <div
                  className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
                  style={{backgroundColor: p.status === 'active' ? '#0084d5' : '#2c2e33'}}
                >
                  <p.icon size={15} style={{color: p.status === 'active' ? '#ffffff' : '#6c757d'}} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-white">Phase {p.num}: {p.label}</span>
                    <span className={`badge text-[10px] ${p.status === 'active' ? 'badge-green' : 'badge-gray'}`}>
                      {p.status === 'active' ? 'Active' : 'Planned'}
                    </span>
                  </div>
                  <div className="text-xs mono mt-0.5" style={{color:'#434a54'}}>{p.emba}</div>
                </div>
                <ArrowRight size={14} style={{color:'#434a54'}} className="flex-shrink-0" />
              </div>
            ))}
          </div>
        </div>

        {/* Tools */}
        <div>
          <div className="text-xs font-semibold uppercase tracking-widest mb-3" style={{color:'#6c757d'}}>
            Tool Availability
          </div>
          <div className="card">
            <div className="mb-4">
              <div className="flex justify-between text-xs mb-1" style={{color:'#6c757d'}}>
                <span>Tools ready</span><span>{ready}/{toolList.length}</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{backgroundColor:'#2c2e33'}}>
                <div
                  className="h-full rounded-full transition-all"
                  style={{width:`${(ready/toolList.length)*100}%`, backgroundColor:'#00c154'}}
                />
              </div>
            </div>
            <div className="space-y-1.5">
              {toolList.map(t => (
                <div key={t.key} className="flex items-center gap-2 text-xs">
                  {tools[t.key]
                    ? <CheckCircle2 size={11} style={{color:'#00c154'}} className="flex-shrink-0" />
                    : <AlertCircle size={11} style={{color:'#434a54'}} className="flex-shrink-0" />}
                  <span className="flex-1" style={{color: tools[t.key] ? '#ffffff' : '#6c757d'}}>{t.label}</span>
                  <span className="text-[10px]" style={{color:'#434a54'}}>P{t.phase}</span>
                </div>
              ))}
            </div>
            {ready < toolList.length && (
              <div className="mt-4 pt-3" style={{borderTop:'1px solid #2c2e33'}}>
                <p className="text-xs mb-1" style={{color:'#eb9d00'}}>Install missing tools:</p>
                <code className="text-xs" style={{color:'#6c757d'}}>./scripts/install.sh</code>
              </div>
            )}
          </div>

          <div className="card mt-4">
            <div className="text-xs font-semibold mb-3" style={{color:'#6c757d'}}>EMBA Engine</div>
            <div className="space-y-1.5 text-xs">
              {[['Version','2.0.1'],['Location','~/emba'],['Modules','93 total'],['P-modules','20 (extraction)'],['S-modules','51 (static)'],['F-modules','7 (reporting)']].map(([k,v]) => (
                <div key={k} className="flex gap-2">
                  <span className="w-20" style={{color:'#434a54'}}>{k}</span>
                  <span className="mono" style={{color:'#ffffff'}}>{v}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
