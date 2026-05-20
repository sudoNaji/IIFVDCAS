import { Outlet, NavLink } from 'react-router-dom'
import { Cpu, LayoutDashboard, HardDrive, Shield, Package, AlertTriangle, BarChart3, FileCheck, Wifi } from 'lucide-react'
import { useWebSocket } from '../hooks/useWebSocket'

const nav = [
  { path:'/dashboard',  icon:LayoutDashboard, label:'Dashboard',           phase:null, status:'active' },
  { path:'/devices',    icon:Cpu,             label:'Device Detection',    phase:1,    status:'active' },
  { path:'/firmware',   icon:HardDrive,       label:'Firmware Extraction', phase:2,    status:'planned' },
  { path:'/analysis',   icon:Shield,          label:'Static Analysis',     phase:3,    status:'planned' },
  { path:'/sbom',       icon:Package,         label:'SBOM / HBOM / CBOM',  phase:4,    status:'planned' },
  { path:'/cve',        icon:AlertTriangle,   label:'CVE Mapping',         phase:5,    status:'planned' },
  { path:'/vex',        icon:BarChart3,       label:'VEX Risk Analysis',   phase:6,    status:'planned' },
  { path:'/compliance', icon:FileCheck,       label:'Compliance Report',   phase:7,    status:'planned' },
]

export default function Layout() {
  const { connected } = useWebSocket('ws://localhost:8000/ws')
  return (
    <div className="flex h-screen bg-gray-950 overflow-hidden">
      <aside className="w-64 flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="p-5 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center">
              <Shield size={16} className="text-white" />
            </div>
            <div>
              <div className="text-sm font-semibold text-white">IIFVDCAS</div>
              <div className="text-xs text-gray-500">Firmware Security Platform</div>
            </div>
          </div>
        </div>
        <nav className="flex-1 p-3 overflow-y-auto">
          <div className="text-xs text-gray-600 font-medium uppercase tracking-wider px-2 mb-2">Analysis Pipeline</div>
          {nav.map(item => (
            <NavLink key={item.path} to={item.path} className={({isActive}) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg mb-0.5 text-sm transition-colors ${isActive ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-600/30' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'}`
            }>
              <item.icon size={16} className="flex-shrink-0" />
              <span className="flex-1 font-medium">{item.label}</span>
              {item.phase && (
                <span className={`badge text-[10px] ${item.status==='active' ? 'badge-green' : 'badge-gray'}`}>P{item.phase}</span>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="p-4 border-t border-gray-800">
          <div className="flex items-center gap-2 text-xs">
            <Wifi size={12} className={connected ? 'text-green-400' : 'text-gray-600'} />
            <span className={connected ? 'text-green-400' : 'text-gray-600'}>{connected ? 'Live connected' : 'Connecting...'}</span>
          </div>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto"><Outlet /></main>
    </div>
  )
}
