import { useState } from 'react'
import { Outlet, NavLink } from 'react-router-dom'
import { Cpu, LayoutDashboard, HardDrive, Shield, Package, AlertTriangle, BarChart3, FileCheck, Wifi, Sparkles, Settings } from 'lucide-react'
import { useWebSocket } from '../hooks/useWebSocket'
import { useAI } from '../hooks/useAI'
import AIChat from './AIChat'

const nav = [
  { path:'/dashboard',  icon:LayoutDashboard, label:'Dashboard',           phase:null, status:'active' },
  { path:'/devices',    icon:Cpu,             label:'Device Detection',    phase:1,    status:'active' },
  { path:'/firmware',   icon:HardDrive,       label:'Firmware Extraction', phase:2,    status:'active' },
  { path:'/analysis',   icon:Shield,          label:'Static Analysis',     phase:3,    status:'planned' },
  { path:'/sbom',       icon:Package,         label:'SBOM / HBOM / CBOM',  phase:4,    status:'active' },
  { path:'/cve',        icon:AlertTriangle,   label:'CVE Mapping',         phase:5,    status:'planned' },
  { path:'/vex',        icon:BarChart3,       label:'VEX Risk Analysis',   phase:6,    status:'planned' },
  { path:'/compliance', icon:FileCheck,       label:'Compliance Report',   phase:7,    status:'planned' },
]

export default function Layout() {
  const { connected } = useWebSocket('ws://localhost:8000/ws')
  const { isConfigured } = useAI()
  const [chatOpen, setChatOpen] = useState(false)

  return (
    <div className="flex h-screen bg-gray-950 overflow-hidden relative">
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

        {/* Sidebar Footer: AI Assistant + Connection Info */}
        <div className="p-3 border-t border-gray-800 space-y-2">
          {/* AI Chat button */}
          <button
            onClick={() => setChatOpen(!chatOpen)}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-semibold transition-all border ${
              chatOpen 
                ? 'bg-indigo-600 text-white border-indigo-500 shadow-lg shadow-indigo-600/20' 
                : 'text-indigo-400 bg-indigo-950/20 border-indigo-800/20 hover:bg-indigo-950/40'
            }`}
          >
            <Sparkles size={13} className={isConfigured ? 'animate-pulse' : ''} />
            <span className="flex-1 text-left">AI Assistant Chat</span>
            <span className={`w-2 h-2 rounded-full ${isConfigured ? 'bg-green-400 shadow-sm shadow-green-400' : 'bg-amber-400'}`} title={isConfigured ? 'AI Settings configured' : 'AI configuration missing'} />
          </button>

          {/* AI settings link */}
          <NavLink 
            to="/ai-settings"
            className={({isActive}) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg text-xs transition-colors ${
                isActive 
                  ? 'bg-gray-800 text-white font-medium border border-gray-700' 
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-850'
              }`
            }
          >
            <Settings size={13} />
            <span>AI Provider Settings</span>
          </NavLink>

          <div className="flex items-center gap-2 text-xs pt-1 px-3">
            <Wifi size={11} className={connected ? 'text-green-400' : 'text-gray-600'} />
            <span className={connected ? 'text-green-400' : 'text-gray-600'}>{connected ? 'Live connected' : 'Connecting...'}</span>
          </div>
        </div>
      </aside>
      
      <main className="flex-1 overflow-y-auto relative">
        <Outlet />
      </main>

      {/* Floating AI Chat Side panel */}
      <AIChat isOpen={chatOpen} onClose={() => setChatOpen(false)} />
    </div>
  )
}
