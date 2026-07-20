import { useState, useEffect } from 'react'
import { Outlet, NavLink } from 'react-router-dom'
import { Cpu, LayoutDashboard, HardDrive, Shield, Package, AlertTriangle, BarChart3, FileCheck, Wifi, Sparkles, Settings, Menu, X } from 'lucide-react'
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
  const [completedPhases, setCompletedPhases] = useState(new Set())

  useEffect(() => {
    const checkPhases = async () => {
      const done = new Set()
      try {
        const fw = await fetch('/api/v1/firmware/jobs').then(r => r.json())
        if (fw.jobs?.some(j => j.status === 'completed' || j.status === 'success')) done.add(2)
      } catch (_) {}
      try {
        const an = await fetch('/api/v1/analysis/jobs').then(r => r.json())
        if (an.jobs?.some(j => j.status === 'success')) done.add(3)
      } catch (_) {}
      try {
        const sb = await fetch('/api/v1/sbom/jobs/list').then(r => r.json())
        if (sb.jobs?.some(j => j.status === 'success')) done.add(4)
      } catch (_) {}
      try {
        const cv = await fetch('/api/v1/cve/jobs/list').then(r => r.json())
        if (cv.jobs?.some(j => j.status === 'completed')) done.add(5)
      } catch (_) {}
      try {
        const vx = await fetch('/api/v1/vex/jobs/list').then(r => r.json())
        const DONE = ['completed','success','done','complete']
        if (vx.jobs?.some(j => DONE.includes(j.status))) done.add(6)
      } catch (_) {}
      try {
        const cp = await fetch('/api/v1/compliance/jobs/list').then(r => r.json())
        const DONE2 = ['completed','success','done','complete']
        if (cp.jobs?.some(j => DONE2.includes(j.status))) done.add(7)
      } catch (_) {}
      setCompletedPhases(done)
    }
    checkPhases()
    const interval = setInterval(checkPhases, 5000)
    return () => clearInterval(interval)
  }, [])
  const { isConfigured } = useAI()
  const [chatOpen, setChatOpen] = useState(false)
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div className="flex h-screen overflow-hidden relative" style={{backgroundColor:'#000000'}}>

      {/* Sidebar */}
      <aside
        className="flex-shrink-0 flex flex-col transition-all duration-300"
        style={{
          width: collapsed ? '60px' : '240px',
          backgroundColor: '#000000',
          borderRight: '1px solid #2c2e33',
        }}
      >
        {/* Logo + Toggle */}
        <div
          className="flex items-center px-3 py-4 flex-shrink-0"
          style={{
            borderBottom: '1px solid #2c2e33',
            justifyContent: collapsed ? 'center' : 'space-between',
          }}
        >
          {!collapsed && (
            <div className="flex items-center gap-2 min-w-0">
              <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style={{backgroundColor:'#0084d5'}}>
                <Shield size={14} className="text-white" />
              </div>
              <div className="min-w-0">
                <div className="text-sm font-bold text-white tracking-wide">IIFVDCAS</div>
                <div className="text-[10px] truncate" style={{color:'#6c757d'}}>Firmware Security</div>
              </div>
            </div>
          )}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="flex-shrink-0 p-1.5 rounded-lg transition-colors hover:bg-gray-800"
            style={{color:'#6c757d'}}
          >
            {collapsed ? <Menu size={16} /> : <X size={16} />}
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-2 py-3 overflow-y-auto overflow-x-hidden">
          {!collapsed && (
            <div className="text-[10px] font-semibold uppercase tracking-widest px-2 mb-2" style={{color:'#6c757d'}}>
              Navigation
            </div>
          )}
          {nav.map(item => (
            <NavLink
              key={item.path}
              to={item.path}
              title={collapsed ? item.label : undefined}
              className="flex items-center mb-0.5 rounded-lg transition-all duration-150 text-sm font-medium"
              style={({isActive}) => ({
                gap: collapsed ? '0' : '10px',
                padding: collapsed ? '10px 0' : '9px 10px',
                justifyContent: collapsed ? 'center' : 'flex-start',
                backgroundColor: isActive ? 'rgba(255,255,255,0.06)' : 'transparent',
                color: isActive ? '#ffffff' : '#8a8d98',
                borderLeft: isActive ? '3px solid #00c154' : '3px solid transparent',
              })}
            >
              <item.icon size={16} className="flex-shrink-0" />
              {!collapsed && <span className="flex-1 truncate">{item.label}</span>}
              {!collapsed && item.phase && (
                <span className={`badge text-[10px] flex-shrink-0 ${item.status === 'active' || completedPhases.has(item.phase) ? 'badge-green' : 'badge-gray'}`}>
                  P{item.phase}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-2 pb-3 pt-2 space-y-1 flex-shrink-0" style={{borderTop:'1px solid #2c2e33'}}>
          <button
            onClick={() => setChatOpen(!chatOpen)}
            title={collapsed ? 'AI Assistant Chat' : undefined}
            className="w-full flex items-center rounded-lg text-xs font-semibold transition-all"
            style={{
              gap: collapsed ? '0' : '10px',
              padding: collapsed ? '9px 0' : '8px 10px',
              justifyContent: collapsed ? 'center' : 'flex-start',
              backgroundColor: chatOpen ? '#0084d5' : 'rgba(0,132,213,0.08)',
              color: chatOpen ? '#ffffff' : '#0084d5',
              border: '1px solid rgba(0,132,213,0.25)',
            }}
          >
            <Sparkles size={14} className={isConfigured ? 'animate-pulse' : ''} />
            {!collapsed && <span className="flex-1 text-left">AI Assistant</span>}
            {!collapsed && (
              <span className="w-2 h-2 rounded-full flex-shrink-0" style={{backgroundColor: isConfigured ? '#00c154' : '#eb9d00'}} />
            )}
          </button>

          <NavLink
            to="/ai-settings"
            title={collapsed ? 'AI Provider Settings' : undefined}
            className="flex items-center rounded-lg text-xs transition-colors"
            style={({isActive}) => ({
              gap: collapsed ? '0' : '10px',
              padding: collapsed ? '9px 0' : '8px 10px',
              justifyContent: collapsed ? 'center' : 'flex-start',
              backgroundColor: isActive ? 'rgba(255,255,255,0.06)' : 'transparent',
              color: isActive ? '#ffffff' : '#8a8d98',
            })}
          >
            <Settings size={14} />
            {!collapsed && <span>AI Provider Settings</span>}
          </NavLink>

          {!collapsed && (
            <div className="flex items-center gap-2 text-xs px-2 pt-1">
              <Wifi size={11} style={{color: connected ? '#00c154' : '#6c757d'}} />
              <span style={{color: connected ? '#00c154' : '#6c757d'}}>
                {connected ? 'Live connected' : 'Connecting...'}
              </span>
            </div>
          )}
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto min-w-0" style={{backgroundColor:'#000000'}}>
        <Outlet />
      </main>

      <AIChat isOpen={chatOpen} onClose={() => setChatOpen(false)} />
    </div>
  )
}
