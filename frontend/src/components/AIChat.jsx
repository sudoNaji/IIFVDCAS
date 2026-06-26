import React, { useState, useEffect, useRef } from 'react'
import { MessageSquare, Send, X, Shield, RefreshCw, Sparkles, HelpCircle } from 'lucide-react'
import { aiApi } from '../utils/api'
import { useAI } from '../hooks/useAI'

export default function AIChat({ isOpen, onClose }) {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: "Hello! I am your IIFVDCAS AI Security Assistant. I can help analyze your firmware vulnerabilities, triage VEX findings, explain static analysis alerts, or help guide your compliance roadmap. How can I assist you today?"
    }
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [scanCtx, setScanCtx] = useState(null)
  const [ctxLoading, setCtxLoading] = useState(false)
  
  const { isConfigured } = useAI()
  const chatEndRef = useRef(null)

  // Scroll to bottom on new message
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  // Automatically fetch active scan context on load / open
  useEffect(() => {
    if (isOpen) {
      loadLatestScanContext()
    }
  }, [isOpen])

  const loadLatestScanContext = async () => {
    setCtxLoading(true)
    try {
      // 1. Try to find VEX results first (most comprehensive)
      const vexJobsResp = await fetch('/api/v1/vex/jobs/list').then(r => r.json())
      const activeVexJob = vexJobsResp.jobs?.sort((a,b) => b.started_at - a.started_at)?.[0]

      if (activeVexJob && activeVexJob.status === 'completed') {
        const vexSumm = await fetch(`/api/v1/vex/${activeVexJob.job_id}/summary`).then(r => r.json())
        const fwc = vexSumm.firmware_context || {}
        
        setScanCtx({
          device: fwc.device_name || 'IoT Device',
          architecture: fwc.architecture || 'unknown',
          is_bare_metal: fwc.is_bare_metal ?? true,
          total_cves: vexSumm.total_cves_input || 0,
          risk_score: vexSumm.risk_score || 0,
          risk_label: vexSumm.risk_label || 'minimal',
          affected_count: vexSumm.affected_count || 0,
          not_affected_count: vexSumm.not_affected_count || 0,
          fixed_count: vexSumm.fixed_count || 0,
          under_inv_count: vexSumm.under_inv_count || 0,
          source: 'Phase 6 VEX Analysis'
        })
        setCtxLoading(false)
        return
      }

      // 2. Fall back to CVE mapping results
      const cveJobsResp = await fetch('/api/v1/cve/jobs/list').then(r => r.json())
      const activeCveJob = cveJobsResp.jobs?.sort((a,b) => b.started_at - a.started_at)?.[0]

      if (activeCveJob && activeCveJob.status === 'completed') {
        const cveSumm = await fetch(`/api/v1/cve/${activeCveJob.job_id}/summary`).then(r => r.json())
        setScanCtx({
          device: 'IoT Device',
          total_cves: cveSumm.total_cves || 0,
          risk_score: cveSumm.critical_count * 15 + cveSumm.high_count * 5, // rough estimate
          critical_cves: cveSumm.critical_count || 0,
          high_cves: cveSumm.high_count || 0,
          kev_count: cveSumm.kev_count || 0,
          source: 'Phase 5 CVE Mapping'
        })
        setCtxLoading(false)
        return
      }

      // 3. Fall back to SBOM
      const sbomJobsResp = await fetch('/api/v1/sbom/jobs/list').then(r => r.json())
      const activeSbomJob = sbomJobsResp.jobs?.sort((a,b) => b.started_at - a.started_at)?.[0]
      if (activeSbomJob && activeSbomJob.status === 'completed') {
        setScanCtx({
          device: activeSbomJob.device_info?.device_name || 'IoT Device',
          architecture: activeSbomJob.device_info?.cpu_arch || 'unknown',
          source: 'Phase 4 SBOM Extraction'
        })
        setCtxLoading(false)
        return
      }

      // No context
      setScanCtx(null)
    } catch (e) {
      console.warn('Failed to load active scan context for chatbot:', e)
    } finally {
      setCtxLoading(false)
    }
  }

  const handleSend = async (e) => {
    if (e) e.preventDefault()
    if (!input.trim() || loading) return

    if (!isConfigured) {
      setMessages(prev => [
        ...prev,
        { role: 'user', content: input },
        { role: 'assistant', content: "⚠️ AI is not configured yet. Please go to the 'AI Settings' page from the sidebar to set up your API Key and provider before chatting." }
      ])
      setInput('')
      return
    }

    const userText = input
    setInput('')
    
    // Add user message to UI
    setMessages(prev => [...prev, { role: 'user', content: userText }])
    setLoading(true)

    try {
      // Map message history to what the endpoint expects: list of {role, content}
      const history = messages.map(m => ({ role: m.role, content: m.content }))

      const resp = await aiApi.chat({
        message: userText,
        scan_context: scanCtx || {},
        history: history
      })

      setMessages(prev => [...prev, { role: 'assistant', content: resp.data.reply }])
    } catch (err) {
      const errorMsg = err.response?.data?.detail || err.message || 'Failed to get a response from AI.'
      setMessages(prev => [
        ...prev, 
        { role: 'assistant', content: `❌ Error: ${errorMsg}` }
      ])
    } finally {
      setLoading(false)
    }
  }

  const handleQuickQuestion = (q) => {
    setInput(q)
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-y-0 right-0 w-[420px] bg-gray-900 border-l border-gray-800 shadow-2xl flex flex-col z-50 animate-slide-in">
      {/* Header */}
      <div className="p-4 border-b border-gray-800 flex items-center justify-between bg-gray-900/80 backdrop-blur-md">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 bg-indigo-600/20 text-indigo-400 rounded-md flex items-center justify-center border border-indigo-500/30">
            <Sparkles size={13} className="animate-pulse" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white">AI Security Assistant</h2>
            <span className="text-[10px] text-gray-500">Context-Aware Chat</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={loadLatestScanContext} 
            disabled={ctxLoading}
            title="Reload firmware context"
            className="p-1 rounded text-gray-500 hover:text-white hover:bg-gray-800 transition-colors"
          >
            <RefreshCw size={13} className={ctxLoading ? 'animate-spin' : ''} />
          </button>
          <button 
            onClick={onClose}
            className="p-1 rounded text-gray-500 hover:text-white hover:bg-gray-800 transition-colors"
          >
            <X size={16} />
          </button>
        </div>
      </div>

      {/* Active Context Banner */}
      <div className="px-4 py-2 bg-gray-950 border-b border-gray-800/60 text-[11px] flex items-center justify-between text-gray-400">
        {scanCtx ? (
          <div className="flex items-center gap-1.5 truncate">
            <Shield size={11} className="text-green-400" />
            <span className="truncate">
              Context loaded from <strong>{scanCtx.source}</strong> ({scanCtx.device}, {scanCtx.total_cves} CVEs, score {scanCtx.risk_score})
            </span>
          </div>
        ) : (
          <div className="flex items-center gap-1.5 text-amber-500">
            <HelpCircle size={11} />
            <span>No active scan loaded. Start scanning in Phases 2-5.</span>
          </div>
        )}
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((m, i) => (
          <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`max-w-[85%] p-3 rounded-lg text-xs leading-relaxed ${
              m.role === 'user' 
                ? 'bg-indigo-600 text-white rounded-br-none' 
                : m.content.startsWith('⚠️') || m.content.startsWith('❌')
                  ? 'bg-red-950/30 border border-red-800/40 text-red-300 rounded-bl-none'
                  : 'bg-gray-800/50 text-gray-200 border border-gray-800 rounded-bl-none'
            }`}>
              <div className="whitespace-pre-wrap">{m.content}</div>
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex justify-start">
            <div className="bg-gray-800/50 text-gray-400 border border-gray-800 p-3 rounded-lg rounded-bl-none text-xs flex items-center gap-2">
              <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></span>
              <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></span>
              <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></span>
              <span className="text-[10px] text-gray-500 ml-1">Analyzing scan data...</span>
            </div>
          </div>
        )}
        <div ref={chatEndRef} />
      </div>

      {/* Quick suggestions if history is fresh */}
      {messages.length === 1 && (
        <div className="px-4 py-2 bg-gray-900/30 border-t border-gray-800/30 flex flex-wrap gap-1.5">
          {[
            "Which CVE should I fix first?",
            "Explain ETSI compliance posture",
            "Generate VEX summary checklist",
            "What security tools ran?"
          ].map(q => (
            <button
              key={q}
              onClick={() => handleQuickQuestion(q)}
              className="text-[10px] bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700/50 px-2 py-1 rounded transition-colors"
            >
              {q}
            </button>
          ))}
        </div>
      )}

      {/* Input Form */}
      <form onSubmit={handleSend} className="p-3 border-t border-gray-800 bg-gray-900/80 backdrop-blur-md flex items-center gap-2">
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder={isConfigured ? "Ask a security question..." : "AI configuration required"}
          className="flex-1 bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500 transition-colors"
          disabled={loading}
        />
        <button
          type="submit"
          disabled={!input.trim() || loading}
          className="p-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-800 disabled:text-gray-600 text-white rounded-lg transition-colors flex-shrink-0"
        >
          <Send size={14} />
        </button>
      </form>
    </div>
  )
}
