import { useState, useEffect } from 'react'
import { Zap, Key, Server, Settings, CheckCircle2, AlertCircle, Eye, EyeOff } from 'lucide-react'
import { loadAIConfig, saveAIConfig } from '../hooks/useAI'
import { aiApi } from '../utils/api'

export default function AISettings() {
  const [provider, setProvider] = useState('nvidia_nim')
  const [apiKey, setApiKey] = useState('')
  const [model, setModel] = useState('meta/llama-3.1-70b-instruct')
  const [baseUrl, setBaseUrl] = useState('https://integrate.api.nvidia.com/v1')
  
  const [showKey, setShowKey] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null) // { success: boolean, msg: string }
  const [saveSuccess, setSaveSuccess] = useState(false)

  // Loaded providers and default configs from backend
  const [availableProviders, setAvailableProviders] = useState([])

  useEffect(() => {
    // Load existing settings
    const cfg = loadAIConfig()
    if (cfg.provider) setProvider(cfg.provider)
    if (cfg.apiKey) setApiKey(cfg.apiKey)
    if (cfg.model) setModel(cfg.model)
    if (cfg.baseUrl) setBaseUrl(cfg.baseUrl)

    // Load available providers info from backend
    aiApi.listProviders()
      .then(resp => {
        setAvailableProviders(resp.data.providers || [])
      })
      .catch(err => {
        console.error('Failed to load providers list from backend:', err)
      })
  }, [])

  // Handle provider change to fill defaults
  const handleProviderChange = (newProvider) => {
    setProvider(newProvider)
    const info = availableProviders.find(p => p.id === newProvider)
    if (info) {
      setModel(info.model || '')
      setBaseUrl(info.base_url || '')
    } else {
      // Fallbacks
      if (newProvider === 'nvidia_nim') {
        setModel('meta/llama-3.1-70b-instruct')
        setBaseUrl('https://integrate.api.nvidia.com/v1')
      } else if (newProvider === 'openai') {
        setModel('gpt-4o-mini')
        setBaseUrl('')
      } else if (newProvider === 'anthropic') {
        setModel('claude-3-5-haiku-20241022')
        setBaseUrl('')
      } else if (newProvider === 'gemini') {
        setModel('gemini-2.0-flash')
        setBaseUrl('')
      } else if (newProvider === 'ollama') {
        setModel('llama3')
        setBaseUrl('http://localhost:11434/v1')
      }
    }
    setTestResult(null)
  }

  const handleSave = () => {
    saveAIConfig({ provider, apiKey, model, baseUrl })
    setSaveSuccess(true)
    setTimeout(() => setSaveSuccess(false), 3000)
  }

  const handleTest = async () => {
    setTesting(true)
    setTestResult(null)
    
    // Temporarily save config to localstorage before testing since the test API pulls it from there
    const originalConfig = loadAIConfig()
    saveAIConfig({ provider, apiKey, model, baseUrl })

    try {
      const resp = await aiApi.test()
      setTestResult({
        success: true,
        msg: `Connection successful! Provider replied: "${resp.data?.reply || 'OK'}" using model: "${resp.data?.model || model}"`
      })
    } catch (err) {
      const errorMsg = err.response?.data?.detail || err.message || 'Verification failed'
      setTestResult({
        success: false,
        msg: errorMsg
      })
      // Restore original config if connection failed (user's choice if they want to undo)
    } finally {
      setTesting(false)
    }
  }

  const activeProviderInfo = availableProviders.find(p => p.id === provider)
  const needsKey = activeProviderInfo ? activeProviderInfo.needs_key : (provider !== 'ollama')
  const needsBaseUrl = activeProviderInfo ? activeProviderInfo.needs_base_url : (provider === 'nvidia_nim' || provider === 'ollama')

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 bg-indigo-600/20 text-indigo-400 rounded-lg flex items-center justify-center border border-indigo-500/30">
          <Settings size={20} className="animate-spin-slow" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white">AI Assistant Settings</h1>
          <p className="text-sm text-gray-400">Configure your preferred Large Language Model provider. Settings are stored locally in your browser.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Settings Form */}
        <div className="md:col-span-2 card space-y-4">
          <div className="flex items-center gap-2 border-b border-gray-800 pb-3">
            <Zap size={16} className="text-indigo-400" />
            <h2 className="text-sm font-semibold text-white">Provider Configuration</h2>
          </div>

          <div className="space-y-4">
            {/* Provider Dropdown */}
            <div className="flex flex-col gap-1.5">
              <label className="text-xs text-gray-400 font-medium">AI Provider</label>
              <select
                value={provider}
                onChange={e => handleProviderChange(e.target.value)}
                className="input py-2 text-sm bg-gray-950 border-gray-800 rounded-lg text-white"
              >
                <option value="nvidia_nim">NVIDIA NIM (Recommended)</option>
                <option value="openai">OpenAI (GPT-4o / GPT-4o-mini)</option>
                <option value="anthropic">Anthropic (Claude 3.5)</option>
                <option value="gemini">Google Gemini</option>
                <option value="ollama">Ollama (Local LLM)</option>
              </select>
            </div>

            {/* Base URL (Conditional) */}
            {needsBaseUrl && (
              <div className="flex flex-col gap-1.5">
                <label className="text-xs text-gray-400 font-medium">Base API URL</label>
                <div className="relative">
                  <Server size={14} className="absolute left-3 top-3.5 text-gray-500" />
                  <input
                    type="text"
                    value={baseUrl}
                    onChange={e => setBaseUrl(e.target.value)}
                    placeholder="https://..."
                    className="input pl-9 w-full text-sm bg-gray-950 border-gray-800 rounded-lg text-white"
                  />
                </div>
                <p className="text-[10px] text-gray-500">
                  {provider === 'nvidia_nim' 
                    ? 'Default NIM API endpoint: https://integrate.api.nvidia.com/v1' 
                    : 'Default Ollama endpoint: http://localhost:11434/v1'}
                </p>
              </div>
            )}

            {/* Model Name */}
            <div className="flex flex-col gap-1.5">
              <label className="text-xs text-gray-400 font-medium">Model ID / Name</label>
              <input
                type="text"
                value={model}
                onChange={e => setModel(e.target.value)}
                placeholder="e.g. meta/llama-3.1-70b-instruct"
                className="input w-full text-sm bg-gray-950 border-gray-800 rounded-lg text-white"
              />
              <p className="text-[10px] text-gray-500">
                Ensure this model exists and is available on your selected provider account.
              </p>
            </div>

            {/* API Key (Conditional) */}
            {needsKey && (
              <div className="flex flex-col gap-1.5">
                <label className="text-xs text-gray-400 font-medium">API Key</label>
                <div className="relative">
                  <Key size={14} className="absolute left-3 top-3.5 text-gray-500" />
                  <input
                    type={showKey ? 'text' : 'password'}
                    value={apiKey}
                    onChange={e => setApiKey(e.target.value)}
                    placeholder="Enter your API provider secret key"
                    className="input pl-9 pr-10 w-full text-sm bg-gray-950 border-gray-800 rounded-lg text-white"
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(!showKey)}
                    className="absolute right-3 top-3 text-gray-500 hover:text-gray-300"
                  >
                    {showKey ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
                <p className="text-[10px] text-gray-500">
                  Your key is never sent to the IIFVDCAS database. It is stored inside your browser's local storage.
                </p>
              </div>
            )}

            {/* Actions */}
            <div className="flex gap-3 pt-3">
              <button
                type="button"
                onClick={handleTest}
                disabled={testing}
                className="btn btn-secondary text-xs flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg border border-gray-700 bg-gray-900 hover:bg-gray-800 text-white font-medium"
              >
                {testing ? 'Testing...' : 'Test Connection'}
              </button>
              <button
                type="button"
                onClick={handleSave}
                className="btn btn-primary text-xs flex-1 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium shadow-lg shadow-indigo-600/20"
              >
                Save Configuration
              </button>
            </div>

            {saveSuccess && (
              <div className="p-3 bg-green-950/40 border border-green-800/40 rounded-lg text-green-400 text-xs flex items-center gap-2">
                <CheckCircle2 size={14} />
                <span>AI Configuration saved successfully!</span>
              </div>
            )}

            {testResult && (
              <div className={`p-3 border rounded-lg text-xs flex items-start gap-2 ${
                testResult.success 
                  ? 'bg-green-950/40 border-green-800/40 text-green-400' 
                  : 'bg-red-950/40 border-red-800/40 text-red-400'
              }`}>
                {testResult.success ? <CheckCircle2 size={14} className="mt-0.5 flex-shrink-0" /> : <AlertCircle size={14} className="mt-0.5 flex-shrink-0" />}
                <div>{testResult.msg}</div>
              </div>
            )}
          </div>
        </div>

        {/* Side Panel: Information */}
        <div className="card space-y-4 bg-gray-900/50">
          <h3 className="text-xs font-semibold text-white uppercase tracking-wider">How this works</h3>
          <div className="text-xs text-gray-400 space-y-3 leading-relaxed">
            <p>
              The IIFVDCAS AI assistant layers security expertise directly on top of your scan results.
            </p>
            <p>
              <strong>Security context:</strong> Whenever you ask the assistant to explain a CVE, justify a VEX state, or audit a compliance failure, the platform automatically feeds relevant technical context (such as the target architecture, bare-metal state, CBOM libraries, and scan findings) directly into the LLM system prompt.
            </p>
            <p>
              This turns a generic AI model into a dedicated security consultant who understands your specific IoT firmware's exact details.
            </p>
            <div className="border-t border-gray-800 pt-3 mt-3">
              <span className="font-semibold text-indigo-400 block mb-1">Recommended Models:</span>
              <ul className="list-disc list-inside space-y-1 text-gray-500 text-[10px]">
                <li><strong>NVIDIA NIM:</strong> meta/llama-3.1-70b-instruct</li>
                <li><strong>OpenAI:</strong> gpt-4o-mini / gpt-4o</li>
                <li><strong>Anthropic:</strong> claude-3-5-haiku-20241022</li>
                <li><strong>Gemini:</strong> gemini-2.0-flash</li>
                <li><strong>Ollama:</strong> llama3 / mistral</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
