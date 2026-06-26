/**
 * useAI — React hook for IIFVDCAS AI features.
 *
 * Reads AI provider config from localStorage and adds the required headers
 * (X-AI-Provider, X-AI-Key, X-AI-Model, X-AI-Base-URL) to every AI request.
 */
import { useState, useCallback } from 'react'
import axios from 'axios'

const STORAGE_KEY = 'iifvdcas_ai_config'

/** Default config shape */
const DEFAULT_CONFIG = {
  provider:  '',        // nvidia_nim | openai | anthropic | gemini | ollama
  apiKey:    '',
  model:     '',
  baseUrl:   '',
}

/**
 * Load config from localStorage.
 * @returns {typeof DEFAULT_CONFIG}
 */
export function loadAIConfig() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...DEFAULT_CONFIG }
    return { ...DEFAULT_CONFIG, ...JSON.parse(raw) }
  } catch {
    return { ...DEFAULT_CONFIG }
  }
}

/**
 * Save config to localStorage.
 * @param {typeof DEFAULT_CONFIG} config
 */
export function saveAIConfig(config) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(config))
}

/**
 * Build Axios headers from a config object.
 * @param {typeof DEFAULT_CONFIG} config
 */
export function buildAIHeaders(config) {
  const headers = {}
  if (config.provider)  headers['X-AI-Provider']  = config.provider
  if (config.apiKey)    headers['X-AI-Key']        = config.apiKey
  if (config.model)     headers['X-AI-Model']      = config.model
  if (config.baseUrl)   headers['X-AI-Base-URL']   = config.baseUrl
  return headers
}

const aiAxios = axios.create({ baseURL: '/api/v1/ai', timeout: 60000 })

/**
 * Primary hook — use inside any component that needs AI features.
 *
 * @example
 *   const { callAI, isConfigured, loading, error } = useAI()
 *   const result = await callAI('explain-cve', { cve_id, description, firmware_context })
 */
export function useAI() {
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')

  const config = loadAIConfig()
  const isConfigured = !!(config.provider && (config.apiKey || config.provider === 'ollama'))

  const callAI = useCallback(async (endpoint, body) => {
    const cfg = loadAIConfig()
    if (!cfg.provider) {
      throw new Error('AI not configured. Go to AI Settings to set up your provider.')
    }
    setLoading(true)
    setError('')
    try {
      const resp = await aiAxios.post(`/${endpoint}`, body, {
        headers: buildAIHeaders(cfg),
      })
      return resp.data
    } catch (err) {
      const msg =
        err.response?.data?.detail ||
        err.response?.data?.message ||
        err.message ||
        'AI request failed'
      setError(msg)
      throw new Error(msg)
    } finally {
      setLoading(false)
    }
  }, [])

  return { callAI, isConfigured, loading, error, setError, config }
}

export default useAI
