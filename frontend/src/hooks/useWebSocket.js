import { useEffect, useRef, useState, useCallback } from 'react'
export function useWebSocket(url) {
  const ws = useRef(null)
  const [connected, setConnected] = useState(false)
  const [lastEvent, setLastEvent] = useState(null)
  const listeners = useRef([])
  const connect = useCallback(() => {
    try {
      ws.current = new WebSocket(url)
      ws.current.onopen = () => setConnected(true)
      ws.current.onclose = () => { setConnected(false); setTimeout(connect, 3000) }
      ws.current.onerror = () => ws.current?.close()
      ws.current.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          setLastEvent(data)
          listeners.current.forEach(fn => fn(data))
        } catch {}
      }
    } catch {}
  }, [url])
  useEffect(() => { connect(); return () => ws.current?.close() }, [connect])
  const subscribe = useCallback((fn) => {
    listeners.current.push(fn)
    return () => { listeners.current = listeners.current.filter(f => f !== fn) }
  }, [])
  return { connected, lastEvent, subscribe }
}
