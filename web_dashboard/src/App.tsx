import { useEffect, useState } from 'react'

interface PredictionEvent {
  id: string
  timestamp: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: number
  packets: number
  bytes: number
  prediction: string
  risk: number
  latency_ms: number
}

interface StateData {
  status: string
  flows_tracked: number
  recent_predictions: PredictionEvent[]
}

function App() {
  const [data, setData] = useState<StateData>({ status: 'connecting', flows_tracked: 0, recent_predictions: [] })
  const [prevIds, setPrevIds] = useState<Set<string>>(new Set())

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/state')
        if (!res.ok) throw new Error('API Error')
        const json = await res.json()
        
        setData(prev => {
          setPrevIds(new Set(prev.recent_predictions.map(p => p.id)))
          return json
        })
      } catch (err) {
        console.error(err)
        setData(prev => ({ ...prev, status: 'offline' }))
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 1000)
    return () => clearInterval(interval)
  }, [])

  const attackCount = data.recent_predictions.filter(p => p.prediction === 'attack').length

  const getProtoName = (proto: number) => {
    if (proto === 6) return 'TCP'
    if (proto === 17) return 'UDP'
    if (proto === 1) return 'ICMP'
    return `PROT-${proto}`
  }

  const formatTime = (iso: string) => {
    const d = new Date(iso)
    return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' })
  }

  return (
    <div className="dashboard-container">
      <header>
        <h1>FluxShield ML Core</h1>
        <div className="status-badge" style={{ 
          borderColor: data.status === 'active' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
          color: data.status === 'active' ? 'var(--accent-green)' : 'var(--accent-red)',
          background: data.status === 'active' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)'
        }}>
          <div className="status-indicator" style={{
             backgroundColor: data.status === 'active' ? 'var(--accent-green)' : 'var(--accent-red)',
             boxShadow: `0 0 8px ${data.status === 'active' ? 'var(--accent-green)' : 'var(--accent-red)'}`
          }}></div>
          {data.status === 'active' ? 'SYSTEM LIVE' : 'SYSTEM OFFLINE'}
        </div>
      </header>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-title">Active Flows Tracked</div>
          <div className="stat-value blue">{data.flows_tracked.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="stat-title">Recent Detections</div>
          <div className="stat-value">{data.recent_predictions.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-title">DDoS Threat Alerts</div>
          <div className="stat-value red">{attackCount}</div>
        </div>
      </div>

      <div className="table-container">
        <div className="table-header">
          <h2>Live Network Telemetry & Inference</h2>
        </div>
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Proto</th>
              <th>Packets</th>
              <th>ML Decision</th>
              <th>Risk Score</th>
              <th>Latency</th>
            </tr>
          </thead>
          <tbody>
            {data.recent_predictions.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                  Awaiting network traffic...
                </td>
              </tr>
            ) : data.recent_predictions.map(event => (
              <tr key={event.id} className={!prevIds.has(event.id) ? 'new-row' : ''}>
                <td style={{ color: 'var(--text-muted)' }}>{formatTime(event.timestamp)}</td>
                <td style={{ fontFamily: 'monospace' }}>{event.src_ip}:{event.src_port}</td>
                <td style={{ fontFamily: 'monospace' }}>{event.dst_ip}:{event.dst_port}</td>
                <td>{getProtoName(event.protocol)}</td>
                <td>{event.packets.toLocaleString()}</td>
                <td>
                  <span className={`badge ${event.prediction}`}>
                    {event.prediction}
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <div className="risk-bar-container">
                      <div className={`risk-bar ${event.risk > 0.5 ? 'high' : 'low'}`} style={{ width: `${Math.max(5, event.risk * 100)}%` }}></div>
                    </div>
                    <span style={{ fontSize: '0.875rem', fontWeight: 600 }}>{(event.risk * 100).toFixed(1)}%</span>
                  </div>
                </td>
                <td style={{ color: 'var(--text-muted)' }}>{event.latency_ms.toFixed(1)} ms</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default App
