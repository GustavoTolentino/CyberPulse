'use client'
import './globals.css'
import { useState } from 'react'

export default function Home() {
  const [range, setRange] = useState('192.168.1.0/24')
  const [loading, setLoading] = useState(false)
  const [devices, setDevices] = useState(null)
  const [error, setError] = useState(null)

  const iniciarAnalise = async () => {
    console.log(`Iniciando análise para range: ${range}`)
    setLoading(true)
    setDevices(null)
    setError(null)
    try {
      const res = await fetch(`/api/scan?range=${encodeURIComponent(range)}`)
      console.log('Fetch concluído, status:', res.status)
      const data = await res.json()
      console.log('Dados recebidos:', data)
      setDevices(data.devices)
    } catch (err) {
      console.error('Erro na análise:', err)
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="card">
      <h1>Analisador de Vulnerabilidades</h1>

      <div className="form-group">
        <label htmlFor="range">Intervalo de rede:</label>
        <input
          id="range"
          type="text"
          value={range}
          onChange={e => setRange(e.target.value)}
        />
      </div>

      <button onClick={iniciarAnalise} disabled={loading} className="btn">
        {loading ? 'Analisando...' : 'Iniciar Análise'}
      </button>

      {/* Barra de progresso indeterminada */}
      {loading && <div className="progress"></div>}

      {/* Erro */}
      {error && <p className="error">{error}</p>}

      {/* Resultados */}
      {devices && (
        <div className="results">
          <h2>Resultados:</h2>
          <ul>
            {devices.map((device, idx) => (
              <li key={idx}>
                <strong>{device.ip}</strong> — {device.status}
                {device.openPorts.length > 0 ? (
                  <ul>
                    {device.openPorts.map((port, j) => (
                      <li key={j}>Porta {port.port}: {port.service}</li>
                    ))}
                  </ul>
                ) : (
                  <em>nenhuma porta aberta</em>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </main>
  )
}