'use client'
import './globals.css'
import { useState, useRef } from 'react'

export default function Home() {
  const [range, setRange] = useState('192.168.1.0/24')
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const cancelRef = useRef(false)

  const chunk = (array, size) =>
    array.reduce((acc, _, i) =>
      i % size === 0 ? [...acc, array.slice(i, i + size)] : acc,
    [])

  async function iniciarAnalise() {
    setLoading(true)
    setResults([])
    setError(null)
    cancelRef.current = false

    const [network] = range.split('/')
    const octets = network.split('.')
    const base = octets.slice(0, 3).join('.') + '.'
    const ips = Array.from({ length: 256 }, (_, i) => `${base}${i}`)
    const batches = chunk(ips, 5)

    try {
      for (const batch of batches) {
        if (cancelRef.current) break
        const responses = await Promise.all(
          batch.map(ip =>
            fetch(`/api/scan?range=${encodeURIComponent(ip)}`)
          )
        )
        const data = await Promise.all(
          responses.map((r, idx) =>
            r.ok
              ? r.json()
              : { ip: batch[idx], status: 'down', openPorts: [], error: `HTTP ${r.status}` }
          )
        )
        setResults(prev => [...prev, ...data])
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  function cancelar() {
    cancelRef.current = true
    setLoading(false)
  }

  return (
    <main className="card">
      <h1>Analisador de Vulnerabilidades</h1>

      <div className="form-group">
        <label>Intervalo:</label>
        <input
          value={range}
          onChange={e => setRange(e.target.value)}
        />
      </div>

      <div className="button-group">
        <button
          onClick={iniciarAnalise}
          disabled={loading}
          className="btn"
        >
          {loading ? 'Analisando...' : 'Iniciar Análise'}
        </button>
        {loading && (
          <button
            onClick={cancelar}
            className="btn-secondary"
          >
            Cancelar
          </button>
        )}
      </div>

      {loading && <div className="progress"></div>}
      {error && <p className="error">{error}</p>}

      <div className="results">
        {results.map(({ ip, status, openPorts, error }) => (
          <div key={ip}>
            <strong>{ip}</strong> — {error || status}
            {openPorts.length ? (
              <ul>
                {openPorts.map(p => (
                  <li key={p.port}>{p.port}/{p.service}</li>
                ))}
              </ul>
            ) : (
              <em>  nenhuma porta aberta</em>
            )}
          </div>
        ))}
      </div>
    </main>
  )
}