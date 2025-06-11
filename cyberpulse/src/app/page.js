'use client'
import './globals.css'
import { useEffect, useState, useRef } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, Cell
} from 'recharts'

export default function Home() {
  const [range, setRange] = useState('172.16.43.0/24')
  const [results, setResults] = useState([])
  const [resumo, setResumo] = useState({ total: 0, comPortas: 0, comVulns: 0, escaneados: 0 })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [history, setHistory] = useState([])
  const [currentScanIndex, setCurrentScanIndex] = useState(-1)
  const cancelRef = useRef(false)

  useEffect(() => {
    setResumo({ total: 0, comPortas: 0, comVulns: 0, escaneados: 0 })
    setResults([])
  }, [])

  const chunk = (array, size) =>
    array.reduce((acc, _, i) =>
      i % size === 0 ? [...acc, array.slice(i, i + size)] : acc, [])

  async function iniciarAnalise() {
    setLoading(true)
    setResults([])
    setResumo({ total: 0, comPortas: 0, comVulns: 0, escaneados: 0 })
    setError(null)
    cancelRef.current = false

    const isCIDR = range.includes('/')
    let ips = []

    if (!isCIDR) {
      ips = [range]
    } else {
      const [network] = range.split('/')
      const octets = network.split('.')
      const base = octets.slice(0, 3).join('.') + '.'
      ips = Array.from({ length: 256 }, (_, i) => `${base}${i}`)
    }

    const batches = chunk(ips, isCIDR ? 5 : 1)

    try {
      let totalEscaneados = 0
      let allResults = []
      for (const batch of batches) {
        if (cancelRef.current) break
        const responses = await Promise.all(
          batch.map(ip =>
            fetch(`/api/scan?range=${encodeURIComponent(ip)}${!isCIDR ? '&modo=fast' : ''}`)
          )
        )
        const data = await Promise.all(
          responses.map((r, idx) =>
            r.ok
              ? r.json()
              : { ip: batch[idx], status: 'down', openPorts: [], vulnerabilities: [], error: `HTTP ${r.status}` }
          )
        )
        const comPortas = data.filter(d => d.openPorts.length > 0)
        const comVulns = data.filter(d => d.vulnerabilities?.length > 0)

        totalEscaneados += data.length
        allResults = [...allResults, ...data]
        setResults(prev => [...prev, ...data])
        setResumo(prev => ({
          total: ips.length,
          escaneados: totalEscaneados,
          comPortas: prev.comPortas + comPortas.length,
          comVulns: prev.comVulns + comVulns.length,
        }))
      }
      salvarCSV(allResults)
      setHistory(prev => [...prev, { results: allResults, resumo: { ...resumo } }])
      setCurrentScanIndex(history.length)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  function salvarCSV(data) {
    const headers = ['IP', 'Status', 'Portas', 'Vulnerabilidades']
    const linhas = data.map(r => {
      const portas = r.openPorts.map(p => `${p.port}/${p.service}`).join(', ')
      const vulns = r.vulnerabilities?.map(v => v.id).join(', ') || ''
      return `${r.ip},${r.error || r.status},${portas},${vulns}`
    })
    const csvContent = [headers.join(','), ...linhas].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `scan-${new Date().toISOString()}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  function cancelar() {
    cancelRef.current = true
    setLoading(false)
  }

  const progressoData = [
    { name: 'Escaneados', value: resumo.escaneados, fill: '#007bff' },
    { name: 'Restantes', value: resumo.total - resumo.escaneados, fill: '#66b2ff' },
  ]

  const resultadoData = [
    { name: 'Escaneados', value: resumo.escaneados - resumo.comPortas, fill: '#e9ecef' },
    { name: 'IPs com Portas', value: resumo.comPortas, fill: '#28a745' },
    { name: 'IPs com Vulns', value: resumo.comVulns, fill: '#dc3545' }
  ]

  function copiarResultado() {
    const texto = results.map(r => {
      const portas = r.openPorts.map(p => `${p.port}/${p.service}`).join(', ')
      const vulns = r.vulnerabilities?.map(v => v.id).join(', ') || ''
      return `${r.ip} — ${r.error || r.status} — Portas: ${portas || 'nenhuma'} — Vulns: ${vulns || 'nenhuma'}`
    }).join('\n')
    navigator.clipboard.writeText(texto)
  }

  function navegarScan(delta) {
    const newIndex = currentScanIndex + delta
    if (newIndex >= 0 && newIndex < history.length) {
      const scan = history[newIndex]
      setResults(scan.results)
      setResumo(scan.resumo)
      setCurrentScanIndex(newIndex)
    }
  }

  return (
    <main className="card" style={{ maxWidth: '1100px', margin: '2rem auto', padding: '0 2rem' }}>
      <h1 style={{ paddingTop: '20px' }}>
        <span style={{ fontFamily: "'Quantico', sans-serif" }}>CYBERPULSE</span> Analisador de Vulnerabilidades
      </h1>

      <div className="form-group">
        <label>Intervalo:</label>
        <input value={range} onChange={e => setRange(e.target.value)} />
      </div>

      <div className="button-group" style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
        <button onClick={iniciarAnalise} disabled={loading} className="btn">
          {loading ? 'Analisando...' : 'Iniciar Análise'}
        </button>
        {loading && (
          <button onClick={cancelar} className="btn-secondary">
            Cancelar
          </button>
        )}
      </div>

      {loading && <div className="progress"></div>}
      {error && <p className="error">{error}</p>}

      <div className="chart-row" style={{ display: 'flex', gap: '2rem' }}>
        <div className="chart-container">
          <h3>Progresso</h3>
          <BarChart width={400} height={250} data={progressoData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="value">
              {progressoData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </div>

        <div className="chart-container">
          <h3>Resultados</h3>
          <BarChart width={400} height={250} data={resultadoData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis domain={[0, resumo.escaneados]} />
            <Tooltip />
            <Legend />
            <Bar dataKey="value">
              {resultadoData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </div>
      </div>

      <div className="pagination-controls" style={{ display: 'flex', justifyContent: 'center', gap: '1rem', marginTop: '1.5rem' }}>
        <button onClick={() => navegarScan(-1)} disabled={currentScanIndex <= 0} className="btn-secondary">⬅ Anterior</button>
        <button onClick={() => navegarScan(1)} disabled={currentScanIndex >= history.length - 1} className="btn-secondary">Próximo ➡</button>
        {results.length > 0 && (
          <button onClick={copiarResultado} className="btn">📋 Copiar Resultados</button>
        )}
      </div>

      {results.length > 0 && (
  <div style={{ marginTop: '2rem' }} className='results'>
    <h2>Logs</h2>
    <ul className="log-list">
      {results.map((r, i) => (
        <li key={i}>
          <div>
            <strong>{r.ip}</strong> — {r.error || r.status} — Portas: {r.openPorts.map(p => `${p.port}/${p.service}`).join(', ') || 'nenhuma'}
          </div>
          {r.vulnerabilities?.length > 0 ? (
            <ul style={{ paddingLeft: '1.5rem', marginTop: '0.2rem' }}>
              {r.vulnerabilities.map((v, idx) => (
                <li key={idx} style={{ listStyleType: 'disc' }}>🛑 {v.id}</li>
              ))}
            </ul>
          ) : (
            <div style={{ paddingLeft: '1.5rem' }}>Vulns: nenhuma</div>
          )}
        </li>
      ))}
    </ul>
  </div>
)}

    </main>
  )
}
