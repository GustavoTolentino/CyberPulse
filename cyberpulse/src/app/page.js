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
  const [fastMode, setFastMode] = useState(false)
  const cancelRef = useRef(false)

  const fastScanIPs = [
    '172.16.43.1','172.16.43.19','172.16.43.21','172.16.43.43','172.16.43.57',
    '172.16.43.60','172.16.43.61','172.16.43.80','172.16.43.85','172.16.43.101',
    '172.16.43.105','172.16.43.120','172.16.43.140','172.16.43.146','172.16.43.160',
    '172.16.43.180','172.16.43.202','172.16.43.227','172.16.43.245','172.16.43.253',
    '172.16.43.254'
  ]

  useEffect(() => {
    setResumo({ total: 0, comPortas: 0, comVulns: 0, escaneados: 0 })
    setResults([])
  }, [fastMode])

  const chunk = (array, size) =>
    array.reduce((acc, _, i) =>
      i % size === 0 ? [...acc, array.slice(i, i + size)] : acc, [])

  async function iniciarAnalise() {
    setLoading(true)
    setResults([])
    setResumo({ total: 0, comPortas: 0, comVulns: 0, escaneados: 0 })
    setError(null)
    cancelRef.current = false

    const [network] = range.split('/')
    const octets = network.split('.')
    const base = octets.slice(0, 3).join('.') + '.'
    const ips = fastMode
      ? fastScanIPs
      : Array.from({ length: 256 }, (_, i) => `${base}${i}`)

    const batches = chunk(ips, 5)

    try {
      let totalEscaneados = 0
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
              : { ip: batch[idx], status: 'down', openPorts: [], vulnerabilities: [], error: `HTTP ${r.status}` }
          )
        )
        const comPortas = data.filter(d => d.openPorts.length > 0)
        const comVulns = data.filter(d => d.vulnerabilities?.length > 0)

        totalEscaneados += data.length
        setResults(prev => [...prev, ...data])
        setResumo(prev => ({
          total: ips.length,
          escaneados: totalEscaneados,
          comPortas: prev.comPortas + comPortas.length,
          comVulns: prev.comVulns + comVulns.length,
        }))
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

  return (
    <main className="card" style={{ maxWidth: '1100px', margin: '2rem auto', padding: '0 2rem' }}>
      <h1 style={{ paddingTop: '20px' }}>
        <span style={{ fontFamily: "'Quantico', sans-serif" }}>CYBERPULSE</span> Analisador de Vulnerabilidades
      </h1>

      <div className="form-group">
        <label>Intervalo:</label>
        <input value={range} onChange={e => setRange(e.target.value)} />
      </div>

      <div className="form-group switch-group" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <label className="switch">
          <input type="checkbox" checked={fastMode} onChange={() => setFastMode(!fastMode)} />
          <span className="slider round"></span>
        </label>
        <span style={{ fontWeight: 'bold', fontSize: '1rem' }}>Fast Scan</span>
      </div>

      <div className="button-group">
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

      {results.length > 0 && (
        <button
          title="Copiar resultados"
          onClick={copiarResultado}
          style={{ float: 'right', marginTop: '1rem', fontSize: '1rem', border: 'none', background: 'transparent', cursor: 'pointer' }}
        >
          📄
        </button>
      )}

      <div className="results" style={{ maxHeight: '300px', overflowY: 'auto', marginTop: '3rem' }}>
        {results.map(({ ip, status, openPorts, vulnerabilities, error }, idx) => (
          <div key={`${ip}-${idx}`}>
            <strong>{ip}</strong> — {error || status}
            {openPorts.length ? (
              <ul>
                {openPorts.map((p, i) => (
                  <li key={`${ip}-${p.port}-${i}`}>{p.port}/{p.service}</li>
                ))}
              </ul>
            ) : (
              <em> nenhuma porta aberta</em>
            )}
            {vulnerabilities?.length > 0 && (
              <details>
                <summary>Vulnerabilidades encontradas</summary>
                <ul>
                  {vulnerabilities.map((v, i) => (
                    <li key={`${ip}-vuln-${i}`}>{v.port}: {v.id} — {v.output}</li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        ))}
      </div>
    </main>
  )
}
