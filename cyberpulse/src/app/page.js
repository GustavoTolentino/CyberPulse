'use client'
import './globals.css'
import { useEffect, useState, useRef } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, Cell
} from 'recharts'
import { Table } from 'react-bootstrap'

export default function Home() {
  const [range, setRange] = useState('172.16.43.0/24')
  const [results, setResults] = useState([])
  const [resumo, setResumo] = useState({ total: 0, comPortas: 0, comVulns: 0, escaneados: 0 })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [history, setHistory] = useState([])  // Histórico de resultados de scans
  const [currentScanIndex, setCurrentScanIndex] = useState(-1)  // Índice do scan atual no histórico
  const cancelRef = useRef(false)
  const [csvDate, setCsvDate] = useState('')

  useEffect(() => {
    const savedHistory = localStorage.getItem('scanHistory');
    if (savedHistory) {
      setHistory(JSON.parse(savedHistory));
    }
  }, []);

  useEffect(() => {
    if (history.length > 0) {
      localStorage.setItem('scanHistory', JSON.stringify(history));
    }
  }, [history]);

  const chunk = (array, size) =>
    array.reduce((acc, _, i) =>
      i % size === 0 ? [...acc, array.slice(i, i + size)] : acc, [])

  // Função para formatar a data no formato dd/mm/yyyy - HH:MM
  function formatDate(date) {
    const d = new Date(date);
    const day = String(d.getDate()).padStart(2, '0');
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const year = d.getFullYear();
    const hours = String(d.getHours()).padStart(2, '0');
    const minutes = String(d.getMinutes()).padStart(2, '0');
    return `${day}/${month}/${year} - ${hours}:${minutes}`;  // Garantir que a hora seja dinâmica
  }

  async function iniciarAnalise() {
    if (loading) return;  // Evitar que múltiplos cliques iniciem várias análises simultâneas

    setLoading(true)
    setResults([])  // Resetar os resultados antigos
    setResumo({ total: 0, comPortas: 0, comVulns: 0, escaneados: 0 })  // Resetar resumo

    const isCIDR = range.includes('/')
    let ips = []

    if (!isCIDR) {
      ips = [range]
      setResumo(prev => ({ ...prev, total: 1 }))
    } else {
      const [network] = range.split('/')
      const octets = network.split('.')
      const base = octets.slice(0, 3).join('.') + '.'
      ips = Array.from({ length: 256 }, (_, i) => `${base}${i}`)
      setResumo(prev => ({ ...prev, total: ips.length }))
    }

    setResumo(prev => ({ ...prev, escaneados: 0 }))

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

      const scanTime = new Date().toISOString()  // Guardar a data/hora do scan
      setCsvDate(formatDate(scanTime))  // Armazenar a data do scan formatada
      salvarCSV(allResults, scanTime)  // Passar a data também para o CSV

      setHistory(prev => [...prev, { results: allResults, resumo: { ...resumo }, scanTime }])  // Salvar a data no histórico
      setCurrentScanIndex(history.length)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
      cancelRef.current = false // Resetando o cancelamento para permitir novo scan
    }
  }

  function salvarCSV(data, scanTime) {
    if (!results.length) return;  // Impedir que o CSV seja baixado sem resultados

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
    a.download = `scan-${scanTime}.csv`  // Nomear o arquivo com a data do scan
    a.click()
    URL.revokeObjectURL(url)
  }

  function cancelar() {
    cancelRef.current = true
    setLoading(false)
    setResults([]) // Limpa os resultados quando o scan for cancelado
    setResumo({ total: 0, comPortas: 0, comVulns: 0, escaneados: 0 }) // Limpa o resumo também
  }

  function navegarScan(delta) {
    const newIndex = currentScanIndex + delta
    if (newIndex >= 0 && newIndex < history.length) {
      const scan = history[newIndex]
      setResults(scan.results)
      setResumo(scan.resumo)
      setCsvDate(formatDate(scan.scanTime))  // Atualiza a data do CSV com a data do scan atual
      setCurrentScanIndex(newIndex)
    }
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
      <h1 style={{ paddingTop: '30px', paddingBottom: '20px', fontFamily: 'Quantico, sans-serif' }}>
        <span style={{fontSize: 30}}>CYBERPULSE</span> - Analisador de Vulnerabilidades
      </h1>

      <div className="form-group" style={{ display: 'flex', gap: '1rem', alignItems: 'center', justifyContent: 'center' }}>
        <input
          value={range}
          onChange={e => setRange(e.target.value)}
          style={{ width: '30%', padding: '8px', borderRadius: '6px', border: '1px solid var(--border)' }}
        />
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

      <div className="chart-row" style={{ display: 'flex', gap: '2rem', alignItems: 'center', justifyContent: 'center' }}>
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

      <div className="pagination-controls" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '1rem', marginTop: '1.5rem', paddingBottom: '4rem' }}>
        <button onClick={() => navegarScan(-1)} disabled={currentScanIndex <= 0} className="btn-secondary">⬅ Anterior</button>
        <button onClick={() => navegarScan(1)} disabled={currentScanIndex >= history.length - 1} className="btn-secondary">Próximo ➡</button>
      </div>

      {results.length > 0 ? (
        <div style={{ marginTop: '2rem', paddingBottom: '4rem' }} className='results'>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <h2>Logs</h2>
            <span style={{ fontWeight: 'bold' }}>{`Scan realizado em: ${csvDate}`}</span>
            <button onClick={copiarResultado} className="btn" style={{ marginLeft: '4rem' }}>📋 Copiar</button>
          </div>

          <div className="table-container">
            <Table striped bordered hover>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Status</th>
                  <th>Portas</th>
                  <th>Vulnerabilidades</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => (
                  <tr key={i}>
                    <td>{r.ip}</td>
                    <td>{r.error || r.status}</td>
                    <td>{r.openPorts.length > 0 ? r.openPorts.map(p => `${p.port}/${p.service}`).join(', ') : 'nenhuma'}</td>
                    <td>
                      {r.vulnerabilities?.length > 0 ? r.vulnerabilities.map(v => (
                        <a key={v.id} href={`https://www.google.com/search?q=${encodeURIComponent(v.id)}`} target="_blank" rel="noopener noreferrer">
                          {v.id}
                        </a>
                      )) : 'nenhuma'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        </div>
      ) : (
        <div style={{ marginTop: '2rem', paddingBottom: '4rem' }}>
          <div className="table-container">
            <Table striped bordered hover>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Status</th>
                  <th>Portas</th>
                  <th>Vulnerabilidades</th>
                </tr>
              </thead>
              <tbody>
                <tr className="skeleton-row">
                  <td>000.000.000.0</td>
                  <td>up</td>
                  <td>0000</td>
                  <td>http://xxxxxxxxxx.com</td>
                </tr>
                <tr className="skeleton-row">
                  <td>000.000.000.1</td>
                  <td>down</td>
                  <td>0000</td>
                  <td>nenhuma</td>
                </tr>
              </tbody>
            </Table>
          </div>
        </div>
      )}
        <style>
    @import url('https://fonts.googleapis.com/css2?family=Quantico:ital,wght@0,400;0,700;1,400;1,700&display=swap');
    </style>
    </main>
    
  )
}
