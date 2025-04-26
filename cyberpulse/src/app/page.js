'use client'

import { useState } from 'react'

export default function Home() {
  const [range, setRange] = useState('192.168.1.0/24')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const iniciarAnalise = async () => {
    setLoading(true)
    setResult(null)
    setError(null)
    try {
      const res = await fetch(`/api/scan?range=${encodeURIComponent(range)}`)
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Erro desconhecido')
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="flex flex-col items-center justify-center min-h-screen bg-gray-100 p-6 text-gray-900">
      <h1 className="text-3xl font-bold mb-6 text-center">CyberPulse</h1>

      <label className="mb-2 flex flex-col items-start w-full max-w-md">
        <span className="mb-1 font-medium">Intervalo de rede:</span>
        <input
          type="text"
          value={range}
          onChange={e => setRange(e.target.value)}
          className="w-full p-2 border rounded text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </label>

      <button
        onClick={iniciarAnalise}
        disabled={loading}
        className="mt-4 bg-blue-600 disabled:opacity-50 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-lg mb-6"
      >
        {loading ? 'Analisando...' : 'Iniciar Análise'}
      </button>

      {error && (
        <div className="text-red-600 font-medium mb-4">
          {error}
        </div>
      )}

      {result && (
        <div className="w-full max-w-2xl bg-white p-6 rounded-lg shadow-md text-gray-900">
          <h2 className="text-2xl font-bold mb-4">Resultados:</h2>
          <ul className="list-disc list-inside space-y-2">
            {result.devices.map((device, i) => (
              <li key={i}>
                <strong>{device.ip}</strong> — {device.status}
                {device.openPorts.length > 0 ? (
                  <ul className="list-disc list-inside ml-5 text-sm">
                    {device.openPorts.map((p, j) => (
                      <li key={j}>Porta {p.port}: {p.service}</li>
                    ))}
                  </ul>
                ) : (
                  <span className="ml-2 text-sm text-gray-500">nenhuma porta aberta</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </main>
  )
}
