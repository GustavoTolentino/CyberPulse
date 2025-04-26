import { parseStringPromise } from 'xml2js'
import { promisify } from 'util'
import { execFile } from 'child_process'

// Caminho completo do nmap.exe com barras escapadas
const NMAP_CMD = "D:\\Program Files (x86)\\Nmap\\nmap.exe"

const execFileAsync = promisify(execFile)

// Lista de portas personalizadas
const COMMON_PORTS = [21,22,23,25,53,67]
const PORT_LIST = COMMON_PORTS.join(',')

export async function GET(request) {
  const { searchParams } = new URL(request.url)
  const range = searchParams.get('range') || '192.168.1.0/24'

  // Feedback no console do comando exato sendo executado
  console.log('🔍 Executando Nmap com:', NMAP_CMD, ['-Pn','-T4','-p',PORT_LIST,'-oX','-',range])

  try {
    const { stdout } = await execFileAsync(
      NMAP_CMD,
      ['-Pn', '-T4', '-p', PORT_LIST, '-oX', '-', range]
    )

    console.log('✅ Nmap finalizado em', range)

    const parsed = await parseStringPromise(stdout, { explicitArray: false })
    let hosts = parsed.nmaprun.host || []
    hosts = Array.isArray(hosts) ? hosts : [hosts]

    const devices = hosts.map(host => {
      const addrs = host.address
        ? (Array.isArray(host.address) ? host.address : [host.address])
        : []
      const addrObj = addrs.find(a => a.$.addrtype === 'ipv4') || addrs[0] || {}
      const ip = addrObj.$?.addr || 'unknown'
      const status = host.status?.$.state || 'unknown'

      const portsArr = host.ports?.port
        ? (Array.isArray(host.ports.port) ? host.ports.port : [host.ports.port])
        : []
      const openPorts = portsArr
        .filter(p => p.state?.$?.state === 'open')
        .map(p => ({ port: Number(p.$.portid), service: p.service?.$.name || 'unknown' }))

      return { ip, status, openPorts }
    })

    return new Response(JSON.stringify({ devices }), {
      headers: { 'Content-Type': 'application/json' }
    })
  } catch (err) {
    console.error('Erro ao chamar Nmap:', err)
    return new Response(
      JSON.stringify({ error: 'Falha na varredura', detail: err.message }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    )
  }
}