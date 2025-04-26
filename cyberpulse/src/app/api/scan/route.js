import { parseStringPromise } from 'xml2js'
import { promisify } from 'util'
import { execFile } from 'child_process'

// CAMINHO DO NMAP (ajuste via "Copy as path")
const NMAP_CMD = "D:\\Program Files (x86)\\Nmap\\nmap.exe"
const execFileAsync = promisify(execFile)

// 100 portas TCP comuns
const COMMON_PORTS = [
  21,22,23,25,53,67,68,69,80,81,
  110,119,123,137,138,139,143,161,162,179,
  389,443,445,465,514,515,587,631,636,873,
  993,995,1080,1194,1433,1521,1723,2049,2100,2222,
  2483,3306,3389,3986,5432,5631,5900,5985,5986,6379,
  6667,7001,8080,8443,8888,9000,9090,9200,9300,11211,
  27017,27018,27019,28017,5000,5001,5002,5003,54321,32768,
  49152,49153,49154,49155,49156,49157,6000,6001,6666,7000,
  7443,8000,8008,8009,8443,9001,10000,10514,11234,16200,
  20000,32769,49158,49159,49160,49161,49162,49163,49164,49165
]
const PORT_LIST = COMMON_PORTS.join(',')

export async function GET(request) {
  const { searchParams } = new URL(request.url)
  const range = searchParams.get('range') || '192.168.1.0/24'

  console.log('🔍 Iniciando Nmap em', range)

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
        .map(p => ({
          port: Number(p.$.portid),
          service: p.service?.$.name || 'unknown'
        }))

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