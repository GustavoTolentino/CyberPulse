import { parseStringPromise } from 'xml2js'
import { promisify } from 'util'
import { execFile } from 'child_process'
import path from 'path'

// Se o VSCode não “vê” o nmap no PATH, você pode apontar direto para o .exe:
// const NMAP_CMD = 'C:\\Program Files (x86)\\Nmap\\nmap.exe'
const NMAP_CMD = 'D:\\Program Files (x86)\\Nmap\\nmap.exe'

const execFileAsync = promisify(execFile)

export async function GET(request) {
  const { searchParams } = new URL(request.url)
  const range = searchParams.get('range') || '192.168.1.0/24'

  try {
    // Chama o nmap escaneando portas 1-1024, saída em XML no stdout
    const { stdout } = await execFileAsync(NMAP_CMD, [
      '-p', '1-1024',
      '-T4',
      '-oX', '-',    // “-” envia XML para stdout
      range
    ])

    // Converte XML para JS
    const parsed = await parseStringPromise(stdout, { explicitArray: false })
    const hosts = parsed.nmaprun.host
    const devicesArray = Array.isArray(hosts) ? hosts : [hosts]

    const devices = devicesArray.map(host => {
      const addr = host.address?.$.addr
      const status = host.status?.$.state

      let openPorts = []
      if (host.ports && host.ports.port) {
        const ports = Array.isArray(host.ports.port)
          ? host.ports.port
          : [host.ports.port]
        openPorts = ports
          .filter(p => p.state.$.state === 'open')
          .map(p => ({
            port: Number(p.$.portid),
            service: p.service?.$.name || 'unknown'
          }))
      }

      return { ip: addr, status, openPorts }
    })

    return new Response(JSON.stringify({ devices }), {
      headers: { 'Content-Type': 'application/json' }
    })
  } catch (err) {
    console.error('Erro ao chamar Nmap:', err)
    return new Response(
      JSON.stringify({ error: 'Falha ao executar varredura', detail: err.message }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    )
  }
}
